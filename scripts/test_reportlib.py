#!/usr/bin/env python3
"""Unit tests for report JSON, the email body, and the DIUN notifier."""

from __future__ import annotations

import json
import os
import smtplib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reportlib import (
    annotate_report,
    atomic_write_json,
    build_message,
    count_vulnerabilities,
    email_subject,
    error_report,
    findings_for_email,
    load_env_file,
    parse_env_line,
    read_update_status,
    redact,
    render_html,
    render_plain,
    safe_report_filename,
    send_email,
    summary_from_reports,
)
from scan_runner import _publish
from send_report import main as send_main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


class EnvTests(unittest.TestCase):
    def test_parse_quotes_comments_and_export(self) -> None:
        self.assertIsNone(parse_env_line("# comment"))
        self.assertIsNone(parse_env_line("not a setting"))
        self.assertEqual(parse_env_line('export SERVER_ID="edge-01"'), ("SERVER_ID", "edge-01"))
        self.assertEqual(parse_env_line('SMTP_PASSWORD="sec#ret=1"'), ("SMTP_PASSWORD", "sec#ret=1"))
        self.assertEqual(parse_env_line("FOO='bar'"), ("FOO", "'bar'"))

    def test_load_does_not_override_existing_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text('SERVER_ID="from-file"\nSMTP_HOST="mail.example"\n', encoding="utf-8")
            with mock.patch.dict(os.environ, {"SERVER_ID": "from-env", "SMTP_HOST": ""}, clear=False):
                load_env_file(path)
                self.assertEqual(os.environ["SERVER_ID"], "from-env")
                self.assertEqual(os.environ["SMTP_HOST"], "mail.example")


class ReportTests(unittest.TestCase):
    def test_filenames(self) -> None:
        used: set[str] = set()
        self.assertEqual(safe_report_filename("nginx:latest", used), "nginx_latest.json")
        self.assertEqual(safe_report_filename("postgres:16", used), "postgres_16.json")
        self.assertEqual(
            safe_report_filename("ghcr.io/org/app:1.2.3", used),
            "ghcr.io_org_app_1.2.3.json",
        )
        self.assertEqual(
            safe_report_filename("registry.example/app:1.2.3", set()),
            "registry.example_app_1.2.3.json",
        )
        collided = safe_report_filename("nginx_latest", used)
        self.assertTrue(collided.endswith(".json"))
        self.assertNotEqual(collided, "nginx_latest.json")

    def test_counts_skip_low_and_duplicates(self) -> None:
        document = {
            "Results": [
                {
                    "Target": "os",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-1", "PkgName": "liba", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-1", "PkgName": "liba", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"},
                        {"VulnerabilityID": "CVE-2", "PkgName": "libb", "InstalledVersion": "1", "FixedVersion": "", "Severity": "low"},
                        {"VulnerabilityID": "CVE-3", "PkgName": "libc", "InstalledVersion": "1", "FixedVersion": "", "Severity": "MEDIUM"},
                    ],
                }
            ]
        }
        self.assertEqual(count_vulnerabilities(document), {"critical": 0, "high": 1, "medium": 1})
        rows, _omitted = findings_for_email(document)
        self.assertEqual([row.vulnerability_id for row in rows], ["CVE-1", "CVE-3"])
        self.assertEqual(rows[1].fixed, "unfixed")

    def test_annotate_and_summary_carry_server_id(self) -> None:
        report = annotate_report(
            {"SchemaVersion": 2, "Results": []},
            server_id="edge-01",
            hostname="edge-01.internal",
            image="nginx:latest",
            report_file="nginx_latest.json",
            scanned_at="2026-11-20T02:00:00Z",
            duration_seconds=4,
            containers=[{"id": "abc", "name": "web", "compose_project": "web", "compose_service": "nginx"}],
        )
        self.assertEqual(report["server_id"], "edge-01")
        self.assertEqual(report["SchemaVersion"], 2)
        failed = error_report(
            server_id="edge-01",
            hostname="edge-01.internal",
            image="app:1",
            report_file="app_1.json",
            scanned_at="2026-11-20T02:00:00Z",
            duration_seconds=1,
            containers=[],
            error="boom",
        )
        summary = summary_from_reports(
            [report, failed],
            server_id="edge-01",
            hostname="edge-01.internal",
            scan_time="2026-11-20T02:00:00Z",
            finished_at="2026-11-20T02:00:05Z",
            duration_seconds=5,
            reports_dir="/srv/data/trivy/reports",
            severity_filter=["CRITICAL", "HIGH", "MEDIUM"],
            update_status={"file": "updates.json", "available": 0, "updated_at": None},
        )
        for key in ("server_id", "scan_time", "images_scanned", "critical", "high", "medium", "images"):
            self.assertIn(key, summary)
        self.assertEqual(summary["server_id"], "edge-01")
        self.assertEqual(summary["images_scanned"], 2)
        self.assertEqual(summary["images_failed"], 1)
        self.assertEqual(summary["images"][0]["status"], "error")

    def test_email_is_container_scoped_and_escapes_html(self) -> None:
        nasty = annotate_report(
            {
                "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
                "Results": [
                    {
                        "Target": "app",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-9",
                                "PkgName": "lib<script>",
                                "InstalledVersion": "1",
                                "FixedVersion": "2",
                                "Severity": "CRITICAL",
                                "Title": "<script>alert(1)</script>",
                                "PrimaryURL": "javascript:alert(1)",
                            }
                        ],
                    }
                ],
            },
            server_id="edge-01",
            hostname="edge-01",
            image="app:1",
            report_file="app_1.json",
            scanned_at="2026-11-20T02:00:00Z",
            duration_seconds=1,
            containers=[
                {"id": "c1", "name": "web-a", "compose_project": "web", "compose_service": "a"},
                {"id": "c2", "name": "web-b", "compose_project": "web", "compose_service": "b"},
            ],
        )
        summary = summary_from_reports(
            [nasty],
            server_id="edge-01",
            hostname="edge-01",
            scan_time="2026-11-20T02:00:00Z",
            finished_at="2026-11-20T02:00:01Z",
            duration_seconds=1,
            reports_dir="/srv/data/trivy/reports",
            severity_filter=["CRITICAL", "HIGH", "MEDIUM"],
            update_status={"file": "updates.json", "available": 2, "updated_at": "2026-11-20T04:00:00Z"},
        )
        plain = render_plain(summary, {"app_1.json": nasty})
        html = render_html(summary, {"app_1.json": nasty})
        self.assertEqual(plain.count("Container web-a"), 1)
        self.assertEqual(plain.count("Container web-b"), 1)
        self.assertIn("Image: app:1", plain)
        self.assertIn("CVE-9", plain)
        self.assertIn("MEDIUM (0)", plain)
        self.assertIn("Update notifications: 2", plain)
        self.assertNotIn("javascript:", plain)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("edge-01", email_subject(summary))

    def test_row_cap_is_per_severity(self) -> None:
        vulnerabilities = [
            {
                "VulnerabilityID": f"CVE-{index}",
                "PkgName": f"pkg{index}",
                "InstalledVersion": "1",
                "FixedVersion": "2",
                "Severity": "MEDIUM",
            }
            for index in range(3)
        ]
        document = {"Results": [{"Target": "os", "Vulnerabilities": vulnerabilities}]}
        with mock.patch.dict(os.environ, {"EMAIL_MAX_ROWS_PER_SEVERITY": "1"}, clear=False):
            rows, omitted = findings_for_email(document)
        self.assertEqual(len(rows), 1)
        self.assertEqual(omitted["MEDIUM"], 2)

    def test_publish_keeps_update_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            staging = reports / ".incoming"
            staging.mkdir()
            (reports / "updates.json").write_text("{}\n", encoding="utf-8")
            (reports / "old_image.json").write_text("{}\n", encoding="utf-8")
            (staging / "summary.json").write_text('{"server_id":"edge-01"}\n', encoding="utf-8")
            (staging / "nginx_latest.json").write_text("{}\n", encoding="utf-8")
            _publish(staging, reports)
            self.assertEqual((reports / "updates.json").read_text(encoding="utf-8"), "{}\n")
            self.assertFalse((reports / "old_image.json").exists())
            self.assertTrue((reports / "nginx_latest.json").is_file())
            self.assertIn("edge-01", (reports / "summary.json").read_text(encoding="utf-8"))

    def test_update_status_counts_actionable_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "updates.json"
            atomic_write_json(
                path,
                {
                    "server_id": "edge-01",
                    "updated_at": "2026-11-20T04:00:00Z",
                    "updates": [
                        {"status": "update", "update_available": True},
                        {"status": "new"},
                        {"status": "skip", "update_available": False},
                    ],
                },
            )
            status = read_update_status(path)
        self.assertEqual(status["available"], 2)


class MailTests(unittest.TestCase):
    def test_send_starttls(self) -> None:
        summary = {"server_id": "edge-01", "critical": 1, "high": 0, "medium": 0, "images_failed": 0}
        sent: list = []

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                self.host = host
                self.port = port
                self.tls = False
                self.auth = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def ehlo(self):
                return None

            def starttls(self, context=None):
                self.tls = True

            def login(self, user, password):
                self.auth = (user, password)

            def send_message(self, message):
                sent.append(message)

        env = {
            "SMTP_HOST": "mail.example",
            "SMTP_PORT": "587",
            "SMTP_TLS": "starttls",
            "SMTP_USER": "scanner",
            "SMTP_PASSWORD": "s3cret",
            "SMTP_FROM": "scanner@example.com",
            "SMTP_TO": "ops@example.com, oncall@example.com",
            "EMAIL_SUBJECT_PREFIX": "[trivy]",
        }
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(smtplib, "SMTP", FakeSMTP):
            send_email(summary, "plain", "<p>plain</p>")
        self.assertEqual(len(sent), 1)
        self.assertIn("edge-01", sent[0]["Subject"])
        self.assertEqual(sent[0]["To"], "ops@example.com, oncall@example.com")
        self.assertNotIn("s3cret", sent[0].as_string())

    def test_dry_run_and_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            summary = {
                "server_id": "edge-01",
                "hostname": "edge-01",
                "scan_time": "2026-11-20T02:00:00Z",
                "finished_at": "2026-11-20T02:00:01Z",
                "scan_duration_seconds": 1,
                "images_scanned": 0,
                "images_failed": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "images": [],
                "update_status": {"available": 0},
                "reports_dir": str(reports),
            }
            (reports / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            (reports / "empty.env").write_text("", encoding="utf-8")
            with mock.patch.dict(os.environ, {"EMAIL_ENABLED": "false", "TRIVY_ENV_FILE": str(reports / "empty.env")}):
                buffer = StringIO()
                with redirect_stdout(buffer):
                    self.assertEqual(send_main(["--reports", str(reports), "--dry-run"]), 0)
                self.assertIn("edge-01", buffer.getvalue())
                self.assertEqual(send_main(["--reports", str(reports)]), 0)

    def test_enabled_without_smtp_is_a_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            summary = {
                "server_id": "edge-01",
                "hostname": "edge-01",
                "scan_time": "2026-11-20T02:00:00Z",
                "finished_at": "2026-11-20T02:00:01Z",
                "scan_duration_seconds": 1,
                "images_scanned": 0,
                "images_failed": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "images": [],
                "update_status": {"available": None},
            }
            (reports / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            (reports / "empty.env").write_text("", encoding="utf-8")
            env = {
                "EMAIL_ENABLED": "true",
                "SMTP_HOST": "",
                "SMTP_FROM": "",
                "SMTP_TO": "",
                "TRIVY_ENV_FILE": str(reports / "empty.env"),
            }
            with mock.patch.dict(os.environ, env, clear=False):
                self.assertEqual(send_main(["--reports", str(reports)]), 4)

    def test_redact_hides_the_password(self) -> None:
        with mock.patch.dict(os.environ, {"SMTP_PASSWORD": "s3cret"}, clear=False):
            self.assertNotIn("s3cret", redact("login failed for s3cret"))

    def test_message_sets_server_header(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"SMTP_FROM": "scanner@example.com", "SMTP_TO": "ops@example.com"},
            clear=False,
        ):
            message = build_message({"server_id": "edge-01", "critical": 0, "high": 0, "medium": 0}, "plain", "<p>x</p>")
        self.assertEqual(message["X-Image-Watch-Server"], "edge-01")


class ExampleTests(unittest.TestCase):
    def test_examples_have_server_id_and_match_the_renderer(self) -> None:
        documents = list(EXAMPLES.glob("*.json"))
        self.assertGreaterEqual(len(documents), 4)
        for path in documents:
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document.get("server_id"), "example-server", path.name)
            self.assertEqual(document.get("report_schema"), 1, path.name)
        summary = json.loads((EXAMPLES / "summary.json").read_text(encoding="utf-8"))
        reports = {
            image["report_file"]: json.loads((EXAMPLES / image["report_file"]).read_text(encoding="utf-8"))
            for image in summary["images"]
        }
        rendered = render_plain(summary, reports)
        self.assertEqual((EXAMPLES / "email-report.txt").read_text(encoding="utf-8"), rendered)
        self.assertIn("Container web-nginx", rendered)
        self.assertIn("Container web-db", rendered)
        self.assertIn("CVE-2099-9001", rendered)
        self.assertIn("fixed=unfixed", rendered)
        self.assertNotIn("LOW", rendered)
        failed = json.loads((EXAMPLES / "summary-with-failure.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(failed["images_failed"], 1)
        failed_reports = {
            image["report_file"]: json.loads((EXAMPLES / image["report_file"]).read_text(encoding="utf-8"))
            for image in failed["images"]
        }
        failed_mail = render_plain(failed, failed_reports)
        self.assertIn("Scan failures", failed_mail)
        self.assertIn("web-app", failed_mail)
        self.assertIn("Container web-nginx", failed_mail)
        self.assertNotIn("Container web-app", failed_mail)


class DiunTests(unittest.TestCase):
    def _run(self, directory: Path, **extra: str) -> dict:
        env = os.environ.copy()
        env.update(
            {
                "REPORTS_DIR": str(directory),
                "SERVER_ID": "example-server",
                "DIUN_HOSTNAME": "example-server",
                "OBSERVED_AT": "2026-11-20T04:00:00Z",
                "DIUN_ENTRY_STATUS": "update",
                "DIUN_ENTRY_IMAGE": "docker.io/library/nginx:latest",
                "DIUN_ENTRY_DIGEST": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "DIUN_ENTRY_PLATFORM": "linux/amd64",
                "DIUN_ENTRY_PROVIDER": "docker",
                "DIUN_ENTRY_HUBLINK": "https://hub.docker.com/_/nginx",
                "DIUN_ENTRY_CREATED": "2026-11-20 03:00:00 +0000 UTC",
                "DIUN_ENTRY_METADATA_CTN_NAMES": "web-nginx,web-nginx-b",
            }
        )
        env.update(extra)
        subprocess.run(["sh", str(ROOT / "scripts" / "diun-notify.sh")], check=True, env=env, cwd=directory)
        return json.loads((directory / "updates.json").read_text(encoding="utf-8"))

    def test_notifier_matches_the_example_and_escapes(self) -> None:
        example = json.loads((EXAMPLES / "updates.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            produced = self._run(Path(tmp))
            self.assertEqual(produced, example)
            self.assertTrue(produced["updates"][0]["update_available"])
            quoted = self._run(Path(tmp), DIUN_ENTRY_IMAGE='nginx"latest\\tag', OBSERVED_AT="2026-11-20T05:00:00Z")
            self.assertFalse((Path(tmp) / ".updates.lock").exists())
        self.assertEqual(quoted["updates"][-1]["image"], 'nginx"latest\\tag')

    def test_notifier_keeps_the_newest_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for index in range(3):
                self._run(
                    directory,
                    OBSERVED_AT=f"2026-11-20T04:00:0{index}Z",
                    DIUN_ENTRY_IMAGE=f"app:{index}",
                    UPDATES_MAX_EVENTS="2",
                )
            document = json.loads((directory / "updates.json").read_text(encoding="utf-8"))
        self.assertEqual([item["image"] for item in document["updates"]], ["app:1", "app:2"])


if __name__ == "__main__":
    unittest.main()
