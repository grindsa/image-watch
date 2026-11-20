#!/usr/bin/env python3
"""Write the illustrative JSON and email samples under examples/."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from reportlib import (
    annotate_report,
    atomic_write_json,
    error_report,
    read_update_status,
    render_html,
    render_plain,
    summary_from_reports,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SERVER = "example-server"
REPORTS_DIR = "/srv/data/trivy/reports"


def main() -> int:
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    nginx = annotate_report(
        _nginx_document(),
        server_id=SERVER,
        hostname=SERVER,
        image="nginx:latest",
        report_file="nginx_latest.json",
        scanned_at="2026-11-20T02:00:40Z",
        duration_seconds=40,
        containers=[
            {"id": "abc111111111", "name": "web-nginx", "compose_project": "web", "compose_service": "nginx"},
            {"id": "abc222222222", "name": "web-nginx-b", "compose_project": "web", "compose_service": "nginx"},
        ],
    )
    postgres = annotate_report(
        _postgres_document(),
        server_id=SERVER,
        hostname=SERVER,
        image="postgres:16",
        report_file="postgres_16.json",
        scanned_at="2026-11-20T02:01:35Z",
        duration_seconds=55,
        containers=[
            {"id": "def333333333", "name": "web-db", "compose_project": "web", "compose_service": "db"},
        ],
    )
    atomic_write_json(EXAMPLES / "nginx_latest.json", nginx)
    atomic_write_json(EXAMPLES / "postgres_16.json", postgres)
    updates = _updates_example()
    atomic_write_json(EXAMPLES / "updates.json", updates)
    summary = summary_from_reports(
        [nginx, postgres],
        server_id=SERVER,
        hostname=SERVER,
        scan_time="2026-11-20T02:00:00Z",
        finished_at="2026-11-20T02:01:35Z",
        duration_seconds=95,
        reports_dir=REPORTS_DIR,
        severity_filter=["CRITICAL", "HIGH", "MEDIUM"],
        update_status=read_update_status(EXAMPLES / "updates.json"),
    )
    atomic_write_json(EXAMPLES / "summary.json", summary)
    documents = {"nginx_latest.json": nginx, "postgres_16.json": postgres}
    (EXAMPLES / "email-report.txt").write_text(render_plain(summary, documents), encoding="utf-8")
    (EXAMPLES / "email-report.html").write_text(render_html(summary, documents), encoding="utf-8")

    broken = error_report(
        server_id=SERVER,
        hostname=SERVER,
        image="registry.example/app:1.2.3",
        report_file="registry.example_app_1.2.3.json",
        scanned_at="2026-11-20T02:01:40Z",
        duration_seconds=3,
        containers=[
            {"id": "fff444444444", "name": "web-app", "compose_project": "web", "compose_service": "app"},
        ],
        error="trivy exited 1: image not found",
    )
    atomic_write_json(EXAMPLES / "registry.example_app_1.2.3.json", broken)
    failed = summary_from_reports(
        [nginx, broken],
        server_id=SERVER,
        hostname=SERVER,
        scan_time="2026-11-20T02:00:00Z",
        finished_at="2026-11-20T02:01:40Z",
        duration_seconds=100,
        reports_dir=REPORTS_DIR,
        severity_filter=["CRITICAL", "HIGH", "MEDIUM"],
        update_status={"file": "updates.json", "available": 0, "updated_at": None},
    )
    atomic_write_json(EXAMPLES / "summary-with-failure.json", failed)
    return 0


def _updates_example() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        env = os.environ.copy()
        env.update(
            {
                "REPORTS_DIR": tmp,
                "SERVER_ID": SERVER,
                "DIUN_HOSTNAME": SERVER,
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
        subprocess.run(["sh", str(ROOT / "scripts" / "diun-notify.sh")], check=True, env=env, cwd=tmp)
        return json.loads(Path(tmp, "updates.json").read_text(encoding="utf-8"))


def _nginx_document() -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "nginx:latest",
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "debian", "Name": "12"},
            "ImageID": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "RepoDigests": ["nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111"],
            "RepoTags": ["nginx:latest"],
        },
        "Results": [
            {
                "Target": "nginx:latest (debian 12)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    _finding(
                        "CVE-2099-9001",
                        "liba",
                        "1.0.0",
                        "1.0.1",
                        "CRITICAL",
                        "Example critical finding, not a real vulnerability.",
                    )
                ],
            },
            {
                "Target": "usr/local/lib/example/package.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    _finding(
                        "CVE-2099-9002",
                        "left-pad-example",
                        "1.2.0",
                        "",
                        "MEDIUM",
                        "Example medium finding, not a real vulnerability.",
                    )
                ],
            },
        ],
    }


def _postgres_document() -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "postgres:16",
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "debian", "Name": "13"},
            "ImageID": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "RepoDigests": ["postgres@sha256:2222222222222222222222222222222222222222222222222222222222222222"],
            "RepoTags": ["postgres:16"],
        },
        "Results": [
            {
                "Target": "postgres:16 (debian 13)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": [
                    _finding(
                        "CVE-2099-9003",
                        "libpq",
                        "16.1",
                        "16.2",
                        "HIGH",
                        "Example high finding, not a real vulnerability.",
                    )
                ],
            }
        ],
    }


def _finding(cve: str, package: str, installed: str, fixed: str, severity: str, title: str) -> dict:
    return {
        "VulnerabilityID": cve,
        "PkgName": package,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": title,
        "PrimaryURL": f"https://example.invalid/{cve}",
    }


if __name__ == "__main__":
    sys.exit(main())
