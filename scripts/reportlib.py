#!/usr/bin/env python3
"""Shared JSON, summary, and email helpers for the image-watch scanner.

The dashboard reads the JSON files directly. Every document this module
writes carries report_schema 1 and a server_id.
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape
from pathlib import Path

REPORT_SCHEMA = 1
GENERATOR = "image-watch"
TRACKED = ("CRITICAL", "HIGH", "MEDIUM")
DATA_DIR_DEFAULT = "/srv/data/trivy"
EXIT_OK = 0
EXIT_SCAN_FAILED = 1
EXIT_EMAIL_FAILED = 2
EXIT_BOTH_FAILED = 3
EXIT_PREREQ = 4


class ConfigError(Exception):
    """The env file is incomplete for the requested action."""


@dataclass(frozen=True)
class Finding:
    severity: str
    vulnerability_id: str
    package: str
    installed: str
    fixed: str
    target: str
    title: str
    url: str


@dataclass(frozen=True)
class ContainerSection:
    container_name: str
    container_id: str
    compose: str
    image_name: str
    os_name: str
    digest: str
    report_file: str
    shared_with: str
    findings: tuple[Finding, ...]
    omitted: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class EmailView:
    summary: dict
    sections: tuple[ContainerSection, ...]
    failures: tuple[dict, ...]


def log(message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"{stamp} {message}", flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_env_line(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("export "):
        stripped = stripped[len("export ") :].strip()
    if "=" not in stripped:
        return None
    key, value = stripped.split("=", 1)
    key = key.strip()
    value = value.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return None
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return key, value


def load_env_file(path: Path) -> None:
    """Fill unset or empty variables from an env file."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        parsed = parse_env_line(line)
        if parsed is None:
            continue
        key, value = parsed
        current = os.environ.get(key)
        if current is None or current == "":
            os.environ[key] = value


def load_default_env() -> None:
    candidates: list[Path] = []
    configured = os.environ.get("TRIVY_ENV_FILE", "").strip()
    if configured:
        candidates.append(Path(configured))
    stack = os.environ.get("TRIVY_STACK_DIR", "").strip()
    if stack:
        candidates.append(Path(stack) / ".env")
    candidates.append(Path("/srv/stacks/trivy/.env"))
    seen: set[Path] = set()
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        if path.is_file():
            load_env_file(path)
            return


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def email_enabled() -> bool:
    return env_bool("EMAIL_ENABLED", False)


def resolve_server_id() -> str:
    value = os.environ.get("SERVER_ID", "").strip()
    if value:
        return value
    return socket.gethostname().strip() or "unknown"


def resolve_hostname() -> str:
    return socket.gethostname().strip() or "unknown"


def safe_report_filename(image: str, used: set[str]) -> str:
    """Filesystem-safe report name. nginx:latest becomes nginx_latest.json."""
    collapsed = re.sub(r"[^A-Za-z0-9._-]+", "_", image).strip("._")
    if not collapsed:
        collapsed = "image"
    digest = _short_hash(image)
    if len(collapsed) > 140:
        collapsed = f"{collapsed[:140]}_{digest}"
    name = f"{collapsed}.json"
    if name in used:
        name = f"{collapsed}_{digest}.json"
    used.add(name)
    return name


def _short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def empty_counts() -> dict[str, int]:
    return {name.lower(): 0 for name in TRACKED}


def one_line(value: object) -> str:
    return " ".join(str(value or "").split())


def iter_vulnerabilities(document: dict) -> list[dict]:
    found: list[dict] = []
    for result in document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = one_line(result.get("Target"))
        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            item = dict(vulnerability)
            item["_target"] = target
            found.append(item)
    return found


def count_vulnerabilities(document: dict) -> dict[str, int]:
    """Count unique findings the email will list.

    Trivy sometimes repeats one package advisory under the same target.
    The summary and the mail use one row per severity, CVE, package,
    installed version, fixed version, and target.
    """
    counts = empty_counts()
    seen: set[tuple[str, ...]] = set()
    for vulnerability in iter_vulnerabilities(document):
        severity = one_line(vulnerability.get("Severity")).upper()
        if severity not in TRACKED:
            continue
        key = (
            severity,
            one_line(vulnerability.get("VulnerabilityID")) or "UNREPORTED",
            one_line(vulnerability.get("PkgName")) or "unknown",
            one_line(vulnerability.get("InstalledVersion")) or "unknown",
            one_line(vulnerability.get("FixedVersion")) or "unfixed",
            one_line(vulnerability.get("_target")) or "unknown",
        )
        if key in seen:
            continue
        seen.add(key)
        counts[severity.lower()] += 1
    return counts


def findings_for_email(document: dict) -> tuple[list[Finding], dict[str, int]]:
    rows: list[Finding] = []
    seen: set[tuple[str, ...]] = set()
    for vulnerability in iter_vulnerabilities(document):
        severity = one_line(vulnerability.get("Severity")).upper()
        if severity not in TRACKED:
            continue
        vulnerability_id = one_line(vulnerability.get("VulnerabilityID")) or "UNREPORTED"
        package = one_line(vulnerability.get("PkgName")) or "unknown"
        installed = one_line(vulnerability.get("InstalledVersion")) or "unknown"
        fixed = one_line(vulnerability.get("FixedVersion")) or "unfixed"
        target = one_line(vulnerability.get("_target")) or "unknown"
        title = one_line(vulnerability.get("Title") or vulnerability.get("Description"))
        if len(title) > 220:
            title = title[:217] + "..."
        if not title:
            title = "(no description)"
        url = _safe_url(one_line(vulnerability.get("PrimaryURL")))
        key = (severity, vulnerability_id, package, installed, fixed, target)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            Finding(
                severity=severity,
                vulnerability_id=vulnerability_id,
                package=package,
                installed=installed,
                fixed=fixed,
                target=target,
                title=title,
                url=url,
            )
        )
    rows.sort(key=lambda row: (TRACKED.index(row.severity), row.package, row.vulnerability_id, row.target))
    omitted = {name: 0 for name in TRACKED}
    limit = _row_limit()
    if not limit:
        return rows, omitted
    kept: list[Finding] = []
    used = {name: 0 for name in TRACKED}
    for row in rows:
        if used[row.severity] >= limit:
            omitted[row.severity] += 1
            continue
        used[row.severity] += 1
        kept.append(row)
    return kept, omitted


def _row_limit() -> int:
    raw = os.environ.get("EMAIL_MAX_ROWS_PER_SEVERITY", "0").strip() or "0"
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _safe_url(url: str) -> str:
    if url.startswith("https://") or url.startswith("http://"):
        return url
    return ""


def annotate_report(
    document: dict,
    *,
    server_id: str,
    hostname: str,
    image: str,
    report_file: str,
    scanned_at: str,
    duration_seconds: int,
    containers: list[dict],
) -> dict:
    annotated = {
        "report_schema": REPORT_SCHEMA,
        "generator": GENERATOR,
        "server_id": server_id,
        "hostname": hostname,
        "image": image,
        "report_file": report_file,
        "scanned_at": scanned_at,
        "duration_seconds": duration_seconds,
        "containers": containers,
        "counts": count_vulnerabilities(document),
        "status": "ok",
        "error": None,
    }
    for key, value in document.items():
        if key not in annotated:
            annotated[key] = value
    return annotated


def error_report(
    *,
    server_id: str,
    hostname: str,
    image: str,
    report_file: str,
    scanned_at: str,
    duration_seconds: int,
    containers: list[dict],
    error: str,
) -> dict:
    return {
        "report_schema": REPORT_SCHEMA,
        "generator": GENERATOR,
        "server_id": server_id,
        "hostname": hostname,
        "image": image,
        "report_file": report_file,
        "scanned_at": scanned_at,
        "duration_seconds": duration_seconds,
        "containers": containers,
        "counts": empty_counts(),
        "status": "error",
        "error": one_line(error),
        "Results": [],
    }


def image_row(report: dict) -> dict:
    counts = report.get("counts") or count_vulnerabilities(report)
    return {
        "name": report.get("image") or report.get("ArtifactName") or report.get("report_file"),
        "report_file": report.get("report_file") or "",
        "critical": int(counts.get("critical", 0)),
        "high": int(counts.get("high", 0)),
        "medium": int(counts.get("medium", 0)),
        "status": report.get("status") or "ok",
        "error": report.get("error"),
        "duration_seconds": report.get("duration_seconds"),
        "containers": list(report.get("containers") or []),
    }


def summary_from_reports(
    reports: list[dict],
    *,
    server_id: str,
    hostname: str,
    scan_time: str,
    finished_at: str,
    duration_seconds: int,
    reports_dir: str,
    severity_filter: list[str],
    update_status: dict,
) -> dict:
    rows = [image_row(report) for report in reports]
    rows.sort(key=lambda row: (-row["critical"], -row["high"], -row["medium"], row["name"] or ""))
    critical = high = medium = failed = 0
    failures = []
    for row in rows:
        if row["status"] != "ok":
            failed += 1
            failures.append(
                {
                    "name": row["name"],
                    "report_file": row["report_file"],
                    "error": row["error"],
                }
            )
            continue
        critical += row["critical"]
        high += row["high"]
        medium += row["medium"]
    return {
        "report_schema": REPORT_SCHEMA,
        "generator": GENERATOR,
        "server_id": server_id,
        "hostname": hostname,
        "scan_time": scan_time,
        "finished_at": finished_at,
        "scan_duration_seconds": duration_seconds,
        "images_scanned": len(rows),
        "images_failed": failed,
        "critical": critical,
        "high": high,
        "medium": medium,
        "severity_filter": severity_filter,
        "reports_dir": reports_dir,
        "update_status": update_status,
        "failures": failures,
        "images": rows,
    }


def read_update_status(path: Path) -> dict:
    status = {"file": "updates.json", "available": None, "updated_at": None}
    if not path.is_file():
        return status
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        status["error"] = one_line(exc)
        return status
    if not isinstance(document, dict):
        status["error"] = "updates.json is not an object"
        return status
    available = 0
    for item in document.get("updates") or []:
        if not isinstance(item, dict):
            continue
        state = one_line(item.get("status"))
        if item.get("update_available") is True or state in {"new", "update"}:
            available += 1
    status["available"] = available
    status["updated_at"] = document.get("updated_at")
    return status


def ensure_updates_file(path: Path, server_id: str, hostname: str) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "report_schema": REPORT_SCHEMA,
        "generator": GENERATOR,
        "server_id": server_id,
        "hostname": hostname,
        "updated_at": None,
        "source": "diun",
        "updates": [],
    }
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def image_os(report: dict) -> str:
    metadata = report.get("Metadata") or {}
    os_meta = metadata.get("OS") or {}
    if not isinstance(os_meta, dict):
        return ""
    return one_line(" ".join(part for part in (os_meta.get("Family"), os_meta.get("Name")) if part))


def image_digest(report: dict) -> str:
    metadata = report.get("Metadata") or {}
    digests = metadata.get("RepoDigests") or []
    value = ""
    if isinstance(digests, list) and digests:
        value = one_line(digests[0])
        if "@" in value:
            value = value.split("@", 1)[1]
    if not value:
        value = one_line(metadata.get("ImageID"))
    if value.startswith("sha256:") and len(value) > 19:
        return value[:19] + "..."
    return value


def build_email_view(summary: dict, reports: dict[str, dict]) -> EmailView:
    sections: list[ContainerSection] = []
    failures: list[dict] = []
    for image in summary.get("images") or []:
        if not isinstance(image, dict):
            continue
        if image.get("status") != "ok":
            failures.append(image)
            continue
        report = reports.get(image.get("report_file") or "", {})
        finding_rows, omitted_map = findings_for_email(report if isinstance(report, dict) else {})
        findings = tuple(finding_rows)
        omitted = tuple((name, count) for name, count in omitted_map.items() if count)
        containers = list(image.get("containers") or [])
        if not containers:
            containers = [
                {
                    "id": "",
                    "name": "(no container metadata)",
                    "compose_project": "",
                    "compose_service": "",
                }
            ]
        names = [one_line(container.get("name")) for container in containers if isinstance(container, dict)]
        for container in containers:
            if not isinstance(container, dict):
                continue
            name = one_line(container.get("name")) or "(unnamed)"
            project = one_line(container.get("compose_project"))
            service = one_line(container.get("compose_service"))
            compose = "/".join(part for part in (project, service) if part)
            others = [item for item in names if item and item != name]
            sections.append(
                ContainerSection(
                    container_name=name,
                    container_id=one_line(container.get("id")),
                    compose=compose,
                    image_name=one_line(image.get("name")),
                    os_name=image_os(report if isinstance(report, dict) else {}),
                    digest=image_digest(report if isinstance(report, dict) else {}),
                    report_file=one_line(image.get("report_file")),
                    shared_with=", ".join(others),
                    findings=findings,
                    omitted=omitted,
                )
            )
    sections.sort(key=lambda section: (section.container_name, section.image_name))
    return EmailView(summary=summary, sections=tuple(sections), failures=tuple(failures))


def render_plain(summary: dict, reports: dict[str, dict]) -> str:
    view = build_email_view(summary, reports)
    lines = [
        "image-watch vulnerability report",
        f"Server: {summary.get('server_id', '')}",
        f"Hostname: {summary.get('hostname', '')}",
        f"Scan start: {summary.get('scan_time', '')}",
        f"Scan finished: {summary.get('finished_at', '')}",
        f"Scan duration: {summary.get('scan_duration_seconds', 0)}s",
        f"Images scanned: {summary.get('images_scanned', 0)}",
        f"Images failed: {summary.get('images_failed', 0)}",
        f"Critical: {summary.get('critical', 0)}",
        f"High: {summary.get('high', 0)}",
        f"Medium: {summary.get('medium', 0)}",
        _updates_line(summary),
        "",
        "Totals count each image once. Container sections repeat findings when containers share an image.",
        "",
        "Images",
    ]
    images = summary.get("images") or []
    if not images:
        lines.append("  (no running containers)")
    for image in images:
        if not isinstance(image, dict):
            continue
        names = ", ".join(
            one_line(container.get("name"))
            for container in image.get("containers") or []
            if isinstance(container, dict) and one_line(container.get("name"))
        )
        lines.append(
            "  {name}  critical={critical} high={high} medium={medium}  status={status}  containers={containers}".format(
                name=image.get("name") or "",
                critical=image.get("critical", 0),
                high=image.get("high", 0),
                medium=image.get("medium", 0),
                status=image.get("status") or "",
                containers=names or "-",
            )
        )
    if view.failures:
        lines.extend(["", "Scan failures"])
        for image in view.failures:
            names = ", ".join(
                one_line(container.get("name"))
                for container in image.get("containers") or []
                if isinstance(container, dict) and one_line(container.get("name"))
            )
            lines.append(f"  {image.get('name')}: {image.get('error') or 'scan failed'}")
            if names:
                lines.append(f"    Containers: {names}")
    if not view.sections:
        lines.extend(["", "No running containers had a successful scan."])
    for section in view.sections:
        lines.extend(["", f"Container {section.container_name}"])
        if section.container_id:
            lines.append(f"  ID: {section.container_id}")
        lines.append(f"  Image: {section.image_name}")
        if section.compose:
            lines.append(f"  Compose: {section.compose}")
        if section.os_name:
            lines.append(f"  OS: {section.os_name}")
        if section.digest:
            lines.append(f"  Digest: {section.digest}")
        if section.shared_with:
            lines.append(f"  Shared image with: {section.shared_with}")
        lines.append(f"  Report: {section.report_file}")
        grouped = _group_findings(section.findings)
        total = sum(len(grouped[name]) for name in TRACKED)
        for severity in TRACKED:
            rows = grouped[severity]
            lines.append(f"  {severity} ({len(rows)})")
            for finding in rows:
                lines.append(
                    f"    {finding.vulnerability_id}  {finding.package}  "
                    f"installed={finding.installed}  fixed={finding.fixed}  target={finding.target}"
                )
                lines.append(f"      {finding.title}")
                if finding.url:
                    lines.append(f"      {finding.url}")
        for severity, count in section.omitted:
            lines.append(f"  {severity}: {count} more not shown")
        if total == 0:
            lines.append("  No CRITICAL, HIGH, or MEDIUM vulnerabilities.")
    reports_dir = one_line(summary.get("reports_dir"))
    if reports_dir:
        lines.extend(["", f"Reports directory: {reports_dir}"])
    lines.extend(
        [
            "",
            "This report lists CRITICAL, HIGH, and MEDIUM vulnerabilities for containers that were running at scan start.",
            "",
        ]
    )
    return "\n".join(lines)


def render_html(summary: dict, reports: dict[str, dict]) -> str:
    view = build_email_view(summary, reports)
    parts = [
        "<!DOCTYPE html>",
        '<html><head><meta charset="utf-8"></head>',
        '<body style="font-family: sans-serif; color: #1d1d1d;">',
        "<h1>image-watch vulnerability report</h1>",
        "<ul>",
        f"<li>Server: {escape(str(summary.get('server_id', '')))}</li>",
        f"<li>Hostname: {escape(str(summary.get('hostname', '')))}</li>",
        f"<li>Scan start: {escape(str(summary.get('scan_time', '')))}</li>",
        f"<li>Scan finished: {escape(str(summary.get('finished_at', '')))}</li>",
        f"<li>Scan duration: {escape(str(summary.get('scan_duration_seconds', 0)))}s</li>",
        f"<li>Images scanned: {escape(str(summary.get('images_scanned', 0)))}</li>",
        f"<li>Images failed: {escape(str(summary.get('images_failed', 0)))}</li>",
        f"<li>Critical: {escape(str(summary.get('critical', 0)))}</li>",
        f"<li>High: {escape(str(summary.get('high', 0)))}</li>",
        f"<li>Medium: {escape(str(summary.get('medium', 0)))}</li>",
        f"<li>{escape(_updates_line(summary))}</li>",
        "</ul>",
        "<p>Totals count each image once. Container sections repeat findings when containers share an image.</p>",
        "<h2>Images</h2>",
        '<table border="1" cellpadding="4" cellspacing="0">',
        "<tr><th>Image</th><th>Critical</th><th>High</th><th>Medium</th><th>Status</th><th>Containers</th></tr>",
    ]
    for image in summary.get("images") or []:
        if not isinstance(image, dict):
            continue
        names = ", ".join(
            one_line(container.get("name"))
            for container in image.get("containers") or []
            if isinstance(container, dict) and one_line(container.get("name"))
        )
        parts.append(
            "<tr>"
            f"<td>{escape(str(image.get('name') or ''))}</td>"
            f"<td>{int(image.get('critical', 0))}</td>"
            f"<td>{int(image.get('high', 0))}</td>"
            f"<td>{int(image.get('medium', 0))}</td>"
            f"<td>{escape(str(image.get('status') or ''))}</td>"
            f"<td>{escape(names or '-')}</td>"
            "</tr>"
        )
    parts.append("</table>")
    if view.failures:
        parts.append("<h2>Scan failures</h2><ul>")
        for image in view.failures:
            parts.append(
                f"<li>{escape(str(image.get('name') or ''))}: {escape(str(image.get('error') or 'scan failed'))}</li>"
            )
        parts.append("</ul>")
    for section in view.sections:
        parts.append(f"<h2>Container {escape(section.container_name)}</h2><ul>")
        if section.container_id:
            parts.append(f"<li>ID: {escape(section.container_id)}</li>")
        parts.append(f"<li>Image: {escape(section.image_name)}</li>")
        if section.compose:
            parts.append(f"<li>Compose: {escape(section.compose)}</li>")
        if section.os_name:
            parts.append(f"<li>OS: {escape(section.os_name)}</li>")
        if section.digest:
            parts.append(f"<li>Digest: {escape(section.digest)}</li>")
        if section.shared_with:
            parts.append(f"<li>Shared image with: {escape(section.shared_with)}</li>")
        parts.append(f"<li>Report: {escape(section.report_file)}</li></ul>")
        grouped = _group_findings(section.findings)
        for severity in TRACKED:
            rows = grouped[severity]
            parts.append(f"<h3>{severity} ({len(rows)})</h3>")
            if not rows:
                continue
            parts.append('<table border="1" cellpadding="4" cellspacing="0">')
            parts.append("<tr><th>CVE</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Target</th><th>Title</th></tr>")
            for finding in rows:
                url = (
                    f'<a href="{escape(finding.url, quote=True)}">{escape(finding.vulnerability_id)}</a>'
                    if finding.url
                    else escape(finding.vulnerability_id)
                )
                parts.append(
                    "<tr>"
                    f"<td>{url}</td>"
                    f"<td>{escape(finding.package)}</td>"
                    f"<td>{escape(finding.installed)}</td>"
                    f"<td>{escape(finding.fixed)}</td>"
                    f"<td>{escape(finding.target)}</td>"
                    f"<td>{escape(finding.title)}</td>"
                    "</tr>"
                )
            parts.append("</table>")
        for severity, count in section.omitted:
            parts.append(f"<p>{escape(severity)}: {count} more not shown</p>")
        if not section.findings:
            parts.append("<p>No CRITICAL, HIGH, or MEDIUM vulnerabilities.</p>")
    reports_dir = one_line(summary.get("reports_dir"))
    if reports_dir:
        parts.append(f"<p>Reports directory: {escape(reports_dir)}</p>")
    parts.append(
        "<p>This report lists CRITICAL, HIGH, and MEDIUM vulnerabilities for containers that were running at scan start.</p>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def _group_findings(findings: tuple[Finding, ...] | list[Finding]) -> dict[str, list[Finding]]:
    grouped = {name: [] for name in TRACKED}
    for finding in findings:
        grouped[finding.severity].append(finding)
    return grouped


def _updates_line(summary: dict) -> str:
    update_status = summary.get("update_status") or {}
    available = update_status.get("available")
    if available is None:
        return "Update notifications: unknown"
    return f"Update notifications: {available}"


def email_subject(summary: dict) -> str:
    prefix = os.environ.get("EMAIL_SUBJECT_PREFIX", "[trivy]").strip() or "[trivy]"
    subject = (
        f"{prefix} {summary.get('server_id', '')}: "
        f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        f"{summary.get('medium', 0)} medium"
    )
    failed = int(summary.get("images_failed") or 0)
    if failed:
        subject += f", {failed} scan failures"
    return subject


def _recipients() -> list[str]:
    raw = os.environ.get("SMTP_TO", "")
    return [part.strip() for part in raw.replace(";", ",").split(",") if part.strip()]


def _require_address(value: str, label: str) -> str:
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ConfigError(f"{label} is not an email address")
    return value


def smtp_settings() -> dict:
    host = os.environ.get("SMTP_HOST", "").strip()
    sender = os.environ.get("SMTP_FROM", "").strip()
    recipients = _recipients()
    if not host:
        raise ConfigError("SMTP_HOST is empty")
    if not sender:
        raise ConfigError("SMTP_FROM is empty")
    if not recipients:
        raise ConfigError("SMTP_TO is empty")
    _require_address(sender, "SMTP_FROM")
    for recipient in recipients:
        _require_address(recipient, "SMTP_TO")
    port_raw = os.environ.get("SMTP_PORT", "587").strip() or "587"
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ConfigError("SMTP_PORT is not a number") from exc
    mode = os.environ.get("SMTP_TLS", "starttls").strip().lower() or "starttls"
    if mode not in {"starttls", "ssl", "none"}:
        raise ConfigError("SMTP_TLS must be starttls, ssl, or none")
    timeout_raw = os.environ.get("SMTP_TIMEOUT", "30").strip() or "30"
    try:
        timeout = int(timeout_raw)
    except ValueError as exc:
        raise ConfigError("SMTP_TIMEOUT is not a number") from exc
    return {
        "host": host,
        "port": port,
        "mode": mode,
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", ""),
        "sender": sender,
        "recipients": recipients,
        "timeout": timeout,
        "context": _smtp_context(),
    }


def _smtp_context() -> ssl.SSLContext:
    if env_bool("SMTP_TLS_INSECURE", False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    context = ssl.create_default_context()
    ca_file = os.environ.get("SMTP_CA_FILE", "").strip()
    if ca_file:
        context.load_verify_locations(ca_file)
    return context


def build_message(summary: dict, plain: str, html: str) -> EmailMessage:
    settings_sender = os.environ.get("SMTP_FROM", "").strip()
    recipients = _recipients()
    message = EmailMessage()
    message["Subject"] = email_subject(summary)
    message["From"] = settings_sender
    message["To"] = ", ".join(recipients)
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain="image-watch.local")
    message["X-Image-Watch-Server"] = str(summary.get("server_id") or "")
    message.set_content(plain)
    message.add_alternative(html, subtype="html")
    return message


def send_email(summary: dict, plain: str, html: str) -> None:
    settings = smtp_settings()
    message = build_message(summary, plain, html)
    log(
        f"email sending via {settings['host']}:{settings['port']} {settings['mode']} "
        f"to {', '.join(settings['recipients'])}"
    )
    client_type = smtplib.SMTP_SSL if settings["mode"] == "ssl" else smtplib.SMTP
    with client_type(settings["host"], settings["port"], timeout=settings["timeout"]) as client:
        client.ehlo()
        if settings["mode"] == "starttls":
            client.starttls(context=settings["context"])
            client.ehlo()
        if settings["user"]:
            client.login(settings["user"], settings["password"])
        client.send_message(message)
    log(f"email sent to {', '.join(settings['recipients'])}")


def redact(text: str) -> str:
    password = os.environ.get("SMTP_PASSWORD", "")
    if password:
        text = text.replace(password, "********")
    return text


def load_summary_reports(reports_dir: Path) -> tuple[dict, dict[str, dict]]:
    summary_path = reports_dir / "summary.json"
    if not summary_path.is_file():
        raise ConfigError(f"missing {summary_path}")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if not isinstance(summary, dict):
        raise ConfigError("summary.json is not an object")
    loaded: dict[str, dict] = {}
    for image in summary.get("images") or []:
        if not isinstance(image, dict):
            continue
        name = Path(str(image.get("report_file") or "")).name
        if not name.endswith(".json") or name != image.get("report_file"):
            raise ConfigError(f"invalid report_file {image.get('report_file')!r}")
        path = reports_dir / name
        if not path.is_file():
            log(f"email missing report {name}")
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict):
            loaded[name] = document
    return summary, loaded
