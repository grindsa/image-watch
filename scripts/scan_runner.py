#!/usr/bin/env python3
"""Scan running container images with the persistent Trivy container."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

from reportlib import (
    EXIT_OK,
    EXIT_PREREQ,
    EXIT_SCAN_FAILED,
    annotate_report,
    atomic_write_json,
    ensure_updates_file,
    error_report,
    load_default_env,
    log,
    read_update_status,
    resolve_hostname,
    resolve_server_id,
    safe_report_filename,
    summary_from_reports,
    utc_now,
)

FIXED_DATA_DIR = Path("/srv/data/trivy")
PS_FORMAT = (
    "{{.ID}}\t{{.Names}}\t{{.Image}}\t"
    '{{.Label "com.docker.compose.project"}}\t'
    '{{.Label "com.docker.compose.service"}}'
)


class PrerequisiteError(Exception):
    """The host cannot run a scan."""


def main(argv: list[str] | None = None) -> int:
    load_default_env()
    parser = argparse.ArgumentParser(description="Scan running Docker images with Trivy")
    parser.parse_args(argv)
    try:
        failed = run_scan()
    except PrerequisiteError as exc:
        log(f"prerequisite failed: {exc}")
        return EXIT_PREREQ
    except Exception as exc:
        log(f"scan aborted: {exc}")
        traceback.print_exc()
        return EXIT_PREREQ
    return EXIT_SCAN_FAILED if failed else EXIT_OK


def run_scan() -> bool:
    data_dir = Path(os.environ.get("TRIVY_DATA_DIR", str(FIXED_DATA_DIR)))
    if data_dir.resolve() != FIXED_DATA_DIR.resolve():
        raise PrerequisiteError(
            "TRIVY_DATA_DIR must be /srv/data/trivy. "
            "The compose files mount that path into the scanner."
        )
    stack_dir = Path(os.environ.get("TRIVY_STACK_DIR", "/srv/stacks/trivy"))
    container = os.environ.get("TRIVY_CONTAINER", "trivy").strip() or "trivy"
    severity = _parse_severity(os.environ.get("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM"))
    scanners = _parse_scanners(os.environ.get("TRIVY_SCANNERS", "vuln"))
    timeout_token = os.environ.get("TRIVY_TIMEOUT", "15m").strip() or "15m"
    timeout_seconds = _parse_duration(timeout_token) + 120
    server_id = resolve_server_id()
    hostname = resolve_hostname()
    if not os.environ.get("SERVER_ID", "").strip():
        log(f"SERVER_ID is empty; using hostname {server_id}")

    reports_dir = data_dir / "reports"
    cache_dir = data_dir / "cache"
    for path in (reports_dir, cache_dir, cache_dir / "tmp", data_dir / "logs", data_dir / "diun"):
        path.mkdir(parents=True, exist_ok=True)

    _require_docker()
    _ensure_container(container, stack_dir)
    _require_trivy(container)
    _download_database(container)

    started = time.monotonic()
    scan_time = utc_now()
    containers = list_running_containers()
    grouped: dict[str, list[dict]] = {}
    for item in containers:
        grouped.setdefault(item["image"], []).append(
            {
                "id": item["id"],
                "name": item["name"],
                "compose_project": item["compose_project"],
                "compose_service": item["compose_service"],
            }
        )
    for image_name in grouped:
        grouped[image_name].sort(key=lambda row: row["name"])

    staging = reports_dir / ".incoming"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    used_names: set[str] = set()
    written: list[dict] = []
    try:
        for image_name in sorted(grouped):
            filename = safe_report_filename(image_name, used_names)
            written.append(
                _scan_one(
                    image=image_name,
                    filename=filename,
                    containers=grouped[image_name],
                    staging=staging,
                    container=container,
                    severity=severity,
                    scanners=scanners,
                    timeout_token=timeout_token,
                    timeout_seconds=timeout_seconds,
                    server_id=server_id,
                    hostname=hostname,
                )
            )
        finished_at = utc_now()
        duration = max(0, int(round(time.monotonic() - started)))
        ensure_updates_file(reports_dir / "updates.json", server_id, hostname)
        summary = summary_from_reports(
            written,
            server_id=server_id,
            hostname=hostname,
            scan_time=scan_time,
            finished_at=finished_at,
            duration_seconds=duration,
            reports_dir=str(reports_dir),
            severity_filter=severity.split(","),
            update_status=read_update_status(reports_dir / "updates.json"),
        )
        atomic_write_json(staging / "summary.json", summary)
        _publish(staging, reports_dir)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    log(
        "scan result "
        f"server_id={summary['server_id']} images_scanned={summary['images_scanned']} "
        f"images_failed={summary['images_failed']} critical={summary['critical']} "
        f"high={summary['high']} medium={summary['medium']} "
        f"duration_seconds={summary['scan_duration_seconds']}"
    )
    return summary["images_failed"] > 0


def _scan_one(
    *,
    image: str,
    filename: str,
    containers: list[dict],
    staging: Path,
    container: str,
    severity: str,
    scanners: str,
    timeout_token: str,
    timeout_seconds: int,
    server_id: str,
    hostname: str,
) -> dict:
    started = time.monotonic()
    log(f"scan image {image}")
    invalid = _invalid_image(image)
    if invalid:
        report = error_report(
            server_id=server_id,
            hostname=hostname,
            image=image,
            report_file=filename,
            scanned_at=utc_now(),
            duration_seconds=0,
            containers=containers,
            error=invalid,
        )
        atomic_write_json(staging / filename, report)
        log(f"scan failed image={image} error={invalid}")
        return report

    command = [
        "docker",
        "exec",
        "-e",
        "TRIVY_CACHE_DIR=/root/.cache/trivy",
        "-e",
        "TMPDIR=/root/.cache/trivy/tmp",
        container,
        "trivy",
        "image",
        "--cache-dir",
        "/root/.cache/trivy",
        "--scanners",
        scanners,
        "--severity",
        severity,
        "--timeout",
        timeout_token,
        "--skip-version-check",
        "--format",
        "json",
        "--output",
        f"/reports/.incoming/{filename}",
        "--quiet",
        image,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        completed = None
        detail = f"timed out after {timeout_seconds}s"
        code = 124
    else:
        code = completed.returncode
        detail = _tail(completed.stderr or completed.stdout)

    duration = max(0, int(round(time.monotonic() - started)))
    raw_path = staging / filename
    if code != 0 or not raw_path.is_file():
        if raw_path.exists():
            raw_path.unlink()
        message = detail or f"trivy exited {code}"
        report = error_report(
            server_id=server_id,
            hostname=hostname,
            image=image,
            report_file=filename,
            scanned_at=utc_now(),
            duration_seconds=duration,
            containers=containers,
            error=message,
        )
        atomic_write_json(staging / filename, report)
        log(f"scan failed image={image} exit={code}")
        return report

    try:
        document = json.loads(raw_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raw_path.unlink(missing_ok=True)
        report = error_report(
            server_id=server_id,
            hostname=hostname,
            image=image,
            report_file=filename,
            scanned_at=utc_now(),
            duration_seconds=duration,
            containers=containers,
            error=f"trivy wrote invalid JSON: {exc}",
        )
        atomic_write_json(staging / filename, report)
        log(f"scan failed image={image} invalid json")
        return report
    if not isinstance(document, dict):
        report = error_report(
            server_id=server_id,
            hostname=hostname,
            image=image,
            report_file=filename,
            scanned_at=utc_now(),
            duration_seconds=duration,
            containers=containers,
            error="trivy JSON root is not an object",
        )
        atomic_write_json(staging / filename, report)
        return report

    report = annotate_report(
        document,
        server_id=server_id,
        hostname=hostname,
        image=image,
        report_file=filename,
        scanned_at=utc_now(),
        duration_seconds=duration,
        containers=containers,
    )
    atomic_write_json(raw_path, report)
    counts = report["counts"]
    log(
        f"scan finish image={image} critical={counts['critical']} "
        f"high={counts['high']} medium={counts['medium']} duration_seconds={duration}"
    )
    return report


def list_running_containers() -> list[dict]:
    completed = subprocess.run(
        ["docker", "ps", "--format", PS_FORMAT],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise PrerequisiteError(_tail(completed.stderr) or "docker ps failed")
    containers = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            parts.extend([""] * (5 - len(parts)))
        container_id, name, image, project, service = (part.strip() for part in parts[:5])
        if not image:
            continue
        containers.append(
            {
                "id": container_id,
                "name": name,
                "image": image,
                "compose_project": project,
                "compose_service": service,
            }
        )
    log(f"running containers={len(containers)} unique images={len({item['image'] for item in containers})}")
    return containers


def _publish(staging: Path, reports_dir: Path) -> None:
    names = {path.name for path in staging.glob("*.json")}
    for path in list(staging.glob("*.json")):
        os.replace(path, reports_dir / path.name)
    for existing in reports_dir.glob("*.json"):
        if existing.name == "updates.json":
            continue
        if existing.name not in names:
            existing.unlink()


def _ensure_container(name: str, stack_dir: Path) -> None:
    if _container_running(name):
        return
    compose_file = stack_dir / "docker-compose.yml"
    if not compose_file.is_file():
        raise PrerequisiteError(f"missing {compose_file}")
    log(f"starting {name}")
    completed = subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d", "trivy"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(stack_dir),
        timeout=180,
    )
    if completed.returncode != 0 or not _container_running(name):
        detail = _tail(completed.stderr or completed.stdout)
        raise PrerequisiteError(detail or f"container {name} did not start")


def _container_running(name: str) -> bool:
    completed = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "true"


def _require_docker() -> None:
    completed = subprocess.run(
        ["docker", "info"],
        check=False,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        raise PrerequisiteError(_tail(completed.stderr) or "docker info failed")


def _require_trivy(container: str) -> None:
    completed = subprocess.run(
        ["docker", "exec", container, "trivy", "--version"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        detail = _tail(completed.stderr or completed.stdout)
        raise PrerequisiteError(detail or "trivy --version failed inside the container")
    first = (completed.stdout or "").splitlines()
    if first:
        log(f"trivy version {first[0]}")


def _download_database(container: str) -> None:
    log("vulnerability database update start")
    completed = subprocess.run(
        [
            "docker",
            "exec",
            "-e",
            "TRIVY_CACHE_DIR=/root/.cache/trivy",
            container,
            "trivy",
            "image",
            "--download-db-only",
            "--cache-dir",
            "/root/.cache/trivy",
            "--skip-version-check",
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=900,
    )
    if completed.returncode != 0:
        log(f"vulnerability database update failed: {_tail(completed.stderr or completed.stdout)}")
        return
    log("vulnerability database update finish")


def _parse_severity(value: str) -> str:
    parts = [part.strip().upper() for part in value.split(",") if part.strip()]
    allowed = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    if not parts or any(part not in allowed for part in parts):
        raise PrerequisiteError("TRIVY_SEVERITY must be a comma-separated list of Trivy severities")
    return ",".join(parts)


def _parse_scanners(value: str) -> str:
    parts = [part.strip().lower() for part in value.split(",") if part.strip()]
    allowed = {"vuln", "misconfig", "secret", "license"}
    if not parts or any(part not in allowed for part in parts):
        raise PrerequisiteError("TRIVY_SCANNERS must be a comma-separated list of vuln, misconfig, secret, license")
    return ",".join(parts)


def _parse_duration(value: str) -> int:
    import re

    match = re.fullmatch(r"(\d+)([smh]?)", value.strip())
    if not match:
        raise PrerequisiteError("TRIVY_TIMEOUT must look like 90s, 15m, or 1h")
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    return amount * {"s": 1, "m": 60, "h": 3600}[unit]


def _invalid_image(image: str) -> str:
    if not image or len(image) > 1024:
        return "image reference is empty or too long"
    if image.startswith("-") or any(char in image for char in "\n\r\x00"):
        return "image reference contains characters the scanner will not pass through"
    return ""


def _tail(text: str, limit: int = 2000) -> str:
    cleaned = " ".join((text or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[-limit:]


if __name__ == "__main__":
    sys.exit(main())
