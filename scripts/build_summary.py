#!/usr/bin/env python3
"""Rebuild summary.json from per-image report files already on disk."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reportlib import (
    DATA_DIR_DEFAULT,
    EXIT_OK,
    EXIT_PREREQ,
    atomic_write_json,
    load_default_env,
    log,
    read_update_status,
    resolve_hostname,
    resolve_server_id,
    summary_from_reports,
    utc_now,
)

SKIP = {"summary.json", "updates.json"}


def main(argv: list[str] | None = None) -> int:
    load_default_env()
    parser = argparse.ArgumentParser(description="Rebuild summary.json from image reports")
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    import os

    reports_dir = args.reports or Path(os.environ.get("TRIVY_DATA_DIR", DATA_DIR_DEFAULT)) / "reports"
    output = args.output or reports_dir / "summary.json"
    if not reports_dir.is_dir():
        log(f"missing reports directory {reports_dir}")
        return EXIT_PREREQ
    documents = []
    for path in sorted(reports_dir.glob("*.json")):
        if path.name in SKIP:
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log(f"skipping {path.name}: {exc}")
            continue
        if isinstance(document, dict):
            document.setdefault("report_file", path.name)
            documents.append(document)
    server_id = resolve_server_id()
    if documents and documents[0].get("server_id") and not os.environ.get("SERVER_ID", "").strip():
        server_id = str(documents[0]["server_id"])
    scanned = [str(document.get("scanned_at") or "") for document in documents if document.get("scanned_at")]
    scan_time = max(scanned) if scanned else utc_now()
    durations = [document.get("duration_seconds") for document in documents]
    duration = sum(item for item in durations if isinstance(item, int))
    summary = summary_from_reports(
        documents,
        server_id=server_id,
        hostname=resolve_hostname(),
        scan_time=scan_time,
        finished_at=utc_now(),
        duration_seconds=duration,
        reports_dir=str(reports_dir),
        severity_filter=[part.strip() for part in os.environ.get("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM").split(",") if part.strip()],
        update_status=read_update_status(reports_dir / "updates.json"),
    )
    atomic_write_json(output, summary)
    log(f"wrote {output} images_scanned={summary['images_scanned']} server_id={summary['server_id']}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
