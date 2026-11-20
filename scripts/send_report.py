#!/usr/bin/env python3
"""Send the latest scan as a per-container email.

The message lists CRITICAL, HIGH, and MEDIUM findings for every running
container. SMTP settings come from the environment or the stack env file.
"""

from __future__ import annotations

import argparse
import smtplib
import sys
from pathlib import Path

from reportlib import (
    DATA_DIR_DEFAULT,
    EXIT_EMAIL_FAILED,
    EXIT_OK,
    EXIT_PREREQ,
    ConfigError,
    email_enabled,
    load_default_env,
    load_summary_reports,
    log,
    redact,
    render_html,
    render_plain,
    send_email,
)


def main(argv: list[str] | None = None) -> int:
    load_default_env()
    parser = argparse.ArgumentParser(description="Email the latest image-watch scan")
    parser.add_argument("--reports", type=Path, help="Directory that contains summary.json")
    parser.add_argument("--dry-run", action="store_true", help="Print the plain-text report and do not send mail")
    args = parser.parse_args(argv)
    reports_dir = args.reports or Path(os_data_dir()) / "reports"
    try:
        summary, documents = load_summary_reports(reports_dir)
        plain = render_plain(summary, documents)
        html = render_html(summary, documents)
    except (OSError, ConfigError, ValueError) as exc:
        log(f"email report failed: {redact(str(exc))}")
        return EXIT_PREREQ
    if args.dry_run:
        sys.stdout.write(plain if plain.endswith("\n") else plain + "\n")
        return EXIT_OK
    if not email_enabled():
        log("email disabled")
        return EXIT_OK
    try:
        send_email(summary, plain, html)
    except ConfigError as exc:
        log(f"email config failed: {redact(str(exc))}")
        return EXIT_PREREQ
    except (OSError, smtplib.SMTPException, TimeoutError) as exc:
        log(f"email failed: {redact(f'{type(exc).__name__}: {exc}')}")
        return EXIT_EMAIL_FAILED
    return EXIT_OK


def os_data_dir() -> str:
    import os

    return os.environ.get("TRIVY_DATA_DIR", DATA_DIR_DEFAULT)


if __name__ == "__main__":
    sys.exit(main())
