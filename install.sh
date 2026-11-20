#!/usr/bin/env bash
# Install the scanner under /srv/stacks/trivy and the data directories under /srv/data/trivy.
# Watchtower is never started here.

set -euo pipefail

PREFIX="${PREFIX:-/srv/stacks/trivy}"
DATA="${DATA:-/srv/data/trivy}"
WITH_DIUN=0
NO_START=0

usage() {
  cat <<'EOF'
usage: install.sh [--with-diun] [--no-start]

Copies this repository to /srv/stacks/trivy, creates /srv/data/trivy,
installs /etc/cron.d/trivy-scan, and starts the Trivy container.
--with-diun sets DIUN_ENABLED=true so that same cron job also checks
for newer images. It does not start a second scheduler.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-diun) WITH_DIUN=1 ;;
    --no-start) NO_START=1 ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  printf '%s\n' "install.sh must run as root" >&2
  exit 1
fi

if [ "$PREFIX" != "/srv/stacks/trivy" ]; then
  printf '%s\n' "The cron job is hard-coded to /srv/stacks/trivy." >&2
  exit 1
fi
if [ "$NO_START" -eq 0 ] && [ "$DATA" != "/srv/data/trivy" ]; then
  printf '%s\n' "compose files mount /srv/data/trivy. Use that path or pass --no-start." >&2
  exit 1
fi

SOURCE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ "$SOURCE" != "$PREFIX" ]; then
  mkdir -p "$PREFIX"
  tar -C "$SOURCE" \
    --exclude .git \
    --exclude .env \
    --exclude __pycache__ \
    -cf - . | tar -C "$PREFIX" -xf -
fi

mkdir -p "$DATA/cache/tmp" "$DATA/reports" "$DATA/logs" "$DATA/diun"
chmod 755 "$DATA" "$DATA/cache" "$DATA/cache/tmp" "$DATA/reports" "$DATA/logs" "$DATA/diun"

if [ ! -f "$PREFIX/.env" ]; then
  cp "$PREFIX/.env.example" "$PREFIX/.env"
  printf 'Created %s. Set SERVER_ID before the first scan.\n' "$PREFIX/.env"
fi
chmod 600 "$PREFIX/.env"

set_env_value() {
  local file="$1" key="$2" value="$3" tmp
  tmp=$(mktemp "${file}.XXXXXX")
  if [ -f "$file" ] && grep -q "^${key}=" "$file"; then
    awk -v key="$key" -v value="$value" '
      $0 ~ "^" key "=" { print key "=" value; next }
      { print }
    ' "$file" > "$tmp"
  else
    if [ -f "$file" ]; then
      cat "$file" > "$tmp"
    fi
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
  fi
  cat "$tmp" > "$file"
  rm -f "$tmp"
  chmod 600 "$file"
}

if [ "$WITH_DIUN" -eq 1 ]; then
  set_env_value "$PREFIX/.env" DIUN_ENABLED true
fi

chmod 755 \
  "$PREFIX/install.sh" \
  "$PREFIX/deploy.sh" \
  "$PREFIX/scripts/scan.sh" \
  "$PREFIX/scripts/diun-notify.sh" \
  "$PREFIX/scripts/scan_runner.py" \
  "$PREFIX/scripts/send_report.py" \
  "$PREFIX/scripts/build_summary.py" \
  "$PREFIX/scripts/build_examples.py" \
  "$PREFIX/scripts/test_reportlib.py" \
  "$PREFIX/scripts/test_load_env.sh"
chmod 644 "$PREFIX/scripts/load_env.sh" "$PREFIX/scripts/reportlib.py"
if [ -d "$PREFIX/scripts/hooks.d" ]; then
  chmod 644 "$PREFIX/scripts/hooks.d"/*
fi

if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
  printf '%s\n' "python 3.8 or newer is required" >&2
  exit 1
fi

if [ ! -d /etc/cron.d ]; then
  printf '%s\n' "/etc/cron.d is not available. Cron is required." >&2
  exit 1
fi
cron_dest="/etc/cron.d/trivy-scan"
cron_src="$PREFIX/cron/trivy-scan"
cron_schedule=""
if [ -f "$cron_dest" ]; then
  cron_schedule=$(awk '
    $1 ~ /^#/ { next }
    $6 == "root" && $7 ~ /\/scripts\/scan\.sh$/ { print $1, $2, $3, $4, $5; exit }
  ' "$cron_dest")
fi
if [ -n "$cron_schedule" ]; then
  awk -v schedule="$cron_schedule" '
    $6 == "root" && $7 ~ /\/scripts\/scan\.sh$/ { print schedule, "root", $7; next }
    { print }
  ' "$cron_src" > "$cron_dest"
  printf '%s\n' "Updated /etc/cron.d/trivy-scan (kept schedule: ${cron_schedule})."
else
  cp "$cron_src" "$cron_dest"
  printf '%s\n' "Installed /etc/cron.d/trivy-scan (03:00 local time)."
fi
chmod 644 "$cron_dest"

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now trivy-scan.timer >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/trivy-scan.service /etc/systemd/system/trivy-scan.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$NO_START" -eq 0 ]; then
  if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' "docker is required" >&2
    exit 1
  fi
  docker compose version >/dev/null
  docker compose -f "$PREFIX/docker-compose.yml" up -d
  if docker ps -a --format '{{.Names}}' | grep -qx diun; then
    set_env_value "$PREFIX/.env" DIUN_ENABLED true
    printf '%s\n' "Found a DIUN container. DIUN_ENABLED=true so the cron job keeps that check."
  fi
  if docker ps -a --format '{{.Names}}' | grep -qx watchtower; then
    set_env_value "$PREFIX/.env" WATCHTOWER_ENABLED true
    printf '%s\n' "Found a Watchtower container. WATCHTOWER_ENABLED=true so the cron job runs it once."
  fi
  docker rm -f diun >/dev/null 2>&1 || true
  docker rm -f watchtower >/dev/null 2>&1 || true
fi

cat <<EOF
Trivy is installed.
  Stack: $PREFIX
  Data:  $DATA
  Env:   $PREFIX/.env

Edit SERVER_ID. The cron job runs every night at 03:00 host local time:
  $PREFIX/scripts/scan.sh

DIUN runs inside that job when DIUN_ENABLED=true.
Watchtower runs inside that job when WATCHTOWER_ENABLED=true.
Neither container is left running. Read docs/security.md before enabling Watchtower.
EOF
