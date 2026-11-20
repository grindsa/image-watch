#!/usr/bin/env bash
# Nightly cron entry point.
# Optionally checks for newer images, scans running images, writes JSON,
# sends the email, then optionally runs Watchtower. One invocation, one schedule.

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STACK_DEFAULT=$(cd "$SCRIPT_DIR/.." && pwd)

usage() {
  printf '%s\n' "usage: scan.sh [--skip-email]"
}

SKIP_EMAIL=0
case "${1:-}" in
  --help|-h)
    usage
    exit 0
    ;;
  --skip-email)
    SKIP_EMAIL=1
    shift
    ;;
esac
if [ "$#" -gt 0 ]; then
  usage >&2
  exit 4
fi

export TRIVY_ENV_FILE="${TRIVY_ENV_FILE:-${TRIVY_STACK_DIR:-$STACK_DEFAULT}/.env}"
# shellcheck source=load_env.sh
source "$SCRIPT_DIR/load_env.sh"
load_env_file "$TRIVY_ENV_FILE"

: "${TRIVY_STACK_DIR:=$STACK_DEFAULT}"
: "${TRIVY_DATA_DIR:=/srv/data/trivy}"
export TRIVY_STACK_DIR TRIVY_DATA_DIR TRIVY_ENV_FILE
export PYTHONUNBUFFERED=1

LOG_DIR="$TRIVY_DATA_DIR/logs"
mkdir -p "$LOG_DIR" "$TRIVY_DATA_DIR/reports" "$TRIVY_DATA_DIR/cache" "$TRIVY_DATA_DIR/diun"
LOG_FILE="$LOG_DIR/scan.log"

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

is_enabled() {
  local value
  value=$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

remove_leftover_container() {
  local name="$1"
  if ! command -v docker >/dev/null 2>&1; then
    return 0
  fi
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    log "removing leftover ${name} container so it cannot keep its own schedule"
    docker rm -f "$name" >/dev/null
  fi
}

run_compose_once() {
  local service="$1"
  local file="$2"
  log "${service} start"
  set +e
  docker compose --profile cron -f "$file" run --rm --no-deps -T "$service" 2>&1 | tee -a "$LOG_FILE"
  local status=${PIPESTATUS[0]}
  set -e
  if [ "$status" -ne 0 ]; then
    log "${service} failed exit=$status"
    return "$status"
  fi
  log "${service} finish"
  return 0
}

if ! command -v python3 >/dev/null 2>&1; then
  log "python3 is required"
  exit 4
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
  log "python 3.8 or newer is required"
  exit 4
fi

cd "$TRIVY_STACK_DIR"
exec 9>>"$LOG_DIR/scan.lock"
if command -v flock >/dev/null 2>&1; then
  if ! flock -n 9; then
    log "scan skipped because another scan is running"
    exit 0
  fi
else
  log "flock is not installed; continuing without a lock"
fi

start_epoch=$(date +%s)
log "scan start pid=$$ stack=$TRIVY_STACK_DIR data=$TRIVY_DATA_DIR"
remove_leftover_container diun
remove_leftover_container watchtower

diun_status=0
if is_enabled "${DIUN_ENABLED:-false}"; then
  if ! command -v docker >/dev/null 2>&1; then
    log "diun failed: docker is not available"
    diun_status=1
  else
    set +e
    run_compose_once diun "$TRIVY_STACK_DIR/docker-compose.diun.yml"
    diun_status=$?
    set -e
  fi
else
  log "diun skipped (DIUN_ENABLED is not true)"
fi

set +e
python3 "$SCRIPT_DIR/scan_runner.py" 2>&1 | tee -a "$LOG_FILE"
scan_status=${PIPESTATUS[0]}
set -e

email_status=0
if [ "$SKIP_EMAIL" -eq 1 ]; then
  log "email skipped because --skip-email was set"
elif [ "$scan_status" -eq 4 ]; then
  log "email skipped because the scan did not publish a new summary"
else
  set +e
  python3 "$SCRIPT_DIR/send_report.py" 2>&1 | tee -a "$LOG_FILE"
  email_status=${PIPESTATUS[0]}
  set -e
fi

if [ -d "$SCRIPT_DIR/hooks.d" ]; then
  hook=""
  for hook in "$SCRIPT_DIR/hooks.d"/*; do
    [ -f "$hook" ] || continue
    [ -x "$hook" ] || continue
    case "$hook" in
      *.example) continue ;;
    esac
    log "hook start ${hook##*/}"
    set +e
    env -u SMTP_PASSWORD \
      SUMMARY_PATH="$TRIVY_DATA_DIR/reports/summary.json" \
      REPORTS_DIR="$TRIVY_DATA_DIR/reports" \
      TRIVY_DATA_DIR="$TRIVY_DATA_DIR" \
      TRIVY_STACK_DIR="$TRIVY_STACK_DIR" \
      "$hook" 2>&1 | tee -a "$LOG_FILE"
    hook_status=${PIPESTATUS[0]}
    set -e
    if [ "$hook_status" -ne 0 ]; then
      log "hook failed ${hook##*/} exit=$hook_status"
    else
      log "hook finish ${hook##*/}"
    fi
  done
fi

watchtower_status=0
if is_enabled "${WATCHTOWER_ENABLED:-false}"; then
  if ! command -v docker >/dev/null 2>&1; then
    log "watchtower failed: docker is not available"
    watchtower_status=1
  else
    set +e
    run_compose_once watchtower "$TRIVY_STACK_DIR/docker-compose.watchtower.yml"
    watchtower_status=$?
    set -e
  fi
else
  log "watchtower skipped (WATCHTOWER_ENABLED is not true)"
fi

end_epoch=$(date +%s)
duration=$((end_epoch - start_epoch))
exit_code=0
if [ "$scan_status" -ne 0 ] && [ "$email_status" -ne 0 ]; then
  exit_code=3
elif [ "$email_status" -ne 0 ]; then
  exit_code=$email_status
elif [ "$scan_status" -ne 0 ]; then
  exit_code=$scan_status
elif [ "$diun_status" -ne 0 ] || [ "$watchtower_status" -ne 0 ]; then
  exit_code=1
fi
log "scan finish exit=$exit_code scan_status=$scan_status email_status=$email_status diun_status=$diun_status watchtower_status=$watchtower_status duration_seconds=$duration"
exit "$exit_code"
