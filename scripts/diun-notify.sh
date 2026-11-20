#!/bin/sh
# DIUN script notifier. Appends one JSON event and rewrites updates.json.
# The DIUN image has no Python, so this stays POSIX sh.
# Invoked as: /bin/sh /diun-notify.sh

set -eu

REPORTS_DIR="${REPORTS_DIR:-/reports}"
NDJSON="$REPORTS_DIR/updates.jsonl"
JSON_FILE="$REPORTS_DIR/updates.json"
SERVER_ID="${SERVER_ID:-${DIUN_HOSTNAME:-unknown}}"
HOSTNAME_VALUE="${DIUN_HOSTNAME:-$SERVER_ID}"
MAX="${UPDATES_MAX_EVENTS:-200}"
LOCK="$REPORTS_DIR/.updates.lock"

case "$MAX" in
  ''|*[!0-9]*) MAX=200 ;;
esac
if [ "$MAX" -eq 0 ]; then
  MAX=200
fi

json_escape() {
  # Character loop avoids sed/awk replacement differences between busybox and BSD.
  printf '%s' "$1" | awk '
    BEGIN { RS = "\034"; ORS = "" }
    {
      out = ""
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if (c == "\\") out = out "\\\\"
        else if (c == "\"") out = out "\\\""
        else if (c == "\t") out = out "\\t"
        else if (c == "\r") out = out "\\r"
        else if (c == "\n") out = out "\\n"
        else out = out c
      }
      printf "%s", out
    }
  '
}

mkdir -p "$REPORTS_DIR"

if [ -d "$LOCK" ]; then
  old=$(find "$LOCK" -mmin +2 2>/dev/null || true)
  if [ -n "$old" ]; then
    rmdir "$LOCK" 2>/dev/null || true
  fi
fi

waited=0
while ! mkdir "$LOCK" 2>/dev/null; do
  waited=$((waited + 1))
  if [ "$waited" -gt 50 ]; then
    printf '%s\n' "updates lock timeout" >&2
    exit 1
  fi
  sleep 0.1
done

cleanup() {
  rmdir "$LOCK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

now="${OBSERVED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
status="${DIUN_ENTRY_STATUS:-}"
available=false
case "$status" in
  new|update) available=true ;;
esac

line=$(printf '{"server_id":"%s","observed_at":"%s","status":"%s","update_available":%s,"image":"%s","digest":"%s","platform":"%s","provider":"%s","hub_link":"%s","created":"%s","container_names":"%s","diun_hostname":"%s"}' \
  "$(json_escape "$SERVER_ID")" \
  "$(json_escape "$now")" \
  "$(json_escape "$status")" \
  "$available" \
  "$(json_escape "${DIUN_ENTRY_IMAGE:-}")" \
  "$(json_escape "${DIUN_ENTRY_DIGEST:-}")" \
  "$(json_escape "${DIUN_ENTRY_PLATFORM:-}")" \
  "$(json_escape "${DIUN_ENTRY_PROVIDER:-}")" \
  "$(json_escape "${DIUN_ENTRY_HUBLINK:-}")" \
  "$(json_escape "${DIUN_ENTRY_CREATED:-}")" \
  "$(json_escape "${DIUN_ENTRY_METADATA_CTN_NAMES:-}")" \
  "$(json_escape "$HOSTNAME_VALUE")")

printf '%s\n' "$line" >> "$NDJSON"
tail -n "$MAX" "$NDJSON" > "$NDJSON.tmp.$$"
mv "$NDJSON.tmp.$$" "$NDJSON"

{
  printf '{\n  "report_schema": 1,\n  "generator": "image-watch",\n  "server_id": "%s",\n  "hostname": "%s",\n  "updated_at": "%s",\n  "source": "diun",\n  "updates": [\n' \
    "$(json_escape "$SERVER_ID")" \
    "$(json_escape "$HOSTNAME_VALUE")" \
    "$(json_escape "$now")"
  awk '
    {
      if (NR > 1) printf ",\n"
      printf "    %s", $0
    }
    END { if (NR > 0) printf "\n" }
  ' "$NDJSON"
  printf '  ]\n}\n'
} > "$JSON_FILE.tmp.$$"
mv "$JSON_FILE.tmp.$$" "$JSON_FILE"

printf '%s\n' "recorded ${status:-unknown} ${DIUN_ENTRY_IMAGE:-unknown}"
