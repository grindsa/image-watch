#!/usr/bin/env bash
# Checks the env loader against the same cases the Python parser accepts.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=load_env.sh
source "$SCRIPT_DIR/load_env.sh"

tmp=$(mktemp)
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

cat > "$tmp" <<'EOF'
# comment
export SERVER_ID="edge-01"
SMTP_PASSWORD="sec ret"
ALREADY=from-file
QUOTED_HASH="a#b"
SINGLE='bar'
EOF

unset SERVER_ID
unset SMTP_PASSWORD
unset QUOTED_HASH
unset SINGLE
export ALREADY=from-env

load_env_file "$tmp"

[ "$SERVER_ID" = "edge-01" ]
[ "$SMTP_PASSWORD" = "sec ret" ]
[ "$ALREADY" = "from-env" ]
[ "$QUOTED_HASH" = "a#b" ]
[ "$SINGLE" = "'bar'" ]

printf '%s\n' "load_env ok"
