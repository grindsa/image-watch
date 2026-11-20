#!/usr/bin/env bash
# Update an image-watch install from GitHub and refresh the local stack.
# Expected location: /srv/stacks/trivy
# Data volume:       /srv/data/trivy  (left in place)
# Usage (on the server): sudo ./deploy.sh

set -euo pipefail

EXPECTED_ROOT="/srv/stacks/trivy"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "deploy.sh must run as root" >&2
  exit 1
fi

if [[ "$ROOT" != "$EXPECTED_ROOT" ]]; then
  echo "deploy.sh must run from ${EXPECTED_ROOT} (this copy is ${ROOT})." >&2
  exit 1
fi

if [[ ! -d .git ]]; then
  cat >&2 <<MSG
This directory is not a git checkout, so it cannot fetch GitHub.
Clone the repository in place, then install:

  git clone https://github.com/grindsa/image-watch.git ${EXPECTED_ROOT}
  cd ${EXPECTED_ROOT}
  ./install.sh
MSG
  exit 1
fi

if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.example and fill in values before deploying." >&2
  exit 1
fi

BRANCH="${DEPLOY_BRANCH:-main}"

# /srv/stacks is often owned by another user. Pass the exception per command
# instead of writing git config.
git_repo() {
  git -c "safe.directory=${ROOT}" "$@"
}

# Last KEY= value in .env, with one pair of matching quotes removed.
env_is_enabled() {
  local key="$1" value
  value="$(awk -F= -v key="$key" '
    $1 == key { value = substr($0, index($0, "=") + 1) }
    END { print value }
  ' .env)"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  case "$value" in
    \"*\") value="${value#\"}"; value="${value%\"}" ;;
    \'*\') value="${value#\'}"; value="${value%\'}" ;;
  esac
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ -z "${IMAGE_WATCH_DEPLOY_UPDATED:-}" ]]; then
  echo "==> Fetching ${BRANCH} in ${ROOT}"
  git_repo fetch origin
  # Secrets stay put: .env is gitignored, and /srv/data/trivy is outside the repo.
  # Local edits to tracked files would otherwise block the update.
  if ! git_repo diff --quiet || ! git_repo diff --cached --quiet; then
    echo "Note: discarding local changes to tracked files before reset to origin/${BRANCH}" >&2
    git_repo status --short || true
  fi
  git_repo checkout -f -B "$BRANCH" "origin/${BRANCH}"
  # Bash keeps executing the pre-pull copy of this file, so restart on the
  # version that was just checked out.
  export IMAGE_WATCH_DEPLOY_UPDATED=1
  exec "$ROOT/deploy.sh" "$@"
fi

echo "==> Pulling container images"
if ! docker compose -f "$ROOT/docker-compose.yml" pull; then
  echo "ERROR: docker compose pull failed" >&2
  exit 1
fi
if env_is_enabled DIUN_ENABLED; then
  if ! docker compose --profile cron -f "$ROOT/docker-compose.diun.yml" pull; then
    echo "ERROR: DIUN image pull failed" >&2
    exit 1
  fi
fi
if env_is_enabled WATCHTOWER_ENABLED; then
  if ! docker compose --profile cron -f "$ROOT/docker-compose.watchtower.yml" pull; then
    echo "ERROR: Watchtower image pull failed" >&2
    exit 1
  fi
fi

echo "==> Updating cron, permissions, and the Trivy container"
if ! "$ROOT/install.sh"; then
  echo "ERROR: install.sh failed" >&2
  exit 1
fi

if ! docker compose -f "$ROOT/docker-compose.yml" ps --status running --services | grep -qx 'trivy'; then
  echo "ERROR: trivy container is not running after deploy" >&2
  docker compose -f "$ROOT/docker-compose.yml" ps >&2 || true
  exit 1
fi

echo "Deploy complete."
echo "IMAGE_WATCH_DEPLOY_OK"
