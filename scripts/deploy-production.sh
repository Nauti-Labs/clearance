#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REMOTE="${DEPLOY_REMOTE:-origin}"
BRANCH="${DEPLOY_BRANCH:-main}"
UPSTREAM="$REMOTE/$BRANCH"

echo "== Clearance production deploy guard =="
echo "Repo: $ROOT"
echo "Upstream: $UPSTREAM"

git fetch "$REMOTE" "$BRANCH" --prune

local_sha="$(git rev-parse HEAD)"
upstream_sha="$(git rev-parse "$UPSTREAM")"
base_sha="$(git merge-base HEAD "$UPSTREAM")"

if [[ "$local_sha" == "$upstream_sha" ]]; then
  echo "Git: local matches $UPSTREAM ($local_sha)"
elif [[ "$local_sha" == "$base_sha" ]]; then
  echo "ERROR: Local checkout is behind $UPSTREAM."
  echo "Run: git pull --ff-only $REMOTE $BRANCH"
  echo "Refusing to deploy stale code."
  exit 1
elif [[ "$upstream_sha" == "$base_sha" ]]; then
  echo "Git: local is ahead of $UPSTREAM."
  if [[ "${ALLOW_AHEAD_DEPLOY:-0}" != "1" ]]; then
    echo "ERROR: Refusing to deploy unpushed commits."
    echo "Push first, or rerun with ALLOW_AHEAD_DEPLOY=1 if this is an intentional emergency."
    exit 1
  fi
else
  echo "ERROR: Local checkout and $UPSTREAM have diverged."
  echo "Resolve with a merge/rebase before deploying."
  exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "ERROR: Working tree has uncommitted changes."
  echo "Commit/stash them, or rerun with ALLOW_DIRTY_DEPLOY=1 only for a deliberate hotfix."
  if [[ "${ALLOW_DIRTY_DEPLOY:-0}" != "1" ]]; then
    git status --short
    exit 1
  fi
  git status --short
fi

echo "Running tests..."
python3 -m pytest -q
python3 -m py_compile app.py database.py test_clearance.py crypto_verify.py models.py jwt_compat.py

echo "Deploying to Railway..."
railway up --detach

echo "Waiting for Railway to activate the new deployment..."
for _ in {1..30}; do
  latest_status="$(
    railway deployment list |
      awk -F'|' '/^[[:space:]]*[0-9a-f-]+[[:space:]]*\|/ { gsub(/[[:space:]]/, "", $2); print $2; exit }'
  )"
  if [[ "$latest_status" == "SUCCESS" ]]; then
    break
  fi
  if [[ "$latest_status" == "FAILED" || "$latest_status" == "REMOVED" ]]; then
    echo "ERROR: Latest Railway deployment ended with status: $latest_status"
    exit 1
  fi
  sleep 4
done

if [[ "${latest_status:-}" != "SUCCESS" ]]; then
  echo "ERROR: Latest Railway deployment did not report SUCCESS in time. Last status: ${latest_status:-unknown}"
  exit 1
fi

echo "Verifying live site markers..."
html="$(curl -L --max-time 20 -s https://clearance.nauti-labs.com)"

if grep -qi "glitch" <<<"$html"; then
  echo "ERROR: Live page still contains Glitch markers."
  exit 1
fi

required_markers=(
  "Card · Apple Pay · USDC accepted"
  "Google Pay"
  "USPTO SN 99745587"
)

for marker in "${required_markers[@]}"; do
  if ! grep -Fq "$marker" <<<"$html"; then
    echo "ERROR: Live page is missing marker: $marker"
    exit 1
  fi
done

echo "Production deploy verified."
