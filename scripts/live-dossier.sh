#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
unset NEAR_AI_API_KEY
if [[ -f "$HOME/near-build/.env.near-ai" ]]; then
  set -a
  . "$HOME/near-build/.env.near-ai"
  set +a
fi
if [[ -z "${NEAR_AI_API_KEY:-}" ]]; then
  echo "NEAR_AI_API_KEY missing" >&2
  exit 2
fi
node scripts/live.mjs "$@"
