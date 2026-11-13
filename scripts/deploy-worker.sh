#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../worker"
npx -y wrangler@latest deploy
