#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--visual" ]]; then
  visual=1
else
  visual=0
fi

export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/shieldnet-uv-cache}"
if [[ "$visual" == "1" ]]; then
  uv sync --extra dev --extra visual --python 3.12
else
  uv sync --extra dev --python 3.12
fi

if [[ "$visual" == "1" ]]; then
  uv run playwright install chromium
fi

printf 'ShieldNet environment ready. Run: uv run shieldnet serve\n'
