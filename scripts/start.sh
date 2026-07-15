#!/usr/bin/env bash
set -euo pipefail

exec "${PYTHON_BIN:-.venv/bin/python}" main.py serve \
  --host "${SHIELDNET_HOST:-127.0.0.1}" \
  --port "${SHIELDNET_PORT:-8000}" \
  --workers "${SHIELDNET_WORKERS:-1}"

