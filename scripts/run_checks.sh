#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON_BIN:-.venv/bin/python}"
"$python_bin" -m compileall -q api integrations ml_engine netguard pipeline main.py config.py
CUDA_VISIBLE_DEVICES=-1 TF_CPP_MIN_LOG_LEVEL=3 "$python_bin" scripts/verify_models.py >/dev/null
"$python_bin" -m pytest -q
