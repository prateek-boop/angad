#!/usr/bin/env bash
set -euo pipefail

python_bin="${PYTHON_BIN:-.venv/bin/python}"
"$python_bin" -m compileall -q api ml_engine pipeline main.py config.py
"$python_bin" -m pytest -q

