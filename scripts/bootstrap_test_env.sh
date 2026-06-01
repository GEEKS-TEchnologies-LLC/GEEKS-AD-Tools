#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-venv}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "Python command not found: $PYTHON_BIN" >&2
    exit 1
fi

"$PYTHON_BIN" -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install --upgrade pip
"$VENV_DIR/bin/python" -m pip install -r requirements.txt

export SECRET_KEY
SECRET_KEY="$("$VENV_DIR/bin/python" - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
)"

"$VENV_DIR/bin/python" scripts/security_scan.py
"$VENV_DIR/bin/python" -m py_compile app/__init__.py app/ad.py app/exchange.py app/views.py build.py scripts/security_scan.py
"$VENV_DIR/bin/python" -m pytest -q
"$VENV_DIR/bin/python" build.py test
