#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required." >&2
  exit 1
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap is required." >&2
  exit 1
fi

exec python3 "$SCRIPT_DIR/app.py" "$@"
