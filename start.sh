#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

PROFILE="${WIREDIN_PROFILE:-$HOME/CONFIGURE-THIS}"
export WIREDIN_PROFILE="$PROFILE"

if ! command -v python3 &>/dev/null; then
  echo "error: python3 is required" >&2
  exit 1
fi

if [ ! -d __pycache__ ] && ! python3 -c "import defusedxml, certifi, textual" 2>/dev/null; then
  echo "==> installing dependencies..."
  pip install -r requirements.txt
fi

exec python3 wiredIn_tui.py "$@"
