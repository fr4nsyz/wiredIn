#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8000}"
echo "wiredIn papers: http://localhost:$PORT/web/"
( sleep 1; open "http://localhost:$PORT/web/" 2>/dev/null || xdg-open "http://localhost:$PORT/web/" 2>/dev/null || true ) &
exec python3 -m http.server "$PORT" --bind 127.0.0.1
