#!/usr/bin/env bash
cd "$(dirname "$0")"
if [ -f data/.pids ]; then
  while read pid; do
    kill "$pid" 2>/dev/null && echo "killed $pid" || true
  done < data/.pids
  rm data/.pids
else
  echo "no pidfile found; try: pkill -f 'grid.server'; pkill -f 'kiosk.server'"
fi
