#!/usr/bin/env bash
# Launch Grid and Kiosk in two background processes.
# Use on Linux/Mac. On Windows, run the two commands in separate terminals.
set -e
cd "$(dirname "$0")"
mkdir -p data
python3 -m grid.server  > data/grid.log  2>&1 &
GRID_PID=$!
python3 -m kiosk.server > data/kiosk.log 2>&1 &
KIOSK_PID=$!
echo "Grid PID=$GRID_PID  (logs: data/grid.log)"
echo "Kiosk PID=$KIOSK_PID (logs: data/kiosk.log)"
echo "$GRID_PID"  >  data/.pids
echo "$KIOSK_PID" >> data/.pids
sleep 1
echo ""
echo "Servers running. Next steps (in another terminal):"
echo "  1. Register a franchise:  python3 -m franchise.cli register"
echo "  2. Boot the kiosk:        python3 -m franchise.cli boot"
echo "  3. Register an EV owner:  python3 -m user_device.client register"
echo "  4. Charge:                python3 -m user_device.client charge"
echo ""
echo "To stop both servers:      ./stop_all.sh"
