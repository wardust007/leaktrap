#!/bin/bash
# Double-click this file on a Mac (or run ./"Start LeakTrap.command" on Linux).
cd "$(dirname "$0")" || exit 1
echo ""
echo "  Starting LeakTrap... your browser will open in a moment."
echo "  To stop, close this window."
echo ""
python3 -m leaktrap ui || {
  echo ""
  echo "  Could not start LeakTrap. Install Python 3.10+ from https://www.python.org/downloads/"
  read -r -p "  Press Enter to close..."
}
