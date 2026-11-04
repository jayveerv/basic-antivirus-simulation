#!/usr/bin/env bash
# Basic Antivirus Simulation - Linux / macOS launcher
set -e
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Python 3.10+ is required"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements-dev.txt
case "${1:-web}" in
  web)     python webapp/app.py ;;
  demo)    python scan.py samples demo_files && python scan.py scan demo_files --report both --quarantine ;;
  watch)   python scan.py watch "${2:-watched}" --quarantine ;;
  test)    python -m pytest -q ;;
  *)       python scan.py "$@" ;;
esac
