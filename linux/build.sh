#!/bin/bash
# Builds a single-file Linux binary: dist/Mute (works as GUI and, with arguments, as CLI).
# Build on the oldest distribution you want to support (glibc compatibility).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then python3 -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -r requirements.txt pyinstaller
python -m PyInstaller --onefile --name Mute \
  --hidden-import stem.control --hidden-import stem.process --hidden-import socks \
  --collect-submodules noise mute.py

echo
echo "Done: dist/Mute"
echo "GUI: ./dist/Mute      CLI: ./dist/Mute --listen   (see linux/README.md)"
