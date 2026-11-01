#!/bin/bash
# Builds dist/Mute.app. Run from anywhere; the script switches to the repository root.
# Prerequisite: Python 3 with Tkinter (python.org installer, or: brew install python-tk)
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install pyinstaller
python3 -m PyInstaller --windowed --icon assets/mute.icns --name Mute \
  --hidden-import stem.control --hidden-import stem.process --hidden-import socks \
  --collect-submodules noise --collect-all tkinterdnd2 mute.py

echo
echo "Done: dist/Mute.app"
echo "Unsigned app blocked by Gatekeeper? Run: xattr -dr com.apple.quarantine dist/Mute.app"
echo "Tor mode needs tor: brew install tor  (see macos/README.md)"
