#!/bin/bash
# macOS build. Előfeltételek: Python 3 Tkinterrel (python.org telepítő, vagy: brew install python-tk)
# Tor módhoz: brew install tor   (vagy Tor Browser az /Applications mappában)
set -e
pip3 install -r requirements.txt pyinstaller
pyinstaller --windowed --name Mute \
  --hidden-import stem.control --hidden-import stem.process --hidden-import socks \
  --collect-submodules noise mute.py
echo "Kész: dist/Mute.app"
echo "Ha a Gatekeeper blokkolja (aláíratlan app): xattr -dr com.apple.quarantine dist/Mute.app"
