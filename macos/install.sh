#!/usr/bin/env bash
# Mute installer for macOS. Uses Homebrew for Python, Tkinter and Tor, sets up a private
# environment and creates ~/Applications/Mute.app. Run as your normal user.
#
#   bash macos/install.sh              install everything (asks before installing Homebrew)
#   bash macos/install.sh --yes        do not ask questions
#   bash macos/install.sh --dry-run    only print what would be done
#   bash macos/install.sh --no-packages  skip Homebrew (python3 with Tk and tor are already installed)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

DRY=0; NOPKG=0; YES=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --no-packages) NOPKG=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
try() { if [ "$DRY" = 1 ]; then printf '+ %s   (optional)\n' "$*"; else "$@" || echo "   (optional step failed: $*)"; fi; }

if [ "$(uname -s)" != "Darwin" ] && [ "${MUTE_ALLOW_NON_MAC:-0}" != 1 ]; then
  echo "This installer is for macOS. On Linux use linux/install.sh."; exit 1
fi
if [ "$(id -u)" = 0 ]; then echo "Please run this as your normal user, not as root."; exit 1; fi

PY="${PYTHON:-}"
if [ "$NOPKG" = 0 ]; then
  say "[1/5] Homebrew"
  for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
    if [ -x "$b" ]; then eval "$("$b" shellenv)"; break; fi
  done
  if ! command -v brew >/dev/null 2>&1; then
    echo "Homebrew is not installed."
    if [ "$DRY" = 1 ]; then
      echo "+ install Homebrew with the official installer from https://brew.sh"
    else
      ans="n"
      if [ "$YES" = 1 ]; then ans="y"; else read -r -p "Install it now with the official installer from https://brew.sh ? [y/N] " ans; fi
      case "$ans" in
        y|Y) /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
             for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do [ -x "$b" ] && eval "$("$b" shellenv)" && break; done ;;
        *) echo "Install Homebrew from https://brew.sh and run this again (or use --no-packages)."; exit 1 ;;
      esac
    fi
  fi
  say "[2/5] Installing Python 3.12 with Tk, and Tor"
  run brew install python@3.12 python-tk@3.12 tor
  try brew install lyrebird
  if [ "$DRY" = 0 ]; then PY="$(brew --prefix python@3.12)/bin/python3.12"; else PY=python3.12; fi
else
  say "[1/5] Skipping Homebrew (--no-packages)"
  say "[2/5] Checking Python"
  PY="${PY:-python3}"
fi

if [ "$DRY" = 0 ]; then
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
    || { echo "Python 3.10 or newer is required."; exit 1; }
  "$PY" -c 'import tkinter' 2>/dev/null || echo "   Warning: Tkinter is missing - the GUI will not start."
  command -v tor >/dev/null 2>&1 || [ -x /opt/homebrew/bin/tor ] || [ -x /usr/local/bin/tor ] \
    || echo "   Warning: tor not found - TOR mode will not work (DIRECT mode is fine)."
fi

say "[3/5] Creating a private environment in .venv"
run "$PY" -m venv .venv
say "[4/5] Installing Python dependencies (hash-checked)"
if [ "$DRY" = 1 ]; then
  echo "+ .venv/bin/python -m pip install --require-hashes -r requirements.lock   (fallback: requirements.txt)"
else
  .venv/bin/python -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  .venv/bin/python -m pip install --require-hashes -r requirements.lock \
    || { echo "   Hash-checked install failed, trying the normal install..."; .venv/bin/python -m pip install -r requirements.txt; }
fi

say "[5/5] Creating ~/Applications/Mute.app"
APP="${MUTE_APP_DIR:-$HOME/Applications}/Mute.app"
if [ "$DRY" = 1 ]; then
  echo "+ write $APP"
else
  mkdir -p "$APP/Contents/MacOS"
  cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Mute</string>
  <key>CFBundleDisplayName</key><string>Mute</string>
  <key>CFBundleIdentifier</key><string>local.mute.launcher</string>
  <key>CFBundleExecutable</key><string>Mute</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
  cat > "$APP/Contents/MacOS/Mute" <<EOF
#!/bin/sh
export PATH="/opt/homebrew/bin:/usr/local/bin:\$PATH"
cd "$ROOT"
exec "$ROOT/.venv/bin/python" "$ROOT/mute.py" "\$@"
EOF
  chmod +x "$APP/Contents/MacOS/Mute"
fi

echo
echo "Done. Open Mute from ~/Applications (Spotlight: Mute), or run:  $ROOT/.venv/bin/python $ROOT/mute.py"
echo "If macOS blocks the first start: right-click Mute.app > Open."
