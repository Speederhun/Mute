#!/usr/bin/env bash
# Mute installer for Linux (Arch/Manjaro, Debian/Ubuntu/Kali/Mint, Fedora/RHEL, openSUSE).
# Installs Python + Tkinter + Tor with your package manager, sets up a private environment,
# and creates a `mute` command and an application-menu entry. Run as your normal user.
#
#   bash linux/install.sh                 install everything
#   bash linux/install.sh --dry-run       only print what would be done
#   bash linux/install.sh --no-packages   skip system packages (you already have python3, tk, tor)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

DRY=0; NOPKG=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --no-packages) NOPKG=1 ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a"; exit 2 ;;
  esac
done

say() { printf '\n==> %s\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
try() { if [ "$DRY" = 1 ]; then printf '+ %s   (optional)\n' "$*"; else "$@" || echo "   (optional step failed: $*)"; fi; }

if [ "$(id -u)" = 0 ]; then
  echo "Please run this as your normal user, not as root (sudo is used where needed)."
  exit 1
fi
SUDO=""
if [ "$NOPKG" = 0 ] && [ "$DRY" = 0 ]; then
  command -v sudo >/dev/null 2>&1 || { echo "sudo is required to install packages (or use --no-packages)."; exit 1; }
  SUDO="sudo"
elif [ "$DRY" = 1 ]; then
  SUDO="sudo"
fi

# --- distribution
ID_STR="${MUTE_OS_ID:-}"
if [ -z "$ID_STR" ] && [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  ID_STR="${ID:-} ${ID_LIKE:-}"
fi
FAMILY=""
case " $ID_STR " in
  *" arch "*|*" manjaro "*|*" endeavouros "*|*" cachyos "*) FAMILY=arch ;;
  *" debian "*|*" ubuntu "*|*" kali "*|*" linuxmint "*|*" pop "*|*" raspbian "*) FAMILY=debian ;;
  *" fedora "*|*" rhel "*|*" centos "*) FAMILY=fedora ;;
  *" suse "*|*" opensuse "*|*" opensuse-leap "*|*" opensuse-tumbleweed "*) FAMILY=suse ;;
esac

if [ "$NOPKG" = 0 ]; then
  [ -n "$FAMILY" ] || { echo "Unknown distribution ($ID_STR). Install python3 (3.10+), tkinter and tor yourself, then run with --no-packages."; exit 1; }
  say "[1/5] Installing system packages ($FAMILY): python, tkinter, tor"
  case "$FAMILY" in
    arch)
      if ! run $SUDO pacman -S --needed --noconfirm python tk tor; then
        echo "pacman failed. If it says files are not found (404) or versions mismatch, update your system"
        echo "first with: sudo pacman -Syu   (Arch does not support installing single packages on a stale database)."
        exit 1
      fi
      echo "   Bridges (obfs4/snowflake) need an extra program from the AUR, see linux/arch.md." ;;
    debian)
      run $SUDO apt-get update
      run $SUDO apt-get install -y python3 python3-venv python3-pip python3-tk tor
      try $SUDO apt-get install -y lyrebird
      try $SUDO apt-get install -y obfs4proxy
      try $SUDO apt-get install -y snowflake-client ;;
    fedora)
      run $SUDO dnf install -y python3 python3-pip python3-tkinter tor
      try $SUDO dnf install -y obfs4 ;;
    suse)
      run $SUDO zypper --non-interactive install python3 python3-pip python3-tk tor ;;
  esac
else
  say "[1/5] Skipping system packages (--no-packages)"
fi

# --- python check
say "[2/5] Checking Python"
PY="${PYTHON:-python3}"
if [ "$DRY" = 0 ]; then
  command -v "$PY" >/dev/null 2>&1 || { echo "python3 not found."; exit 1; }
  "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' \
    || { echo "Python 3.10 or newer is required (found: $("$PY" --version))."; exit 1; }
  "$PY" -c 'import tkinter' 2>/dev/null \
    || echo "   Warning: Tkinter is missing - the GUI will not start (terminal mode still works)."
  command -v tor >/dev/null 2>&1 || [ -x /usr/sbin/tor ] || echo "   Warning: tor not found - TOR mode will not work (DIRECT mode is fine)."
else
  echo "+ check python3 >= 3.10, tkinter, tor"
fi

# --- environment
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

# --- launcher + menu entry
say "[5/5] Creating the 'mute' command and the menu entry"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
if [ "$DRY" = 1 ]; then
  echo "+ write $BIN/mute and $APPS/mute.desktop"
else
  mkdir -p "$BIN" "$APPS"
  cat > "$BIN/mute" <<EOF
#!/bin/sh
exec "$ROOT/.venv/bin/python" "$ROOT/mute.py" "\$@"
EOF
  chmod +x "$BIN/mute"
  cat > "$APPS/mute.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Mute
Comment=End-to-end encrypted chat and file transfer
Exec=$BIN/mute
Terminal=false
Categories=Network;Chat;
EOF
  case ":$PATH:" in *":$BIN:"*) ;; *) echo "   Note: add $BIN to your PATH to run 'mute' from any terminal." ;; esac
fi

echo
echo "Done. Start Mute from your application menu, or run:  $BIN/mute"
echo "Terminal mode:  mute --listen   |   mute --tor"
