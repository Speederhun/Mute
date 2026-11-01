# Mute on Windows

Tested status: the shared core is tested on Linux. The Windows packaging and these
instructions have **not** been tested on a real Windows machine yet - please open an issue
if something does not work.

## Easiest: one double-click installer

Download the repository (green **Code** button > *Download ZIP*, unzip it) and double-click **`windows\install.bat`**.
It looks for Python 3.10+, **installs Python 3.12 for your user account if it is missing** (via `winget`, otherwise
from python.org), creates a private environment, installs the pinned dependencies and puts a **Mute** shortcut on your desktop.
No administrator rights needed. This installer has not been tested on a real Windows machine yet.

## Option A - run from source (recommended, avoids antivirus false positives)

1. Install Python 3.10+ from [python.org](https://www.python.org/downloads/windows/)
   (tick **"Add python.exe to PATH"**; Tcl/Tk is included by default).
2. In the repository folder:
   ```bat
   python -m pip install --require-hashes -r requirements.lock
   python mute.py
   ```
   Terminal mode: `python mute.py --listen` (see the main README for all options).

### Option A2 - install as a command with pipx
```bat
python -m pip install --user pipx
python -m pipx ensurepath
pipx install git+https://github.com/Speederhun/Mute-.git
mute
```

## Option B - build the .exe

```bat
windows\build.bat
```
Produces `dist\Mute.exe` (GUI) and `dist\Mute-cli.exe` (terminal mode; the GUI build has no console).
Unsigned PyInstaller executables are sometimes flagged by Windows Defender/SmartScreen -
that is a false positive, but it is the reason Option A exists. Prefer CI artifacts only if you
trust the build; otherwise build it yourself.

## Tor mode (works across networks, hides IPs)

1. Download the **Tor Expert Bundle** (Windows) from <https://www.torproject.org/download/tor/>.
2. Unzip it and copy the `tor` folder (it contains `tor.exe`) **next to `Mute.exe`**
   (or next to `mute.py` if you run from source).
   Installed Tor Browser is also detected (`Desktop\Tor Browser`, `C:\Program Files\Tor Browser`).
3. In Mute choose **TOR** and press **START** (or just **CONNECT** to a `.onion` address).

### Bridges (hide that you use Tor)
Click **Tor bridges...**, paste bridge lines from <https://bridges.torproject.org/>
(obfs4, meek_lite, snowflake). The pluggable-transport programs (`lyrebird.exe`,
`snowflake-client.exe`) come with the Tor Expert Bundle in its `pluggable_transports` folder -
keep that folder next to `tor`, Mute finds it automatically.

## Firewall
DIRECT mode needs an inbound TCP rule for the port you listen on (default 5555);
Windows will prompt on first start. Tor mode needs no inbound rule.

## Privacy options specific to Windows
**Options... > block screenshots / screen recording** sets the window display-affinity flag, so ordinary screen capture
shows a black window. It does not stop a camera or malware. This feature has not been tested on a real Windows machine yet.
