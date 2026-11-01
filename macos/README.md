# Mute on macOS

Tested status: the shared core is tested on Linux. The macOS packaging and these instructions
have **not** been tested on a real Mac yet - please open an issue if something does not work.

> **Automatic:** `bash macos/install.sh` installs **Python, Tk, Tor and the dependencies** for you via Homebrew.

## One-command installer

```bash
git clone https://github.com/Speederhun/Mute-.git && cd Mute-
bash macos/install.sh
```
Uses [Homebrew](https://brew.sh) (it offers to install it with the official installer if missing) for Python 3.12 + Tk and **Tor**,
creates a private environment with hash-checked dependencies and `~/Applications/Mute.app`. Use `--yes` to skip the question,
`--dry-run` to only print the steps. The environment/launcher logic was tested on Linux; **the Homebrew steps and the app
bundle have not been tested on a real Mac.** If macOS blocks the first start: right-click > Open.

## Run from source

1. Python 3.10+ **with Tkinter**: either the installer from [python.org](https://www.python.org/downloads/macos/)
   or Homebrew: `brew install python python-tk`.
2. In the repository folder:
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install --require-hashes -r requirements.lock
   python mute.py
   ```
   Terminal mode: `python mute.py --listen` (see the main README).

## Install as a command with pipx

```bash
brew install pipx python-tk && pipx ensurepath
pipx install git+https://github.com/Speederhun/Mute-.git
mute
```

## Build Mute.app

```bash
bash macos/build.sh      # produces dist/Mute.app
```
The app is **unsigned**. On first start use right-click -> Open, or:
```bash
xattr -dr com.apple.quarantine dist/Mute.app
```

## Tor mode

```bash
brew install tor
```
Mute looks for `tor` in `/opt/homebrew/bin` (Apple Silicon), `/usr/local/bin` (Intel), next to
`Mute.app` in a `tor` folder, and inside `/Applications/Tor Browser.app`.
Then choose **TOR** and press **START** (or **CONNECT** to a `.onion` address).

### Bridges (hide that you use Tor)
Click **Tor bridges...** and paste lines from <https://bridges.torproject.org/>
(obfs4, meek_lite, snowflake). The pluggable-transport programs come with Tor Browser
(`Tor Browser.app/Contents/MacOS/Tor/PluggableTransports`) - Mute finds them next to the
Tor Browser `tor` binary - or install `lyrebird` yourself (for example via Homebrew, if available
for your setup) and make sure it is on your `PATH`.

## Notes
- Allow incoming connections if macOS asks (DIRECT mode only).
- The first Tor start can take up to a minute.
