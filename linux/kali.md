# Mute on Kali Linux

Status: written from the standard Debian/Kali package layout; **not tested on a real Kali install**
(the core itself is tested on Linux). Please open an issue if a step fails.
Works the same on other Debian/Ubuntu-based systems.

## 1. Install dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-tk tor git
```
- `python3-tk` - Tkinter (GUI)
- `tor` - needed for Tor mode. The Debian package starts a **system** Tor daemon; Mute does not use it,
  it launches its own private Tor on random local ports, so the two do not conflict.
  If you do not need the system daemon: `sudo systemctl disable --now tor`.

> **Shortcut:** `bash linux/install.sh` does steps 1-3 for you (apt packages incl. bridge helpers if available, venv, launcher).

## 2. Get Mute and install the Python packages in a virtual environment

```bash
git clone https://github.com/Speederhun/Mute-.git
cd Mute-
python3 -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
```
Run as your normal user - there is no reason to use root.

## 3. Run

```bash
python mute.py                         # GUI
python mute.py --listen --port 5555    # terminal mode, DIRECT
python mute.py --tor                   # terminal mode, onion service
```
Next time: `cd Mute- && source .venv/bin/activate`.

**Alternative - pipx** (`sudo apt install pipx`, then `pipx ensurepath` and a new shell):
```bash
pipx install git+https://github.com/Speederhun/Mute-.git
mute
```

## Optional: bridges (hide that you use Tor)

You need a pluggable-transport program in addition to `tor`. Package names depend on the Kali release;
look them up instead of guessing:

```bash
apt search lyrebird
apt search obfs4proxy
apt search snowflake
```
- **obfs4 / meek_lite** - `lyrebird` (newer) or `obfs4proxy` (older), whichever your release offers.
- **snowflake** - `snowflake-client`, if your release has it.
- **Nothing in the repo?** Download Tor Browser or the Tor Expert Bundle from
  <https://www.torproject.org/download/> and keep its `PluggableTransports` / `pluggable_transports`
  folder next to the `tor` binary or the `Mute` folder - Mute searches those locations.

Then paste bridge lines from <https://bridges.torproject.org/> into **Tor bridges...** (GUI) or use
`--bridge` / `--bridge-file` (CLI).

## Troubleshooting on Debian-based systems

- **Tor exits immediately / "permission denied"**: Debian's `tor` package ships an AppArmor profile
  that can confine `/usr/bin/tor` even when you run it as a normal user. Check `sudo aa-status`
  and `sudo dmesg | grep -i denied`. Workaround: use a `tor` binary from the Tor Expert Bundle
  placed in a `tor/` folder next to `mute.py` (Mute prefers it over the system one).
- **`No module named tkinter`**: `sudo apt install python3-tk`, and make sure the venv uses the same Python.
- **GUI over SSH**: use `ssh -X`, or just use terminal mode (`--listen`, `--tor`, `/send`).

## Optional: single-file binary

```bash
bash linux/build.sh      # dist/Mute
```
