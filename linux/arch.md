# Mute on Arch Linux

Status: written from the standard Arch package layout; **not tested on a real Arch install**
(the core itself is tested on Linux). Please open an issue if a step fails.

## 1. Install dependencies

```bash
sudo pacman -S --needed python tk tor git
```
- `python` + `tk` - interpreter and Tkinter (GUI)
- `tor` - needed for Tor mode (Mute starts its own private Tor process; you do **not** need to
  enable or start the `tor.service` system daemon)

> **Shortcut:** `bash linux/install.sh` does steps 1-3 for you (pacman packages, venv, launcher).
> It only installs what is missing and never upgrades your system. If pacman reports missing files or conflicts, fix your mirrors/database your own way first.

## 2. Get Mute and install the Python packages in a virtual environment

Arch marks the system Python as externally managed, so use a venv:

```bash
git clone https://github.com/Speederhun/Mute-.git
cd Mute-
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
```
(`noiseprotocol` has no official Arch package, which is why pip inside the venv is used.)

## 3. Run

```bash
python mute.py                         # GUI
python mute.py --listen --port 5555    # terminal mode, DIRECT
python mute.py --tor                   # terminal mode, onion service
```
Next time just `cd Mute- && source .venv/bin/activate`.

**Alternative - pipx** (`sudo pacman -S python-pipx`):
```bash
pipx install git+https://github.com/Speederhun/Mute-.git
mute
```

## Optional: bridges (hide that you use Tor)

You need a pluggable-transport program in addition to `tor`:

- **obfs4 / meek_lite** - `lyrebird` (successor of `obfs4proxy`). At the time of writing it is
  available from the AUR as [`lyrebird-proxy`](https://aur.archlinux.org/packages/lyrebird-proxy)
  (`yay -S lyrebird-proxy`, or build it with `makepkg`). Check `pacman -Ss obfs4proxy lyrebird`
  first - an official package may exist by the time you read this.
- **snowflake** - search with `pacman -Ss snowflake` and `yay -Ss snowflake` for `snowflake-client`.
- **No AUR?** Install `torbrowser-launcher` (official repo), run it once to download Tor Browser;
  Mute finds the transports in `~/.local/share/torbrowser/.../Tor/PluggableTransports`.

Then paste bridge lines from <https://bridges.torproject.org/> into **Tor bridges...** (GUI) or use
`--bridge` / `--bridge-file` (CLI).

## Optional: single-file binary

```bash
bash linux/build.sh      # dist/Mute
```

## Notes
- Wayland: Tkinter runs through XWayland; no extra steps needed on a normal desktop session.
- Firewall (`ufw`/`nftables`): DIRECT mode needs inbound TCP on your chosen port; Tor mode does not.
