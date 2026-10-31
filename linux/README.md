# Mute on Linux

The shared core is developed and tested on Linux (Python 3.12/3.13, headless GUI test under Xvfb).
Distribution-specific guides:

- **[Arch Linux](arch.md)** (and derivatives: Manjaro, EndeavourOS)
- **[Kali Linux](kali.md)** (and other Debian/Ubuntu-based systems)

## Generic quick start

Requirements: Python 3.10+, Tkinter (for the GUI), and `tor` for Tor mode.

```bash
git clone https://github.com/Speederhun/Mute-.git && cd Mute-
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python mute.py                      # GUI
python mute.py --listen             # terminal mode, DIRECT, port 5555
python mute.py --tor                # terminal mode, onion service
python mute.py --tor --connect abcd...xyz.onion
```
A virtual environment is the safe route on modern distributions: system Python is usually
"externally managed" and refuses `pip install` outside a venv.

## Single-file binary (optional)

```bash
bash linux/build.sh      # produces dist/Mute
```
Build on the oldest distribution you want to support (glibc compatibility).

## Using bridges

Tor bridges (obfs4, meek_lite, snowflake) need a pluggable-transport program in addition to `tor`:

| Transport | Program Mute looks for |
|-----------|------------------------|
| obfs4, meek_lite | `lyrebird` or `obfs4proxy` |
| snowflake | `snowflake-client` |

Mute searches `PATH`, the folders next to the app (`tor/`, `pluggable_transports/`) and, if you use
Tor Browser, its `PluggableTransports` folder. Package names differ between distributions and releases -
see the Arch and Kali guides.

CLI examples:
```bash
python mute.py --tor --bridge "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0"
python mute.py --tor --bridge-file bridges.txt
```
Bridge lines are kept in memory only and never written to disk.

## Troubleshooting

- `ModuleNotFoundError: No module named 'tkinter'` - install the Tk package for your distribution
  (`tk` on Arch, `python3-tk` on Debian/Kali/Ubuntu).
- Tor does not start - run `tor --version` to check it is installed, and read the log lines Mute prints.
  If Tor is confined by AppArmor/SELinux, look for `DENIED` messages in `dmesg`/`journalctl`
  and use a `tor` binary outside the confinement (for example from the Tor Expert Bundle).
- A firewall can block DIRECT mode (inbound TCP, default port 5555). Tor mode needs no inbound rules.
