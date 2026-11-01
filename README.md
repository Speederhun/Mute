# Mute

Serverless, end-to-end encrypted chat and file/folder transfer with a hacker-style GUI and a terminal mode.
No account, no server, no logs. Connect by exchanging an address (IP or `.onion`) and a fingerprint.

![Mute screenshot](docs/screenshot.png)

<details><summary>Options window</summary>

![Mute options](docs/options.png)

</details>

## Features

- **Peer-to-peer**: two (or more) people connect directly; nothing is stored on any server.
- **Two network modes**
  - **DIRECT** - plain TCP to `IP:port` (LAN, port forward, or any VPN address such as Tailscale/WireGuard).
  - **TOR** - built-in onion service: works across networks and through NAT without port forwarding, and hides both IP addresses. Optional **bridges** (obfs4, meek_lite, snowflake) hide that you use Tor.
- **Strong, standard cryptography**: Noise_XX_25519_ChaChaPoly_SHA256 handshake, mutual authentication, forward secrecy, identities encrypted on the wire, periodic key ratchet, message padding.
- **Files and folders**: large files in chunks with speed/ETA, **resumable** after an interruption, folders sent as a clean zip.
- **Metadata scrubbing** (on by default) for outgoing files - see below.
- **Group chat**: connect to several peers; messages and files go to everyone you are connected to (full mesh, or via a relay hub).
- **Know who is writing**: every peer is identified by its cryptographic key. When someone connects you give them a name
  (only you see it; it is not sent, not saved, and a peer cannot choose or fake it). Each peer gets its own colour.
  Unnamed peers show an 8-character ID derived from their key. In group chats name everyone as soon as you have
  verified their fingerprint.
- **Leave no trace**: no chat logs, **burner identity** (random key per start, nothing saved), amnesia mode, **wipe** clears the chat window,
  **PANIC** (button, `Ctrl+Shift+Q` or `Esc` x3) wipes and exits, optional **auto-clear** of old chat lines and **auto-lock** screen (`Ctrl+L`).
- **Access control**: **closed mode** (only allowlisted fingerprints can connect, no prompts), optional **shared secret**
  (Noise `XXpsk3`, stops man-in-the-middle even if the fingerprint check is skipped), **onion client authorization**
  (without your key nobody can even find your onion service).
- **Easy verification**: besides the hex fingerprint every identity has **6 pronounceable words** to read aloud over the phone.
- **Group chat extras**: optional **relay hub** (one person forwards messages between peers who are not connected to each other)
  and **cover traffic** (random dummy frames so idle and active periods look alike).
- **Passphrase-protected identity key** (scrypt + ChaCha20-Poly1305); the list of known peers is encrypted with the same passphrase.
- **Hygiene options**: clipboard auto-clear after 30 s, notifications without message content, screenshot/recording block on Windows.
- Runs on **Windows, Linux and macOS** from one Python file (`mute.py`).

## Download

Each platform has its **own release** on the [Releases page](../../releases): `windows-vX.Y.Z`, `linux-vX.Y.Z`, `macos-vX.Y.Z`.
Every release contains the binaries for that system, an installer pack (installs Python/Tor if needed) and SHA-256 checksums.
They are built by GitHub Actions when a `vX.Y.Z` tag is pushed (`git tag v1.1.0 && git push origin v1.1.0`).

## Install

Pick your platform - each folder has its own guide and build script:

| Platform | Guide | Build script |
|----------|-------|--------------|
| Windows | [windows/README.md](windows/README.md) - double-click `windows/install.bat` (installs Python if needed) | `windows/build.bat` |
| Linux | [linux/README.md](linux/README.md) - [Arch](linux/arch.md), [Kali](linux/kali.md) - `bash linux/install.sh` (installs Python, Tk, Tor) | `linux/build.sh` |
| macOS | [macos/README.md](macos/README.md) - `bash macos/install.sh` (Homebrew: Python, Tk, Tor) | `macos/build.sh` |

The GitHub Actions workflow (`.github/workflows/build.yml`) builds each platform separately
(`Mute-windows`, `Mute-linux`, `Mute-macos`).

Quick start from source on any platform:
```bash
git clone https://github.com/Speederhun/Mute-.git && cd Mute-
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements.lock       # pinned, hash-checked dependencies
python mute.py
```
Or install it as a command with [pipx](https://pipx.pypa.io/) (no venv to manage):
```bash
pipx install git+https://github.com/Speederhun/Mute-.git
mute            # GUI        mute --listen   # terminal
```

## How to connect

1. Start Mute. On first run set a passphrase for your identity key (or leave it empty).
2. **Person A**: choose a mode and press **START**.
   - DIRECT: your IP is shown (port 5555 by default).
   - TOR: after a short while an `xxxx.onion:5555` address appears (new on every start).
3. Give A's address **and fingerprint** to **Person B over a different channel** (phone call, in person, another messenger).
4. **Person B**: choose the same mode, paste the address into **PEER**, press **CONNECT** (in TOR mode this starts Tor automatically).
5. The first time, Mute shows the peer's fingerprint. Compare it with what the other person told you and accept only if it matches. You can also type the expected fingerprint into **expect fp** to make Mute check it automatically.

You do **not** need to be on the same network in TOR mode. DIRECT mode needs the listening side to be reachable
(same LAN, a forwarded port, or a shared VPN).

## Terminal mode

```bash
mute --listen --port 5555                 # wait for peers (DIRECT)
mute --connect 192.168.1.20:5555          # connect (repeatable)
mute --tor                                # onion service
mute --tor --connect abcd...xyz.onion     # connect through Tor
mute --tor --bridge "obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"
mute --tor --bridge-file bridges.txt
mute --burner --listen --closed --allow "1a2b 3c4d ..."    # throw-away identity, only one trusted peer
mute --listen --psk                       # ask for a shared secret (hidden input)
```
(From a source checkout use `python mute.py` instead of `mute`.)

| Option | Meaning |
|--------|---------|
| `--burner` | random identity for this run, nothing saved |
| `--amnesia` | save nothing (known peers, etc.) |
| `--closed`, `--allow FP` | only trusted fingerprints may connect (repeat `--allow`) |
| `--psk` | both sides enter the same secret before connecting |
| `--relay` | forward chat messages between your peers (hub) |
| `--cover` | send dummy traffic at random intervals |
| `--client-auth` | create an onion client key (memory only) and print the public part |
| `--allow-client KEY` | only holders of these onion client keys can reach your onion service |
| `--fp FP` | expected fingerprint of the peer you connect to |
| `--no-scrub` | do not scrub metadata from sent files |
| `--persistent` | GUI: skip the burner/persistent question |

Commands inside: `/send <file|folder>`, `/connect <host[:port]> [fp]`, `/peers`, `/name <id-or-name> <new name>`,
`/fp`, `/words`, `/allow <fp>`, `/relay on|off`, `/cover on|off`, `/quit`; any other text is sent to everyone.

In the GUI the same settings are under **Options...** (closed mode, allowlist, shared secret, relay, cover traffic, onion client keys,
auto-clear, auto-lock, clipboard, notifications, screenshot block on Windows).

## Metadata scrubbing

Enabled by default (checkbox **scrub metadata**, CLI `--no-scrub` to disable). Files are scrubbed
**on your machine, before sending**; the original is never modified.

| Type | What happens |
|------|--------------|
| JPEG | EXIF (camera, GPS, timestamps), XMP, IPTC, comments removed without re-encoding; the orientation flag is kept so photos are not rotated |
| PNG | text, EXIF and time chunks and trailing data removed |
| DOCX / XLSX / PPTX | author, last-modified-by, title, company, dates etc. removed from document properties |
| Folders (zip) | timestamps zeroed, permissions/owners normalised, each supported file scrubbed |
| **Anything else** (PDF, video, audio, Office text content, ...) | **not scrubbed** - Mute tells you which files were skipped. Scrub those with a dedicated tool before sending |

Limits: text inside documents (tracked changes, comments, author tags), pixel-level or steganographic
identifiers, and custom document properties are **not** removed. Scrubbing is best-effort hygiene, not anonymity.

## Security model

**Protects**: message and file contents (end-to-end), peer authentication (fingerprint, optionally plus a shared secret),
identities from network observers, message lengths (1 KB padding), and your disk (no logs; known peers encrypted).
In TOR mode also your IP address and who talks to whom. Closed mode and onion client authorization keep strangers out entirely.

**Does not protect against**:
- a compromised device or keylogger, or skipping the fingerprint check (use words/fingerprint, a shared secret, or closed mode);
- traffic-timing analysis by a strong adversary - **cover traffic helps only against simple observers**, it is not a guarantee;
- metadata in DIRECT mode (IP addresses and traffic volume are visible);
- **a malicious relay hub**: in relay mode the hub operator can drop, delay or **forge** relayed messages (the origin shown for
  a relayed message is the hub's claim, not a cryptographic proof). Use it only with a hub you trust, or connect to everyone directly;
- unencrypted data at rest: received files and `.partial` files are plain on disk - use full-disk encryption (BitLocker, FileVault, LUKS);
- the screenshot block is a Windows display-affinity flag: it stops ordinary screen capture, not a camera or a compromised OS;
- RAM, swap and crash dumps (secrets live in memory while the app runs).

The key ratchet gives forward secrecy but not full post-compromise security (no double ratchet).
Adding one would be a protocol change; use a vetted implementation rather than hand-rolling it.

**Not audited.** The cryptography uses the standard Noise protocol via a library, but the surrounding code
(framing, file transfer, fingerprints, relay, scrubbing) has had no independent review. Get one before relying on it for high-risk use.
See [SECURITY.md](SECURITY.md) for reporting problems.

**Tested automatically** (CI on Windows, Linux and macOS): loopback connections, messages, resumable large transfers,
shared secrets, closed mode, burner identities, encrypted known-peers file, relay and cover frames, tampered/replayed/reordered
frames, garbage handshakes, and fuzzed scrubbers and parsers. **Not tested on real systems**: Tor bootstrap and onion
services end to end, bridges, the Windows screenshot block, and the Windows/macOS/Arch/Kali packaging - see the status notes in each platform guide.

## Repository layout

```
mute.py             application (GUI + CLI + core)
pyproject.toml      packaging (pipx install / pip install .)
requirements.txt    dependency ranges
requirements.lock   pinned dependencies with hashes (pip install --require-hashes -r requirements.lock)
SECURITY.md         how to report problems, what is and is not tested
windows/ linux/ macos/   per-platform guides and build scripts
tests/              scrubbing, loopback network/crypto, fuzz tests
docs/               screenshot
.github/            CI (test matrix, security checks, per-platform builds) and Dependabot
```

## License

MIT - see [LICENSE](LICENSE).
