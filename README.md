# Mute

Serverless, end-to-end encrypted chat and file/folder transfer with a hacker-style GUI and a terminal mode.
No account, no server, no logs. Connect by exchanging an address (IP or `.onion`) and a fingerprint.

![Mute screenshot](docs/screenshot.png)

## Features

- **Peer-to-peer**: two (or more) people connect directly; nothing is stored on any server.
- **Two network modes**
  - **DIRECT** - plain TCP to `IP:port` (LAN, port forward, or any VPN address such as Tailscale/WireGuard).
  - **TOR** - built-in onion service: works across networks and through NAT without port forwarding, and hides both IP addresses. Optional **bridges** (obfs4, meek_lite, snowflake) hide that you use Tor.
- **Strong, standard cryptography**: Noise_XX_25519_ChaChaPoly_SHA256 handshake, mutual authentication, forward secrecy, identities encrypted on the wire, periodic key ratchet, message padding.
- **Files and folders**: large files in chunks with speed/ETA, **resumable** after an interruption, folders sent as a clean zip.
- **Metadata scrubbing** (on by default) for outgoing files - see below.
- **Group chat**: connect to several peers; messages and files go to everyone you are connected to (full mesh, no relaying).
- **Leave no trace**: no chat logs, optional amnesia mode, **wipe** clears the chat window, **PANIC** wipes and exits.
- **Passphrase-protected identity key** (scrypt + ChaCha20-Poly1305).
- Runs on **Windows, Linux and macOS** from one Python file (`mute.py`).

## Install

Pick your platform - each folder has its own guide and build script:

| Platform | Guide | Build script |
|----------|-------|--------------|
| Windows | [windows/README.md](windows/README.md) | `windows/build.bat` |
| Linux | [linux/README.md](linux/README.md) - [Arch](linux/arch.md), [Kali](linux/kali.md) | `linux/build.sh` |
| macOS | [macos/README.md](macos/README.md) | `macos/build.sh` |

The GitHub Actions workflow (`.github/workflows/build.yml`) builds each platform separately
(`Mute-windows`, `Mute-linux`, `Mute-macos`).

Quick start from source on any platform:
```bash
git clone https://github.com/Speederhun/Mute-.git && cd Mute-
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python mute.py
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
python mute.py --listen --port 5555                 # wait for peers (DIRECT)
python mute.py --connect 192.168.1.20:5555          # connect (repeatable)
python mute.py --tor                                # onion service
python mute.py --tor --connect abcd...xyz.onion     # connect through Tor
python mute.py --tor --bridge "obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"
python mute.py --tor --bridge-file bridges.txt
```
Options: `--fp <fingerprint>` (expected peer), `--no-scrub`, `--amnesia`.
Commands inside: `/send <file|folder>`, `/peers`, `/fp`, `/quit`; any other text is sent to everyone.

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

**Protects**: message and file contents (end-to-end), peer authentication (fingerprint), identities from network observers,
message lengths (1 KB padding), and your disk (no logs). In TOR mode also your IP address and who talks to whom.

**Does not protect against**: a compromised device or keylogger, skipping the fingerprint check,
traffic-timing analysis by a strong adversary, metadata in DIRECT mode (IP addresses and traffic volume are visible),
or unencrypted data at rest (received files, `.partial` files, and - unless amnesia is on - the list of known peers).
The key ratchet gives forward secrecy but not full post-compromise security (no double ratchet).

**Not audited.** The cryptography uses the standard Noise protocol via a library, but the surrounding code
(framing, file transfer, fingerprints, scrubbing) has had no independent review. Get one before relying on it for high-risk use.

Tor mode, bridges, and the Windows/macOS/Arch/Kali packaging have not been tested on real systems yet - see the
status notes in each platform guide.

## Repository layout

```
mute.py            application (GUI + CLI + core)
requirements.txt   Python dependencies
windows/ linux/ macos/   per-platform guides and build scripts
tests/             unit tests (scrubbing, bridge parsing)
docs/              screenshot
.github/workflows/ CI: separate build per platform
```

## License

MIT - see [LICENSE](LICENSE).
