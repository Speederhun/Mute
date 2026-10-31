#!/usr/bin/env python3
"""
Mute - serverless, end-to-end encrypted chat and file/folder transfer.

Network modes:
  DIRECT : plain TCP (LAN / port forward / any VPN address)
  TOR    : Tor onion service - works through NAT, hides both IP addresses.
           Optional bridges (obfs4, meek_lite, snowflake) hide that you use Tor.

Cryptography:
  * Noise_XX_25519_ChaChaPoly_SHA256 handshake (noiseprotocol library):
    mutual authentication, forward secrecy, identities encrypted on the wire
  * X25519 identity key (optionally passphrase-protected: scrypt + ChaCha20-Poly1305)
  * 1 KB padding (hides message length), key ratchet (rekey) every 512 frames
  * Outgoing files can be scrubbed of metadata (EXIF/GPS, document properties,
    zip timestamps) before they leave your machine
  * No logs, messages live in memory only
"""
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)
from noise.connection import Keypair, NoiseConnection

APP_DIR = os.path.join(os.path.expanduser("~"), ".mute")
DOWNLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "Mute")
DEFAULT_PORT = 5555
MAGIC = b"Mute/3 Noise_XX"   # Noise prologue: binds both sides to this protocol version
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
ENC_MAGIC = b"SP2PENC1"
CHUNK = 60 * 1024            # a Noise message is at most 65535 bytes
PAD = 1024
REKEY_EVERY = 512            # ratchet the key every N frames
MAX_FRAME = 65535 + 64

T_MSG, T_FILE_START, T_FILE_CHUNK, T_FILE_END, T_FILE_OFFSET = 1, 2, 3, 4, 5

_BAD = '<>:"/\\|?*'
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name):
    """File name that is safe on Windows, macOS and Linux."""
    name = os.path.basename(name.replace("\\", "/"))
    name = "".join("_" if (c in _BAD or ord(c) < 32) else c for c in name)
    name = name.strip(" .")
    if not name:
        return "file"
    stem, ext = os.path.splitext(name)
    if stem.upper() in _RESERVED:
        stem = "_" + stem
    if len(stem) + len(ext) > 150:
        stem = stem[:150 - len(ext)]
    return stem + ext


def file_id(path, name, size):
    """Resume identifier: name + size + hash of the first 1 MiB."""
    h = hashlib.sha256(f"{name}|{size}|".encode())
    with open(path, "rb") as f:
        h.update(f.read(1 << 20))
    return h.hexdigest()


# ---------------------------------------------------------------- helpers
def raw_pub(key):
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def fingerprint(pub_bytes):
    h = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


def short(fp):
    return fp.replace(" ", "")[:8]


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part:
            raise ConnectionError("Connection closed")
        buf += part
    return bytes(buf)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # sends no packets
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            a = info[4][0]
            if ":" not in a and not a.startswith("127."):
                ips.add(a)
    except OSError:
        pass
    return sorted(ips)


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024


# ---------------------------------------------------------------- identity
class NeedPassphrase(Exception):
    pass


def _kdf(pw, salt):
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(pw.encode())


def identity_state(app_dir=None):
    path = os.path.join(app_dir or APP_DIR, "identity.key")
    if not os.path.exists(path):
        return "missing"
    with open(path, "rb") as f:
        return "encrypted" if f.read(8) == ENC_MAGIC else "plain"


def load_identity(app_dir=None, passphrase=None):
    app_dir = app_dir or APP_DIR
    os.makedirs(app_dir, exist_ok=True)
    path = os.path.join(app_dir, "identity.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            blob = f.read()
        if blob.startswith(ENC_MAGIC):
            if passphrase is None:
                raise NeedPassphrase()
            salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
            try:
                raw = ChaCha20Poly1305(_kdf(passphrase, salt)).decrypt(nonce, ct, b"")
            except InvalidTag:
                raise ValueError("Wrong passphrase")
        else:
            raw = blob
        return X25519PrivateKey.from_private_bytes(raw)
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    if passphrase:
        salt, nonce = os.urandom(16), os.urandom(12)
        raw = ENC_MAGIC + salt + nonce + ChaCha20Poly1305(
            _kdf(passphrase, salt)).encrypt(nonce, raw, b"")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return key


# ---------------------------------------------------------------- handshake (Noise XX)
def _hs_send(sock, msg):
    sock.sendall(struct.pack(">H", len(msg)) + msg)


def _hs_recv(sock):
    (n,) = struct.unpack(">H", recv_exact(sock, 2))
    if n > 1024:
        raise ConnectionError("Invalid handshake message")
    return recv_exact(sock, n)


def _capture_remote_static():
    """The library wipes its handshake state when the handshake completes, so the
    peer's authenticated static key (rs) is saved at the end of read_message."""
    from noise.state import HandshakeState
    if getattr(HandshakeState.read_message, "_mute_patched", False):
        return
    orig = HandshakeState.read_message

    def read_message(self, message, payload_buffer):
        try:
            return orig(self, message, payload_buffer)
        finally:
            rs = getattr(self, "rs", None)
            if hasattr(rs, "public_bytes"):  # starts as an empty placeholder object
                self.noise_protocol._mute_rs = bytes(rs.public_bytes)

    read_message._mute_patched = True
    HandshakeState.read_message = read_message


_capture_remote_static()


def handshake(sock, ident, initiator):
    """Noise XX: -> e | <- e, ee, s, es | -> s, se.
    Returns (peer static public key, NoiseConnection with transport state)."""
    c = NoiseConnection.from_name(NOISE_NAME)
    c.set_prologue(MAGIC)
    c.set_keypair_from_private_bytes(
        Keypair.STATIC, ident.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    if initiator:
        c.set_as_initiator()
        c.start_handshake()
        _hs_send(sock, c.write_message())
        c.read_message(_hs_recv(sock))
        _hs_send(sock, c.write_message())
    else:
        c.set_as_responder()
        c.start_handshake()
        c.read_message(_hs_recv(sock))
        _hs_send(sock, c.write_message())
        c.read_message(_hs_recv(sock))
    if not c.handshake_finished:
        raise ConnectionError("Handshake did not complete")
    rs = getattr(c.noise_protocol, "_mute_rs", None)
    if rs is None or len(rs) != 32:
        raise ConnectionError("Could not determine the peer's key")
    return rs, c


class Channel:
    def __init__(self, sock, noise):
        self.sock = sock
        self.noise = noise
        self.sn = self.rn = 0
        self.lock = threading.Lock()
        self.offset_q = queue.Queue()

    def send(self, typ, payload=b""):
        body = struct.pack(">BI", typ, len(payload)) + payload
        body += b"\0" * ((-len(body)) % PAD)  # length hiding: 1 KB units
        with self.lock:
            ct = self.noise.encrypt(body)
            self.sn += 1
            if self.sn % REKEY_EVERY == 0:
                self.noise.rekey_outbound_cipher()  # old key is erased
            self.sock.sendall(struct.pack(">I", len(ct)) + ct)

    def recv(self):
        (n,) = struct.unpack(">I", recv_exact(self.sock, 4))
        if n > MAX_FRAME or n < 16 + 5:
            raise ConnectionError("Invalid frame")
        pt = self.noise.decrypt(recv_exact(self.sock, n))  # raises on tampering
        self.rn += 1
        if self.rn % REKEY_EVERY == 0:
            self.noise.rekey_inbound_cipher()
        typ, ln = struct.unpack(">BI", pt[:5])
        if 5 + ln > len(pt):
            raise ConnectionError("Invalid length")
        return typ, pt[5:5 + ln]


# ---------------------------------------------------------------- metadata scrubbing
_EPOCH = (1980, 1, 1, 0, 0, 0)
_PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB",
             b"iCCP", b"sBIT", b"bKGD", b"pHYs", b"acTL", b"fcTL", b"fdAT", b"cICP"}
_OOXML_EXT = (".docx", ".xlsx", ".pptx")


def _exif_orientation(exif):
    """Reads the Orientation tag (0x0112) from raw EXIF data (after 'Exif\\0\\0')."""
    try:
        e = {b"II": "<", b"MM": ">"}.get(exif[:2])
        if e is None or struct.unpack(e + "H", exif[2:4])[0] != 42:
            return None
        off = struct.unpack(e + "I", exif[4:8])[0]
        (n,) = struct.unpack(e + "H", exif[off:off + 2])
        for i in range(n):
            ent = exif[off + 2 + 12 * i: off + 14 + 12 * i]
            tag, typ, cnt = struct.unpack(e + "HHI", ent[:8])
            if tag == 0x0112 and typ == 3 and cnt == 1:
                return struct.unpack(e + "H", ent[8:10])[0]
    except (struct.error, IndexError):
        pass
    return None


def _orientation_segment(o):
    """Minimal EXIF segment holding only the orientation (so photos are not rotated)."""
    tiff = (b"MM\x00\x2a\x00\x00\x00\x08" + struct.pack(">H", 1)
            + struct.pack(">HHIHH", 0x0112, 3, 1, o, 0) + struct.pack(">I", 0))
    payload = b"Exif\x00\x00" + tiff
    return b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload


def scrub_jpeg(d):
    """Removes EXIF/GPS, XMP, IPTC/Photoshop, comments and other APPn segments without
    re-encoding. Keeps JFIF, ICC profile, Adobe marker and the orientation flag."""
    if d[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    keep_app = {0xE0, 0xE2, 0xEE}
    out = bytearray(b"\xff\xd8")
    n, i, orient = len(d), 2, None
    while i < n:
        if d[i] != 0xFF:
            raise ValueError("corrupt JPEG")
        while i < n and d[i] == 0xFF:
            i += 1
        if i >= n:
            break
        m = d[i]
        i += 1
        if m == 0xD9:
            break
        if m == 0x01 or 0xD0 <= m <= 0xD8:
            out += bytes([0xFF, m])
            continue
        (ln,) = struct.unpack(">H", d[i:i + 2])
        seg = d[i:i + ln]
        i += ln
        if m == 0xE1 and seg[2:8] == b"Exif\x00\x00":
            orient = _exif_orientation(seg[8:])
            continue
        if m == 0xFE or (0xE0 <= m <= 0xEF and m not in keep_app):
            continue
        out += bytes([0xFF, m]) + seg
        if m == 0xDA:  # start of scan: copy entropy-coded data up to the next real marker
            j = i
            while j < n - 1:
                if d[j] == 0xFF and d[j + 1] == 0xFF:
                    j += 1
                    continue
                if d[j] == 0xFF and d[j + 1] != 0x00 and not (0xD0 <= d[j + 1] <= 0xD7):
                    break
                j += 1
            else:
                j = n
            out += d[i:j]
            i = j
    out += b"\xff\xd9"
    if orient and orient != 1:
        pos = 2
        if out[2:4] == b"\xff\xe0":  # keep JFIF first
            pos = 4 + struct.unpack(">H", out[4:6])[0]
        out[pos:pos] = _orientation_segment(orient)
    return bytes(out)


def scrub_png(d):
    """Drops text, EXIF, time and unknown ancillary chunks and any data after IEND."""
    sig = b"\x89PNG\r\n\x1a\n"
    if d[:8] != sig:
        raise ValueError("not a PNG")
    out, i = bytearray(sig), 8
    while i + 8 <= len(d):
        (ln,) = struct.unpack(">I", d[i:i + 4])
        typ = d[i + 4:i + 8]
        end = i + 12 + ln
        if typ in _PNG_KEEP:
            out += d[i:end]
        i = end
        if typ == b"IEND":
            break
    return bytes(out)


def scrub_ooxml(src, dst):
    """Removes author/title/company etc. from .docx/.xlsx/.pptx and zeroes zip timestamps.
    Text inside the document (tracked changes, comments, author tags) is NOT touched."""
    core_tags = ("dc:creator|cp:lastModifiedBy|dc:title|dc:subject|dc:description|"
                 "cp:keywords|cp:category|cp:lastPrinted|dcterms:created|dcterms:modified")
    app_tags = "Company|Manager|TotalTime|Application|AppVersion"

    def strip(data, tags):
        data = re.sub(rb"<(" + tags.encode() + rb")\b[^>]*?/>", b"", data)
        return re.sub(rb"<(" + tags.encode() + rb")\b[^>]*>.*?</\1>", b"", data, flags=re.S)

    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
        for info in zi.infolist():
            data = zi.read(info.filename)
            if info.filename == "docProps/core.xml":
                data = strip(data, core_tags)
            elif info.filename == "docProps/app.xml":
                data = strip(data, app_tags)
            zinfo = zipfile.ZipInfo(info.filename, _EPOCH)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = 0o644 << 16
            zo.writestr(zinfo, data)


def scrub_file(src, dst):
    """Writes a scrubbed copy to dst. Returns (changed, note)."""
    ext = os.path.splitext(src)[1].lower()
    try:
        if ext in (".jpg", ".jpeg", ".jpe"):
            with open(src, "rb") as f:
                data = scrub_jpeg(f.read())
            note = "EXIF/GPS, XMP, IPTC and comments removed"
        elif ext == ".png":
            with open(src, "rb") as f:
                data = scrub_png(f.read())
            note = "text/EXIF/time chunks removed"
        elif ext in _OOXML_EXT:
            scrub_ooxml(src, dst)
            return True, "document properties removed (text inside the document is untouched)"
        else:
            return False, "type not supported"
        with open(dst, "wb") as f:
            f.write(data)
        return True, note
    except Exception as e:  # corrupt file etc. - never send half-scrubbed data
        return False, f"scrub failed ({e})"


def make_clean_zip(folder, zip_path, scrub=True):
    """Zips a folder with zeroed timestamps and normalised permissions (no names,
    dates or owners leak); optionally scrubs each file. Returns a list of
    (relative_path, note) for files that could not be scrubbed."""
    skipped, files = [], []
    for root, dirs, names in os.walk(folder):
        dirs.sort()
        for nm in sorted(names):
            full = os.path.join(root, nm)
            if os.path.isfile(full) and not os.path.islink(full):
                files.append((os.path.relpath(full, folder), full))
    tmpd = tempfile.mkdtemp(prefix="mute_scrub_")
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for k, (rel, full) in enumerate(files):
                src = full
                if scrub:
                    dst = os.path.join(tmpd, str(k))
                    ok, note = scrub_file(full, dst)
                    if ok:
                        src = dst
                    else:
                        skipped.append((rel, note))
                zi = zipfile.ZipInfo(rel.replace(os.sep, "/"), _EPOCH)
                zi.compress_type = zipfile.ZIP_DEFLATED
                zi.external_attr = 0o644 << 16
                with open(src, "rb") as f, z.open(zi, "w") as w:
                    shutil.copyfileobj(f, w)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    return skipped


# ---------------------------------------------------------------- Tor
SUPPORTED_PT = {"obfs4": ("lyrebird", "obfs4proxy"), "meek_lite": ("lyrebird", "obfs4proxy"),
                "snowflake": ("snowflake-client",)}


def _tor_search_dirs(tor_cmd=None):
    dirs = []
    # Next to the executable (PyInstaller --onefile unpacks to a temp dir, so the
    # folder beside the real .exe/.app binary must be searched explicitly) or the script.
    bases = [os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__))]
    if getattr(sys, "_MEIPASS", None):
        bases.append(sys._MEIPASS)
    if sys.platform == "darwin" and getattr(sys, "frozen", False):
        # Mute.app/Contents/MacOS/Mute -> let users drop a 'tor' folder next to Mute.app
        bases.append(os.path.abspath(os.path.join(bases[0], "..", "..", "..")))
    for base in bases:
        dirs += [os.path.join(base, "tor"), os.path.join(base, "pluggable_transports"), base]
    if tor_cmd:
        d = os.path.dirname(tor_cmd)
        dirs += [d, os.path.join(d, "PluggableTransports"), os.path.join(d, "pluggable_transports"),
                 os.path.join(os.path.dirname(d), "pluggable_transports")]
    return dirs


def find_tor():
    names = ["tor.exe", "tor"] if os.name == "nt" else ["tor"]
    cands = []
    for n in names:
        for d in _tor_search_dirs():
            cands.append(os.path.join(d, n))
        w = shutil.which(n)
        if w:
            cands.append(w)
    home = os.path.expanduser("~")
    cands += [
        os.path.join(home, "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
        r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        os.path.join(home, ".local", "share", "torbrowser", "tbb", "x86_64",
                     "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
        # macOS: Homebrew (Apple Silicon / Intel) and Tor Browser
        "/opt/homebrew/bin/tor", "/usr/local/bin/tor",
        # Linux: GUI launchers often lack /usr/sbin in PATH
        "/usr/bin/tor", "/usr/sbin/tor",
        "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor.real",
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


def find_pt(binary_names, tor_cmd=None):
    exe = [n + ".exe" for n in binary_names] if os.name == "nt" else list(binary_names)
    for n in exe:
        for d in _tor_search_dirs(tor_cmd):
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
        w = shutil.which(n)
        if w:
            return w
    return None


def parse_bridges(text):
    """Parses pasted bridge lines. Returns [(line, transport_or_None)]."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^bridge\s+", "", line, flags=re.I)
        tok = line.split()[0]
        transport = tok if re.fullmatch(r"[A-Za-z0-9_]+", tok) else None
        if transport and transport not in SUPPORTED_PT:
            raise ValueError(f"Unsupported bridge transport '{transport}'. "
                             f"Supported: {', '.join(sorted(SUPPORTED_PT))} or plain bridges")
        out.append((line, transport))
    return out


def _tq(path):
    """Quotes a path for torrc (forward slashes work everywhere, also on Windows)."""
    p = path.replace("\\", "/").replace('"', "")
    return f'"{p}"' if " " in p or p != path else p


def torrc_text(cfg):
    lines = []
    for key, val in cfg.items():
        for item in (val if isinstance(val, list) else [val]):
            lines.append(f"{key} {item}")
    return "\n".join(lines) + "\n"


def build_tor_config(data_dir, socks_port, ctrl_port, bridges=(), pt_paths=None):
    """Builds the torrc options dict (values may be lists for repeated options)."""
    cfg = {"SocksPort": str(socks_port), "ControlPort": str(ctrl_port),
           "DataDirectory": _tq(data_dir), "Log": "NOTICE stdout",
           # control port is protected by a cookie file readable only by this user
           "CookieAuthentication": "1",
           "CookieAuthFile": _tq(os.path.join(data_dir, "control_auth_cookie")),
           # tor exits by itself if Mute dies
           "__OwningControllerProcess": str(os.getpid())}
    if bridges:
        cfg["UseBridges"] = "1"
        cfg["Bridge"] = [b[0] for b in bridges]
        plugins = [f"{t} exec {_tq(p)}" for t, p in (pt_paths or {}).items()]
        if plugins:
            cfg["ClientTransportPlugin"] = plugins
    return cfg


# ---------------------------------------------------------------- node
class Node:
    """GUI-independent core. Events are put on the `events` queue."""

    def __init__(self, confirm_cb=None, passphrase=None, amnesia=False, app_dir=None,
                 scrub=True):
        self.app_dir = app_dir or APP_DIR
        self.ident = load_identity(self.app_dir, passphrase)
        self.my_fp = fingerprint(raw_pub(self.ident.public_key()))
        self.events = queue.Queue()
        self.confirm_cb = confirm_cb
        self.amnesia = amnesia
        self.scrub = scrub
        self.bridges = []   # [(line, transport)] - memory only, never written to disk
        self.names = {}     # fp -> nickname chosen by YOU (memory only, never sent or saved)
        self.chans = {}     # fp -> Channel
        self.state_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.server = None
        self.transport = "direct"
        self.socks_port = None
        self.onion = None
        self.tor_proc = self.controller = self.tor_dir = None
        self.known_path = os.path.join(self.app_dir, "known_peers.json")
        self.known = set() if amnesia else self._load_known()

    def _load_known(self):
        try:
            with open(self.known_path) as f:
                return set(json.load(f))
        except (OSError, ValueError):
            return set()

    def _save_known(self):
        if self.amnesia:
            return
        os.makedirs(self.app_dir, exist_ok=True)
        with open(self.known_path, "w") as f:
            json.dump(sorted(self.known), f)

    def emit(self, kind, *args):
        self.events.put((kind, *args))

    def label(self, fp):
        """Display name: your own nickname for this key, else the key's short ID."""
        return self.names.get(fp) or short(fp)

    def find_peer(self, ident):
        """Finds a connected peer by nickname or by the start of its short ID."""
        ident = ident.strip().lower()
        for fp in self.chans:
            if short(fp).startswith(ident) or self.names.get(fp, "").lower() == ident:
                return fp
        return None

    def set_bridges(self, text):
        self.bridges = parse_bridges(text)

    # -- start Tor + onion service
    def _launch_tor(self, tor_cmd, torrc, timeout=240):
        """Starts tor ourselves (stem's launcher refuses timeouts on Windows and outside
        the main thread) and waits for 100% bootstrap or fails with the tor log."""
        kw = {}
        if os.name == "nt":
            kw["creationflags"] = subprocess.CREATE_NO_WINDOW
        proc = subprocess.Popen([tor_cmd, "-f", torrc], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, **kw)
        self.tor_proc = proc
        state, done, tail = {"ok": False}, threading.Event(), []

        def reader():
            for line in proc.stdout:  # keeps draining so tor never blocks on a full pipe
                line = line.rstrip()
                tail.append(line)
                del tail[:-40]
                if "Bootstrapped" in line:
                    self.emit("sys", line.split("]", 1)[-1].strip())
                    if "Bootstrapped 100%" in line:
                        state["ok"] = True
                        done.set()
            done.set()  # tor exited
        threading.Thread(target=reader, daemon=True).start()
        done.wait(timeout)
        if not state["ok"]:
            problems = [ln.split("]", 1)[-1].strip() for ln in tail
                        if "[warn]" in ln or "[err]" in ln][-3:]
            try:
                proc.terminate()
            except OSError:
                pass
            why = "exited" if proc.poll() is not None else f"did not finish bootstrapping in {timeout}s"
            raise RuntimeError(f"Tor {why}. " + " | ".join(problems))

    def start_tor(self, local_port):
        import stem.control
        tor_cmd = find_tor()
        if not tor_cmd:
            raise RuntimeError(
                "tor not found. Install it (Windows: put tor.exe in a 'tor' folder next to "
                "the app; macOS: brew install tor; Linux: your package manager) "
                "or install Tor Browser.")
        pt_paths = {}
        for _, transport in self.bridges:
            if transport and transport not in pt_paths:
                names = SUPPORTED_PT[transport]
                p = find_pt(names, tor_cmd)
                if not p:
                    raise RuntimeError(
                        f"No pluggable transport binary found for '{transport}' "
                        f"(looked for: {', '.join(names)}). Install it or use the one "
                        "bundled with Tor Browser / the Tor Expert Bundle.")
                pt_paths[transport] = p
        # transports served by the same binary share one ClientTransportPlugin line
        by_bin = {}
        for t, p in pt_paths.items():
            by_bin.setdefault(p, []).append(t)
        plugin_cfg = {",".join(ts): p for p, ts in by_bin.items()}
        if self.bridges:
            self.emit("sys", f"Using {len(self.bridges)} bridge(s)")
        self.emit("sys", "Starting Tor (this can take up to a minute)...")
        self.tor_dir = tempfile.mkdtemp(prefix="mute_tor_")
        self.socks_port, ctrl = free_port(), free_port()
        torrc = os.path.join(self.tor_dir, "torrc")
        with open(torrc, "w", encoding="utf-8") as f:
            f.write(torrc_text(build_tor_config(self.tor_dir, self.socks_port, ctrl,
                                                self.bridges, plugin_cfg)))
        self._launch_tor(tor_cmd, torrc)
        self.controller = stem.control.Controller.from_port(port=ctrl)
        self.controller.authenticate()
        svc = self.controller.create_ephemeral_hidden_service(
            {DEFAULT_PORT: local_port}, await_publication=True,
            key_type="NEW", key_content="ED25519-V3")
        self.onion = svc.service_id + ".onion"
        self.transport = "tor"
        self.emit("sys", f"Your onion address: {self.onion}")

    # -- listen / connect
    def listen(self, port, local_only=False):
        if self.server:
            return
        if local_only:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
        else:
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("::", port))
            except OSError:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
        s.listen(16)
        self.server = s
        self.emit("sys", f"Listening on port {port}")
        threading.Thread(target=self._accept_loop, args=(s,), daemon=True).start()

    def _accept_loop(self, s):
        while True:
            try:
                c, addr = s.accept()
            except OSError:
                return
            if self.transport != "tor":
                self.emit("sys", f"Incoming connection from {addr[0]}")
            else:
                self.emit("sys", "Incoming connection (Tor)")
            threading.Thread(target=self._session, args=(c, False, None),
                             daemon=True).start()

    def connect(self, host, port, expected_fp=None):
        def run():
            try:
                self.emit("sys", f"Connecting to {host}:{port}...")
                if self.transport == "tor":
                    import socks
                    c = socks.create_connection(
                        (host, port), timeout=90, proxy_type=socks.SOCKS5,
                        proxy_addr="127.0.0.1", proxy_port=self.socks_port,
                        proxy_rdns=True)
                else:
                    c = socket.create_connection((host, port), timeout=10)
            except Exception as e:
                self.emit("sys", f"Could not connect: {e}")
                return
            self._session(c, True, expected_fp)
        threading.Thread(target=run, daemon=True).start()

    # -- session
    def _session(self, sock, initiator, expected_fp):
        try:
            sock.settimeout(90 if self.transport == "tor" else 15)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            peer_pub, noise = handshake(sock, self.ident, initiator)
            fp = fingerprint(peer_pub)
            if expected_fp and fp.replace(" ", "") != expected_fp.replace(" ", "").lower():
                raise ConnectionError(f"Fingerprint does NOT match! Got: {fp}")
            if fp == self.my_fp:
                raise ConnectionError("You connected to yourself")
            if fp not in self.known:
                ok = self.confirm_cb(fp) if self.confirm_cb else False
                if not ok:
                    raise ConnectionError("Peer was not accepted")
                self.known.add(fp)
                self._save_known()
            with self.state_lock:
                if fp in self.chans:
                    raise ConnectionError("Already connected to this peer")
                sock.settimeout(None)
                chan = Channel(sock, noise)
                self.chans[fp] = chan
        except Exception as e:
            self.emit("sys", f"Connection failed: {e}")
            try:
                sock.close()
            except OSError:
                pass
            return
        self.emit("connected", fp)
        self._recv_loop(fp, chan)

    def _recv_loop(self, fp, chan):
        fobj, remaining, total, path, last, t0 = None, 0, 0, None, 0, 0
        try:
            while True:
                typ, data = chan.recv()
                if typ == T_MSG:
                    self.emit("msg", fp, data.decode("utf-8", "replace"))
                elif typ == T_FILE_START:
                    if fobj:
                        fobj.close()
                    meta = json.loads(data)
                    name = safe_name(str(meta["name"]))
                    total = int(meta["size"])
                    fid = "".join(c for c in str(meta.get("fid", "")) if c in "0123456789abcdef")[:64]
                    part_dir = os.path.join(DOWNLOAD_DIR, ".partial")
                    os.makedirs(part_dir, exist_ok=True)
                    part = os.path.join(part_dir, (fid or "x" + short(fp)) + ".part")
                    offset = 0
                    if fid and os.path.exists(part):
                        offset = os.path.getsize(part)
                        if offset > total:
                            offset = 0
                    fobj = open(part, "ab" if offset else "wb")
                    remaining = total - offset
                    t0, last = time.time(), 0
                    chan.send(T_FILE_OFFSET, struct.pack(">Q", offset))
                    self.emit("progress", f"RX {name}", offset, total, 0)
                elif typ == T_FILE_CHUNK and fobj:
                    remaining -= len(data)
                    if remaining < 0:
                        raise ConnectionError("Too much file data")
                    fobj.write(data)
                    now = time.time()
                    if now - last > 0.1:
                        last = now
                        done = total - remaining
                        self.emit("progress", "RX", done, total,
                                  done / max(now - t0, 1e-6))
                elif typ == T_FILE_END and fobj:
                    fobj.close()
                    fobj = None
                    ok = remaining == 0
                    if ok:
                        path = os.path.join(DOWNLOAD_DIR, name)
                        base, ext = os.path.splitext(path)
                        i = 1
                        while os.path.exists(path):
                            path = f"{base} ({i}){ext}"
                            i += 1
                        os.replace(part, path)
                    else:
                        os.remove(part)
                        path = name
                    self.emit("progress", "RX", total, total, 0)
                    self.emit("file", fp, path, ok)
                elif typ == T_FILE_OFFSET:
                    chan.offset_q.put(struct.unpack(">Q", data[:8])[0])
                else:
                    raise ConnectionError("Unexpected frame")
        except Exception as e:
            if fobj:
                fobj.close()
            self.emit("sys", f"{self.label(fp)} disconnected: {e}")
        finally:
            with self.state_lock:
                if self.chans.get(fp) is chan:
                    del self.chans[fp]
            try:
                chan.sock.close()
            except OSError:
                pass
            self.emit("disconnected", fp)

    # -- sending (to every connected peer)
    def send_text(self, text):
        chans = list(self.chans.items())
        if not chans:
            raise ConnectionError("Not connected")
        for fp, ch in chans:
            try:
                ch.send(T_MSG, text.encode("utf-8"))
            except OSError as e:
                self.emit("sys", f"{self.label(fp)}: send error: {e}")

    def send_file(self, path):
        targets = list(self.chans.items())
        if not targets:
            raise ConnectionError("Not connected")
        scrub = self.scrub

        def run():
            tmp = None
            with self.send_lock:
                try:
                    p = path
                    if os.path.isdir(path):
                        self.emit("sys", "Zipping folder" + (" and scrubbing metadata..." if scrub else "..."))
                        tmp = tempfile.mkdtemp(prefix="mute_zip_")
                        nm = os.path.basename(path.rstrip("/\\")) or "folder"
                        p = os.path.join(tmp, nm + ".zip")
                        skipped = make_clean_zip(path, p, scrub)
                        if scrub and skipped:
                            exts = sorted({os.path.splitext(r)[1].lower() or "(none)" for r, _ in skipped})
                            self.emit("sys", f"Not scrubbed: {len(skipped)} file(s) of type "
                                             f"{', '.join(exts)} - check them for metadata")
                        elif scrub:
                            self.emit("sys", "All files scrubbed")
                    elif scrub:
                        tmp = tempfile.mkdtemp(prefix="mute_scrub_")
                        dst = os.path.join(tmp, os.path.basename(path))
                        ok, note = scrub_file(path, dst)
                        if ok:
                            p = dst
                            self.emit("sys", f"Scrubbed {os.path.basename(path)}: {note}")
                        else:
                            self.emit("sys", f"NOT scrubbed {os.path.basename(path)}: {note}")
                    size, name = os.path.getsize(p), os.path.basename(p)
                    hdr = json.dumps({"name": name, "size": size,
                                      "fid": file_id(p, name, size)}).encode()
                    multi = len(targets) > 1

                    def to_peer(fp, ch):
                        # One thread per peer: each peer gets the file from its own resume point.
                        try:
                            while not ch.offset_q.empty():
                                ch.offset_q.get_nowait()
                            ch.send(T_FILE_START, hdr)
                            offset = ch.offset_q.get(timeout=120)
                            if not 0 <= offset <= size:
                                raise ConnectionError("Invalid resume offset")
                            if offset:
                                self.emit("sys", f"{self.label(fp)}: resuming from {human(offset)}")
                            sent, last, t0 = offset, 0, time.time()
                            label = f"TX {self.label(fp)} {name}" if multi else f"TX {name}"
                            with open(p, "rb") as f:
                                f.seek(offset)
                                while True:
                                    b = f.read(CHUNK)
                                    if not b:
                                        break
                                    ch.send(T_FILE_CHUNK, b)
                                    sent += len(b)
                                    now = time.time()
                                    if now - last > 0.1:
                                        last = now
                                        self.emit("progress", label, sent, size,
                                                  (sent - offset) / max(now - t0, 1e-6))
                            ch.send(T_FILE_END)
                            self.emit("progress", label, size, size, 0)
                            self.emit("sys", f"Sent to {self.label(fp)}: {name} ({human(size)})")
                        except Exception as e:
                            self.emit("sys", f"{self.label(fp)}: transfer interrupted ({e}); "
                                             "sending again will resume")

                    ths = [threading.Thread(target=to_peer, args=t, daemon=True)
                           for t in targets]
                    for t in ths:
                        t.start()
                    for t in ths:
                        t.join()
                except Exception as e:
                    self.emit("sys", f"File send error: {e}")
                finally:
                    if tmp:
                        shutil.rmtree(tmp, ignore_errors=True)
        threading.Thread(target=run, daemon=True).start()

    def shutdown(self):
        for ch in list(self.chans.values()):
            try:
                ch.sock.close()
            except OSError:
                pass
        if self.server:
            try:
                self.server.close()
            except OSError:
                pass
        try:
            if self.controller:
                self.controller.close()
        except Exception:
            pass
        try:
            if self.tor_proc:
                self.tor_proc.terminate()
        except Exception:
            pass
        if self.tor_dir:
            shutil.rmtree(self.tor_dir, ignore_errors=True)


# ---------------------------------------------------------------- GUI (hacker style)
BANNER = r"""
 __  __ _   _ _____ _____
|  \/  | | | |_   _| ____|
| |\/| | | | | | | |  _|
| |  | | |_| | | | | |___
|_|  |_|\___/  |_| |_____|
 end-to-end · no server · no logs
"""


def main():
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog

    BG, FG, DIM, ACC, RED = "#000000", "#00ff41", "#0a7a28", "#00e5ff", "#ff3b3b"
    FONT = (("Consolas" if os.name == "nt" else
             "Menlo" if sys.platform == "darwin" else "DejaVu Sans Mono"), 10)

    root = tk.Tk()
    root.title("Mute")
    root.configure(bg=BG)
    root.geometry("820x700")

    # --- unlock / create identity
    state = identity_state()
    passphrase = None
    if state == "encrypted":
        while True:
            passphrase = simpledialog.askstring("Unlock", "Identity passphrase:", show="*", parent=root)
            if passphrase is None:
                return
            try:
                load_identity(None, passphrase)
                break
            except ValueError:
                messagebox.showerror("Error", "Wrong passphrase")
    elif state == "missing":
        passphrase = simpledialog.askstring(
            "New identity", "Set a passphrase for your identity key (empty = none):",
            show="*", parent=root) or None

    pending = {}

    def confirm_cb(fp):
        ev = threading.Event()
        pending.update(ev=ev, ok=False)
        node.emit("confirm", fp)
        ev.wait(180)
        return pending["ok"]

    node = Node(confirm_cb, passphrase)

    def mk_label(parent, text, fg=FG):
        return tk.Label(parent, text=text, bg=BG, fg=fg, font=FONT, anchor="w")

    def mk_entry(parent, var, width=20, show=None):
        return tk.Entry(parent, textvariable=var, width=width, bg="#050505", fg=FG,
                        insertbackground=FG, relief="flat", font=FONT, show=show,
                        highlightthickness=1, highlightbackground=DIM, highlightcolor=FG)

    def mk_btn(parent, text, cmd, fg=FG):
        return tk.Button(parent, text=text, command=cmd, bg="#001a00", fg=fg, font=FONT,
                         relief="flat", bd=0, padx=8, pady=2, activebackground=fg,
                         activeforeground="#000", highlightthickness=1,
                         highlightbackground=fg, cursor="hand2")

    def mk_check(parent, text, var, cmd=None):
        return tk.Checkbutton(parent, text=text, variable=var, bg=BG, fg=DIM,
                              selectcolor="#001a00", activebackground=BG,
                              activeforeground=FG, font=FONT, command=cmd)

    tk.Label(root, text=BANNER, bg=BG, fg=FG, font=("Courier", 9), justify="left").pack(anchor="w", padx=8)

    f1 = tk.Frame(root, bg=BG)
    f1.pack(fill="x", padx=8)
    mk_label(f1, "FINGERPRINT>", DIM).grid(row=0, column=0, sticky="w")
    fp_var = tk.StringVar(value=node.my_fp)
    mk_entry(f1, fp_var, 44).grid(row=0, column=1, padx=6, pady=2)
    mk_btn(f1, "copy", lambda: (root.clipboard_clear(), root.clipboard_append(node.my_fp))).grid(row=0, column=2)
    mk_label(f1, "ADDRESS>", DIM).grid(row=1, column=0, sticky="w")
    addr_var = tk.StringVar(value=", ".join(local_ips()) or "?")
    mk_entry(f1, addr_var, 44).grid(row=1, column=1, padx=6, pady=2)
    mk_btn(f1, "copy", lambda: (root.clipboard_clear(), root.clipboard_append(addr_var.get()))).grid(row=1, column=2)

    f2 = tk.Frame(root, bg=BG)
    f2.pack(fill="x", padx=8, pady=(6, 0))
    mode = tk.StringVar(value="direct")
    for i, (t, v) in enumerate((("DIRECT (IP:port)", "direct"), ("TOR (.onion, anonymous)", "tor"))):
        tk.Radiobutton(f2, text=t, variable=mode, value=v, bg=BG, fg=FG, selectcolor="#001a00",
                       activebackground=BG, activeforeground=FG, font=FONT).grid(row=0, column=i, padx=4)
    mk_label(f2, "port:", DIM).grid(row=0, column=2)
    port_var = tk.StringVar(value=str(DEFAULT_PORT))
    mk_entry(f2, port_var, 6).grid(row=0, column=3, padx=4)
    start_btn = mk_btn(f2, "[ START ]", lambda: do_start())
    start_btn.grid(row=0, column=4, padx=6)

    f2b = tk.Frame(root, bg=BG)
    f2b.pack(fill="x", padx=8, pady=(2, 6))
    amnesia = tk.BooleanVar(value=False)
    mk_check(f2b, "amnesia (save nothing)", amnesia,
             lambda: setattr(node, "amnesia", amnesia.get())).pack(side="left", padx=4)
    scrub_var = tk.BooleanVar(value=True)
    mk_check(f2b, "scrub metadata", scrub_var,
             lambda: setattr(node, "scrub", scrub_var.get())).pack(side="left", padx=4)
    mk_btn(f2b, "Tor bridges...", lambda: edit_bridges(), DIM).pack(side="left", padx=8)

    f3 = tk.Frame(root, bg=BG)
    f3.pack(fill="x", padx=8)
    mk_label(f3, "PEER (ip/.onion)>", DIM).grid(row=0, column=0)
    host_var = tk.StringVar()
    mk_entry(f3, host_var, 40).grid(row=0, column=1, padx=4)
    rport_var = tk.StringVar(value=str(DEFAULT_PORT))
    mk_entry(f3, rport_var, 6).grid(row=0, column=2)
    mk_btn(f3, "[ CONNECT ]", lambda: do_connect()).grid(row=0, column=3, padx=6)
    mk_label(f3, "expect fp:", DIM).grid(row=1, column=0, sticky="e")
    exp_var = tk.StringVar()
    mk_entry(f3, exp_var, 40).grid(row=1, column=1, padx=4, pady=2, columnspan=2, sticky="w")

    status_var = tk.StringVar(value="offline")
    tk.Label(root, textvariable=status_var, bg=BG, fg=ACC, font=FONT, anchor="w").pack(fill="x", padx=8, pady=2)

    chat = tk.Text(root, bg="#030803", fg=FG, font=FONT, wrap="word", state="disabled",
                   relief="flat", highlightthickness=1, highlightbackground=DIM, height=14)
    chat.pack(fill="both", expand=True, padx=8, pady=4)
    chat.tag_config("me", foreground=FG)
    chat.tag_config("peer", foreground=ACC)
    chat.tag_config("sys", foreground=DIM)
    chat.tag_config("err", foreground=RED)
    PALETTE = [ACC, "#ffd166", "#ff6bd6", "#a78bfa", "#ff9f43", "#5eead4", "#f472b6", "#93c5fd"]
    peer_tag = {}

    def tag_for(fp):
        if fp not in peer_tag:
            tag = f"peer{len(peer_tag)}"
            chat.tag_config(tag, foreground=PALETTE[len(peer_tag) % len(PALETTE)])
            peer_tag[fp] = tag
        return peer_tag[fp]

    def log(text, tag="sys"):
        chat.config(state="normal")
        chat.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n", tag)
        chat.config(state="disabled")
        chat.see("end")

    prog_var = tk.StringVar(value="")
    tk.Label(root, textvariable=prog_var, bg=BG, fg=FG, font=FONT, anchor="w").pack(fill="x", padx=8)

    f4 = tk.Frame(root, bg=BG)
    f4.pack(fill="x", padx=8, pady=6)
    msg_var = tk.StringVar()
    mk_label(f4, ">", FG).pack(side="left")
    entry = mk_entry(f4, msg_var, 10)
    entry.pack(side="left", fill="x", expand=True, padx=4)
    mk_btn(f4, "send", lambda: do_send()).pack(side="left", padx=2)
    mk_btn(f4, "file", lambda: do_file()).pack(side="left", padx=2)
    mk_btn(f4, "folder", lambda: do_folder()).pack(side="left", padx=2)
    mk_btn(f4, "wipe", lambda: wipe(), ACC).pack(side="left", padx=2)
    mk_btn(f4, "PANIC", lambda: panic(), RED).pack(side="left", padx=2)

    def edit_bridges():
        win = tk.Toplevel(root)
        win.title("Tor bridges")
        win.configure(bg=BG)
        tk.Label(win, bg=BG, fg=FG, font=FONT, justify="left",
                 text="One bridge per line (get them at bridges.torproject.org).\n"
                      "Supported: obfs4, meek_lite, snowflake, plain bridges.\n"
                      "Kept in memory only; applied the next time Tor starts.").pack(padx=8, pady=6)
        txt = tk.Text(win, height=8, width=84, bg="#050505", fg=FG, insertbackground=FG,
                      font=FONT, relief="flat", highlightthickness=1, highlightbackground=DIM)
        txt.pack(padx=8)
        txt.insert("1.0", "\n".join(b[0] for b in node.bridges))

        def save():
            try:
                node.set_bridges(txt.get("1.0", "end"))
            except ValueError as e:
                return messagebox.showerror("Bridges", str(e), parent=win)
            note = " (restart the app to apply - Tor is already running)" if node.transport == "tor" else ""
            log(f"{len(node.bridges)} bridge(s) set{note}")
            win.destroy()
        mk_btn(win, "save", save).pack(pady=8)

    def do_start(after=None):
        try:
            port = int(port_var.get())
        except ValueError:
            return messagebox.showerror("Error", "Invalid port")
        if node.server or node.transport == "tor":
            return log("Already running. Restart the app to change mode.", "err")
        start_btn.config(state="disabled")

        def run():
            try:
                if mode.get() == "tor":
                    lp = free_port()
                    node.start_tor(lp)
                    node.listen(lp, local_only=True)
                    node.emit("addr", node.onion + f":{DEFAULT_PORT}")
                else:
                    node.listen(port)
                if after:
                    after()
            except Exception as e:
                node.emit("sys", f"Error: {e}")
                node.emit("enable_start")
        threading.Thread(target=run, daemon=True).start()

    def do_connect():
        host = host_var.get().strip()
        port_txt = rport_var.get().strip()
        if host.count(":") == 1:  # pasted "something.onion:5555" or "1.2.3.4:5555"
            host, port_txt = host.split(":")
        try:
            port = int(port_txt)
        except ValueError:
            return messagebox.showerror("Error", "Invalid port")
        if not host:
            return messagebox.showerror("Error", "Enter the peer's address")
        exp = exp_var.get().strip() or None

        def go():
            node.connect(host, port, exp)
        # In Tor mode CONNECT starts Tor first if it is not running yet
        if mode.get() == "tor" and node.transport != "tor":
            do_start(after=go)
        else:
            go()

    def do_send(_=None):
        t = msg_var.get().strip()
        if not t:
            return
        try:
            node.send_text(t)
            log("me> " + t, "me")
            msg_var.set("")
        except Exception as e:
            log(f"{e}", "err")

    def do_file():
        p = filedialog.askopenfilename()
        if p:
            try:
                node.send_file(p)
            except Exception as e:
                log(f"{e}", "err")

    def do_folder():
        p = filedialog.askdirectory()
        if p:
            try:
                node.send_file(p)
            except Exception as e:
                log(f"{e}", "err")

    def wipe():
        chat.config(state="normal")
        chat.delete("1.0", "end")
        chat.config(state="disabled")

    def panic():
        wipe()
        node.shutdown()
        os._exit(0)

    entry.bind("<Return>", do_send)
    root.protocol("WM_DELETE_WINDOW", lambda: (node.shutdown(), root.destroy()))

    def poll():
        try:
            while True:
                ev = node.events.get_nowait()
                k = ev[0]
                if k == "sys":
                    log(ev[1])
                elif k == "msg":
                    log(f"{node.label(ev[1])}> {ev[2]}", tag_for(ev[1]))
                elif k == "connected":
                    fp = ev[1]
                    name = simpledialog.askstring(
                        "Name this peer",
                        f"Peer {short(fp)} connected securely.\n"
                        "Give it a name (only you see it, it is not sent or saved).\n"
                        "The ID is derived from their key and cannot be faked.",
                        initialvalue=node.names.get(fp, ""), parent=root)
                    if name and name.strip():
                        node.names[fp] = name.strip()[:24]
                    log(f"[+] {node.label(fp)} ({short(fp)}) connected securely", tag_for(fp))
                    status_var.set("online · " + ", ".join(node.label(f) for f in node.chans))
                elif k == "disconnected":
                    status_var.set("online · " + ", ".join(node.label(f) for f in node.chans)
                                   if node.chans else "offline")
                elif k == "addr":
                    addr_var.set(ev[1])
                elif k == "enable_start":
                    start_btn.config(state="normal")
                elif k == "progress":
                    _, label, done, total, speed = ev
                    pct = int(100 * done / total) if total else 100
                    bar = "#" * (pct // 4) + "-" * (25 - pct // 4)
                    eta = ""
                    if speed > 0 and total > done:
                        s = int((total - done) / speed)
                        eta = f" ETA {s // 60:02d}:{s % 60:02d}"
                    prog_var.set(f"{label} [{bar}] {pct}% {human(speed)}/s{eta}" if speed
                                 else f"{label} [{bar}] {pct}%")
                elif k == "file":
                    log(("[+] file received: " if ev[3] else "[!] DAMAGED file: ") + ev[2],
                        "me" if ev[3] else "err")
                elif k == "confirm":
                    ok = messagebox.askyesno(
                        "New peer",
                        "Unknown peer fingerprint:\n\n" + ev[1] +
                        "\n\nCompare it over a DIFFERENT channel (phone, in person).\nAccept?")
                    pending["ok"] = ok
                    pending["ev"].set()
        except queue.Empty:
            pass
        root.after(80, poll)

    log("Share your fingerprint over a trusted channel. Nothing is written to disk.")
    poll()
    root.mainloop()


# ---------------------------------------------------------------- CLI mode
def cli_main(argv):
    import argparse
    import getpass

    ap = argparse.ArgumentParser(prog="mute", description="Mute - terminal mode")
    ap.add_argument("--cli", action="store_true", help="terminal mode (no GUI)")
    ap.add_argument("--listen", action="store_true", help="wait for incoming connections")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--tor", action="store_true",
                    help="run an onion service / connect through Tor")
    ap.add_argument("--connect", action="append", default=[], metavar="HOST[:PORT]",
                    help="connect to a peer (repeatable)")
    ap.add_argument("--fp", help="expected peer fingerprint (for --connect)")
    ap.add_argument("--bridge", action="append", default=[], metavar="LINE",
                    help="Tor bridge line, e.g. 'obfs4 1.2.3.4:443 FPR cert=... iat-mode=0' (repeatable)")
    ap.add_argument("--bridge-file", metavar="PATH", help="file with Tor bridge lines")
    ap.add_argument("--no-scrub", action="store_true", help="do not scrub metadata from sent files")
    ap.add_argument("--amnesia", action="store_true", help="save nothing")
    args = ap.parse_args(argv)

    state = identity_state()
    pw = None
    if state == "encrypted":
        while True:
            pw = getpass.getpass("Identity passphrase: ")
            try:
                load_identity(None, pw)
                break
            except ValueError:
                print("Wrong passphrase")
    elif state == "missing":
        pw = getpass.getpass("New identity passphrase (empty = none): ") or None

    answer = {"ev": None, "val": None}

    def confirm_cb(fp):
        answer["ev"], answer["val"] = threading.Event(), False
        print(f"\n[?] Unknown peer fingerprint:\n    {fp}\n"
              "    Compare it over a DIFFERENT channel. Accept? (y/n)")
        answer["ev"].wait(180)
        return answer["val"]

    node = Node(confirm_cb, pw, args.amnesia, scrub=not args.no_scrub)
    print(BANNER)
    print("Your fingerprint:", node.my_fp)

    bridge_text = "\n".join(args.bridge)
    if args.bridge_file:
        with open(args.bridge_file, encoding="utf-8") as f:
            bridge_text += "\n" + f.read()
    if bridge_text.strip():
        try:
            node.set_bridges(bridge_text)
        except ValueError as e:
            print(f"Error: {e}")
            return

    def printer():
        while True:
            ev = node.events.get()
            k = ev[0]
            if k == "sys":
                print(f"[*] {ev[1]}")
            elif k == "msg":
                print(f"{node.label(ev[1])}> {ev[2]}")
            elif k == "connected":
                print(f"[+] {node.label(ev[1])} connected securely")
            elif k == "disconnected":
                print(f"[-] {node.label(ev[1])} disconnected")
            elif k == "file":
                print(("[+] File received: " if ev[3] else "[!] DAMAGED file: ") + ev[2])
    threading.Thread(target=printer, daemon=True).start()

    try:
        if args.tor:
            lp = free_port()
            node.start_tor(lp)
            node.listen(lp, local_only=True)
            print(f"Your onion address: {node.onion}:{DEFAULT_PORT}")
        elif args.listen:
            node.listen(args.port)
            print("Your IPs:", ", ".join(local_ips()) or "?", f"(port {args.port})")
        for c in args.connect:
            host, _, prt = c.rpartition(":") if c.count(":") == 1 else (c, "", "")
            node.connect(host or c, int(prt) if prt else DEFAULT_PORT, args.fp)
    except Exception as e:
        print(f"Error: {e}")
        node.shutdown()
        return

    print("Commands: /send <file|folder>  /peers  /name <id> <name>  /fp  /quit   (other text goes to everyone)")
    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            if answer["ev"] and not answer["ev"].is_set():
                answer["val"] = line.strip().lower() in ("y", "yes")
                answer["ev"].set()
            elif line in ("/quit", "/q"):
                break
            elif line == "/fp":
                print(node.my_fp)
            elif line.startswith("/name "):
                parts = line.split(None, 2)
                fp = node.find_peer(parts[1]) if len(parts) == 3 else None
                if fp:
                    node.names[fp] = parts[2].strip()[:24]
                    print(f"[*] {short(fp)} is now called {node.names[fp]}")
                else:
                    print("Usage: /name <id-or-name> <new name>   (see /peers)")
            elif line == "/peers":
                print(", ".join(f"{node.label(f)} ({short(f)})" for f in node.chans) or "(none)")
            elif line.startswith("/send "):
                try:
                    node.send_file(line[6:].strip().strip('"'))
                except Exception as e:
                    print(f"[!] {e}")
            elif line.strip():
                try:
                    node.send_text(line)
                except Exception as e:
                    print(f"[!] {e}")
    except KeyboardInterrupt:
        pass
    node.shutdown()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli_main(sys.argv[1:])
    else:
        main()
