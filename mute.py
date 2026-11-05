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
  * 1 KB padding (hides message length), key ratchet (rekey) every 512 frames + fresh DH renewal every ~10 min
  * Outgoing files can be scrubbed of metadata (EXIF/GPS, document properties,
    zip timestamps) before they leave your machine
  * No logs, messages live in memory only
"""
import array
import base64
import collections
import hashlib
import hmac
import itertools
import json
import os
import queue
import random
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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)
from noise.connection import Keypair, NoiseConnection

APP_DIR = os.path.join(os.path.expanduser("~"), ".mute")
DOWNLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "Mute")
DEFAULT_PORT = 5555
MAGIC = b"Mute/4 Noise_XX"   # Noise prologue: binds both sides to this protocol version
NOISE_NAME = b"Noise_XX_25519_ChaChaPoly_SHA256"
NOISE_NAME_PSK = b"Noise_XXpsk3_25519_ChaChaPoly_SHA256"
KNOWN_MAGIC = b"SP2PKNW1"
ENC_MAGIC = b"SP2PENC1"
CHUNK = 60 * 1024            # a Noise message is at most 65535 bytes
PAD = 1024
REKEY_EVERY = 512            # ratchet the key every N frames
MAX_FRAME = 65535 + 64

T_MSG, T_FILE_START, T_FILE_CHUNK, T_FILE_END, T_FILE_OFFSET = 1, 2, 3, 4, 5
T_RELAY, T_COVER, T_FRAG = 6, 7, 8
T_FILE_CANCEL = 12            # sender abandons the running file transfer
T_RATCH_INIT, T_RATCH_ACK, T_RATCH_DONE = 9, 10, 11   # fresh Diffie-Hellman key renewal
RATCHET_SECONDS = 600        # default: new ephemeral DH exchange about every 10 minutes (0 = off)

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


def normalize_fp(text):
    """Accepts a fingerprint with any spacing/case, returns the canonical 8x4 hex form."""
    h = re.sub(r"[^0-9a-fA-F]", "", text or "").lower()
    if len(h) != 32:
        raise ValueError("A fingerprint is 32 hex characters (8 groups of 4)")
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


_CONS, _VOWS = "bdfghklmnprstvwz", "aeio"  # 16 x 4 = 64 syllables = 6 bits each


def fp_words(fp):
    """Pronounceable form of the whole fingerprint (22 syllables = 128 bits) that is easy
    to read out loud on a phone call: e.g. 'bakofedi nuzolimo ...'."""
    n = int(fp.replace(" ", ""), 16) << 4  # 128 -> 132 bits
    syl = []
    for i in range(22):
        v = (n >> (132 - 6 * (i + 1))) & 63
        syl.append(_CONS[v >> 2] + _VOWS[v & 3])
    words, k = [], 0
    for size in (4, 4, 4, 4, 3, 3):
        words.append("".join(syl[k:k + size]))
        k += size
    return " ".join(words)


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
    try:                                    # IPv6 address that would be used to reach the internet (if any)
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.connect(("2001:4860:4860::8888", 1))   # sends no packets
        a6 = s6.getsockname()[0].split("%")[0]
        s6.close()
        if not a6.startswith(("fe80", "::1")):
            ips.add(f"[{a6}]")
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


def handshake(sock, ident, initiator, psk=None):
    """Noise XX: -> e | <- e, ee, s, es | -> s, se. With a pre-shared secret the XXpsk3
    variant is used (both sides must use the same secret).
    Returns (peer static public key, NoiseConnection with transport state)."""
    c = NoiseConnection.from_name(NOISE_NAME_PSK if psk else NOISE_NAME)
    if psk:
        c.set_psks(psk)
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


FRAG_HDR = ">BBH"                      # original type, flags (1 = last fragment), message id
FRAG_DATA = PAD - 5 - struct.calcsize(FRAG_HDR)   # payload bytes per constant-size frame
MAX_ASSEMBLED = 2 * 1024 * 1024        # largest message accepted from fragments
SHAPE_QUEUE = 16                       # frames waiting for their time slot (keeps chat responsive)


def shape_estimate(rate, tor=True):
    """Human-readable traffic estimate for constant-rate mode (per direction, per peer)."""
    if rate <= 0:
        return "off"
    per_frame = 1.5 if tor else 1.05   # KB on the wire (Tor splits frames into 514-byte cells)
    kbs = rate * per_frame
    month_gb = kbs * 3600 * 24 * 30 / 1e6
    return f"{kbs:.1f} KB/s per direction, about {month_gb:.1f} GB per month per peer"


class Channel:
    def __init__(self, sock, noise, initiator=False):
        self.sock = sock
        self.noise = noise
        self.initiator = initiator      # the side that opened the connection starts key renewals
        self._eph = None                # our pending ratchet ephemeral key (initiator)
        self._pend_rx = None            # receive key to switch to when the peer says DONE (responder)
        self._ratchets = 0
        self.ratchet_every = 0.0
        self._ratch_thread = None
        self.sn = self.rn = 0
        self.lock = threading.Lock()
        self.offset_q = queue.Queue()
        self.rate = 0.0                # constant-rate mode: frames per second (0 = off)
        self.dead = threading.Event()
        self._q = None
        self._shaper = None
        self._mid = 0
        self._mid_lock = threading.Lock()
        self._asm = {}                 # message id -> [type, bytearray]

    # -- raw frame
    def _send_raw(self, typ, payload=b"", after=None):
        body = struct.pack(">BI", typ, len(payload)) + payload
        body += b"\0" * ((-len(body)) % PAD)  # length hiding: 1 KB units
        with self.lock:
            ct = self.noise.encrypt(body)
            self.sn += 1
            if self.sn % REKEY_EVERY == 0:
                self.noise.rekey_outbound_cipher()  # old key is erased
            if after:
                after()                              # e.g. switch to the renewed send key, atomically
            self.sock.sendall(struct.pack(">I", len(ct)) + ct)

    # -- constant-rate mode: every frame is exactly one 1 KB unit, sent on a fixed clock;
    #    when there is nothing to say a dummy frame goes out instead
    def set_rate(self, rate):
        rate = max(0.0, float(rate))
        self.rate = rate
        if rate > 0 and not (self._shaper and self._shaper.is_alive()):
            self._q = queue.Queue(maxsize=SHAPE_QUEUE)
            self._shaper = threading.Thread(target=self._shape_loop, daemon=True)
            self._shaper.start()

    def _shape_loop(self):
        nxt = time.monotonic()
        try:
            while self.rate > 0 and not self.dead.is_set():
                nxt += 1.0 / self.rate
                try:
                    typ, payload, after = self._q.get_nowait()
                except queue.Empty:
                    typ, payload, after = T_COVER, b"", None
                self._send_raw(typ, payload, after)
                self.dead.wait(max(0.0, nxt - time.monotonic()))
        except OSError:
            self.dead.set()
            return
        # rate switched off: flush what is still queued
        try:
            while True:
                typ, payload, after = self._q.get_nowait()
                self._send_raw(typ, payload, after)
        except (queue.Empty, OSError):
            pass

    def _put(self, frame):
        while True:
            if self.dead.is_set():
                raise ConnectionError("Connection closed")
            try:
                self._q.put(frame, timeout=1)
                return
            except queue.Full:
                continue

    def _send_ctl(self, typ, payload, after=None):
        """Control frame (key renewal): goes through the shaper queue when constant-rate is on, so
        the order of frames and the moment of the key switch stay exact."""
        if self.rate > 0 and self._q is not None:
            self._put((typ, payload, after))
        else:
            self._send_raw(typ, payload, after)

    def send_realtime(self, typ, payload):
        """For audio: never waits. In constant-rate mode a packet that would sit in a long queue is
        dropped instead (old audio is worthless). Returns False if dropped."""
        if self.rate <= 0 or self._q is None:
            self._send_raw(typ, payload)
            return True
        if self._q.qsize() > 3 or len(payload) > FRAG_DATA:
            return False
        with self._mid_lock:
            self._mid = (self._mid + 1) & 0xFFFF
            mid = self._mid
        try:
            self._q.put_nowait((T_FRAG, struct.pack(FRAG_HDR, typ, 1, mid) + payload, None))
        except queue.Full:
            return False
        return True

    def send(self, typ, payload=b""):
        if self.rate <= 0:
            return self._send_raw(typ, payload)
        with self._mid_lock:
            self._mid = (self._mid + 1) & 0xFFFF
            mid = self._mid
        n = max(1, -(-len(payload) // FRAG_DATA))
        for k in range(n):
            part = payload[k * FRAG_DATA:(k + 1) * FRAG_DATA]
            self._put((T_FRAG, struct.pack(FRAG_HDR, typ, 1 if k == n - 1 else 0, mid) + part, None))

    # -- periodic fresh Diffie-Hellman: both directions get brand-new keys that depend on new
    #    random ephemeral keys, so a key that leaked earlier stops working for later traffic
    def _ratchet_keys(self, dh):
        self._ratchets += 1
        okm = HKDF(algorithm=hashes.SHA256(), length=64,
                   salt=self.noise.get_handshake_hash() + struct.pack(">I", self._ratchets),
                   info=b"Mute/4 ratchet").derive(dh)
        return okm[:32], okm[32:]        # initiator->responder, responder->initiator

    def _dh(self, priv, pub):
        try:
            return priv.exchange(X25519PublicKey.from_public_bytes(pub))
        except ValueError as e:
            raise ConnectionError("Invalid key in renewal") from e

    def _set_send_key(self, k):
        self.noise.noise_protocol.cipher_state_encrypt.initialize_key(k)

    def _set_recv_key(self, k):
        self.noise.noise_protocol.cipher_state_decrypt.initialize_key(k)

    def ratchet_now(self):
        """Initiator: start a key renewal (the peer answers, then both switch keys)."""
        if not self.initiator or self._eph is not None or self.dead.is_set():
            return False
        self._eph = X25519PrivateKey.generate()
        self._send_ctl(T_RATCH_INIT, self._eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        return True

    def start_ratchet(self, seconds):
        self.ratchet_every = float(seconds)
        if self.initiator and seconds > 0 and not (self._ratch_thread and self._ratch_thread.is_alive()):
            self._ratch_thread = threading.Thread(target=self._ratchet_loop, daemon=True)
            self._ratch_thread.start()

    def _ratchet_loop(self):
        try:
            while self.ratchet_every > 0:
                if self.dead.wait(self.ratchet_every * random.uniform(0.8, 1.2)):
                    return
                if self.ratchet_every > 0:
                    self.ratchet_now()
        except (OSError, ConnectionError):
            self.dead.set()

    def _on_ratchet(self, typ, data):
        if len(data) != 32:
            raise ConnectionError("Invalid key renewal")
        if typ == T_RATCH_INIT:
            if self.initiator or self._pend_rx is not None:
                raise ConnectionError("Unexpected key renewal")
            eph = X25519PrivateKey.generate()
            k_ir, k_ri = self._ratchet_keys(self._dh(eph, data))
            self._pend_rx = k_ir
            self._send_ctl(T_RATCH_ACK, eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                           after=lambda: self._set_send_key(k_ri))
        elif typ == T_RATCH_ACK:
            if not self.initiator or self._eph is None:
                raise ConnectionError("Unexpected key renewal")
            k_ir, k_ri = self._ratchet_keys(self._dh(self._eph, data))
            self._eph = None
            self._set_recv_key(k_ri)         # everything the peer sends after its ACK uses the new key
            self._send_ctl(T_RATCH_DONE, bytes(32), after=lambda: self._set_send_key(k_ir))
        else:                                 # T_RATCH_DONE
            if self.initiator or self._pend_rx is None:
                raise ConnectionError("Unexpected key renewal")
            self._set_recv_key(self._pend_rx)
            self._pend_rx = None

    def close(self):
        self.dead.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # wakes a thread blocked in recv and tells the peer
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _recv_frame(self):
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

    def recv(self):
        while True:
            typ, data = self._recv_frame()
            if typ in (T_RATCH_INIT, T_RATCH_ACK, T_RATCH_DONE):
                self._on_ratchet(typ, data)
                continue
            if typ != T_FRAG:
                return typ, data
            hdr = struct.calcsize(FRAG_HDR)
            if len(data) < hdr:
                raise ConnectionError("Invalid fragment")
            otyp, flags, mid = struct.unpack(FRAG_HDR, data[:hdr])
            if otyp == T_FRAG:
                raise ConnectionError("Invalid fragment")
            entry = self._asm.setdefault(mid, [otyp, bytearray()])
            if entry[0] != otyp:
                raise ConnectionError("Inconsistent fragment")
            entry[1] += data[hdr:]
            if len(entry[1]) > MAX_ASSEMBLED or len(self._asm) > 64:
                raise ConnectionError("Fragmented message too large")
            if flags & 1:
                del self._asm[mid]
                return otyp, bytes(entry[1])


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


def _saved_tor_path():
    """tor_path.txt next to the app (written by windows/install.bat) holds the full path to tor.exe."""
    base = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
    try:
        with open(os.path.join(base, "tor_path.txt"), encoding="utf-8-sig") as f:
            p = f.readline().strip().strip('"')
        return p if p and os.path.isfile(p) else None
    except OSError:
        return None


def find_tor():
    names = ["tor.exe", "tor"] if os.name == "nt" else ["tor"]
    saved = _saved_tor_path()
    if saved:
        return saved
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
    ]
    if os.name == "nt":
        tb = os.path.join("Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe")
        od = os.environ.get("OneDrive", "")
        for root in (os.path.join(od, "Desktop") if od else "",
                     os.environ.get("LOCALAPPDATA", ""), os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs"),
                     os.environ.get("APPDATA", ""), os.environ.get("ProgramFiles", ""),
                     os.environ.get("ProgramFiles(x86)", "")):
            if root:
                cands.append(os.path.join(root, tb))
    cands += [
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
                 scrub=True, burner=False):
        self.app_dir = app_dir or APP_DIR
        self.burner = burner
        self.passphrase = passphrase  # memory only
        if burner:
            # throw-away identity: no key file, nothing remembered, new fingerprint every start
            self.ident = X25519PrivateKey.generate()
            amnesia = True
        else:
            self.ident = load_identity(self.app_dir, passphrase)
        self.my_fp = fingerprint(raw_pub(self.ident.public_key()))
        self.events = queue.Queue()
        self.confirm_cb = confirm_cb
        self.amnesia = amnesia
        self.scrub = scrub
        self.bridges = []   # [(line, transport)] - memory only, never written to disk
        self.names = {}     # fp -> nickname chosen by YOU (memory only, never sent or saved)
        self.remote_names = {}  # fp -> name a relay hub gave that peer (memory only; your own nickname wins)
        self.closed = False       # closed mode: only allowlisted fingerprints may connect
        self.psk = None           # optional pre-shared secret (32 bytes, memory only)
        self.relay = False        # hub mode: forward chat messages between your peers
        self.cover_profile = "random"
        self._cover_ev = threading.Event()
        self.cover = False        # send dummy frames to hide when you are idle/active
        self.proxy = None                # (host, port) SOCKS5 proxy for direct connections
        self.ratchet = RATCHET_SECONDS   # fresh DH key renewal interval in seconds (0 = off)
        self.shape = 0.0          # constant-rate mode: frames per second per peer (0 = off)
        self._cover_thread = None
        self.client_auth = None   # (private b64, public b32) for onion client authorization
        self.allowed_clients = [] # onion client public keys allowed to reach your service
        self.chans = {}     # fp -> Channel
        self.state_lock = threading.Lock()
        self.send_queue = []              # files waiting to be sent (and the one being sent)
        self._queue_lock = threading.Lock()
        self._queue_worker = None
        self._qid = itertools.count(1)
        self.paused = threading.Event()   # set = file transfers paused
        self.speed_limit = 0              # bytes per second per peer, 0 = unlimited
        self.server = None
        self.stop_requested = threading.Event()
        self.calls = CallManager(self)
        self.transport = "direct"
        self.socks_port = None
        self.onion = None
        self.tor_proc = self.controller = self.tor_dir = None
        self.known_path = os.path.join(self.app_dir, "known_peers.json")
        self.known = set() if amnesia else self._load_known()

    def _load_known(self):
        try:
            with open(self.known_path, "rb") as f:
                blob = f.read()
        except OSError:
            return set()
        try:
            if blob.startswith(KNOWN_MAGIC):
                if not self.passphrase:
                    return set()
                salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
                blob = ChaCha20Poly1305(_kdf(self.passphrase, salt)).decrypt(nonce, ct, b"")
            return set(json.loads(blob))
        except (ValueError, InvalidTag):
            return set()

    def _save_known(self):
        if self.amnesia:
            return
        os.makedirs(self.app_dir, exist_ok=True)
        raw = json.dumps(sorted(self.known)).encode()
        if self.passphrase:  # list of people you talk to is protected like the key
            salt, nonce = os.urandom(16), os.urandom(12)
            raw = KNOWN_MAGIC + salt + nonce + ChaCha20Poly1305(
                _kdf(self.passphrase, salt)).encrypt(nonce, raw, b"")
        fd = os.open(self.known_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)

    def emit(self, kind, *args):
        self.events.put((kind, *args))

    def label(self, fp):
        """Display name: your own nickname for this key, else the key's short ID."""
        return self.names.get(fp) or self.remote_names.get(fp) or short(fp)

    def find_peer(self, ident):
        """Finds a connected peer by nickname or by the start of its short ID."""
        ident = ident.strip().lower()
        for fp in self.chans:
            if short(fp).startswith(ident) or self.names.get(fp, "").lower() == ident:
                return fp
        return None

    def set_bridges(self, text):
        self.bridges = parse_bridges(text)

    def allow(self, text):
        """Adds a fingerprint to the trusted list (used by closed mode, skips the prompt)."""
        fp = normalize_fp(text)
        self.known.add(fp)
        self._save_known()
        return fp

    def set_psk(self, secret):
        """Pre-shared secret agreed out-of-band. Protects against a man-in-the-middle even
        if the fingerprint check is skipped. Use a long passphrase (it is stretched with scrypt,
        but a recorded handshake could be attacked offline if the secret is weak)."""
        if not secret:
            self.psk = None
            return
        self.psk = Scrypt(salt=b"Mute/psk/v1", length=32, n=2 ** 16, r=8, p=1).derive(secret.encode())

    def set_cover(self, on, profile=None):
        """Dummy traffic that imitates a usage pattern (see COVER_PROFILES). Unlike constant-rate mode it
        only adds noise on top of real traffic - it does not hide when you really talk."""
        if profile:
            if profile not in COVER_PROFILES:
                raise ValueError("Unknown cover profile: " + profile)
            self.cover_profile = profile
        self.cover = bool(on)
        if not self.cover:
            self._cover_ev.set()
        else:
            self._cover_ev.clear()
            if not (self._cover_thread and self._cover_thread.is_alive()):
                self._cover_thread = threading.Thread(target=self._cover_loop, daemon=True)
                self._cover_thread.start()

    def _cover_loop(self):
        rnd = random.SystemRandom()
        while self.cover:
            steps, idle = cover_plan(self.cover_profile, rnd)
            for wait_s, size in steps + [(idle, None)]:
                if self._cover_ev.wait(wait_s) or not self.cover:
                    break
                if size is None:
                    continue
                for ch in list(self.chans.values()):
                    if ch.rate > 0:
                        continue  # constant-rate mode already fills the silence
                    try:
                        ch.send(T_COVER, os.urandom(size))
                    except (OSError, ConnectionError):
                        pass

    def set_shape(self, rate):
        """Constant-rate traffic: every frame is 1 KB and goes out on a fixed clock (dummy frames fill
        the gaps), so an observer cannot see when you talk or how much. 0 turns it off.
        Costs bandwidth and limits throughput to about rate KB/s - see shape_estimate()."""
        self.shape = max(0.0, float(rate))
        for ch in list(self.chans.values()):
            ch.set_rate(self.shape)

    def _forward(self, origin, text):
        d = {"o": origin, "t": text}
        nick = self.names.get(origin)
        if nick:
            d["n"] = nick[:24]      # lets the other peers see who is talking (the hub's own nickname for them)
        payload = json.dumps(d).encode()
        for ofp, ch in list(self.chans.items()):
            if ofp != origin:
                try:
                    ch.send(T_RELAY, payload)
                except OSError:
                    pass

    # -- onion client authorization (only holders of your key can even find the service)
    def new_client_auth(self):
        """Creates a client-auth key pair (memory only). Give the PUBLIC part to whoever runs
        the onion service; it must be on their allowed list BEFORE they start."""
        k = X25519PrivateKey.generate()
        priv = base64.b64encode(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
        pub = base64.b32encode(raw_pub(k.public_key())).decode().rstrip("=")
        self.client_auth = (priv, pub)
        return pub

    def set_allowed_clients(self, text):
        keys = []
        for line in text.splitlines():
            line = line.strip().upper()
            if not line or line.startswith("#"):
                continue
            if not re.fullmatch(r"[A-Z2-7]{52}", line):
                raise ValueError("Onion client keys are 52 characters (A-Z and 2-7)")
            keys.append(line)
        self.allowed_clients = keys

    def _add_client_auth(self, host):
        if not (self.client_auth and self.controller and host.endswith(".onion")):
            return
        r = self.controller.msg(f"ONION_CLIENT_AUTH_ADD {host[:-6]} x25519:{self.client_auth[0]}")
        code = r.content()[0][0]
        if code not in ("250", "251"):
            raise RuntimeError(f"Tor rejected the client authorization key: {r}")

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
                        if ("[warn]" in ln or "[err]" in ln) and "Path for GeoIP" not in ln][-3:]
            joined = " ".join(tail)
            old = ("You should upgrade" in joined or "not supported by this version of Tor" in joined)
            try:
                proc.terminate()
            except OSError:
                pass
            why = "exited" if proc.poll() is not None else f"did not finish bootstrapping in {timeout}s"
            hint = (f"\n>>> The Tor program Mute found is TOO OLD for the current Tor network: {tor_cmd}\n"
                    ">>> Install the newest Tor Browser (torproject.org/download) and run the installer again,\n"
                    ">>> or put a current tor.exe in a 'tor' folder next to Mute (it is used first)." if old else "")
            raise RuntimeError(f"Tor {why}. " + " | ".join(problems) + hint)

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
        self._publish_onion(local_port)

    def attach_tor(self, socks_port, ctrl_port, local_port):
        """Uses a Tor that the host app already runs inside its own process (iOS cannot start
        programs): no subprocess and no torrc, only the control port and the SOCKS port."""
        import stem.control
        self.stop_requested.clear()
        self.socks_port = int(socks_port)
        self.controller = stem.control.Controller.from_port(port=int(ctrl_port))
        self.controller.authenticate()
        self.emit("sys", "Using the Tor built into the app")
        if self.bridges:
            pts = sorted({t for _, t in self.bridges if t})
            if pts:
                raise RuntimeError("This app has no obfs4/snowflake support: " + ", ".join(pts)
                                   + " bridges cannot be used here. Plain bridges (IP:port fingerprint) work.")
            self.controller.set_options({"UseBridges": "1", "Bridge": [b[0] for b in self.bridges]})
            self.emit("sys", f"Using {len(self.bridges)} bridge(s)")
        self._wait_bootstrap()
        self._publish_onion(local_port)

    def _wait_bootstrap(self, timeout=240):
        """Waits until the (already running) Tor reports 100% bootstrap, reporting the progress."""
        end, last = time.time() + timeout, -1
        while time.time() < end:
            if self.stop_requested.is_set():
                raise RuntimeError("Stopped")
            try:
                info = self.controller.get_info("status/bootstrap-phase")
            except Exception:
                info = ""
            m = re.search(r"PROGRESS=(\d+)", info or "")
            pct = int(m.group(1)) if m else 0
            if pct != last:
                last = pct
                self.emit("sys", f"Bootstrapped {pct}%")
            if pct >= 100:
                return
            time.sleep(1)
        raise RuntimeError("Tor did not finish starting within %d seconds (check the network)" % timeout)

    def _publish_onion(self, local_port):
        if self.allowed_clients:
            # stem only accepts one client key and cannot set the V3Auth flag, so use the raw command
            cmd = (f"ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,V3Auth Port={DEFAULT_PORT},{local_port} "
                   + " ".join("ClientAuthV3=" + k for k in self.allowed_clients))
            r = self.controller.msg(cmd)
            sid = next((x[2].split("=", 1)[1] for x in r.content() if x[2].startswith("ServiceID=")), None)
            if not sid:
                raise RuntimeError(f"Tor refused the restricted onion service: {r}")
            service_id = sid
            time.sleep(5)  # let the descriptor upload start
        else:
            svc = self.controller.create_ephemeral_hidden_service(
                {DEFAULT_PORT: local_port}, await_publication=True,
                key_type="NEW", key_content="ED25519-V3")
            service_id = svc.service_id
        self.onion = service_id + ".onion"
        self.transport = "tor"
        if self.allowed_clients:
            self.emit("sys", f"Onion service restricted to {len(self.allowed_clients)} client key(s)")
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
        host = clean_host(host)

        def run():
            try:
                self.emit("sys", f"Connecting to {host}:{port}...")
                if self.transport == "tor":
                    import socks
                    self._add_client_auth(host)
                    c = socks.create_connection(
                        (host, port), timeout=90, proxy_type=socks.SOCKS5,
                        proxy_addr="127.0.0.1", proxy_port=self.socks_port,
                        proxy_rdns=True)
                elif self.proxy:
                    import socks
                    c = socks.create_connection(
                        (host, port), timeout=30, proxy_type=socks.SOCKS5,
                        proxy_addr=self.proxy[0], proxy_port=self.proxy[1], proxy_rdns=True)
                else:
                    c = socket.create_connection((host, port), timeout=10)
            except Exception as e:
                hint = ""
                if self.transport == "tor":
                    if not host.endswith(".onion") and not re.fullmatch(r"[\d.]+", host):
                        hint = " (in TOR mode the address should end in .onion)"
                    else:
                        hint = (" - the other side must be running (START pressed, Tor bootstrapped, "
                                "app still open) and the address must be copied completely."
                                " A just-started onion service can need a minute to become reachable.")
                self.emit("sys", f"Could not connect: {e}{hint}")
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
            try:
                peer_pub, noise = handshake(sock, self.ident, initiator, self.psk)
            except ConnectionError:
                raise
            except Exception as e:  # library errors are cryptic - give the likely reasons
                raise ConnectionError("Handshake failed (shared secret mismatch, different "
                                      "version, or not a Mute peer)") from e
            fp = fingerprint(peer_pub)
            if expected_fp and fp.replace(" ", "") != expected_fp.replace(" ", "").lower():
                raise ConnectionError(f"Fingerprint does NOT match! Got: {fp}")
            if fp == self.my_fp:
                raise ConnectionError("You connected to yourself")
            if fp not in self.known:
                if self.closed:
                    raise ConnectionError(f"Rejected {short(fp)}: not on the allowlist")
                ok = self.confirm_cb(fp) if self.confirm_cb else False
                if not ok:
                    raise ConnectionError("Peer was not accepted")
                self.known.add(fp)
                self._save_known()
            with self.state_lock:
                if fp in self.chans:
                    raise ConnectionError("Already connected to this peer")
                sock.settimeout(None)
                chan = Channel(sock, noise, initiator)
                chan.set_rate(self.shape)
                chan.start_ratchet(self.ratchet)
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
                    text = data.decode("utf-8", "replace")
                    self.emit("msg", fp, text)
                    if self.relay:
                        self._forward(fp, text)
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
                elif typ == T_FILE_CANCEL:
                    if fobj:
                        fobj.close()
                        fobj = None
                        try:
                            os.remove(part)
                        except OSError:
                            pass
                        self.emit("progress", "RX", 0, 0, 0)
                        self.emit("sys", f"{self.label(fp)} cancelled the transfer of {name}")
                elif typ == T_FILE_OFFSET:
                    chan.offset_q.put(struct.unpack(">Q", data[:8])[0])
                elif typ == T_RELAY:
                    d = json.loads(data)
                    try:
                        origin = normalize_fp(str(d.get("o", "")))
                    except ValueError:
                        origin = ""
                    nick = "".join(c for c in str(d.get("n", "")) if c.isprintable())[:24].strip()
                    if origin and nick and origin != self.my_fp:
                        self.remote_names[origin] = nick
                    self.emit("relayed", fp, origin, str(d.get("t", ""))[:4000])
                elif typ == T_COVER:
                    pass  # dummy traffic
                elif typ == T_CALL:
                    self.calls.on_call(fp, chan, data)
                elif typ == T_AUDIO:
                    self.calls.on_audio(fp, data)
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
                chan.close()
            except OSError:
                pass
            self.calls.on_disconnect(fp)
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

    # -- file queue: files go out one after another, in the order they were added
    def send_file(self, path):
        """Adds a file or folder to the send queue (and returns its queue item)."""
        if not self.chans:
            raise ConnectionError("Not connected")
        item = {"id": next(self._qid), "path": path, "state": "queued", "cancel": threading.Event(),
                "name": os.path.basename(path.rstrip("/\\")) or path}
        with self._queue_lock:
            self.send_queue.append(item)
            if not (self._queue_worker and self._queue_worker.is_alive()):
                self._queue_worker = threading.Thread(target=self._queue_loop, daemon=True)
                self._queue_worker.start()
        self.emit("queue")
        return item

    def queue_info(self):
        with self._queue_lock:
            return [(it["id"], it["name"], it["state"]) for it in self.send_queue]

    def pause_transfers(self):
        self.paused.set()
        self.emit("sys", "File transfers paused")
        self.emit("queue")

    def resume_transfers(self):
        self.paused.clear()
        self.emit("sys", "File transfers resumed")
        self.emit("queue")

    def cancel_transfer(self, which=None):
        """Cancels the running transfer (which=None) or a queued one by its id; 'all' cancels everything."""
        n = 0
        with self._queue_lock:
            for it in self.send_queue:
                if which == "all" or (which is None and it["state"] == "sending") or it["id"] == which:
                    it["cancel"].set()
                    n += 1
        self.emit("queue")
        return n

    def set_speed_limit(self, bytes_per_sec):
        """Upper limit for file data per peer (0 = unlimited)."""
        self.speed_limit = max(0, int(bytes_per_sec))

    def _queue_loop(self):
        while True:
            with self._queue_lock:
                nxt = next((it for it in self.send_queue if it["state"] == "queued"), None)
                if nxt is None:
                    self.send_queue.clear()
                    return
                nxt["state"] = "sending"
            self.emit("queue")
            try:
                if nxt["cancel"].is_set():
                    self.emit("sys", f"Cancelled: {nxt['name']}")
                else:
                    self._send_item(nxt)
            except Exception as e:
                self.emit("sys", f"File send error: {e}")
            with self._queue_lock:
                nxt["state"] = "done"
                self.send_queue.remove(nxt)
            self.emit("queue")

    def _send_item(self, item):
        path, cancel = item["path"], item["cancel"]
        targets = list(self.chans.items())
        if not targets:
            raise ConnectionError("Not connected")
        scrub = self.scrub
        tmp = None
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
            hdr = json.dumps({"name": name, "size": size, "fid": file_id(p, name, size)}).encode()
            multi = len(targets) > 1

            def to_peer(fp, ch):
                # One thread per peer: each peer gets the file from its own resume point.
                try:
                    while not ch.offset_q.empty():
                        ch.offset_q.get_nowait()
                    ch.send(T_FILE_START, hdr)
                    offset = None
                    for _ in range(120):
                        if cancel.is_set():
                            break
                        try:
                            offset = ch.offset_q.get(timeout=1)
                            break
                        except queue.Empty:
                            continue
                    if offset is None and not cancel.is_set():
                        raise ConnectionError("Peer did not answer")
                    if offset is not None and not 0 <= offset <= size:
                        raise ConnectionError("Invalid resume offset")
                    if offset:
                        self.emit("sys", f"{self.label(fp)}: resuming from {human(offset)}")
                    sent, last, t0 = offset or 0, 0, time.time()
                    start = sent
                    label = f"TX {self.label(fp)} {name}" if multi else f"TX {name}"
                    if offset is not None and not cancel.is_set():
                        with open(p, "rb") as f:
                            f.seek(sent)
                            while not cancel.is_set():
                                if self.paused.is_set() or self.calls.active():
                                    while (self.paused.is_set() or self.calls.active()) and not cancel.is_set():
                                        self.emit("progress", label + (" (paused during call)" if self.calls.active() else " (paused)"), sent, size, 0)
                                        time.sleep(0.3)
                                    start, t0 = sent, time.time()   # speed is measured from here again
                                if cancel.is_set():
                                    break
                                b = f.read(CHUNK)
                                if not b:
                                    break
                                ch.send(T_FILE_CHUNK, b)
                                sent += len(b)
                                now = time.time()
                                lim = self.speed_limit
                                if lim:       # keep the average at or below the limit
                                    ahead = (sent - start) / lim - (now - t0)
                                    if ahead > 0:
                                        cancel.wait(min(ahead, 2.0))
                                        now = time.time()
                                if now - last > 0.1:
                                    last = now
                                    self.emit("progress", label, sent, size,
                                              (sent - start) / max(now - t0, 1e-6))
                    if cancel.is_set():
                        try:
                            ch.send(T_FILE_CANCEL)
                        except OSError:
                            pass
                        self.emit("progress", label, 0, 0, 0)
                        self.emit("sys", f"Cancelled sending {name} to {self.label(fp)}")
                        return
                    ch.send(T_FILE_END)
                    self.emit("progress", label, size, size, 0)
                    self.emit("sys", f"Sent to {self.label(fp)}: {name} ({human(size)})")
                except Exception as e:
                    self.emit("sys", f"{self.label(fp)}: transfer interrupted ({e}); "
                                     "sending again will resume")

            ths = [threading.Thread(target=to_peer, args=t, daemon=True) for t in targets]
            for t in ths:
                t.start()
            for t in ths:
                t.join()
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    def stop(self):
        """Stops listening, disconnects every peer and shuts Tor down, so START can be used again
        (also with another mode). Works while Tor is still starting up."""
        self.stop_requested.set()
        self.calls.hangup()
        for ch in list(self.chans.values()):
            ch.close()
        self.chans.clear()
        srv, self.server = self.server, None
        if srv:
            try:
                srv.shutdown(socket.SHUT_RDWR)     # wakes the thread waiting in accept() (Linux)
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass
        ctrl, proc, tdir = self.controller, self.tor_proc, self.tor_dir
        self.controller = self.tor_proc = self.tor_dir = None
        try:
            if ctrl:
                ctrl.close()
        except Exception:
            pass
        try:
            if proc:
                proc.terminate()
        except Exception:
            pass
        if tdir:
            shutil.rmtree(tdir, ignore_errors=True)
        self.onion = None
        self.transport = "direct"
        self.socks_port = None

    def shutdown(self):
        self.stop()


# ---------------------------------------------------------------- voice calls
T_CALL, T_AUDIO = 13, 14            # call signalling (JSON) and audio packets
CALL_RATE = 16000                    # samples per second (wideband speech)
CHUNK_SAMPLES = 320                  # 20 ms
CHUNK_BYTES = CHUNK_SAMPLES * 2
PACKET_CHUNKS = 4                    # 80 ms of audio per network packet
CODEC_ADPCM, CODEC_OPUS = 1, 2
MIN_SHAPE_FOR_CALLS = 14.0           # constant-rate frames/s needed to carry a call (12.5 packets/s)
RING_SECONDS = 45
AUDIO_HDR = ">HB"                    # packet number, codec

_IMA_STEP = [7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80,
             88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544,
             598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749,
             3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635,
             13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767]
_IMA_IDX = [-1, -1, -1, -1, 2, 4, 6, 8]


def adpcm_encode(pcm, pred=0, idx=0):
    """IMA ADPCM, 16-bit mono PCM (bytes, little endian) -> (4 bit codes, predictor, step index)."""
    import array
    s = array.array("h")
    s.frombytes(pcm)
    if sys.byteorder == "big":
        s.byteswap()
    step_t, idx_t = _IMA_STEP, _IMA_IDX
    out = bytearray((len(s) + 1) // 2)
    for i, x in enumerate(s):
        diff = x - pred
        sign = 0
        if diff < 0:
            sign = 8
            diff = -diff
        step = step_t[idx]
        code = 0
        vp = step >> 3
        if diff >= step:
            code = 4
            diff -= step
            vp += step
        step >>= 1
        if diff >= step:
            code |= 2
            diff -= step
            vp += step
        step >>= 1
        if diff >= step:
            code |= 1
            vp += step
        pred += -vp if sign else vp
        pred = 32767 if pred > 32767 else -32768 if pred < -32768 else pred
        idx += idx_t[code]
        idx = 0 if idx < 0 else 88 if idx > 88 else idx
        code |= sign
        if i & 1:
            out[i >> 1] |= code << 4
        else:
            out[i >> 1] = code
    return bytes(out), pred, idx


def adpcm_decode(data, count, pred=0, idx=0):
    """Inverse of adpcm_encode(); returns (16-bit PCM bytes, predictor, step index)."""
    import array
    if not 0 <= idx <= 88:
        raise ValueError("bad ADPCM state")
    out = array.array("h", bytes(count * 2))
    step_t, idx_t = _IMA_STEP, _IMA_IDX
    for i in range(count):
        b = data[i >> 1]
        code = (b >> 4) if i & 1 else (b & 15)
        step = step_t[idx]
        vp = step >> 3
        if code & 4:
            vp += step
        if code & 2:
            vp += step >> 1
        if code & 1:
            vp += step >> 2
        pred += -vp if code & 8 else vp
        pred = 32767 if pred > 32767 else -32768 if pred < -32768 else pred
        idx += idx_t[code & 7]
        idx = 0 if idx < 0 else 88 if idx > 88 else idx
        out[i] = pred
    if sys.byteorder == "big":
        out.byteswap()
    return out.tobytes(), pred, idx


def _opus_module():
    """The opuslib module if it and the native libopus are usable, else None."""
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")          # old opuslib versions warn about their own syntax
            import opuslib
        opuslib.Encoder(CALL_RATE, 1, opuslib.APPLICATION_VOIP)
        return opuslib
    except Exception:
        return None


def call_codecs():
    return ["opus", "adpcm"] if _opus_module() else ["adpcm"]


class _AdpcmCodec:
    cid = CODEC_ADPCM

    def __init__(self):
        self.epred = self.eidx = 0

    def encode(self, pcm):                    # pcm: PACKET_CHUNKS * CHUNK_BYTES
        pred, idx = self.epred, self.eidx
        data, self.epred, self.eidx = adpcm_encode(pcm, pred, idx)
        return struct.pack(">hB", pred, idx) + data

    def decode(self, payload):                # -> list of PCM chunks
        want = PACKET_CHUNKS * CHUNK_SAMPLES
        if len(payload) != 3 + want // 2:
            raise ValueError("bad ADPCM packet")
        pred, idx = struct.unpack(">hB", payload[:3])
        pcm, _, _ = adpcm_decode(payload[3:], want, pred, idx)
        return [pcm[i:i + CHUNK_BYTES] for i in range(0, len(pcm), CHUNK_BYTES)]


class _OpusCodec:
    cid = CODEC_OPUS

    def __init__(self):
        op = _opus_module()
        if not op:
            raise RuntimeError("Opus is not available")
        self.enc = op.Encoder(CALL_RATE, 1, op.APPLICATION_VOIP)
        self.dec = op.Decoder(CALL_RATE, 1)

    def encode(self, pcm):
        out = bytearray()
        for i in range(PACKET_CHUNKS):
            f = self.enc.encode(pcm[i * CHUNK_BYTES:(i + 1) * CHUNK_BYTES], CHUNK_SAMPLES)
            out.append(len(f))
            out += f
        return bytes(out)

    def decode(self, payload):
        chunks, pos = [], 0
        for _ in range(PACKET_CHUNKS):
            if pos >= len(payload):
                raise ValueError("short Opus packet")
            n = payload[pos]
            f = payload[pos + 1:pos + 1 + n]
            if len(f) != n or n == 0:
                raise ValueError("bad Opus frame")
            pos += 1 + n
            pcm = self.dec.decode(bytes(f), CHUNK_SAMPLES)
            if len(pcm) != CHUNK_BYTES:
                raise ValueError("bad Opus frame size")
            chunks.append(pcm)
        if pos != len(payload):
            raise ValueError("trailing bytes in Opus packet")
        return chunks


def _make_codec(cid):
    return _OpusCodec() if cid == CODEC_OPUS else _AdpcmCodec()


def pcm_level(pcm):
    """Root-mean-square level of 16-bit PCM (0..32767)."""
    import array
    s = array.array("h")
    s.frombytes(pcm[:len(pcm) // 2 * 2])
    if not s:
        return 0
    if sys.byteorder == "big":
        s.byteswap()
    return int((sum(x * x for x in s[::4]) / max(1, len(s[::4]))) ** 0.5)


class AudioUnavailable(Exception):
    pass


class SoundDeviceAudio:
    """Microphone and speaker through PortAudio (the 'sounddevice' package)."""

    def __init__(self, in_dev=None, out_dev=None):
        try:
            import sounddevice
        except Exception as e:
            raise AudioUnavailable(
                "Audio needs the 'sounddevice' package and PortAudio "
                f"(Linux: install libportaudio2 / portaudio). Details: {e}") from e
        self.sd = sounddevice
        self.in_dev, self.out_dev = in_dev, out_dev
        self.streams = []

    def start(self, on_mic, pull_out):
        sd = self.sd

        def cin(indata, frames, t, status):
            on_mic(bytes(indata))

        def cout(outdata, frames, t, status):
            outdata[:] = pull_out()
        try:
            si = sd.RawInputStream(samplerate=CALL_RATE, blocksize=CHUNK_SAMPLES, channels=1, dtype="int16",
                                   device=self.in_dev, callback=cin, latency="low")
            so = sd.RawOutputStream(samplerate=CALL_RATE, blocksize=CHUNK_SAMPLES, channels=1, dtype="int16",
                                    device=self.out_dev, callback=cout, latency="low")
            si.start()
            so.start()
        except Exception as e:
            self.stop()
            raise AudioUnavailable(f"Could not open the microphone/speaker: {e}") from e
        self.streams = [si, so]

    def stop(self):
        for s in self.streams:
            try:
                s.stop()
                s.close()
            except Exception:
                pass
        self.streams = []


def default_audio_backend(in_dev=None, out_dev=None):
    return SoundDeviceAudio(in_dev, out_dev)


def list_audio_devices():
    """([(index, name)] of inputs, [(index, name)] of outputs); raises AudioUnavailable."""
    try:
        import sounddevice as sd
        devs = sd.query_devices()
    except Exception as e:
        raise AudioUnavailable(str(e)) from e
    ins = [(i, d["name"]) for i, d in enumerate(devs) if d["max_input_channels"] > 0]
    outs = [(i, d["name"]) for i, d in enumerate(devs) if d["max_output_channels"] > 0]
    return ins, outs


def scale_pcm(pcm, gain):
    """Volume for 16-bit little-endian mono samples (gain 1.0 = unchanged); clips instead of wrapping."""
    if abs(gain - 1.0) < 0.01:
        return pcm
    a = array.array("h")
    a.frombytes(pcm)
    if sys.byteorder != "little":
        a.byteswap()
    for i, v in enumerate(a):
        v = int(v * gain)
        a[i] = 32767 if v > 32767 else -32768 if v < -32768 else v
    if sys.byteorder != "little":
        a.byteswap()
    return a.tobytes()


# ---------------------------------------------------------------- small notification sounds
SOUND_RATE = 22050
SOUND_DEFS = {                                   # name -> [(frequency Hz or 0 for a pause, milliseconds)]
    "message": [(880, 70), (0, 30), (1320, 110)],
    "peer": [(660, 90), (990, 140)],
    "file": [(990, 70), (1320, 70), (1760, 120)],
    "ring": [(880, 160), (0, 70), (880, 160), (0, 70), (660, 320)],
    "ringback": [(425, 450), (0, 150), (425, 450)],
    "connected": [(740, 80), (988, 80), (1318, 130)],
    "ended": [(988, 100), (740, 100), (494, 180)],
    "error": [(330, 130), (0, 40), (262, 220)],
}
SOUND_LOOPS = {"ring": 2.4, "ringback": 3.5}     # sounds that repeat while a call rings (seconds per round)


def make_sound(name, volume=70):
    """WAV file bytes for one of the SOUND_DEFS (volume 0-100)."""
    import io
    import math
    import wave
    amp = 32767 * 0.55 * max(0, min(100, volume)) / 100.0
    out = array.array("h")
    for freq, ms in SOUND_DEFS[name]:
        n = SOUND_RATE * ms // 1000
        fade = max(1, min(n // 2, SOUND_RATE // 200))          # 5 ms fades: no clicks
        for i in range(n):
            if freq:
                env = min(1.0, i / fade, (n - 1 - i) / fade)
                out.append(int(amp * env * math.sin(2 * math.pi * freq * i / SOUND_RATE)))
            else:
                out.append(0)
    if sys.byteorder != "little":
        out.byteswap()
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SOUND_RATE)
        w.writeframes(out.tobytes())
    return buf.getvalue()


class Sounds:
    """Plays the small notification sounds (incoming message, ringing ...) without any extra package:
    winsound on Windows, afplay on macOS, paplay / pw-play / aplay on Linux. Falls back to `fallback()` (the terminal / window bell)."""

    def __init__(self, enabled=True, volume=70, player=None, fallback=None):
        self.enabled, self.volume = enabled, volume
        self.player = player                  # tests: callable(wav_bytes)
        self.fallback = fallback
        self._cache = {}
        self._dir = None
        self._loop_stop = threading.Event()
        self._loop_name = None
        self._lock = threading.Lock()

    def _wav(self, name):
        key = (name, self.volume)
        if key not in self._cache:
            self._cache[key] = make_sound(name, self.volume)
        return self._cache[key]

    def _play_bytes(self, wav, name):
        if self.player:
            return self.player(wav)
        try:
            if os.name == "nt":
                import winsound
                winsound.PlaySound(wav, winsound.SND_MEMORY | winsound.SND_NODEFAULT)
                return
            cmd = None
            for tool, args in (("afplay", []), ("paplay", []), ("pw-play", []), ("aplay", ["-q"])):
                if shutil.which(tool):
                    cmd = [tool] + args
                    break
            if cmd:
                if self._dir is None:
                    self._dir = tempfile.mkdtemp(prefix="mute-snd-")
                path = os.path.join(self._dir, f"{name}-{self.volume}.wav")
                if not os.path.exists(path):
                    with open(path, "wb") as f:
                        f.write(wav)
                subprocess.run(cmd + [path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                return
        except Exception:
            pass
        if self.fallback:
            try:
                self.fallback()
            except Exception:
                pass

    def play(self, name):
        """One short sound in the background (does nothing when sounds are off)."""
        if not self.enabled or name not in SOUND_DEFS:
            return
        threading.Thread(target=lambda: self._play_bytes(self._wav(name), name), daemon=True).start()

    def loop(self, name):
        """Repeats a ring sound until stop() (a new loop replaces the old one)."""
        self.stop()
        if not self.enabled or name not in SOUND_DEFS:
            return
        stop = threading.Event()
        with self._lock:
            self._loop_stop, self._loop_name = stop, name
        gap = SOUND_LOOPS.get(name, 2.5)

        def run():
            while not stop.is_set():
                self._play_bytes(self._wav(name), name)
                stop.wait(max(0.2, gap - sum(ms for _, ms in SOUND_DEFS[name]) / 1000.0))
        threading.Thread(target=run, daemon=True).start()

    def stop(self):
        with self._lock:
            self._loop_stop.set()
            self._loop_name = None

    def looping(self):
        return self._loop_name


AUDIO_PREFS_DEFAULT = {"sounds": True, "sound_volume": 70, "volume": 100, "mic_gain": 100,
                       "ptt": False, "ptt_key": "F8"}


def load_audio_prefs():
    d = dict(AUDIO_PREFS_DEFAULT)
    try:
        with open(os.path.join(APP_DIR, "audio.json"), encoding="utf-8") as f:
            saved = json.load(f)
        for k, v in AUDIO_PREFS_DEFAULT.items():
            if k in saved and type(saved[k]) is type(v):
                d[k] = saved[k]
    except (OSError, ValueError):
        pass
    d["volume"] = max(0, min(300, d["volume"]))
    d["mic_gain"] = max(0, min(300, d["mic_gain"]))
    d["sound_volume"] = max(0, min(100, d["sound_volume"]))
    return d


def save_audio_prefs(d):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, "audio.json"), "w", encoding="utf-8") as f:
            json.dump({k: d[k] for k in AUDIO_PREFS_DEFAULT}, f)
    except OSError:
        pass


class AudioSession:
    """One running call: encodes the microphone, plays what arrives, keeps a small jitter buffer."""

    def __init__(self, mgr, chan, codec_id, backend, tor=False):
        self.mgr, self.chan, self.backend = mgr, chan, backend
        self.codec = _make_codec(codec_id)
        self.rx_codec = _make_codec(codec_id)
        self.rawq = queue.Queue(maxsize=30)
        self.jb = collections.deque()
        self.jb_lock = threading.Lock()
        slow = tor or chan.rate > 0
        self.target = 12 if slow else 5          # chunks (20 ms each) to collect before playing
        self.buffering = True
        self.seq = 0
        self.stop_ev = threading.Event()
        self.level_in = self.level_out = 0
        self.stats = {"tx": 0, "rx": 0, "underruns": 0, "dropped_tx": 0, "dropped_rx": 0, "bad": 0}
        self.started = time.time()

    def start(self):
        self.backend.start(self._on_mic, self._pull_out)
        threading.Thread(target=self._sender, daemon=True).start()

    def stop(self):
        self.stop_ev.set()
        try:
            self.backend.stop()
        except Exception:
            pass

    # microphone side: the audio callback only queues, the sender thread does the work
    def _on_mic(self, pcm):
        m = self.mgr
        if m.muted or (m.ptt and not m.ptt_down) or (m.duck and self.level_out > 1500):
            pcm = bytes(len(pcm))                 # silence: the packet pattern stays the same
        elif m.mic_gain != 1.0:
            pcm = scale_pcm(pcm, m.mic_gain)
        self.level_in = pcm_level(pcm)
        try:
            self.rawq.put_nowait(pcm)
        except queue.Full:
            try:
                self.rawq.get_nowait()
                self.rawq.put_nowait(pcm)
            except (queue.Empty, queue.Full):
                pass
            self.stats["dropped_tx"] += 1

    def _sender(self):
        acc = []
        while not self.stop_ev.is_set():
            try:
                acc.append(self.rawq.get(timeout=0.2))
            except queue.Empty:
                continue
            if len(acc) < PACKET_CHUNKS:
                continue
            pcm, acc = b"".join(acc[:PACKET_CHUNKS]), acc[PACKET_CHUNKS:]
            try:
                payload = struct.pack(AUDIO_HDR, self.seq, self.codec.cid) + self.codec.encode(pcm)
                self.seq = (self.seq + 1) & 0xFFFF
                if self.chan.send_realtime(T_AUDIO, payload):
                    self.stats["tx"] += 1
                else:
                    self.stats["dropped_tx"] += 1
            except (OSError, ConnectionError):
                self.mgr._ended_by_error("connection lost")
                return
            except Exception:
                self.stats["bad"] += 1

    # network side
    def on_packet(self, data):
        if len(data) < 3 or len(data) > 1100:
            self.stats["bad"] += 1
            return
        seq, cid = struct.unpack(AUDIO_HDR, data[:3])
        if cid != self.rx_codec.cid:
            self.stats["bad"] += 1
            return
        try:
            chunks = self.rx_codec.decode(data[3:])
        except Exception:
            self.stats["bad"] += 1
            return
        self.stats["rx"] += 1
        with self.jb_lock:
            self.jb.extend(chunks)
            limit = self.target + 20
            if len(self.jb) > limit:                 # too far behind: skip ahead
                for _ in range(len(self.jb) - self.target):
                    self.jb.popleft()
                self.stats["dropped_rx"] += 1

    def _pull_out(self):
        with self.jb_lock:
            if self.buffering:
                if len(self.jb) >= self.target:
                    self.buffering = False
            if not self.buffering:
                if self.jb:
                    pcm = self.jb.popleft()
                    self.level_out = pcm_level(pcm)
                    return scale_pcm(pcm, self.mgr.volume)
                self.buffering = True                # ran dry: wait for a little more next time
                self.target = min(self.target + 2, 30)
                self.stats["underruns"] += 1
        self.level_out = 0
        return bytes(CHUNK_BYTES)


class CallManager:
    """1:1 voice calls over an existing encrypted connection (signalling = T_CALL, audio = T_AUDIO)."""

    def __init__(self, node):
        self.node = node
        self.lock = threading.RLock()
        self.state = "idle"                # idle | ringing-out | ringing-in | active
        self.peer = None
        self.chan = None
        self.offered = []
        self.codec = None
        self.session = None
        self.muted = False
        self.remote_muted = False
        self.ptt = False                   # push to talk: the microphone only transmits while ptt_down
        self.ptt_down = False
        self.volume = 1.0                  # playback gain
        self.mic_gain = 1.0
        self.duck = False                  # speakerphone mode: mute the microphone while the other side talks
        self.in_dev = self.out_dev = None
        self.backend_factory = default_audio_backend
        self.ring_seconds = RING_SECONDS
        self.codecs_override = None        # tests / settings: codecs this side is willing to use
        self._timer = None
        self.started = 0.0

    def active(self):
        return self.state == "active"

    def busy(self):
        return self.state != "idle"

    def _emit(self, state, fp=None, detail=""):
        self.node.emit("call", state, fp or self.peer, detail)

    def _send(self, chan, **msg):
        try:
            chan.send(T_CALL, json.dumps(msg, separators=(",", ":")).encode())
        except (OSError, ConnectionError):
            pass

    def _arm_timer(self):
        self._cancel_timer()
        self._timer = threading.Timer(self.ring_seconds, self._ring_timeout)
        self._timer.daemon = True
        self._timer.start()

    def _cancel_timer(self):
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _ring_timeout(self):
        with self.lock:
            if self.state == "ringing-out":
                self._send(self.chan, t="cancel")
                self._finish("noanswer")
            elif self.state == "ringing-in":
                self._send(self.chan, t="reject")
                self._finish("missed")

    def _finish(self, why, detail=""):
        with self.lock:
            fp, sess = self.peer, self.session
            self._cancel_timer()
            self.state, self.peer, self.chan, self.session = "idle", None, None, None
            self.offered, self.codec, self.remote_muted = [], None, False
            self.ptt_down = False
        if sess:
            sess.stop()
        self.node.emit("call", why, fp, detail)

    def _ended_by_error(self, msg):
        with self.lock:
            if self.state == "idle":
                return
            if self.chan:
                self._send(self.chan, t="hangup")
        self._finish("error", msg)

    def _check_ready(self, chan):
        if chan.rate > 0 and chan.rate < MIN_SHAPE_FOR_CALLS:
            raise ConnectionError(
                f"Constant-rate traffic is too slow for a call ({chan.rate:g} frames/s; "
                f"at least {MIN_SHAPE_FOR_CALLS:g} needed). Raise it in Options.")
        backend = self.backend_factory(self.in_dev, self.out_dev)   # raises AudioUnavailable early
        del backend

    # ---- user actions
    def call(self, fp):
        with self.lock:
            if self.state != "idle":
                raise ConnectionError("Already in a call")
            chan = self.node.chans.get(fp)
            if not chan:
                raise ConnectionError("Not connected to that peer")
            try:
                self._check_ready(chan)
            except AudioUnavailable as e:
                raise ConnectionError(str(e))
            self.state, self.peer, self.chan = "ringing-out", fp, chan
            self.offered = list(self.codecs_override or call_codecs())
            self._arm_timer()
        self._send(chan, t="invite", codecs=self.offered)
        self._emit("ringing", fp)

    def accept(self):
        with self.lock:
            if self.state != "ringing-in":
                raise ConnectionError("No incoming call")
            mine = self.codecs_override or call_codecs()
            codec = next((c for c in mine if c in self.offered), "adpcm")
            chan, fp = self.chan, self.peer
            self._cancel_timer()
            try:
                self._start_session(codec)
            except Exception as e:
                self._send(chan, t="hangup")
                self._finish("error", str(e))
                raise ConnectionError(str(e))
        self._send(chan, t="accept", codec=codec)
        self._emit("active", fp, codec)

    def reject(self):
        with self.lock:
            if self.state != "ringing-in":
                return
            self._send(self.chan, t="reject")
        self._finish("rejected")

    def hangup(self):
        with self.lock:
            if self.state == "idle":
                return
            st, chan = self.state, self.chan
            if chan:
                self._send(chan, t="cancel" if st == "ringing-out" else "hangup")
        self._finish("ended")

    def set_muted(self, on):
        self.muted = bool(on)
        with self.lock:
            if self.state == "active" and self.chan:
                self._send(self.chan, t="mute", m=self.muted)

    def set_ptt(self, on):
        self.ptt = bool(on)
        if not on:
            self.ptt_down = False

    def ptt_press(self, down):
        self.ptt_down = bool(down)

    def stats(self):
        s = self.session
        if not s:
            return None
        d = dict(s.stats)
        d.update(level_in=s.level_in, level_out=s.level_out, seconds=int(time.time() - self.started),
                 codec=self.codec, remote_muted=self.remote_muted, buffer=len(s.jb), target=s.target)
        return d

    def _start_session(self, codec):
        backend = self.backend_factory(self.in_dev, self.out_dev)
        sess = AudioSession(self, self.chan, CODEC_OPUS if codec == "opus" else CODEC_ADPCM, backend,
                            tor=self.node.transport == "tor")
        sess.start()
        self.session, self.codec, self.state, self.started = sess, codec, "active", time.time()
        if self.muted:
            self._send(self.chan, t="mute", m=True)

    # ---- incoming frames (called from the receive thread of a peer)
    def on_call(self, fp, chan, data):
        try:
            msg = json.loads(data.decode("utf-8"))
            t = msg["t"]
        except (ValueError, KeyError, TypeError, UnicodeDecodeError):
            return                                  # garbage signalling is ignored
        if not isinstance(t, str):
            return
        if t == "invite":
            codecs = [c for c in (msg.get("codecs") or []) if c in ("opus", "adpcm")] if isinstance(msg.get("codecs"), list) else []
            with self.lock:
                if self.state != "idle" or "adpcm" not in codecs:
                    self._send(chan, t="busy")
                    return
                self.state, self.peer, self.chan, self.offered = "ringing-in", fp, chan, codecs
                self._arm_timer()
            self._emit("incoming", fp)
            return
        with self.lock:
            if fp != self.peer:
                return
            state = self.state
        if t == "accept" and state == "ringing-out":
            codec = msg.get("codec")
            if codec not in self.offered:
                self._send(chan, t="hangup")
                self._finish("error", "peer picked an unknown codec")
                return
            with self.lock:
                self._cancel_timer()
                try:
                    self._start_session(codec)
                except Exception as e:
                    self._send(chan, t="hangup")
                    err = str(e)
                else:
                    err = None
            if err:
                self._finish("error", err)
            else:
                self._emit("active", fp, codec)
        elif t in ("reject", "busy") and state == "ringing-out":
            self._finish("rejected" if t == "reject" else "busy")
        elif t == "cancel" and state == "ringing-in":
            self._finish("missed")
        elif t == "hangup" and state in ("active", "ringing-out", "ringing-in"):
            self._finish("ended-remote")
        elif t == "mute" and state == "active":
            self.remote_muted = bool(msg.get("m"))
            self._emit("remote-mute", fp, "1" if self.remote_muted else "")

    def on_audio(self, fp, data):
        s = self.session
        if s is not None and fp == self.peer and self.state == "active":
            s.on_packet(data)

    def on_disconnect(self, fp):
        with self.lock:
            hit = self.peer == fp and self.state != "idle"
        if hit:
            self._finish("ended-remote", "connection closed")


# ---------------------------------------------------------------- GUI (hacker style)
BANNER = r"""
 __  __ _   _ _____ _____
|  \/  | | | |_   _| ____|
| |\/| | | | | | | |  _|
| |  | | |_| | | | | |___
|_|  |_|\___/  |_| |_____|
 end-to-end · no server · no logs
"""


def clean_host(host):
    """Tidies a pasted address: strips spaces, a scheme and slashes, lower-cases it and adds the
    missing '.onion' to a bare 56-character v3 onion name."""
    host = host.strip().lower()
    for prefix in ("http://", "https://", "tor://"):
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.strip("/ ")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]                    # [2001:db8::1] -> 2001:db8::1
    if re.fullmatch(r"[a-z2-7]{56}", host):
        host += ".onion"
    return host


def split_hostport(text, default=DEFAULT_PORT):
    """'host', 'host:port', '[ipv6]', '[ipv6]:port' or a bare IPv6 address -> (host, port)."""
    text = text.strip()
    m6 = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", text)
    if m6:
        port = int(m6.group(2)) if m6.group(2) else default
        if not 0 < port < 65536:
            raise ValueError("Invalid port")
        return m6.group(1), port
    if text.count(":") == 1:
        host, _, prt = text.partition(":")
        try:
            return host, int(prt)
        except ValueError:
            raise ValueError("Invalid port")
    return text, default


def build_parser():
    import argparse
    ap = argparse.ArgumentParser(
        prog="mute", description="Mute - serverless end-to-end encrypted chat and file transfer. "
        "Without --cli/--listen/--tor/--connect the GUI starts.")
    g = ap.add_argument_group("mode")
    g.add_argument("--cli", action="store_true", help="terminal mode (no GUI)")
    g.add_argument("--listen", action="store_true", help="wait for incoming connections")
    g.add_argument("--port", type=int, default=DEFAULT_PORT)
    g.add_argument("--tor", action="store_true", help="run an onion service / connect through Tor")
    g.add_argument("--connect", action="append", default=[], metavar="HOST[:PORT]",
                   help="connect to a peer (repeatable)")
    g.add_argument("--fp", help="expected peer fingerprint (for --connect)")
    g = ap.add_argument_group("Tor")
    g.add_argument("--bridge", action="append", default=[], metavar="LINE",
                   help="Tor bridge line, e.g. 'obfs4 1.2.3.4:443 FPR cert=... iat-mode=0' (repeatable)")
    g.add_argument("--bridge-file", metavar="PATH", help="file with Tor bridge lines")
    g.add_argument("--get-bridges", action="store_true",
                   help="download bridges from the Tor Project (asks you to solve a captcha); with --proxy if the site is blocked")
    g.add_argument("--proxy", metavar="HOST:PORT", help="SOCKS5 proxy for direct connections (hides your IP from the peer behind the proxy) and for --get-bridges")
    g.add_argument("--client-auth", action="store_true",
                   help="create an onion client key (memory only) and print its public part")
    g.add_argument("--allow-client", action="append", default=[], metavar="KEY",
                   help="only these onion client keys (52 chars) can reach your onion service (repeatable)")
    g = ap.add_argument_group("identity and privacy")
    g.add_argument("--burner", action="store_true",
                   help="throw-away identity: random key, nothing saved, new fingerprint every start")
    g.add_argument("--persistent", action="store_true", help="GUI: skip the identity question, use the saved identity")
    g.add_argument("--amnesia", action="store_true", help="save nothing")
    g.add_argument("--no-scrub", action="store_true", help="do not scrub metadata from sent files")
    g.add_argument("--cover", action="store_true", help="send dummy traffic (see --cover-profile)")
    g.add_argument("--cover-profile", choices=sorted(COVER_PROFILES), default=None,
                   help="what the dummy traffic imitates: random (default), chat, browse or stream; implies --cover")
    g.add_argument("--shape", type=float, default=0.0, metavar="FRAMES_PER_SEC",
                   help="constant-rate traffic: one 1 KB frame every 1/RATE s, dummy frames fill the gaps "
                        "(e.g. 0.2 low, 1 normal, 4 high). Hides when you talk; costs bandwidth, limits speed")
    g.add_argument("--ratchet", type=int, default=RATCHET_SECONDS, metavar="SECONDS",
                   help="renew the session keys with a fresh Diffie-Hellman exchange about every SECONDS "
                        f"(default {RATCHET_SECONDS}, 0 = off)")
    g.add_argument("--theme", choices=sorted(THEMES), default=None,
                   help="GUI colour theme (remembered; can also be changed in Options)")
    g = ap.add_argument_group("access control")
    g.add_argument("--closed", action="store_true", help="only allowlisted fingerprints may connect")
    g.add_argument("--allow", action="append", default=[], metavar="FP",
                   help="trusted fingerprint (repeatable; needed for --closed)")
    g.add_argument("--psk", action="store_true",
                   help="ask for a pre-shared secret both sides must know (stops man-in-the-middle)")
    g.add_argument("--relay", action="store_true", help="hub mode: forward chat messages between your peers")
    return ap


def apply_opts(node, args, secret=None):
    """Applies the shared access-control options to a Node. Raises ValueError on bad input."""
    node.closed = args.closed
    node.relay = args.relay
    for f in args.allow:
        node.allow(f)
    if args.allow_client:
        node.set_allowed_clients("\n".join(args.allow_client))
    if secret:
        node.set_psk(secret)
    if args.cover or args.cover_profile:
        node.set_cover(True, args.cover_profile or "random")
    node.ratchet = max(0, args.ratchet)
    node.proxy = parse_proxy(args.proxy)
    if args.shape and args.shape > 0:
        node.set_shape(args.shape)


# ---------------------------------------------------------------- Moat: fetch Tor bridges
MOAT_BASE = "https://bridges.torproject.org/moat"
MOAT_TYPE = "application/vnd.api+json"


class MoatError(Exception):
    pass


def _moat_post(path, body=None, proxy=None, timeout=30, method="POST"):
    """Talks to the Tor Project's bridge distribution service (Moat). `proxy` = (host, port) of a SOCKS5
    proxy (for example a Tor you already run, or a VPN's proxy) - needed where bridges.torproject.org is blocked."""
    import http.client
    import ssl
    from urllib.parse import urlsplit
    u = urlsplit(MOAT_BASE + "/" + path)
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        if proxy:
            import socks
            raw = socks.socksocket()
            raw.set_proxy(socks.SOCKS5, proxy[0], int(proxy[1]), rdns=True)
            raw.settimeout(timeout)
            raw.connect((u.hostname, port))
        else:
            raw = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
        conn = http.client.HTTPConnection(u.hostname, port, timeout=timeout)
        conn.sock = raw
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, u.path, body=data, headers={"Content-Type": MOAT_TYPE, "Accept": MOAT_TYPE})
        resp = conn.getresponse()
        raw_body = resp.read(1 << 20)
        conn.close()
    except Exception as e:
        raise MoatError(f"Could not reach the bridge service: {e}") from e
    try:
        doc = json.loads(raw_body.decode("utf-8", "replace") or "{}")
    except ValueError as e:
        raise MoatError(f"Unexpected answer from the bridge service (HTTP {resp.status})") from e
    if isinstance(doc, dict) and doc.get("errors"):
        errs = doc["errors"]
        if any(isinstance(x, dict) and x.get("code") == 419 for x in errs):
            raise MoatError("Wrong captcha answer - try again")
        raise MoatError("; ".join(str(x.get("detail", x)) if isinstance(x, dict) else str(x) for x in errs))
    if resp.status != 200:
        raise MoatError(f"The bridge service answered HTTP {resp.status}")
    return doc


def moat_captcha(transport="obfs4", proxy=None):
    """Asks for a captcha. Returns (jpeg bytes, challenge token)."""
    doc = _moat_post("fetch", {"data": [{"version": "0.1.0", "type": "client-transports",
                                         "supported": [transport]}]}, proxy)
    try:
        d = doc["data"][0]
        if d["type"] != "moat-challenge" or d.get("transport") != transport:
            raise KeyError("type")
        return base64.b64decode(d["image"], validate=False), str(d["challenge"])
    except (KeyError, IndexError, TypeError, ValueError) as e:
        raise MoatError("Unexpected captcha answer from the bridge service") from e


def moat_solve(challenge, solution, transport="obfs4", proxy=None):
    """Sends the captcha answer. Returns bridge lines, already checked by parse_bridges()."""
    doc = _moat_post("check", {"data": [{"id": "2", "type": "moat-solution", "version": "0.1.0",
                                         "transport": transport, "challenge": challenge,
                                         "solution": solution.strip(), "qrcode": "false"}]}, proxy)
    try:
        d = doc["data"][0]
        if d["type"] != "moat-bridges":
            raise KeyError("type")
        lines = [str(b) for b in d["bridges"]]
    except (KeyError, IndexError, TypeError) as e:
        raise MoatError("Unexpected bridge answer from the bridge service") from e
    return _checked_bridges(lines)


def moat_builtin(proxy=None):
    """Bridges that need no captcha (the same built-in ones Tor Browser offers): obfs4, snowflake, meek."""
    doc = _moat_post("circumvention/builtin", None, proxy)
    lines = []
    items = doc.items() if isinstance(doc, dict) else []
    for _, v in items:
        if isinstance(v, list):
            lines += [x for x in v if isinstance(x, str)]
    if not lines:
        raise MoatError("The bridge service returned no built-in bridges")
    return _checked_bridges(lines)


def _checked_bridges(lines):
    good = []
    for ln in lines:
        if len(ln) > 600 or not ln.isprintable() or "\n" in ln or "\r" in ln:
            continue                      # never let odd characters from the network near torrc
        try:
            good += [b[0] for b in parse_bridges(ln)]
        except ValueError:
            continue                      # a type Mute cannot use (or a malformed line) is skipped
    if not good:
        raise MoatError("The service sent no bridges that Mute can use")
    return good


def parse_proxy(text):
    """'host:port' -> (host, port); empty -> None."""
    text = (text or "").strip()
    if not text:
        return None
    text = re.sub(r"^socks5h?://", "", text)
    host, port = split_hostport(text, 9050)
    return host, port


# ---------------------------------------------------------------- cover traffic profiles
COVER_PROFILES = {
    "random": "random dummy frames every few seconds",
    "chat":   "messenger: short typing bursts, long pauses",
    "browse": "web browsing: a small request, then a burst of larger replies, pauses in between",
    "stream": "video streaming: a media segment every few seconds (heavy, about 50 KB/s)",
}
COVER_MAX = 48000                      # largest dummy payload (stays below the frame limit)


def cover_plan(profile, rnd):
    """One 'episode' of dummy traffic: ([(wait_before_s, payload_bytes), ...], idle_seconds_after)."""
    if profile == "chat":
        steps = [(rnd.uniform(0.4, 1.6), rnd.randint(0, 120)) for _ in range(rnd.randint(1, 4))]
        return steps, min(120.0, max(3.0, rnd.expovariate(1 / 25)))
    if profile == "browse":
        steps = [(0.0, rnd.randint(300, 900))]
        for _ in range(rnd.randint(8, 30)):
            steps.append((rnd.uniform(0.02, 0.25), min(COVER_MAX, max(200, int(rnd.lognormvariate(8.5, 1.0))))))
        return steps, rnd.uniform(8, 45)
    if profile == "stream":
        steps = [(rnd.uniform(0.05, 0.3), rnd.randint(20000, 45000)) for _ in range(rnd.randint(6, 10))]
        return steps, rnd.uniform(2.5, 4.5)
    return [(0.0, rnd.choice([0, 200, 700, 1500]))], rnd.uniform(2, 9)


def cover_estimate(profile):
    """Average extra traffic (per direction, per peer) of a cover profile, as readable text."""
    rnd = random.Random(7)
    total, secs = 0, 0.0
    for _ in range(3000):
        steps, idle = cover_plan(profile, rnd)
        total += sum(-(-(5 + n) // PAD) * PAD for _, n in steps)   # every frame is padded to 1 KB units
        secs += sum(w for w, _ in steps) + idle
    kbs = total / secs / 1024
    gb = kbs * 1024 * 86400 * 30 / 1e9
    return f"about {kbs:.1f} KB/s per direction ({gb:.1f} GB per month per peer)"


APP_ICON_PNG = (
    "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAMe0lEQVR42t2bf5CV1XnHP885533v/rh3d2ERCrhUCMpODCEEqhV1"
    "0WkMsTRDM5Goaf7paEnTSRvbJiROJiVopnbiZEj9Q2vHRJupjjPU0YDSpp1EF6mklml0VFwUUEB+uMIu+3vvfd9znv7x3mUFdFnY"
    "3ZubnJkzs/c973n3PN/z/DrPeR4YT9MNBl3p0A2Gam9Kea1r7Xhel3N+jA0gG8OpZw8ui7giX4/1UlWEF6zyv+8N8oXdpTHXP24A"
    "dK1FNnsA+q9fQsTniM21IPOBRsBU3d5DD+gBSmEHQ+Epmtp3nUXLuAAYmdDXtphatwFrPweRgWFk3yB0liBUGfkCXBShC+tAagAP"
    "Pn2G4L9L3L5rLBDOJh6gtPLP0U8Nop9R+flSNV+cldh5NamNjbcQqrLHxtuLc6lZOzORbUsCukrRG0oMt/3tKdr09E0/nQN0pUPa"
    "U4ptdxHXf4fOfsxX96SyudMBGRNEAkaqUwEGhUQhydhTVzf78ECroaVBKA38kNz2v+bZlY7r29OzARhhkVLbOqL6B+noTu1nX7bs"
    "HRIKLnvTayZp1dyE0Q3qS+HinIYtS1Jd2hxR7F9PzfP3vl8c5JSZY6PS19ZKffQrjpecXbHLsG9IaHQZqr+JLRLo8/A7sfoXlnla"
    "6g3DpSupH9UJZU2+WxCUerkHE+XMVzv0N554yNZesHCkKGZdh2CMoU7uzQY/qhkHjLDDias+xvT8y7LjOKbtV4a8y1j+t6E5gd6U"
    "8PTioKvnGLqGVtC8fSe61hrozMQgH6+FyMgDRwJ6ThepKkRdzsdDEJAHjgYwSoO9JRvoFAPXZSoztitJh5EdPUIkk7f7coFgjjFP"
    "yNwQP95PB4XIIC/2CgODgjPXZAPt3iAbA7uWRWAukQODcKwkRGZi2l4AKxnrvb9bGdt/NGPMk9FPqyqRCLUipKoYkXNzQGzgRGKk"
    "YwCQeexYUUDQbDlxbR5o4N0SlIJMyM6bzAypBa0xaN6iBYvWWzQub+sHHVNsWSXFkr1bsNncGoPa7Jtiss/7EPjXSxbSvuhjNBlD"
    "4v25/XIpc8K7JYAC80IDgDvtlYlyvRUY9IRbZ6HfmA+k2Q4KkCrgkGc6MRveghpTfpYpKS0p+oMFaFszaHmejs4zd+/DPXmcYi6w"
    "ad4CbmqeBSj/tWgxf7J/D/uKw4iMg4QzXnCTrpkUaMnBxxuB0hlSatEC6H3vIAN+VM4VmBujt86CaTWcftBQIMbNzVH0gW/Pnccd"
    "c1pIk4RUleWN07hp+gz+/vBBcs6Rqp43w04qABqVCQ4pJB7CSA/gS9BSA4vrUa8Zx1jJ/v5kAZoi8En27si8xBOlKaWQsm7WLL43"
    "dz5pmqIoNXHMw0ff4Z4jh4isPW/imZIjrSkrLnNmH2ECh17VOGqfy4pRr24EsafpEYzgxJC4wOfzM3hw1kfwwaMaiKKYZ7qOc/vb"
    "e7HGXLD0msobaIWrG6HOolZQK9Dg4KqGswTUeUgdXPeS57GdTYS8ENJA5CJe6D3J2n0diIxKUXUAcC7uIKBL8zA3l2l+AS6pQS+v"
    "z2S/bIFsgNTCkn3KU3+TEg8EvFEi63htcIA1b77OsCrGmAmFJioHwFDItkkVZuRgSf2oDlhWgPo4M1MKtj/gDcw/qmz7WkpjHyQ1"
    "SoTlUGmY1W+8xvE0ITKGoBMzXaYigSoEjicwHE79W13RmJnCvIUVjWVfFUy/xw8lzOgXtn0tYc5RJamHCEu3T1m9dzcHisPkrMXr"
    "xL1VVxEARKA7yX63lM3clQ1wUQyxoMsLQMCIoCcT6rtTnn7I0dqhJM2CK8Jw8Kw5uodXBvsvyNz9+gAoa0bp99Dr0ZY6UI8uqkMW"
    "1kKdgfm1SAiIGKSzyOa7DVceCSTTBTOkkHfcUnOQ5984Sc5FpH7yApKmMsFa0EShYzD7HRRqInRpHv1kAbEWG8BL4JHHctz4do4k"
    "r4gHOwi3/Z3jp1d4coNCKpN7RDcVDVp3DIL3oyGr5QX4RD7T+A423ef50i8syTSQAK4H1q93PNxmiXuExE7+slzlAFB4ewiOluDi"
    "WsCji/NECokJfPtfPHc85Emaygvrgnu/Yrn3SxYXlMROTYiiQlYg21F5L0E6BjON75Wo0ZFMd3x5i+d7mzxpUzYUnYCHbzWs/wuL"
    "SxQ/hausnAikCgMeXu4/5eUlBm56LvBPd6X4PKhA1C9sudFw252urBemNhBdWQASRV7pxxVT0thw/f8FHr0zJcQQRInUsiP08YXV"
    "/YhYVBWd4tBc5QDwCl5xrw+R9hb5xEEyF1fBu4z4V3WQNX4/xaHsBqsSt2+ukgDYolIaGmbBYz0882KOhl4lKUDkLQcp8Yc9e+ka"
    "THAqpJUKGFfKETIBkoGEmXUx235Sy5w4JclDlBi68srqobc41DVAZCxpqFw4viIAGEDTQD4VtjZfxqKaehKf4oJh2Chr9uzm1f4e"
    "4jgiTUJFr99cJeL3oEjO8G/TFnJFXQNJkmDIAh437+tgR3d35uLKyInxtwQAUbAipHge3dXEqjwkPkEQrLXctv8Nthw/Tk3kSEKA"
    "YBhFoDI3M1NqBUaCGv/4Q88XtyhJfebfO+f45sH9/LjzGLnIkaiOxgoqzAFTBoALkMbCdx7x/NWPPMm0zBK4KOL7hw/y/SPvkIsm"
    "71hbVQBEHlIDX3nCc9cmT1omPnIRP+48yjcPvUXsJiegUXUARB5KTbB2V+D+u1N8ARQlEsdPe49z+6G9RNYSPozTdYwzhVa5EnRB"
    "KNZ4/uB/4NGfp4RclrwTDVu25/q55b29mfYfi5YPQyZopiMmWTmaybuCF4ppwrJ8A08emE3Uk+Jrhei9wCvLDH98yyDFkwnGyIe7"
    "uDp6ZhhxnU/1JFOgVSkCVoSi9yzM1bL14lYKtY7EKtGQcGBpzI3319F9sSMaUMI5NlCKIQuW2gjicrdxNpiE6hMBK0IpBGZFEdsu"
    "vZzZcY4kTYis40QosVoOcvjrQvRSH75GRi9EP+zEGAvywGH4RQ+YsuCngjzfAzkz6VkrbmLsI6QhUDCGrZd+lEtr60jSBGcsQz6w"
    "5tgbvPZqN7mikFqynQ3nCJ44QX7Whfz7CbBlxyjVjHg3+cEBN7GLYMUAT3ykld/LN5KkJYwYFOHm/a/z3ye7ycURaVwOhI6HgwNQ"
    "a87ORZyiFD03keu/JAQeX7CIG6Y1kyQZ8dZa/nT/HrZ2ncgcnfQC5DaUtX61+gECJN5z37wF3HzRLJKk7N87x9cP7ueRznerwsub"
    "EgCsCIn3rJ/Twl/OnUexlGWnuyjiHw4f4AdV4uJOGQCqijWGn/V083pfLzkXEbmIhzqPcOfhA8Q5hxc+ID9gHP3X0NyFiKcRw8sD"
    "/Vzf8QrPti7m7eIw6/a+SZRAwKMXqq1q7dSfguWDAOjoGmDxnF5mRk1ERgljx2IDSuwc76YJ17z5KslACssb8PdcigZ/frs54t2W"
    "AubP9sCxUpbjO9kSpKM1BUA/w6EvA0A3GGRjCZ19QC+pm8fMSOlMIB57EV6VyBi6QoqkHjMzh79uZpYZdt7bKFnaY+3eTPvLJAMg"
    "ZS9yehS0td5CeIfLXuxFEQfPGSBQ8juIa6/VFY0qmzuh1o3ttZXFwQWgxqK/7MGs2HnhRzYFjhWzmoQwBZkpJY8ub1IKdUo6/EI2"
    "sNI6mJmteDBsJvbf0i/PNrK5c9x0qJZVaU+K7Dw5sYVOlQ4oJxHputkGEIb849nATB2tF5CNAb/yPzA1q8xnd6Xy9Al3XunyQsa6"
    "TLDiYypqBnpS9NomH9qvsGjpl5jnVsAGQTaG0XoBRejlWwTvw/2twtyc0uezD4yXhYNOrE8F8QMemiMND7Vm1UID+o0sJ3a3jPoB"
    "stnDWsO09pdISutpabBh65KU2bHSk56VsEy159GPJFz3pNDkNDz18ZTLpjtKQ3fR0L7j7JKZkTZSUFRs20Scv4MDJ4NZ16Hyn11Z"
    "asLIicxUKRJaDqYUy0VTbU1e/7lVdNF0QzLwI+L227OquM3hgzOjtVxBAjDcth79VIquUnlysTd/NCOxF8XeioSqLZsTCbY58mZV"
    "cyKPX+7RTyv6aSVZuXG0BHissrkzK8gG264iF23EuBvAwOAg0jGQpZxXZeFkjLbWQaGu/DDZznDyXWq3P3uqMOyMnZdxlc72rryG"
    "WvN5nL0a+F2QAiO1BtWDgIL2AYdI/U6G/RMUtj97YaWz768aPxO1HSsKtFBAQnUpAjXK0bSf33+x9zSRZq0ZX8nsucppdaU7U36q"
    "tp1H+fz/A/fOECO6vgz2AAAAAElFTkSuQmCC"
)

# ---------------------------------------------------------------- GUI themes
# roles: bg, fg (main text), dim (secondary), acc (accent), red (errors), btn (button), ent (input), chat (chat area)
THEMES = {
    "hacker":   dict(bg="#000000", fg="#00ff41", dim="#0a7a28", acc="#00e5ff", red="#ff3b3b", btn="#001a00", ent="#050505", chat="#030803",
                     pal=["#00e5ff", "#ffd166", "#ff6bd6", "#a78bfa", "#ff9f43", "#5eead4", "#f472b6", "#93c5fd"]),
    "amber":    dict(bg="#0a0600", fg="#ffb000", dim="#9a6a00", acc="#ffd866", red="#ff5a3c", btn="#1f1400", ent="#120b00", chat="#0e0800",
                     pal=["#ffd866", "#ff8c42", "#ffe8a3", "#d9a066", "#ff6b6b", "#c8e06c", "#e8c170", "#f2a65a"]),
    "ice":      dict(bg="#04080f", fg="#9fd8ff", dim="#5b86a8", acc="#4fffe3", red="#ff6b81", btn="#0b1a2b", ent="#07111d", chat="#060d17",
                     pal=["#4fffe3", "#ffd166", "#ff9ecf", "#b39bff", "#ffa94d", "#8bf5a8", "#7fb6ff", "#ff8fa3"]),
    "miami":    dict(bg="#12002b", fg="#ff4fd8", dim="#a45fcf", acc="#00f0ff", red="#ff6a5c", btn="#2a0a5e", ent="#1b0640", chat="#0e0023",
                     pal=["#00f0ff", "#ffe66d", "#ff9f43", "#7dffb3", "#c792ff", "#ff7eb6", "#4dd8ff", "#ffd6f5"]),
    "blood":    dict(bg="#080000", fg="#ff3030", dim="#c03a3a", acc="#ff9a3c", red="#ffe0e0", btn="#1f0000", ent="#110000", chat="#0c0000",
                     pal=["#ff9a3c", "#ffd166", "#ff6bd6", "#c792ff", "#ff7a7a", "#ffc2a1", "#f2d06b", "#ff8fa3"]),
    "light":    dict(bg="#f4f5f7", fg="#14181f", dim="#5d6673", acc="#0a5fbf", red="#c0262d", btn="#dfe3ea", ent="#ffffff", chat="#fafbfc",
                     pal=["#0a5fbf", "#8a5a00", "#b0176f", "#5b3fc4", "#b4470d", "#0b7a6e", "#a1244f", "#2d6fa8"]),
    "paper":    dict(bg="#f3ead3", fg="#33281a", dim="#7d6c4f", acc="#8a3a0e", red="#a8141c", btn="#e3d6b6", ent="#fff9e8", chat="#f9f1dc",
                     pal=["#8a3a0e", "#1f6f5c", "#6b2f8a", "#a05a00", "#8a1f4b", "#2a5d8a", "#5a6b0b", "#7a3c3c"]),
    "contrast": dict(bg="#000000", fg="#ffffff", dim="#c8c8c8", acc="#ffff00", red="#ff6060", btn="#1c1c1c", ent="#0c0c0c", chat="#080808",
                     pal=["#ffff00", "#00ffff", "#ff80ff", "#80ff80", "#ffa040", "#a0a0ff", "#ff8080", "#ffffff"]),
}
THEME_ROLES = ("bg", "fg", "dim", "acc", "red", "btn", "ent", "chat")
THEME_OPTS = ("background", "foreground", "selectcolor", "activebackground", "activeforeground",
              "insertbackground", "highlightbackground", "highlightcolor", "readonlybackground",
              "buttonbackground", "troughcolor")


def _lum(hexcol):
    ch = [int(hexcol[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    ch = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in ch]
    return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2]


def contrast_ratio(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def theme_file():
    return os.path.join(APP_DIR, "theme.txt")


def load_theme():
    try:
        with open(theme_file()) as f:
            name = f.read().strip()
        return name if name in THEMES else "hacker"
    except OSError:
        return "hacker"


SHAPE_LABELS = [("off", 0.0), ("low  (1 frame / 5 s)", 0.2), ("normal (1 frame / s)", 1.0),
                ("high (4 frames / s)", 4.0), ("fast (20 frames / s)", 20.0)]


def main(args=None):
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog

    args = args or build_parser().parse_args([])
    theme_name = args.theme or load_theme()
    TH = THEMES[theme_name]
    BG, FG, DIM, ACC, RED = TH["bg"], TH["fg"], TH["dim"], TH["acc"], TH["red"]
    BTN, ENT, CHATBG, PALETTE = TH["btn"], TH["ent"], TH["chat"], list(TH["pal"])
    FONT = (("Consolas" if os.name == "nt" else
             "Menlo" if sys.platform == "darwin" else "DejaVu Sans Mono"), 10)

    try:                                   # optional: drag & drop of files onto the window
        from tkinterdnd2 import DND_FILES, TkinterDnD
        root = TkinterDnD.Tk()
    except Exception:
        DND_FILES = None
        root = tk.Tk()
    root.title("Mute")
    try:                                   # window / taskbar icon (small PNG embedded, no extra file needed)
        root.iconphoto(True, tk.PhotoImage(data=APP_ICON_PNG))
    except Exception:
        pass
    root.configure(bg=BG)
    root.geometry("860x760")

    # --- identity: burner or persistent
    burner = args.burner
    if not burner and not args.persistent:
        ans = messagebox.askyesnocancel(
            "Identity",
            "Use a BURNER identity?\n\nYES  = random key, nothing saved, new fingerprint every start\n"
            "NO   = persistent identity (key file in your profile)", parent=root)
        if ans is None:
            return
        burner = ans
    passphrase = None
    if not burner:
        state = identity_state()
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

    node = Node(confirm_cb, passphrase, args.amnesia, scrub=not args.no_scrub, burner=burner)

    # --- option variables
    closed_var = tk.BooleanVar(value=args.closed)
    relay_var = tk.BooleanVar(value=args.relay)
    cover_var = tk.BooleanVar(value=bool(args.cover or args.cover_profile))
    cover_prof_var = tk.StringVar(value=args.cover_profile or "random")
    shape_var = tk.StringVar(value=SHAPE_LABELS[0][0])
    notify_var = tk.BooleanVar(value=True)
    clip_var = tk.BooleanVar(value=True)
    shot_var = tk.BooleanVar(value=False)
    clear_min = tk.StringVar(value="0")
    lock_min = tk.StringVar(value="0")
    lock_secret = [passphrase]
    locked = [False]
    last_active = [time.time()]

    if args.shape:
        shape_var.set(min(SHAPE_LABELS, key=lambda lr: abs(lr[1] - args.shape))[0])
    secret = None
    if args.psk:
        secret = simpledialog.askstring("Shared secret", "Pre-shared secret (both sides must enter the same):",
                                        show="*", parent=root)
    try:
        apply_opts(node, args, secret)
    except ValueError as e:
        messagebox.showerror("Option error", str(e), parent=root)
        return

    def mk_label(parent, text, fg=FG):
        return tk.Label(parent, text=text, bg=BG, fg=fg, font=FONT, anchor="w")

    def mk_entry(parent, var, width=20, show=None, state="normal"):
        return tk.Entry(parent, textvariable=var, width=width, bg=ENT, fg=FG,
                        insertbackground=FG, relief="flat", font=FONT, show=show, state=state,
                        readonlybackground=ENT, highlightthickness=1,
                        highlightbackground=DIM, highlightcolor=FG)

    def mk_btn(parent, text, cmd, fg=FG):
        return tk.Button(parent, text=text, command=cmd, bg=BTN, fg=fg, font=FONT,
                         relief="flat", bd=0, padx=8, pady=2, activebackground=fg,
                         activeforeground=BG, highlightthickness=1,
                         highlightbackground=fg, cursor="hand2")

    def mk_check(parent, text, var, cmd=None):
        return tk.Checkbutton(parent, text=text, variable=var, bg=BG, fg=DIM,
                              selectcolor=BTN, activebackground=BG,
                              activeforeground=FG, font=FONT, command=cmd)

    def copy_text(s):
        root.clipboard_clear()
        root.clipboard_append(s)
        if clip_var.get():
            def clr():
                try:
                    if root.clipboard_get() == s:
                        root.clipboard_clear()
                        root.clipboard_append("")
                except tk.TclError:
                    pass
            root.after(30000, clr)

    tk.Label(root, text=BANNER, bg=BG, fg=FG, font=("Courier", 9), justify="left").pack(anchor="w", padx=8)

    f1 = tk.Frame(root, bg=BG)
    f1.pack(fill="x", padx=8)
    mk_label(f1, "FINGERPRINT>", DIM).grid(row=0, column=0, sticky="w")
    fp_var = tk.StringVar(value=node.my_fp)
    mk_entry(f1, fp_var, 52).grid(row=0, column=1, padx=6, pady=2)
    mk_btn(f1, "copy", lambda: copy_text(node.my_fp)).grid(row=0, column=2)
    if burner:
        mk_label(f1, "BURNER", RED).grid(row=0, column=3, padx=6)
    mk_label(f1, "WORDS>", DIM).grid(row=1, column=0, sticky="w")
    words_var = tk.StringVar(value=fp_words(node.my_fp))
    mk_entry(f1, words_var, 52, state="readonly").grid(row=1, column=1, padx=6, pady=2)
    mk_btn(f1, "copy", lambda: copy_text(words_var.get())).grid(row=1, column=2)
    mk_label(f1, "ADDRESS>", DIM).grid(row=2, column=0, sticky="w")
    addr_var = tk.StringVar(value=", ".join(local_ips()) or "?")
    mk_entry(f1, addr_var, 52).grid(row=2, column=1, padx=6, pady=2)
    mk_btn(f1, "copy", lambda: copy_text(addr_var.get())).grid(row=2, column=2)

    f2 = tk.Frame(root, bg=BG)
    f2.pack(fill="x", padx=8, pady=(6, 0))
    mode = tk.StringVar(value="tor" if args.tor else "direct")
    for i, (t, v) in enumerate((("DIRECT (IP:port)", "direct"), ("TOR (.onion, anonymous)", "tor"))):
        tk.Radiobutton(f2, text=t, variable=mode, value=v, bg=BG, fg=FG, selectcolor=BTN,
                       activebackground=BG, activeforeground=FG, font=FONT).grid(row=0, column=i, padx=4)
    mk_label(f2, "port:", DIM).grid(row=0, column=2)
    port_var = tk.StringVar(value=str(args.port))
    mk_entry(f2, port_var, 6).grid(row=0, column=3, padx=4)
    start_btn = mk_btn(f2, "[ START ]", lambda: do_start())
    start_btn.grid(row=0, column=4, padx=6)
    stop_btn = mk_btn(f2, "[ STOP ]", lambda: do_stop(), RED)
    stop_btn.grid(row=0, column=5, padx=2)
    stop_btn.config(state="disabled")

    f2b = tk.Frame(root, bg=BG)
    f2b.pack(fill="x", padx=8, pady=(2, 6))
    amnesia = tk.BooleanVar(value=node.amnesia)
    cb_amn = mk_check(f2b, "amnesia (save nothing)", amnesia,
                      lambda: setattr(node, "amnesia", amnesia.get()))
    cb_amn.pack(side="left", padx=4)
    if burner:
        cb_amn.config(state="disabled")
    scrub_var = tk.BooleanVar(value=node.scrub)
    mk_check(f2b, "scrub metadata", scrub_var,
             lambda: setattr(node, "scrub", scrub_var.get())).pack(side="left", padx=4)
    mk_btn(f2b, "Tor bridges...", lambda: edit_bridges(), DIM).pack(side="left", padx=8)
    mk_btn(f2b, "Options...", lambda: open_options(), ACC).pack(side="left", padx=2)
    mk_btn(f2b, "LOCK", lambda: manual_lock(), DIM).pack(side="left", padx=8)

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

    chat = tk.Text(root, bg=CHATBG, fg=FG, font=FONT, wrap="word", state="disabled",
                   relief="flat", highlightthickness=1, highlightbackground=DIM, height=14)
    chat.pack(fill="both", expand=True, padx=8, pady=4)
    chat.tag_config("me", foreground=FG)
    chat.tag_config("peer", foreground=ACC)
    chat.tag_config("sys", foreground=DIM)
    chat.tag_config("err", foreground=RED)
    peer_tag = {}
    chat_lines = []  # (epoch, text, tag) - lets the auto-clear timer remove old lines

    def tag_for(fp):
        if fp not in peer_tag:
            tag = f"peer{len(peer_tag)}"
            chat.tag_config(tag, foreground=PALETTE[len(peer_tag) % len(PALETTE)])
            peer_tag[fp] = tag
        return peer_tag[fp]

    def apply_theme(name, save=True):
        """Switches the colours of every open window at once."""
        nonlocal BG, FG, DIM, ACC, RED, BTN, ENT, CHATBG, PALETTE, theme_name
        old, new = THEMES[theme_name], THEMES[name]
        rev = {old[k].lower(): new[k] for k in THEME_ROLES}

        def walk(w):
            for opt in THEME_OPTS:
                try:
                    v = str(w.cget(opt)).lower()
                except tk.TclError:
                    continue
                if v in rev and v != rev[v].lower():
                    try:
                        w.configure(**{opt: rev[v]})
                    except tk.TclError:
                        pass
            for c in w.winfo_children():
                walk(c)
        walk(root)
        root.configure(bg=new["bg"])
        chat.tag_config("me", foreground=new["fg"])
        chat.tag_config("peer", foreground=new["acc"])
        chat.tag_config("sys", foreground=new["dim"])
        chat.tag_config("err", foreground=new["red"])
        for i in range(len(peer_tag)):
            chat.tag_config(f"peer{i}", foreground=new["pal"][i % len(new["pal"])])
        theme_name = name
        BG, FG, DIM, ACC, RED = new["bg"], new["fg"], new["dim"], new["acc"], new["red"]
        BTN, ENT, CHATBG, PALETTE = new["btn"], new["ent"], new["chat"], list(new["pal"])
        if save and not (burner or args.amnesia):
            try:
                os.makedirs(APP_DIR, exist_ok=True)
                with open(theme_file(), "w") as f:
                    f.write(name)
            except OSError:
                pass

    def render():
        chat.config(state="normal")
        chat.delete("1.0", "end")
        for ts, text, tag in chat_lines:
            chat.insert("end", f"[{time.strftime('%H:%M:%S', time.localtime(ts))}] {text}\n", tag)
        chat.config(state="disabled")
        chat.see("end")

    def log(text, tag="sys"):
        chat_lines.append((time.time(), text, tag))
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
    call_btn = mk_btn(f4, "call", lambda: do_call(), ACC)
    call_btn.pack(side="left", padx=2)
    pause_btn = mk_btn(f4, "pause", lambda: toggle_pause(), DIM)
    pause_btn.pack(side="left", padx=2)
    mk_btn(f4, "cancel", lambda: node.cancel_transfer(), DIM).pack(side="left", padx=2)
    mk_btn(f4, "wipe", lambda: wipe(), ACC).pack(side="left", padx=2)
    mk_btn(f4, "PANIC", lambda: panic(), RED).pack(side="left", padx=2)

    # --- sounds, call volume, push to talk (saved in audio.json unless burner / amnesia)
    prefs = load_audio_prefs()
    node.calls.volume = prefs["volume"] / 100.0
    node.calls.mic_gain = prefs["mic_gain"] / 100.0
    node.calls.set_ptt(prefs["ptt"])
    sounds = Sounds(prefs["sounds"], prefs["sound_volume"], fallback=lambda: root.after(0, root.bell))

    def save_prefs():
        if not (burner or args.amnesia):
            save_audio_prefs(prefs)

    def mk_scale(parent, lo, hi, value, cmd, length=180):
        sc = tk.Scale(parent, from_=lo, to=hi, orient="horizontal", length=length, showvalue=False,
                      bg=BG, fg=FG, troughcolor=ENT, highlightthickness=0, bd=0,
                      sliderrelief="flat", activebackground=ACC, command=cmd)
        sc.set(value)
        sc.bind("<ButtonRelease-1>", lambda e: save_prefs(), add="+")
        return sc

    # --- voice call bar (shown only while a call is ringing or running)
    call_bar = tk.Frame(root, bg=BG, highlightthickness=1, highlightbackground=ACC)
    call_var = tk.StringVar(value="")
    tk.Label(call_bar, textvariable=call_var, bg=BG, fg=ACC, font=FONT, anchor="w").pack(side="left", padx=8, pady=4)
    mk_btn(call_bar, "hang up", lambda: node.calls.hangup(), RED).pack(side="right", padx=6, pady=3)
    mute_btn = mk_btn(call_bar, "mute", lambda: toggle_mute(), DIM)
    mute_btn.pack(side="right", padx=2, pady=3)

    def set_call_volume(v):
        prefs["volume"] = int(float(v))
        node.calls.volume = prefs["volume"] / 100.0
    vol_scale = mk_scale(call_bar, 0, 200, prefs["volume"], set_call_volume, length=80)
    vol_scale.pack(side="right", padx=2, pady=3)
    tk.Label(call_bar, text="vol", bg=BG, fg=DIM, font=FONT).pack(side="right")
    ptt_btn = mk_btn(call_bar, "hold to talk", lambda: None, ACC)
    ptt = {"down": False, "after": None, "key": prefs["ptt_key"]}

    def ptt_set(down):
        ptt["down"] = down
        node.calls.ptt_press(down)
        ptt_btn.config(text="TALKING" if down else "hold to talk")

    def refresh_ptt():
        if node.calls.ptt:
            ptt_btn.pack(side="right", padx=4, pady=3, before=mute_btn)
        else:
            ptt_btn.pack_forget()
            ptt_set(False)
    ptt_btn.bind("<ButtonPress-1>", lambda e: ptt_set(True))
    ptt_btn.bind("<ButtonRelease-1>", lambda e: ptt_set(False))

    def key_down(e):
        if not node.calls.ptt:
            return
        if ptt["after"]:
            root.after_cancel(ptt["after"])
            ptt["after"] = None
        if not ptt["down"]:
            ptt_set(True)

    def key_up(e):                         # key auto-repeat sends release+press pairs: wait a moment before letting go
        if ptt["down"] and not ptt["after"]:
            def let_go():
                ptt["after"] = None
                ptt_set(False)
            ptt["after"] = root.after(90, let_go)

    def bind_ptt_key(new):
        try:
            root.unbind_all(f"<KeyPress-{ptt['key']}>")
            root.unbind_all(f"<KeyRelease-{ptt['key']}>")
        except tk.TclError:
            pass
        ptt["key"] = new
        try:
            root.bind_all(f"<KeyPress-{new}>", key_down)
            root.bind_all(f"<KeyRelease-{new}>", key_up)
        except tk.TclError:
            pass
    bind_ptt_key(prefs["ptt_key"])
    ring = {"win": None, "after": None}

    def bar(level, total=8):
        n = min(total, int(level / 3000 * total + 0.5)) if level else 0
        return "#" * n + "-" * (total - n)

    def call_tick():
        c = node.calls
        if c.state == "idle":
            return
        who = node.label(c.peer) if c.peer else "?"
        if c.state == "active":
            st = c.stats() or {}
            sec = st.get("seconds", 0)
            call_var.set(f"CALL {who}  {sec // 60:02d}:{sec % 60:02d}  [{st.get('codec', '')}]  "
                         f"mic [{bar(st.get('level_in', 0))}]{' MUTED' if c.muted else ''}  "
                         f"them [{bar(st.get('level_out', 0))}]{' (muted)' if c.remote_muted else ''}"
                         + (f"  gaps {st.get('underruns', 0)}" if st.get("underruns") else ""))
        elif c.state == "ringing-out":
            call_var.set(f"CALLING {who}...")
        root.after(300, call_tick)

    def show_call_bar():
        if not call_bar.winfo_ismapped():
            call_bar.pack(fill="x", padx=8, pady=(0, 4), before=f4)
            refresh_ptt()
            call_tick()

    def hide_call_bar():
        call_bar.pack_forget()
        call_var.set("")
        mute_btn.config(text="mute")
        ptt_set(False)

    def toggle_mute():
        node.calls.set_muted(not node.calls.muted)
        mute_btn.config(text="unmute" if node.calls.muted else "mute")

    def close_ring():
        if ring["win"]:
            try:
                ring["win"].destroy()
            except tk.TclError:
                pass
            ring["win"] = None
        if ring["after"]:
            root.after_cancel(ring["after"])
            ring["after"] = None
        sounds.stop()

    def incoming_dialog(fp):
        close_ring()
        win = tk.Toplevel(root)
        win.title("Incoming call")
        win.configure(bg=BG)
        win.attributes("-topmost", True)
        ring["win"] = win
        tk.Label(win, text="INCOMING CALL", bg=BG, fg=ACC, font=(FONT[0], 14)).pack(padx=30, pady=(16, 4))
        tk.Label(win, text=f"{node.label(fp)}  ({short(fp)})", bg=BG, fg=FG, font=FONT).pack(padx=30)
        f = tk.Frame(win, bg=BG)
        f.pack(pady=14)

        def acc():
            close_ring()
            try:
                node.calls.accept()
            except Exception as e:
                log(f"{e}", "err")

        def rej():
            close_ring()
            node.calls.reject()
        mk_btn(f, "accept", acc).pack(side="left", padx=8)
        mk_btn(f, "reject", rej, RED).pack(side="left", padx=8)
        win.protocol("WM_DELETE_WINDOW", rej)

        def beep():
            if ring["win"] is win:
                root.bell()
                ring["after"] = root.after(1500, beep)
        if sounds.enabled:
            sounds.loop("ring")
        else:
            beep()

    def do_call():
        peers = list(node.chans)
        if not peers:
            return log("Not connected - nobody to call", "err")
        if node.calls.busy():
            return log("Already in a call", "err")

        def go(fp):
            try:
                node.calls.call(fp)
            except Exception as e:
                log(f"{e}", "err")
        if len(peers) == 1:
            return go(peers[0])
        menu = tk.Menu(root, tearoff=0, bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT)
        for fp in peers:
            menu.add_command(label=node.label(fp), command=lambda f=fp: go(f))
        menu.tk_popup(call_btn.winfo_rootx(), call_btn.winfo_rooty() + call_btn.winfo_height())

    CALL_TEXT = {"rejected": "Call declined", "busy": "Busy - the other side is in a call",
                 "noanswer": "No answer", "missed": "Call ended before you answered",
                 "ended": "Call ended", "ended-remote": "The other side ended the call"}

    def on_call_event(state, fp, detail):
        who = node.label(fp) if fp else "?"
        if state == "incoming":
            log(f"Incoming call from {who}", "me")
            notify()
            incoming_dialog(fp)
        elif state == "ringing":
            log(f"Calling {who}...")
            show_call_bar()
            sounds.loop("ringback")
        elif state == "active":
            close_ring()
            sounds.play("connected")
            log(f"Call with {who} started ({detail})", "me")
            show_call_bar()
        elif state == "remote-mute":
            log(f"{who} muted their microphone" if detail else f"{who} unmuted")
        elif state in CALL_TEXT or state == "error":
            close_ring()
            sounds.play("error" if state == "error" else "ended")
            hide_call_bar()
            log((f"Call error: {detail}" if state == "error" else f"{CALL_TEXT[state]} ({who})")
                + (f" - {detail}" if detail and state != "error" else ""), "err" if state == "error" else "sys")

    # --- lock screen (covers everything; messages keep arriving behind it)
    lock_frame = tk.Frame(root, bg=BG)
    tk.Label(lock_frame, text="[ LOCKED ]", bg=BG, fg=FG, font=(FONT[0], 20)).pack(pady=(160, 10))
    lock_msg = tk.StringVar(value="")
    lock_var = tk.StringVar()
    lock_entry = mk_entry(lock_frame, lock_var, 28, show="*")
    lock_entry.pack()
    tk.Label(lock_frame, textvariable=lock_msg, bg=BG, fg=RED, font=FONT).pack(pady=6)

    lock_asked = [False]

    def manual_lock(_=None):
        """LOCK button / Ctrl+L. The first time without a password it offers to set one."""
        if not locked[0] and not lock_secret[0] and not lock_asked[0]:
            lock_asked[0] = True
            s = simpledialog.askstring(
                "Lock password", "Choose a lock screen password.\n(Leave empty to lock without one - Enter unlocks.)\n"
                "You can change it later in Options > lock password.", show="*", parent=root)
            if s:
                lock_secret[0] = s
                log("Lock password set")
        lock()

    def lock(_=None):
        if locked[0]:
            return
        locked[0] = True
        lock_var.set("")
        lock_msg.set("" if lock_secret[0] else "press Enter to unlock (set a password in Options > lock password)")
        lock_frame.place(x=0, y=0, relwidth=1, relheight=1)
        lock_frame.lift()
        lock_entry.focus_set()

    def unlock(_=None):
        sec = lock_secret[0]
        if sec and not hmac.compare_digest(lock_var.get().encode(), sec.encode()):
            lock_msg.set("wrong password")
            lock_var.set("")
            return
        lock_frame.place_forget()
        locked[0] = False
        last_active[0] = time.time()
        entry.focus_set()

    lock_entry.bind("<Return>", unlock)

    def minutes(var):
        try:
            return max(0, int(var.get()))
        except (ValueError, tk.TclError):
            return 0

    def idle_check():
        m = minutes(lock_min)
        if m and not locked[0] and time.time() - last_active[0] > m * 60:
            lock()
        root.after(5000, idle_check)

    def prune_check():
        m = minutes(clear_min)
        if m:
            cut = time.time() - m * 60
            keep = [l for l in chat_lines if l[0] >= cut]
            if len(keep) != len(chat_lines):
                chat_lines[:] = keep
                render()
        root.after(5000, prune_check)

    def touch(_=None):
        last_active[0] = time.time()

    for seq in ("<Key>", "<Motion>", "<ButtonPress>"):
        root.bind_all(seq, touch, add="+")

    # --- notifications
    def notify():
        if not notify_var.get():
            return
        if root.focus_displayof() is None or locked[0]:
            try:
                root.bell()
            except tk.TclError:
                pass
            root.title("* Mute")

    root.bind("<FocusIn>", lambda e: root.title("Mute"), add="+")

    # --- screenshot / screen-recording block (Windows only)
    def apply_shot_block():
        if os.name != "nt":
            return
        try:
            import ctypes
            root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            on = shot_var.get()
            res = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x11 if on else 0)
            if on and not res:
                res = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 1)
            log(("Screenshot protection " + ("ON" if on else "OFF")) if res
                else "Could not change screenshot protection on this Windows version", "sys" if res else "err")
        except Exception as e:
            log(f"Screenshot protection failed: {e}", "err")

    # --- dialogs
    def text_dialog(title, intro, initial, on_save, extra=None):
        win = tk.Toplevel(root)
        win.title(title)
        win.configure(bg=BG)
        tk.Label(win, bg=BG, fg=FG, font=FONT, justify="left", text=intro).pack(padx=8, pady=6)
        txt = tk.Text(win, height=8, width=84, bg=ENT, fg=FG, insertbackground=FG,
                      font=FONT, relief="flat", highlightthickness=1, highlightbackground=DIM)
        txt.pack(padx=8)
        txt.insert("1.0", initial)

        def save():
            try:
                on_save(txt.get("1.0", "end"))
            except ValueError as e:
                return messagebox.showerror(title, str(e), parent=win)
            win.destroy()
        bar = tk.Frame(win, bg=BG)
        bar.pack(pady=8)
        mk_btn(bar, "save", save).pack(side="left", padx=4)
        if extra:
            mk_btn(bar, extra[0], lambda: extra[1](txt, win), ACC).pack(side="left", padx=4)

    def moat_dialog(txt, parent):
        """Download bridges from the Tor Project (Moat). Network work runs in a thread."""
        win = tk.Toplevel(parent)
        win.title("Get bridges from the Tor Project")
        win.configure(bg=BG)
        tk.Label(win, bg=BG, fg=FG, font=FONT, justify="left", text=(
            "Asks bridges.torproject.org for bridges. If that site is blocked where you are,\n"
            "enter a SOCKS5 proxy that can reach it (a VPN's proxy, another Tor, ...).")).pack(padx=8, pady=6)
        px_var, sol_var, st_var = (tk.StringVar(value=f"{node.proxy[0]}:{node.proxy[1]}" if node.proxy else ""),
                                   tk.StringVar(), tk.StringVar(value=""))
        f = tk.Frame(win, bg=BG)
        f.pack(padx=8, fill="x")
        tk.Label(f, text="SOCKS5 proxy (optional)", bg=BG, fg=DIM, font=FONT).pack(side="left")
        mk_entry(f, px_var, 22).pack(side="left", padx=6)
        tk.Label(win, textvariable=st_var, bg=BG, fg=ACC, font=FONT, wraplength=520, justify="left").pack(padx=8, pady=4)
        img_lbl = tk.Label(win, bg=BG)
        img_lbl.pack()
        state = {"challenge": None}

        def proxy():
            return parse_proxy(px_var.get())

        def run(work, done):
            def th():
                try:
                    res, err = work(), None
                except (MoatError, ValueError) as e:
                    res, err = None, e
                try:
                    root.after(0, lambda: done(res, err))
                except RuntimeError:
                    pass
            st_var.set("working...")
            threading.Thread(target=th, daemon=True).start()

        def add(lines):
            have = {b.strip() for b in txt.get("1.0", "end").splitlines()}
            txt.insert("end", "\n".join(x for x in lines if x not in have) + "\n")

        def get_builtin():
            try:
                px = proxy()
            except ValueError as e:
                return st_var.set(str(e))

            def done(res, err):
                if err:
                    return st_var.set(str(err))
                add(res)
                st_var.set(f"{len(res)} built-in bridge(s) added - press save in the bridge window")
            run(lambda: moat_builtin(px), done)

        def get_captcha():
            try:
                px = proxy()
            except ValueError as e:
                return st_var.set(str(e))

            def done(res, err):
                if err:
                    return st_var.set(str(err))
                data, state["challenge"] = res
                shown = False
                try:                                    # nicer with Pillow, otherwise the system image viewer
                    import io
                    from PIL import Image, ImageTk
                    ph = ImageTk.PhotoImage(Image.open(io.BytesIO(data)))
                    img_lbl.config(image=ph)
                    img_lbl.image = ph
                    shown = True
                except Exception:
                    pass
                if not shown:
                    path = os.path.join(tempfile.mkdtemp(prefix="mute_captcha_"), "captcha.jpg")
                    with open(path, "wb") as fh:
                        fh.write(data)
                    try:
                        if os.name == "nt":
                            os.startfile(path)
                        else:
                            subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path],
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except Exception:
                        pass
                    st_var.set(f"Captcha image opened in your image viewer (file: {path}). Type what it shows.")
                else:
                    st_var.set("Type the characters shown, then press submit.")
            run(lambda: moat_captcha("obfs4", px), done)

        def submit():
            if not state["challenge"]:
                return st_var.set("Press 'get captcha' first")
            try:
                px = proxy()
            except ValueError as e:
                return st_var.set(str(e))

            def done(res, err):
                if err:
                    return st_var.set(str(err))
                add(res)
                st_var.set(f"{len(res)} bridge(s) added - press save in the bridge window")
                state["challenge"] = None
            run(lambda: moat_solve(state["challenge"], sol_var.get(), "obfs4", px), done)

        bar = tk.Frame(win, bg=BG)
        bar.pack(pady=4)
        mk_btn(bar, "built-in bridges (no captcha)", get_builtin).pack(side="left", padx=4)
        mk_btn(bar, "get captcha", get_captcha, ACC).pack(side="left", padx=4)
        f2 = tk.Frame(win, bg=BG)
        f2.pack(pady=4)
        mk_entry(f2, sol_var, 16).pack(side="left", padx=4)
        mk_btn(f2, "submit", submit).pack(side="left", padx=4)

    def edit_bridges():
        def save(text):
            node.set_bridges(text)
            note = " (restart the app to apply - Tor is already running)" if node.transport == "tor" else ""
            log(f"{len(node.bridges)} bridge(s) set{note}")
        text_dialog("Tor bridges",
                    "One bridge per line (get them at bridges.torproject.org).\n"
                    "Supported: obfs4, meek_lite, snowflake, plain bridges.\n"
                    "Kept in memory only; applied the next time Tor starts.",
                    "\n".join(b[0] for b in node.bridges), save, ("get from Tor Project...", moat_dialog))

    def edit_allowed_fps():
        def save(text):
            added = 0
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                if line:
                    node.allow(line)
                    added += 1
            log(f"{len(node.known)} trusted fingerprint(s) in the allowlist")
        text_dialog("Allowed fingerprints",
                    "One fingerprint per line. In closed mode only these peers can connect,\n"
                    "without any prompt. Everyone else is rejected silently.",
                    "\n".join(sorted(node.known)), save)

    def edit_allowed_clients():
        def save(text):
            node.set_allowed_clients(text)
            note = " - applies the next time Tor starts" if node.transport != "tor" else " - restart the app to apply"
            log(f"{len(node.allowed_clients)} allowed onion client key(s){note}")
        text_dialog("Allowed onion clients",
                    "One client key per line (52 characters). With keys set, nobody without a matching\n"
                    "key can even find your onion service. Set this BEFORE pressing START in TOR mode.",
                    "\n".join(node.allowed_clients), save)

    def show_client_key():
        pub = node.client_auth[1] if node.client_auth else node.new_client_auth()
        win = tk.Toplevel(root)
        win.title("My onion client key")
        win.configure(bg=BG)
        tk.Label(win, bg=BG, fg=FG, font=FONT, justify="left",
                 text="Give this PUBLIC key to the person running the onion service.\n"
                      "They add it under 'Allowed onion clients' BEFORE starting Tor.\n"
                      "It is used automatically when you connect to a .onion address.\n"
                      "The private part stays in memory only (new key every start).").pack(padx=8, pady=6)
        v = tk.StringVar(value=pub)
        mk_entry(win, v, 58, state="readonly").pack(padx=8)
        mk_btn(win, "copy", lambda: copy_text(pub)).pack(pady=8)

    def set_secret():
        s = simpledialog.askstring(
            "Shared secret",
            "Pre-shared secret (empty = none). Both sides must enter the same one\n"
            "BEFORE connecting. Use a long passphrase.", show="*", parent=root)
        if s is None:
            return
        node.set_psk(s)
        log("Shared secret " + ("set" if s else "cleared"))

    def set_lock_password():
        s = simpledialog.askstring("Lock password", "Lock screen password (empty = just press Enter):",
                                   show="*", parent=root)
        if s is not None:
            lock_secret[0] = s or None
            log("Lock password " + ("set" if s else "cleared"))

    def open_options():
        win = tk.Toplevel(root)
        win.title("Options")
        win.configure(bg=BG)
        r = 0

        def section(text):
            nonlocal r
            tk.Label(win, text="-- " + text + " --", bg=BG, fg=ACC, font=FONT, anchor="w").grid(
                row=r, column=0, columnspan=3, sticky="w", padx=8, pady=(8, 2))
            r += 1

        def row(widget, widget2=None):
            nonlocal r
            widget.grid(row=r, column=0, sticky="w", padx=8, pady=1)
            if widget2:
                widget2.grid(row=r, column=1, sticky="w", padx=4)
            r += 1

        def spin(var):
            return tk.Spinbox(win, from_=0, to=999, width=5, textvariable=var, bg=ENT, fg=FG,
                              buttonbackground=BTN, insertbackground=FG, font=FONT, relief="flat")

        section("access control")
        row(mk_check(win, "closed mode (only allowlisted fingerprints connect)", closed_var,
                     lambda: setattr(node, "closed", closed_var.get())), mk_btn(win, "allowed fingerprints...", edit_allowed_fps, DIM))
        row(mk_btn(win, "shared secret...", set_secret, DIM))
        row(mk_check(win, "relay hub (forward messages between my peers)", relay_var,
                     lambda: setattr(node, "relay", relay_var.get())))
        section("network privacy")
        cov_note = tk.StringVar(value="")

        def apply_cover(*_):
            node.set_cover(cover_var.get(), cover_prof_var.get())
            cov_note.set(f"{COVER_PROFILES[cover_prof_var.get()]} - {cover_estimate(cover_prof_var.get())}"
                         if cover_var.get() else "")
        cm = tk.OptionMenu(win, cover_prof_var, *COVER_PROFILES, command=apply_cover)
        cm.config(bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT,
                  relief="flat", highlightthickness=1, highlightbackground=DIM)
        row(mk_check(win, "cover traffic (dummy frames imitating...)", cover_var, apply_cover), cm)
        tk.Label(win, textvariable=cov_note, bg=BG, fg=ACC, font=FONT, anchor="w", wraplength=560, justify="left").grid(
            row=r, column=0, columnspan=3, sticky="w", padx=8)
        r += 1
        if cover_var.get():
            apply_cover()
        est_var = tk.StringVar(value=shape_estimate(node.shape, node.transport == "tor") if node.shape else "")

        def apply_shape(*_):
            rate = dict(SHAPE_LABELS).get(shape_var.get(), 0.0)
            node.set_shape(rate)
            est_var.set(shape_estimate(rate, node.transport == "tor") if rate else "")
            log("Constant-rate traffic: " + (shape_estimate(rate, node.transport == "tor") if rate else "off"))
        om = tk.OptionMenu(win, shape_var, *[l for l, _ in SHAPE_LABELS], command=apply_shape)
        om.config(bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT,
                  relief="flat", highlightthickness=1, highlightbackground=DIM)
        row(tk.Label(win, text="constant-rate traffic (hides when you talk)", bg=BG, fg=DIM, font=FONT), om)
        tk.Label(win, textvariable=est_var, bg=BG, fg=ACC, font=FONT, anchor="w").grid(
            row=r, column=0, columnspan=3, sticky="w", padx=8)
        r += 1
        px_var = tk.StringVar(value=f"{node.proxy[0]}:{node.proxy[1]}" if node.proxy else "")
        px_note = tk.StringVar(value="")

        def apply_proxy(*_):
            try:
                node.proxy = parse_proxy(px_var.get())
                px_note.set("direct connections go through this proxy" if node.proxy else "")
            except ValueError:
                px_note.set("invalid proxy - not used")
                node.proxy = None
        px_var.trace_add("write", apply_proxy)
        row(tk.Label(win, text="SOCKS5 proxy for direct connections (host:port)", bg=BG, fg=DIM, font=FONT),
            mk_entry(win, px_var, 22))
        tk.Label(win, textvariable=px_note, bg=BG, fg=ACC, font=FONT, anchor="w").grid(
            row=r, column=0, columnspan=3, sticky="w", padx=8)
        r += 1
        row(mk_btn(win, "my onion client key...", show_client_key, DIM),
            mk_btn(win, "allowed onion clients...", edit_allowed_clients, DIM))
        section("appearance")
        theme_var = tk.StringVar(value=theme_name)
        tm = tk.OptionMenu(win, theme_var, *THEMES, command=lambda v: apply_theme(v))
        tm.config(bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT,
                  relief="flat", highlightthickness=1, highlightbackground=DIM)
        row(tk.Label(win, text="colour theme", bg=BG, fg=DIM, font=FONT), tm)
        section("voice calls")
        try:
            ins, outs = list_audio_devices()
        except AudioUnavailable as e:
            ins = outs = None
            tk.Label(win, text="Calls need the 'sounddevice' package / PortAudio:\n" + str(e)[:150], bg=BG, fg=RED, font=FONT,
                     justify="left", wraplength=560).grid(row=r, column=0, columnspan=3, sticky="w", padx=8)
            r += 1
        if ins is not None:
            def devmenu(label, devs, attr):
                names = ["(default)"] + [f"{i}: {n}"[:60] for i, n in devs]
                cur = getattr(node.calls, attr)
                var = tk.StringVar(value=next((x for x in names if cur is not None and x.startswith(f"{cur}:")), names[0]))

                def pick(v):
                    setattr(node.calls, attr, None if v == "(default)" else int(v.split(":", 1)[0]))
                om = tk.OptionMenu(win, var, *names, command=pick)
                om.config(bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT, relief="flat",
                          highlightthickness=1, highlightbackground=DIM, width=34)
                row(tk.Label(win, text=label, bg=BG, fg=DIM, font=FONT), om)
            devmenu("microphone", ins, "in_dev")
            devmenu("speaker", outs, "out_dev")
        duck_var = tk.BooleanVar(value=node.calls.duck)
        row(mk_check(win, "speakerphone mode (mute my microphone while the other side talks - avoids echo)", duck_var,
                     lambda: setattr(node.calls, "duck", duck_var.get())))
        ptt_var = tk.BooleanVar(value=node.calls.ptt)

        def ptt_toggle():
            prefs["ptt"] = ptt_var.get()
            node.calls.set_ptt(prefs["ptt"])
            save_prefs()
            if call_bar.winfo_ismapped():
                refresh_ptt()
        row(mk_check(win, "push to talk (the microphone only transmits while you hold the talk button or key)", ptt_var, ptt_toggle))
        key_var = tk.StringVar(value=ptt["key"])

        def pick_key(v):
            prefs["ptt_key"] = v
            bind_ptt_key(v)
            save_prefs()
        km = tk.OptionMenu(win, key_var, "F8", "F9", "F10", "Control_R", "Alt_R", "Pause", "Insert", command=pick_key)
        km.config(bg=BTN, fg=FG, activebackground=FG, activeforeground=BG, font=FONT, relief="flat",
                  highlightthickness=1, highlightbackground=DIM)
        row(tk.Label(win, text="talk key (works while this window is focused)", bg=BG, fg=DIM, font=FONT), km)

        def opt_volume(v):
            prefs["volume"] = int(float(v))
            node.calls.volume = prefs["volume"] / 100.0

        def opt_gain(v):
            prefs["mic_gain"] = int(float(v))
            node.calls.mic_gain = prefs["mic_gain"] / 100.0
        row(tk.Label(win, text="call volume %", bg=BG, fg=DIM, font=FONT), mk_scale(win, 0, 200, prefs["volume"], opt_volume))
        row(tk.Label(win, text="microphone gain %", bg=BG, fg=DIM, font=FONT), mk_scale(win, 0, 300, prefs["mic_gain"], opt_gain))
        section("sounds")
        snd_var = tk.BooleanVar(value=sounds.enabled)

        def snd_toggle():
            sounds.enabled = prefs["sounds"] = snd_var.get()
            if not sounds.enabled:
                sounds.stop()
            save_prefs()
        row(mk_check(win, "play sounds (incoming message, new peer, file received, call ringing / connected / ended)", snd_var, snd_toggle))

        def snd_volume(v):
            sounds.volume = prefs["sound_volume"] = int(float(v))
        row(tk.Label(win, text="sound volume %", bg=BG, fg=DIM, font=FONT), mk_scale(win, 0, 100, prefs["sound_volume"], snd_volume))
        row(mk_btn(win, "test sound", lambda: sounds.play("message")))
        tk.Label(win, text="codec: " + ("Opus (best quality) with ADPCM fallback" if "opus" in call_codecs() else
                                         "ADPCM 16 kHz (Opus not installed)") + " - a call uses about 10 KB/s; use a headset",
                 bg=BG, fg=ACC, font=FONT, anchor="w", wraplength=560, justify="left").grid(
            row=r, column=0, columnspan=3, sticky="w", padx=8)
        r += 1
        section("file transfer")
        limit_var = tk.StringVar(value=str(node.speed_limit // 1024))

        def apply_limit(*_):
            try:
                node.set_speed_limit(int(float(limit_var.get() or 0) * 1024))
            except ValueError:
                pass
        limit_var.trace_add("write", apply_limit)
        row(tk.Label(win, text="speed limit per peer (KB/s, 0 = unlimited)", bg=BG, fg=DIM, font=FONT), spin(limit_var))
        section("on this computer")
        row(tk.Label(win, text="auto-clear chat after (minutes, 0 = off)", bg=BG, fg=DIM, font=FONT), spin(clear_min))
        row(tk.Label(win, text="auto-lock after idle (minutes, 0 = off)", bg=BG, fg=DIM, font=FONT), spin(lock_min))
        row(mk_btn(win, "lock password...", set_lock_password, DIM))
        row(mk_check(win, "clear clipboard 30 s after copying", clip_var))
        row(mk_check(win, "notify when unfocused (beep + title)", notify_var))
        cs = mk_check(win, "block screenshots / screen recording" + ("" if os.name == "nt" else " (Windows only)"),
                      shot_var, apply_shot_block)
        if os.name != "nt":
            cs.config(state="disabled")
        row(cs)
        section("hotkeys")
        tk.Label(win, bg=BG, fg=DIM, font=FONT, justify="left",
                 text="Ctrl+L  lock      Ctrl+Shift+Q  PANIC (wipe + exit)      Esc x3  PANIC").grid(
            row=r, column=0, columnspan=3, sticky="w", padx=8, pady=4)
        r += 1
        mk_btn(win, "close", win.destroy).grid(row=r, column=0, pady=10)

    def do_start(after=None):
        try:
            port = int(port_var.get())
        except ValueError:
            return messagebox.showerror("Error", "Invalid port")
        if node.server or node.transport == "tor":
            return log("Already running. Restart the app to change mode.", "err")
        start_btn.config(state="disabled")
        stop_btn.config(state="normal")
        node.stop_requested.clear()

        def run():
            try:
                if mode.get() == "tor":
                    lp = free_port()
                    node.start_tor(lp)
                    node.listen(lp, local_only=True)
                    node.emit("addr", node.onion + f":{DEFAULT_PORT}")
                else:
                    node.listen(port)
                node.emit("listening")
                if node.stop_requested.is_set():
                    node.stop()            # STOP was pressed while we were still starting
                    return
                if after:
                    after()
            except Exception as e:
                if node.stop_requested.is_set():
                    node.stop()
                    return
                node.emit("sys", f"Error: {e}")
                node.stop()
                node.emit("enable_start")
        threading.Thread(target=run, daemon=True).start()

    def do_stop():
        """STOP: disconnect everybody, stop listening, shut Tor down; START works again."""
        node.stop()
        addr_var.set(", ".join(local_ips()) or "?")
        status_var.set("offline")
        start_btn.config(state="normal")
        stop_btn.config(state="disabled")
        log("Stopped: disconnected, no longer listening" + (" and Tor shut down" if mode.get() == "tor" else ""))

    def do_connect():
        try:
            host, port = split_hostport(host_var.get(), int(rport_var.get().strip() or DEFAULT_PORT))
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

    def toggle_pause():
        if node.paused.is_set():
            node.resume_transfers()
            pause_btn.config(text="pause")
        else:
            node.pause_transfers()
            pause_btn.config(text="resume")

    def drop_files(event):
        for p in root.tk.splitlist(event.data):
            try:
                node.send_file(p)
            except Exception as e:
                log(f"{e}", "err")

    if DND_FILES:
        try:
            root.drop_target_register(DND_FILES)
            root.dnd_bind("<<Drop>>", drop_files)
        except Exception:
            pass

    def do_folder():
        p = filedialog.askdirectory()
        if p:
            try:
                node.send_file(p)
            except Exception as e:
                log(f"{e}", "err")

    def wipe():
        chat_lines.clear()
        render()

    def panic(_=None):
        wipe()
        node.shutdown()
        os._exit(0)

    esc = []

    def on_escape(_=None):
        now = time.time()
        esc[:] = [t for t in esc if now - t < 1.5] + [now]
        if len(esc) >= 3:
            panic()

    entry.bind("<Return>", do_send)
    root.bind_all("<Control-l>", manual_lock)
    root.bind_all("<Control-L>", manual_lock)
    root.bind_all("<Control-Shift-Q>", panic)
    root.bind_all("<Control-Shift-q>", panic)
    root.bind_all("<Escape>", on_escape)
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
                    sounds.play("message")
                    notify()
                elif k == "relayed":
                    via, origin, text = ev[1], ev[2], ev[3]
                    if origin != node.my_fp:
                        who = node.label(origin) if origin else "?"
                        log(f"{who} (via {node.label(via)})> {text}", tag_for(origin or via))
                        sounds.play("message")
                        notify()
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
                    stop_btn.config(state="normal")
                    status_var.set("online · " + ", ".join(node.label(f) for f in node.chans))
                    sounds.play("peer")
                    notify()
                elif k == "listening":
                    if not node.chans:
                        status_var.set("listening · waiting for a peer")
                elif k == "disconnected":
                    status_var.set("online · " + ", ".join(node.label(f) for f in node.chans)
                                   if node.chans else
                                   ("listening · waiting for a peer" if node.server else "offline"))
                elif k == "addr":
                    addr_var.set(ev[1])
                elif k == "enable_start":
                    start_btn.config(state="normal")
                    stop_btn.config(state="disabled")
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
                elif k == "call":
                    on_call_event(ev[1], ev[2], ev[3])
                elif k == "queue":
                    qn = len(node.queue_info())
                    if qn > 1:
                        log(f"{qn} files in the send queue", "sys")
                elif k == "file":
                    log(("[+] file received: " if ev[3] else "[!] DAMAGED file: ") + ev[2],
                        "me" if ev[3] else "err")
                    sounds.play("file" if ev[3] else "error")
                    notify()
                elif k == "confirm":
                    ok = messagebox.askyesno(
                        "New peer",
                        "Unknown peer fingerprint:\n\n" + ev[1] +
                        "\n\nWords (easy to read aloud):\n" + fp_words(ev[1]) +
                        "\n\nCompare it over a DIFFERENT channel (phone, in person).\nAccept?")
                    pending["ok"] = ok
                    pending["ev"].set()
        except queue.Empty:
            pass
        root.after(80, poll)

    if args.closed and not node.known:
        log("Closed mode is on but the allowlist is empty - nobody can connect. Options > allowed fingerprints.", "err")
    if args.client_auth:
        log("Your onion client key (give it to the service owner): " + node.new_client_auth())
    log("Share your fingerprint over a trusted channel. Nothing is written to disk."
        if burner or node.amnesia else "Share your fingerprint over a trusted channel.")
    poll()
    idle_check()
    prune_check()
    root.mainloop()


# ---------------------------------------------------------------- CLI mode
def cli_main(args):
    import getpass

    pw = None
    if not args.burner:
        state = identity_state()
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
    secret = getpass.getpass("Shared secret: ") if args.psk else None

    answer = {"ev": None, "val": None}

    def confirm_cb(fp):
        answer["ev"], answer["val"] = threading.Event(), False
        print(f"\n[?] Unknown peer fingerprint:\n    {fp}\n    words: {fp_words(fp)}\n"
              "    Compare it over a DIFFERENT channel. Accept? (y/n)")
        answer["ev"].wait(180)
        return answer["val"]

    node = Node(confirm_cb, pw, args.amnesia, scrub=not args.no_scrub, burner=args.burner)
    print(BANNER)
    print("Your fingerprint:", node.my_fp)
    print("Your words:      ", fp_words(node.my_fp))
    if args.burner:
        print("(burner identity: random key, nothing saved)")

    try:
        apply_opts(node, args, secret)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if args.closed and not node.known:
        print("[!] Closed mode with an empty allowlist: nobody can connect. Use --allow FP or /allow FP.")
    if args.client_auth:
        print("Your onion client key (give it to the service owner):", node.new_client_auth())

    bridge_text = "\n".join(args.bridge)
    if args.bridge_file:
        with open(args.bridge_file, encoding="utf-8") as f:
            bridge_text += "\n" + f.read()
    if args.get_bridges:
        try:
            px = parse_proxy(args.proxy)
            print("[*] Asking the Tor Project for bridges...")
            data, challenge = moat_captcha("obfs4", px)
            path = os.path.join(tempfile.mkdtemp(prefix="mute_captcha_"), "captcha.jpg")
            with open(path, "wb") as fh:
                fh.write(data)
            print(f"[*] Open this captcha image and type what it shows:\n    {path}")
            answer_txt = input("Captcha> ")
            got = moat_solve(challenge, answer_txt, "obfs4", px)
            print(f"[*] Got {len(got)} bridge(s)")
            bridge_text += "\n" + "\n".join(got)
            try:
                os.remove(path)
            except OSError:
                pass
        except (MoatError, ValueError, EOFError) as e:
            print(f"Error: {e}")
            return
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
            elif k == "relayed":
                if ev[2] != node.my_fp:
                    print(f"{node.label(ev[2]) if ev[2] else '?'} (via {node.label(ev[1])})> {ev[3]}")
            elif k == "connected":
                print(f"[+] {node.label(ev[1])} connected securely")
            elif k == "disconnected":
                print(f"[-] {node.label(ev[1])} disconnected")
            elif k == "file":
                print(("[+] File received: " if ev[3] else "[!] DAMAGED file: ") + ev[2])
            elif k == "call":
                who = node.label(ev[2]) if ev[2] else "?"
                st = ev[1]
                if st == "incoming":
                    print(f"[*] INCOMING CALL from {who} - type /accept or /reject")
                elif st == "ringing":
                    print(f"[*] calling {who}...")
                elif st == "active":
                    print(f"[*] call with {who} started ({ev[3]}) - /mute to mute, /hangup to end")
                elif st == "remote-mute":
                    print(f"[*] {who} {'muted' if ev[3] else 'unmuted'}")
                elif st == "error":
                    print(f"[!] call error: {ev[3]}")
                else:
                    print(f"[*] call: {st} ({who})")
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
            host, port = split_hostport(c)
            node.connect(host, port, args.fp)
    except Exception as e:
        print(f"Error: {e}")
        node.shutdown()
        return

    if node.shape:
        print("[*] Constant-rate traffic:", shape_estimate(node.shape, args.tor))
    print("Commands: /send <file|folder>  /connect <host[:port]> [fp]  /peers  /name <id> <name>  /fp  /words\n"
          "          /allow <fp>  /relay on|off  /cover on|off|chat|browse|stream  /shape <frames/s|off>  /limit <KB/s|off>\n          /queue  /pause  /resume  /cancel [id|all]\n          /call [peer]  /accept  /reject  /hangup  /mute  /quit\n"
          "          (other text goes to everyone)")
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
            elif line == "/words":
                print(fp_words(node.my_fp))
            elif line.startswith("/allow "):
                try:
                    print("[*] trusted:", node.allow(line[7:]))
                except ValueError:
                    print("[!] That is not a valid fingerprint (32 hex characters)")
            elif line.startswith("/relay ") or line.startswith("/cover "):
                cmd, _, val = line.partition(" ")
                val = val.strip().lower()
                on = val in ("on", "1", "yes") or val in COVER_PROFILES
                if cmd == "/relay":
                    node.relay = on
                    print(f"[*] relay {'on' if on else 'off'}")
                else:
                    node.set_cover(on, val if val in COVER_PROFILES else None)
                    print("[*] cover traffic: " + (f"{node.cover_profile} - {cover_estimate(node.cover_profile)}" if on else "off"))
            elif line.startswith("/shape "):
                val = line[7:].strip().lower()
                try:
                    rate = 0.0 if val in ("off", "0", "no") else float(val)
                    if rate < 0 or rate > 200:
                        raise ValueError
                except ValueError:
                    print("[!] Usage: /shape <frames per second, e.g. 0.2 | 1 | 4>  or  /shape off")
                else:
                    node.set_shape(rate)
                    print("[*] constant-rate traffic:", shape_estimate(rate, node.transport == "tor"))
            elif line.startswith("/connect "):
                parts = line.split()
                try:
                    host, port = split_hostport(parts[1])
                    node.connect(host, port, " ".join(parts[2:]) or None)
                except (ValueError, IndexError) as e:
                    print(f"[!] {e}")
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
            elif line.startswith("/call"):
                arg = line[5:].strip()
                fp = node.find_peer(arg) if arg else (next(iter(node.chans)) if len(node.chans) == 1 else None)
                if not fp:
                    print("[!] Usage: /call <id-or-name>   (see /peers; with a single peer no argument is needed)")
                else:
                    try:
                        node.calls.call(fp)
                    except Exception as e:
                        print(f"[!] {e}")
            elif line == "/accept":
                try:
                    node.calls.accept()
                except Exception as e:
                    print(f"[!] {e}")
            elif line == "/reject":
                node.calls.reject()
            elif line == "/hangup":
                node.calls.hangup()
            elif line == "/mute":
                node.calls.set_muted(not node.calls.muted)
                print("[*] microphone " + ("muted" if node.calls.muted else "on"))
            elif line == "/pause":
                node.pause_transfers()
            elif line == "/resume":
                node.resume_transfers()
            elif line.startswith("/cancel"):
                arg = line[7:].strip()
                n = node.cancel_transfer("all" if arg == "all" else int(arg) if arg.isdigit() else None)
                print(f"[*] cancelled {n} transfer(s)")
            elif line == "/queue":
                q = node.queue_info()
                print("\n".join(f"  #{i} {n} [{st}]" for i, n, st in q) or "(queue is empty)")
            elif line.startswith("/limit "):
                v = line[7:].strip()
                try:
                    node.set_speed_limit(0 if v == "off" else int(float(v) * 1024))
                    print("[*] speed limit:", "off" if not node.speed_limit else f"{node.speed_limit // 1024} KB/s per peer")
                except ValueError:
                    print("[!] Usage: /limit <KB/s>  or  /limit off")
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


def entry(argv=None):
    """Console entry point: terminal mode if any terminal flag is given, otherwise the GUI."""
    args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
    if args.cli or args.listen or args.tor or args.connect:
        cli_main(args)
    else:
        main(args)


if __name__ == "__main__":
    entry()
