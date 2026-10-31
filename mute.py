#!/usr/bin/env python3
"""
Mute - szerver nélküli, végpontok közötti titkosított chat + fájl/mappa küldés.

Hálózati módok:
  DIRECT : közvetlen TCP (LAN / port forward / VPN-es IP)
  TOR    : Tor onion service - NAT-on át működik, az IP-címek rejtve maradnak

Titkosítás:
  * Ed25519 identitás (opcionálisan jelszóval védve: scrypt + ChaCha20-Poly1305)
  * X25519 ideiglenes kulcscsere (forward secrecy), aláírt handshake
  * ChaCha20-Poly1305 csatorna, számláló nonce, 1 KB-os paddinggel (üzenethossz elrejtése)
  * Nincs naplózás, az üzenetek csak memóriában élnek
"""
import hashlib
import json
import os
import queue
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)

APP_DIR = os.path.join(os.path.expanduser("~"), ".mute")
DOWNLOAD_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "Mute")
DEFAULT_PORT = 5555
MAGIC = b"SP2P\x02\x00"
ENC_MAGIC = b"SP2PENC1"
CHUNK = 256 * 1024
PAD = 1024
MAX_FRAME = CHUNK + 8192

T_MSG, T_FILE_START, T_FILE_CHUNK, T_FILE_END, T_FILE_OFFSET = 1, 2, 3, 4, 5

_BAD = '<>:"/\\|?*'
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name):
    """Windows és Linux között is biztonságos fájlnév."""
    name = os.path.basename(name.replace("\\", "/"))
    name = "".join("_" if (c in _BAD or ord(c) < 32) else c for c in name)
    name = name.strip(" .")
    if not name:
        return "fajl"
    stem, ext = os.path.splitext(name)
    if stem.upper() in _RESERVED:
        stem = "_" + stem
    if len(stem) + len(ext) > 150:
        stem = stem[:150 - len(ext)]
    return stem + ext


def file_id(path, name, size):
    """Azonosító a folytatáshoz: név + méret + az első 1 MiB hash-e."""
    h = hashlib.sha256(f"{name}|{size}|".encode())
    with open(path, "rb") as f:
        h.update(f.read(1 << 20))
    return h.hexdigest()


# ---------------------------------------------------------------- segédek
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
            raise ConnectionError("A kapcsolat megszakadt")
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
        s.connect(("10.255.255.255", 1))
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


# ---------------------------------------------------------------- identitás
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
                raise ValueError("Hibás jelszó")
        else:
            raw = blob
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    if passphrase:
        salt, nonce = os.urandom(16), os.urandom(12)
        raw = ENC_MAGIC + salt + nonce + ChaCha20Poly1305(
            _kdf(passphrase, salt)).encrypt(nonce, raw, b"")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return key


# ---------------------------------------------------------------- handshake
def handshake(sock, ident, initiator):
    id_pub = raw_pub(ident.public_key())
    eph = X25519PrivateKey.generate()
    eph_pub = raw_pub(eph.public_key())
    L = len(MAGIC)

    if initiator:
        sock.sendall(MAGIC + id_pub + eph_pub)
        m = recv_exact(sock, L + 32 + 32 + 64)
        if m[:L] != MAGIC:
            raise ConnectionError("Ismeretlen protokoll")
        peer_id, peer_eph, sig_r = m[L:L + 32], m[L + 32:L + 64], m[L + 64:]
        transcript = MAGIC + id_pub + eph_pub + peer_id + peer_eph
        try:
            Ed25519PublicKey.from_public_bytes(peer_id).verify(sig_r, b"R" + transcript)
        except InvalidSignature:
            raise ConnectionError("Hibás aláírás a másik féltől")
        sock.sendall(ident.sign(b"I" + transcript))
    else:
        m = recv_exact(sock, L + 64)
        if m[:L] != MAGIC:
            raise ConnectionError("Ismeretlen protokoll")
        peer_id, peer_eph = m[L:L + 32], m[L + 32:]
        transcript = MAGIC + peer_id + peer_eph + id_pub + eph_pub
        sock.sendall(MAGIC + id_pub + eph_pub + ident.sign(b"R" + transcript))
        sig_i = recv_exact(sock, 64)
        try:
            Ed25519PublicKey.from_public_bytes(peer_id).verify(sig_i, b"I" + transcript)
        except InvalidSignature:
            raise ConnectionError("Hibás aláírás a másik féltől")

    shared = eph.exchange(X25519PublicKey.from_public_bytes(peer_eph))
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=hashlib.sha256(transcript).digest(),
               info=b"SP2P session keys v2").derive(shared)
    k_i2r, k_r2i = okm[:32], okm[32:]
    if initiator:
        return peer_id, ChaCha20Poly1305(k_i2r), ChaCha20Poly1305(k_r2i)
    return peer_id, ChaCha20Poly1305(k_r2i), ChaCha20Poly1305(k_i2r)


class Channel:
    def __init__(self, sock, aead_send, aead_recv):
        self.sock = sock
        self.aead_send, self.aead_recv = aead_send, aead_recv
        self.sn = self.rn = 0
        self.lock = threading.Lock()
        self.offset_q = queue.Queue()

    def send(self, typ, payload=b""):
        body = struct.pack(">BI", typ, len(payload)) + payload
        body += b"\0" * ((-len(body)) % PAD)  # hosszrejtés: 1 KB-os egységek
        with self.lock:
            nonce = self.sn.to_bytes(12, "big")
            self.sn += 1
            ct = self.aead_send.encrypt(nonce, body, None)
            self.sock.sendall(struct.pack(">I", len(ct)) + ct)

    def recv(self):
        (n,) = struct.unpack(">I", recv_exact(self.sock, 4))
        if n > MAX_FRAME or n < 16 + 5:
            raise ConnectionError("Érvénytelen keret")
        ct = recv_exact(self.sock, n)
        nonce = self.rn.to_bytes(12, "big")
        self.rn += 1
        pt = self.aead_recv.decrypt(nonce, ct, None)
        typ, ln = struct.unpack(">BI", pt[:5])
        if 5 + ln > len(pt):
            raise ConnectionError("Érvénytelen hossz")
        return typ, pt[5:5 + ln]


# ---------------------------------------------------------------- Tor
def find_tor():
    names = ["tor.exe", "tor"] if os.name == "nt" else ["tor"]
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(
        sys.executable if getattr(sys, "frozen", False) else __file__))
    cands = []
    for n in names:
        cands += [os.path.join(base, "tor", n), os.path.join(base, n)]
        w = shutil.which(n)
        if w:
            cands.append(w)
    home = os.path.expanduser("~")
    cands += [
        os.path.join(home, "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
        r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
        os.path.join(home, ".local", "share", "torbrowser", "tbb", "x86_64",
                     "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
    ]
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None


# ---------------------------------------------------------------- csomópont
class Node:
    """GUI-független mag."""

    def __init__(self, confirm_cb=None, passphrase=None, amnesia=False, app_dir=None):
        self.app_dir = app_dir or APP_DIR
        self.ident = load_identity(self.app_dir, passphrase)
        self.my_fp = fingerprint(raw_pub(self.ident.public_key()))
        self.events = queue.Queue()
        self.confirm_cb = confirm_cb
        self.amnesia = amnesia
        self.chans = {}  # fp -> Channel
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

    # -- Tor indítása + onion service
    def start_tor(self, local_port):
        import stem.control
        import stem.process
        tor_cmd = find_tor()
        if not tor_cmd:
            raise RuntimeError(
                "A tor nem található. Tedd a tor(.exe)-t az app mellé a 'tor' mappába, "
                "telepítsd (apt install tor), vagy használd a Tor Browser-t.")
        self.emit("sys", "Tor indítása (ez eltarthat fél percig)…")
        self.tor_dir = tempfile.mkdtemp(prefix="mute_tor_")
        self.socks_port, ctrl = free_port(), free_port()

        def handler(line):
            if "Bootstrapped" in line:
                self.emit("sys", line.split("]")[-1].strip())

        self.tor_proc = stem.process.launch_tor_with_config(
            tor_cmd=tor_cmd,
            config={"SocksPort": str(self.socks_port), "ControlPort": str(ctrl),
                    "DataDirectory": self.tor_dir, "Log": "NOTICE stdout"},
            init_msg_handler=handler, timeout=180, take_ownership=True)
        self.controller = stem.control.Controller.from_port(port=ctrl)
        self.controller.authenticate()
        svc = self.controller.create_ephemeral_hidden_service(
            {DEFAULT_PORT: local_port}, await_publication=True,
            key_type="NEW", key_content="ED25519-V3")
        self.onion = svc.service_id + ".onion"
        self.transport = "tor"
        self.emit("sys", f"Onion címed: {self.onion}")

    # -- hallgatás / csatlakozás
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
        self.emit("sys", f"Hallgatózás: {port}")
        threading.Thread(target=self._accept_loop, args=(s,), daemon=True).start()

    def _accept_loop(self, s):
        while True:
            try:
                c, addr = s.accept()
            except OSError:
                return
            if self.transport != "tor":
                self.emit("sys", f"Bejövő kapcsolat: {addr[0]}")
            else:
                self.emit("sys", "Bejövő kapcsolat (Tor)")
            threading.Thread(target=self._session, args=(c, False, None),
                             daemon=True).start()

    def connect(self, host, port, expected_fp=None):
        def run():
            try:
                self.emit("sys", f"Csatlakozás: {host}:{port}…")
                if self.transport == "tor":
                    import socks
                    c = socks.create_connection(
                        (host, port), timeout=90, proxy_type=socks.SOCKS5,
                        proxy_addr="127.0.0.1", proxy_port=self.socks_port,
                        proxy_rdns=True)
                else:
                    c = socket.create_connection((host, port), timeout=10)
            except Exception as e:
                self.emit("sys", f"Nem sikerült csatlakozni: {e}")
                return
            self._session(c, True, expected_fp)
        threading.Thread(target=run, daemon=True).start()

    # -- munkamenet
    def _session(self, sock, initiator, expected_fp):
        try:
            sock.settimeout(90 if self.transport == "tor" else 15)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            peer_pub, a_send, a_recv = handshake(sock, self.ident, initiator)
            fp = fingerprint(peer_pub)
            if expected_fp and fp.replace(" ", "") != expected_fp.replace(" ", "").lower():
                raise ConnectionError(f"Az ujjlenyomat NEM egyezik! Kapott: {fp}")
            if fp == self.my_fp:
                raise ConnectionError("Önmagadhoz csatlakoztál")
            if fp not in self.known:
                ok = self.confirm_cb(fp) if self.confirm_cb else False
                if not ok:
                    raise ConnectionError("A partnert nem fogadtad el")
                self.known.add(fp)
                self._save_known()
            with self.state_lock:
                if fp in self.chans:
                    raise ConnectionError("Ezzel a partnerrel már van kapcsolat")
                sock.settimeout(None)
                chan = Channel(sock, a_send, a_recv)
                self.chans[fp] = chan
        except Exception as e:
            self.emit("sys", f"Kapcsolat sikertelen: {e}")
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
                        raise ConnectionError("Túl sok fájladat")
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
                    raise ConnectionError("Váratlan keret")
        except Exception as e:
            if fobj:
                fobj.close()
            self.emit("sys", f"{short(fp)} kapcsolat vége: {e}")
        finally:
            with self.state_lock:
                if self.chans.get(fp) is chan:
                    del self.chans[fp]
            try:
                chan.sock.close()
            except OSError:
                pass
            self.emit("disconnected", fp)

    # -- küldés (minden csatlakoztatott partnernek)
    def send_text(self, text):
        chans = list(self.chans.items())
        if not chans:
            raise ConnectionError("Nincs kapcsolat")
        for fp, ch in chans:
            try:
                ch.send(T_MSG, text.encode("utf-8"))
            except OSError as e:
                self.emit("sys", f"{short(fp)}: küldési hiba: {e}")

    def send_file(self, path):
        targets = list(self.chans.items())
        if not targets:
            raise ConnectionError("Nincs kapcsolat")

        def run():
            tmp = None
            with self.send_lock:
                try:
                    p = path
                    if os.path.isdir(path):
                        self.emit("sys", "Mappa tömörítése…")
                        tmp = tempfile.mkdtemp(prefix="mute_zip_")
                        nm = os.path.basename(path.rstrip("/\\")) or "mappa"
                        p = shutil.make_archive(os.path.join(tmp, nm), "zip", path)
                    size, name = os.path.getsize(p), os.path.basename(p)
                    hdr = json.dumps({"name": name, "size": size,
                                      "fid": file_id(p, name, size)}).encode()
                    multi = len(targets) > 1

                    def to_peer(fp, ch):
                        # Minden partnernek külön szál: mindenki a saját
                        # folytatási pontjától kapja a fájlt.
                        try:
                            while not ch.offset_q.empty():
                                ch.offset_q.get_nowait()
                            ch.send(T_FILE_START, hdr)
                            offset = ch.offset_q.get(timeout=120)
                            if not 0 <= offset <= size:
                                raise ConnectionError("Érvénytelen folytatási pont")
                            if offset:
                                self.emit("sys", f"{short(fp)}: folytatás innen: {human(offset)}")
                            sent, last, t0 = offset, 0, time.time()
                            label = f"TX {short(fp)} {name}" if multi else f"TX {name}"
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
                            self.emit("sys", f"Elküldve {short(fp)}-nek: {name} ({human(size)})")
                        except Exception as e:
                            self.emit("sys", f"{short(fp)}: küldés megszakadt ({e}); "
                                             "újraküldésnél folytatódik")

                    ths = [threading.Thread(target=to_peer, args=t, daemon=True)
                           for t in targets]
                    for t in ths:
                        t.start()
                    for t in ths:
                        t.join()
                except Exception as e:
                    self.emit("sys", f"Fájlküldési hiba: {e}")
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


# ---------------------------------------------------------------- GUI (hacker stílus)
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
    FONT = ("Consolas" if os.name == "nt" else "DejaVu Sans Mono", 10)

    root = tk.Tk()
    root.title("Mute")
    root.configure(bg=BG)
    root.geometry("820x700")

    # --- identitás betöltése (jelszó)
    state = identity_state()
    passphrase = None
    if state == "encrypted":
        while True:
            passphrase = simpledialog.askstring("Feloldás", "Identitás jelszó:", show="*", parent=root)
            if passphrase is None:
                return
            try:
                load_identity(None, passphrase)
                break
            except ValueError:
                messagebox.showerror("Hiba", "Hibás jelszó")
    elif state == "missing":
        passphrase = simpledialog.askstring(
            "Új identitás", "Állíts be jelszót a kulcsodhoz (üres = jelszó nélkül):",
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
    f2.pack(fill="x", padx=8, pady=6)
    mode = tk.StringVar(value="direct")
    for i, (t, v) in enumerate((("DIRECT (IP:port)", "direct"), ("TOR (.onion, anonim)", "tor"))):
        tk.Radiobutton(f2, text=t, variable=mode, value=v, bg=BG, fg=FG, selectcolor="#001a00",
                       activebackground=BG, activeforeground=FG, font=FONT).grid(row=0, column=i, padx=4)
    mk_label(f2, "port:", DIM).grid(row=0, column=2)
    port_var = tk.StringVar(value=str(DEFAULT_PORT))
    mk_entry(f2, port_var, 6).grid(row=0, column=3, padx=4)
    start_btn = mk_btn(f2, "[ START ]", lambda: do_start())
    start_btn.grid(row=0, column=4, padx=6)
    amnesia = tk.BooleanVar(value=False)
    tk.Checkbutton(f2, text="amnesia (semmit se mentsen)", variable=amnesia, bg=BG, fg=DIM,
                   selectcolor="#001a00", activebackground=BG, activeforeground=FG,
                   font=FONT, command=lambda: setattr(node, "amnesia", amnesia.get())
                   ).grid(row=0, column=5, padx=6)

    f3 = tk.Frame(root, bg=BG)
    f3.pack(fill="x", padx=8)
    mk_label(f3, "PEER>", DIM).grid(row=0, column=0)
    host_var = tk.StringVar()
    mk_entry(f3, host_var, 40).grid(row=0, column=1, padx=4)
    rport_var = tk.StringVar(value=str(DEFAULT_PORT))
    mk_entry(f3, rport_var, 6).grid(row=0, column=2)
    mk_btn(f3, "[ CONNECT ]", lambda: do_connect()).grid(row=0, column=3, padx=6)
    mk_label(f3, "expect fp:", DIM).grid(row=1, column=0)
    exp_var = tk.StringVar()
    mk_entry(f3, exp_var, 40).grid(row=1, column=1, padx=4, pady=2, columnspan=2, sticky="w")

    status_var = tk.StringVar(value="offline")
    tk.Label(root, textvariable=status_var, bg=BG, fg=ACC, font=FONT, anchor="w").pack(fill="x", padx=8, pady=2)

    chat = tk.Text(root, bg="#030803", fg=FG, font=FONT, wrap="word", state="disabled",
                   relief="flat", highlightthickness=1, highlightbackground=DIM, height=16)
    chat.pack(fill="both", expand=True, padx=8, pady=4)
    chat.tag_config("me", foreground=FG)
    chat.tag_config("peer", foreground=ACC)
    chat.tag_config("sys", foreground=DIM)
    chat.tag_config("err", foreground=RED)

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

    def do_start():
        try:
            port = int(port_var.get())
        except ValueError:
            return messagebox.showerror("Hiba", "Érvénytelen port")
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
            except Exception as e:
                node.emit("sys", f"Hiba: {e}")
                node.emit("enable_start")
        threading.Thread(target=run, daemon=True).start()

    def do_connect():
        try:
            node.connect(host_var.get().strip(), int(rport_var.get()), exp_var.get().strip() or None)
        except ValueError:
            messagebox.showerror("Hiba", "Érvénytelen port")

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
                    log(f"{short(ev[1])}> {ev[2]}", "peer")
                elif k == "connected":
                    log(f"[+] {short(ev[1])} biztonságosan csatlakozott", "me")
                    status_var.set(f"online · {len(node.chans)} partner")
                elif k == "disconnected":
                    status_var.set(f"online · {len(node.chans)} partner" if node.chans else "offline")
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
                    log(("[+] fájl megérkezett: " if ev[3] else "[!] SÉRÜLT fájl: ") + ev[2],
                        "me" if ev[3] else "err")
                elif k == "confirm":
                    ok = messagebox.askyesno(
                        "Új partner",
                        "Ismeretlen partner ujjlenyomata:\n\n" + ev[1] +
                        "\n\nHasonlítsd össze egy MÁSIK csatornán (telefon, személyesen).\nElfogadod?")
                    pending["ok"] = ok
                    pending["ev"].set()
        except queue.Empty:
            pass
        root.after(80, poll)

    log("Add át az ujjlenyomatodat egy megbízható csatornán. Semmi nem kerül lemezre.")
    poll()
    root.mainloop()


# ---------------------------------------------------------------- CLI mód
def cli_main(argv):
    import argparse
    import getpass

    ap = argparse.ArgumentParser(prog="mute", description="Mute – terminál mód")
    ap.add_argument("--cli", action="store_true", help="terminál mód (GUI nélkül)")
    ap.add_argument("--listen", action="store_true", help="várakozás bejövő kapcsolatra")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--tor", action="store_true", help="Tor onion service / Toron át csatlakozás")
    ap.add_argument("--connect", action="append", default=[], metavar="HOST[:PORT]",
                    help="csatlakozás partnerhez (többször is megadható)")
    ap.add_argument("--fp", help="elvárt partner-ujjlenyomat (a --connect-hez)")
    ap.add_argument("--amnesia", action="store_true", help="semmit ne mentsen")
    args = ap.parse_args(argv)

    state = identity_state()
    pw = None
    if state == "encrypted":
        while True:
            pw = getpass.getpass("Identitás jelszó: ")
            try:
                load_identity(None, pw)
                break
            except ValueError:
                print("Hibás jelszó")
    elif state == "missing":
        pw = getpass.getpass("Új identitás jelszava (üres = nincs): ") or None

    answer = {"ev": None, "val": None}

    def confirm_cb(fp):
        answer["ev"], answer["val"] = threading.Event(), False
        print(f"\n[?] Ismeretlen partner ujjlenyomata:\n    {fp}\n"
              "    Hasonlítsd össze egy MÁSIK csatornán. Elfogadod? (i/n)")
        answer["ev"].wait(180)
        return answer["val"]

    node = Node(confirm_cb, pw, args.amnesia)
    print(BANNER)
    print("Ujjlenyomatod:", node.my_fp)

    def printer():
        while True:
            ev = node.events.get()
            k = ev[0]
            if k == "sys":
                print(f"[*] {ev[1]}")
            elif k == "msg":
                print(f"{short(ev[1])}> {ev[2]}")
            elif k == "connected":
                print(f"[+] {short(ev[1])} biztonságosan csatlakozott")
            elif k == "disconnected":
                print(f"[-] {short(ev[1])} lecsatlakozott")
            elif k == "file":
                print(("[+] Fájl megérkezett: " if ev[3] else "[!] SÉRÜLT fájl: ") + ev[2])
            elif k == "progress" and ev[2] == ev[3] and ev[3]:
                pass
    threading.Thread(target=printer, daemon=True).start()

    try:
        if args.tor:
            lp = free_port()
            node.start_tor(lp)
            node.listen(lp, local_only=True)
            print(f"Onion címed: {node.onion}:{DEFAULT_PORT}")
        elif args.listen:
            node.listen(args.port)
            print("IP címeid:", ", ".join(local_ips()) or "?", f"(port {args.port})")
        for c in args.connect:
            host, _, prt = c.rpartition(":") if c.count(":") == 1 else (c, "", "")
            node.connect(host or c, int(prt) if prt else DEFAULT_PORT, args.fp)
    except Exception as e:
        print(f"Hiba: {e}")
        node.shutdown()
        return

    print("Parancsok: /send <fájl|mappa>  /peers  /fp  /quit   (egyéb szöveg = üzenet mindenkinek)")
    try:
        for line in sys.stdin:
            line = line.rstrip("\n")
            if answer["ev"] and not answer["ev"].is_set():
                answer["val"] = line.strip().lower() in ("i", "igen", "y", "yes")
                answer["ev"].set()
            elif line in ("/quit", "/q"):
                break
            elif line == "/fp":
                print(node.my_fp)
            elif line == "/peers":
                print(", ".join(short(f) for f in node.chans) or "(nincs)")
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
