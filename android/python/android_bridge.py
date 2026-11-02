"""Headless bridge between the Android app (Kotlin, via Chaquopy) and mute.Node.

mute.py itself is used unchanged: this module only
  * points its storage directories at the app's private storage,
  * tells it where Android keeps the bundled tor / pluggable transport executables,
  * turns the Node's event queue into JSON the Kotlin side can read,
  * replaces the GUI confirmation dialog with a blocking call answered from the UI.

All methods are safe to call from any thread, but start_tor() blocks for up to a minute,
so Kotlin must call it from a background thread.
"""
import json
import os
import threading

import mute

CONFIRM_TIMEOUT = 180  # seconds the user has to compare a new peer's fingerprint


def identity_state(app_dir):
    """'missing' | 'plain' | 'encrypted' - lets the UI ask for a passphrase before starting."""
    return mute.identity_state(app_dir)


def check_passphrase(app_dir, passphrase):
    """True if the passphrase opens the stored identity key (or none is needed)."""
    try:
        mute.load_identity(app_dir, passphrase or None)
        return True
    except (ValueError, mute.NeedPassphrase):
        return False


def _patch_tor_lookup(tor_cmd, pt_dir):
    """Android cannot search PATH for tor: the binaries live in the app's native library dir."""
    if tor_cmd:
        mute.find_tor = lambda: tor_cmd if os.path.isfile(tor_cmd) else None
    if pt_dir:
        def find_pt(binary_names, _tor_cmd=None):
            for n in binary_names:
                for cand in (n, "lib" + n + ".so"):
                    p = os.path.join(pt_dir, cand)
                    if os.path.isfile(p):
                        return p
            return None
        mute.find_pt = find_pt


class Bridge:
    def __init__(self, app_dir, download_dir, tor_cmd=None, pt_dir=None,
                 passphrase=None, burner=False, scrub=True):
        os.makedirs(app_dir, exist_ok=True)
        os.makedirs(download_dir, exist_ok=True)
        mute.APP_DIR = app_dir
        mute.DOWNLOAD_DIR = download_dir
        _patch_tor_lookup(tor_cmd, pt_dir)
        self._confirm_lock = threading.Lock()
        self._pending = {}  # fp -> {"ev": Event, "ok": bool}
        self.node = mute.Node(self._confirm_cb, passphrase or None, amnesia=False,
                              app_dir=app_dir, scrub=scrub, burner=burner)
        self.node.emit("sys", "Fingerprint " + self.node.my_fp)

    # ---- identity / state
    def state(self):
        n = self.node
        return json.dumps({
            "fp": n.my_fp,
            "words": mute.fp_words(n.my_fp),
            "ips": mute.local_ips(),
            "transport": n.transport,
            "onion": (n.onion + ":%d" % mute.DEFAULT_PORT) if n.onion else None,
            "listening": n.server is not None,
            "burner": n.burner,
            "peers": [{"fp": fp, "name": n.label(fp), "id": mute.short(fp)} for fp in n.chans],
        })

    # ---- fingerprint confirmation (blocks the handshake thread, not the UI)
    def _confirm_cb(self, fp):
        slot = {"ev": threading.Event(), "ok": False}
        with self._confirm_lock:
            self._pending[fp] = slot
        self.node.emit("confirm", fp)
        slot["ev"].wait(CONFIRM_TIMEOUT)
        with self._confirm_lock:
            self._pending.pop(fp, None)
        return slot["ok"]

    def answer_confirm(self, fp, accept):
        with self._confirm_lock:
            slot = self._pending.get(fp)
        if slot:
            slot["ok"] = bool(accept)
            slot["ev"].set()

    # ---- network
    def start_direct(self, port=mute.DEFAULT_PORT):
        self.node.listen(int(port))
        return self.state()

    def start_tor(self, bridges_text=""):
        """Starts Tor, publishes an onion service and listens on loopback. Slow: run off the UI thread."""
        if bridges_text and bridges_text.strip():
            self.node.set_bridges(bridges_text)
        lp = mute.free_port()
        self.node.start_tor(lp)
        self.node.listen(lp, local_only=True)
        return self.state()

    def connect(self, address, expected_fp=None):
        host, port = mute.split_hostport(address)
        self.node.connect(host, port, (expected_fp or "").strip() or None)

    def set_closed(self, on):
        self.node.closed = bool(on)

    def allow(self, fp_text):
        return self.node.allow(fp_text)

    def set_psk(self, secret):
        self.node.set_psk(secret or "")

    # ---- chat / files
    def send_text(self, text):
        self.node.send_text(text)

    def send_file(self, path):
        self.node.send_file(path)

    def name_peer(self, fp, name):
        self.node.names[fp] = name.strip()[:24]

    def pause_transfers(self):
        self.node.pause_transfers()

    def resume_transfers(self):
        self.node.resume_transfers()

    def cancel_transfers(self):
        return self.node.cancel_transfer("all")

    # ---- events -> JSON for Kotlin
    def poll(self, timeout_ms=500):
        """Blocks up to timeout_ms for the next event, then returns every queued event as a JSON array."""
        out = []
        try:
            ev = self.node.events.get(timeout=timeout_ms / 1000.0)
        except Exception:
            return "[]"
        while ev is not None:
            conv = self._convert(ev)
            if conv:
                out.append(conv)
            try:
                ev = self.node.events.get_nowait()
            except Exception:
                ev = None
        return json.dumps(out, default=str)

    def _convert(self, ev):
        k, a = ev[0], ev[1:]
        n = self.node
        if k == "sys":
            return {"k": "sys", "text": a[0]}
        if k == "msg":
            return {"k": "msg", "fp": a[0], "name": n.label(a[0]), "text": a[1]}
        if k == "relayed":
            via, origin, text = a[0], a[1], a[2]
            if origin == n.my_fp:
                return None
            return {"k": "relayed", "via": n.label(via), "fp": origin or "",
                    "name": n.label(origin) if origin else "?", "text": text}
        if k in ("connected", "disconnected"):
            return {"k": k, "fp": a[0], "name": n.label(a[0])}
        if k == "file":
            return {"k": "file", "fp": a[0], "path": a[1], "ok": bool(a[2])}
        if k == "progress":
            return {"k": "progress", "label": a[0], "done": a[1], "total": a[2],
                    "speed": a[3] if len(a) > 3 else 0}
        if k == "queue":
            return {"k": "queue", "items": [list(i) for i in n.queue_info()]}
        if k == "confirm":
            return {"k": "confirm", "fp": a[0], "words": mute.fp_words(a[0])}
        return None

    def shutdown(self):
        # unblock any pending fingerprint prompt so its handshake thread can end
        with self._confirm_lock:
            for slot in self._pending.values():
                slot["ev"].set()
        self.node.shutdown()
