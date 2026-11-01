"""Robustness tests: random/garbage input must never crash, hang or be accepted.
Run: python tests/test_fuzz.py   (deterministic seed)"""
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

rnd = random.Random(1337)
TMP = tempfile.mkdtemp(prefix="mute_fuzz_")


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


# ---- file scrubbers: never raise out of scrub_file, never hang
t0 = time.time()
PNG = b"\x89PNG\r\n\x1a\n"
for i in range(1500):
    kind = rnd.choice(["jpg", "png", "docx"])
    body = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 600)))
    if kind == "jpg":
        head = b"\xff\xd8" + bytes(rnd.choice([0xFF, 0xE1, 0xDA, 0xFE, 0xE0, 0x00, 0xD9]) for _ in range(rnd.randint(0, 40)))
        data = head + body
    elif kind == "png":
        data = PNG + body
    else:
        data = body
    src, dst = os.path.join(TMP, f"f.{kind}"), os.path.join(TMP, f"o.{kind}")
    with open(src, "wb") as f:
        f.write(data)
    if os.path.exists(dst):
        os.remove(dst)
    changed, note = m.scrub_file(src, dst)
    assert isinstance(changed, bool) and isinstance(note, str)
    if not changed:
        assert not os.path.exists(dst) or kind == "docx", "failed scrub left an output file"
ok(time.time() - t0 < 60, "scrubbers survive 1500 garbage files without crashing or hanging")

# ---- parsers
for _ in range(2000):
    txt = "".join(rnd.choice("abcXYZ0123 :.\n#_-[]") for _ in range(rnd.randint(0, 80)))
    try:
        m.parse_bridges(txt)
    except ValueError:
        pass
    try:
        m.normalize_fp(txt)
    except ValueError:
        pass
    n = m.safe_name("".join(chr(rnd.randint(0, 0x2FF)) for _ in range(rnd.randint(0, 40))) + rnd.choice(["", "/..", "\\x", ".", " "]))
    assert n and "/" not in n and "\\" not in n and n not in (".", ".."), repr(n)
ok(True, "parse_bridges / normalize_fp / safe_name never misbehave on random input")


# ---- handshake garbage in both roles
def run_hs(initiator, feed):
    a, b = socket.socketpair()
    a.settimeout(2)
    res = {}

    def worker():
        try:
            b.sendall(feed)
            time.sleep(0.1)
            b.close()
        except OSError:
            pass
    th = threading.Thread(target=worker, daemon=True)
    th.start()
    try:
        m.handshake(a, X25519PrivateKey.generate(), initiator)
        res["accepted"] = True
    except Exception:
        res["accepted"] = False
    a.close()
    th.join(1)
    return res["accepted"]


accepted = 0
for _ in range(120):
    feed = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
    if rnd.random() < 0.5:
        feed = struct.pack(">H", len(feed)) + feed
    accepted += run_hs(rnd.random() < 0.5, feed)
ok(accepted == 0, "garbage is never accepted as a handshake")

# ---- corrupted / replayed / reordered frames after a valid handshake
def pair():
    a, b = socket.socketpair()
    ia, ib = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    out = {}

    def resp():
        out["r"] = m.handshake(b, ib, False)
    th = threading.Thread(target=resp)
    th.start()
    ra = m.handshake(a, ia, True)
    th.join()
    return a, b, m.Channel(a, ra[1]), m.Channel(b, out["r"][1])


a, b, ca, cb = pair()
ca.send(m.T_MSG, b"first")
ok(cb.recv() == (m.T_MSG, b"first"), "valid frame decrypts")
# tamper: capture a frame, flip one bit, deliver
cap_a, cap_b = socket.socketpair()
ca.sock = cap_a
ca.send(m.T_MSG, b"second")
frame = bytearray(cap_b.recv(65536))
frame[10] ^= 1
a.sendall(bytes(frame))
try:
    cb.recv()
    ok(False, "tampered frame rejected")
except Exception:
    ok(True, "tampered frame rejected")

a, b, ca, cb = pair()
cap_a, cap_b = socket.socketpair()
ca.sock = cap_a
ca.send(m.T_MSG, b"one")
f1 = cap_b.recv(65536)
ca.send(m.T_MSG, b"two")
f2 = cap_b.recv(65536)
a.sendall(f2)  # out of order
try:
    cb.recv()
    ok(False, "reordered frame rejected")
except Exception:
    ok(True, "reordered frame rejected (nonce counter)")

a, b, ca, cb = pair()
cap_a, cap_b = socket.socketpair()
ca.sock = cap_a
ca.send(m.T_MSG, b"once")
f = cap_b.recv(65536)
a.sendall(f)
cb.recv()
a.sendall(f)  # replay
try:
    cb.recv()
    ok(False, "replayed frame rejected")
except Exception:
    ok(True, "replayed frame rejected")

# random garbage on an established channel
a, b, ca, cb = pair()
bad = 0
for _ in range(100):
    junk = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(21, 300)))
    b2, b3 = socket.socketpair()
    cb.sock = b2
    b3.sendall(struct.pack(">I", len(junk)) + junk)
    try:
        cb.recv()
        bad += 1
    except Exception:
        pass
    b2.close(); b3.close()
ok(bad == 0, "random frames are never accepted on an established channel")

# ---- malicious fragments on an established channel
def frag_attack(build):
    a, b, ca, cb = pair()

    def sender():
        try:
            for fr in build():
                ca._send_raw(*fr)
        except OSError:
            pass
    threading.Thread(target=sender, daemon=True).start()
    try:
        cb.sock.settimeout(8)
        for _ in range(5000):
            cb.recv()
        return False
    except ConnectionError:
        return True      # the channel itself rejected it (a timeout would NOT count)
    finally:
        a.close(); b.close()


H = m.FRAG_HDR
ok(frag_attack(lambda: [(m.T_FRAG, b"\x01")]), "too-short fragment header is rejected")
ok(frag_attack(lambda: [(m.T_FRAG, struct.pack(H, m.T_FRAG, 1, 1) + b"x")]), "fragment that claims to be a fragment is rejected")
ok(frag_attack(lambda: [(m.T_FRAG, struct.pack(H, m.T_MSG, 0, 7) + b"a" * m.FRAG_DATA)] * (m.MAX_ASSEMBLED // m.FRAG_DATA + 4)),
   "endless fragmented message is cut off at the size limit")
ok(frag_attack(lambda: [(m.T_FRAG, struct.pack(H, m.T_MSG, 0, i) + b"a") for i in range(80)]),
   "too many half-finished messages are rejected")
ok(frag_attack(lambda: [(m.T_FRAG, struct.pack(H, m.T_MSG, 0, 3) + b"a"), (m.T_FRAG, struct.pack(H, m.T_FILE_CHUNK, 1, 3) + b"b")]),
   "fragments that change type mid-message are rejected")

print("all fuzz tests passed")
