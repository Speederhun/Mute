"""Network + crypto tests over loopback. Run: python tests/test_loopback.py
Works on Linux, macOS and Windows (used by the CI matrix)."""
import hashlib
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m

TMP = tempfile.mkdtemp(prefix="mute_test_")
m.DOWNLOAD_DIR = os.path.join(TMP, "dl")


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


def mk(name, **kw):
    kw.setdefault("amnesia", True)
    return m.Node(lambda fp: True, app_dir=os.path.join(TMP, name), **kw)


def wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def events(node, kind):
    return [e for e in list(node.events.queue) if e[0] == kind]


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---- basic connection, messages, names
A, B = mk("a"), mk("b")
port = m.free_port()
A.listen(port)
B.connect("127.0.0.1", port)
ok(wait(lambda: A.chans and B.chans), "two nodes connect (Noise XX)")
A.send_text("hello árvíztűrő")
ok(wait(lambda: events(B, "msg")), "message delivered")
ok(events(B, "msg")[0][2] == "hello árvíztűrő", "message text intact (unicode)")
fpb = next(iter(A.chans))
ok(A.label(fpb) == m.short(fpb), "unnamed peer shows its short ID")
A.names[fpb] = "Bea"
ok(A.label(fpb) == "Bea" and A.find_peer("bea") == fpb and A.find_peer(m.short(fpb)[:4]) == fpb, "nicknames work")

# ---- fingerprint helpers
fp = A.my_fp
ok(m.normalize_fp(fp.upper().replace(" ", "-")) == fp, "normalize_fp accepts any spacing/case")
w = m.fp_words(fp)
ok(len(w.split()) == 6 and w == m.fp_words(fp) and w != m.fp_words(B.my_fp), "fp_words deterministic and distinct")

# ---- address cleanup
onion = "trzqozoye4bwb2rtf7bq4b52elqrcacr73u5jub4zhtqytb2u2brx5ad"
ok(m.clean_host(onion) == onion + ".onion", "bare 56-char onion name gets .onion appended")
ok(m.clean_host("  HTTP://" + onion.upper() + ".onion/ ") == onion + ".onion", "scheme, case, slashes and spaces are cleaned")
ok(m.clean_host("192.168.1.5") == "192.168.1.5" and m.clean_host("example.org") == "example.org", "normal hosts are left alone")

# ---- wrong expected fingerprint is rejected
C = mk("c")
C.connect("127.0.0.1", port, "0000 0000 0000 0000 0000 0000 0000 0000")
ok(wait(lambda: any("does NOT match" in e[1] for e in events(C, "sys"))) and not C.chans, "wrong expected fingerprint rejected")
A.shutdown(); B.shutdown(); C.shutdown()

# ---- pre-shared secret (XXpsk3)
S = mk("s"); S.set_psk("correct horse battery staple"); sp = m.free_port(); S.listen(sp)
good = mk("good"); good.set_psk("correct horse battery staple"); good.connect("127.0.0.1", sp)
ok(wait(lambda: S.chans and good.chans), "same shared secret connects")
bad = mk("bad"); bad.set_psk("wrong secret"); bad.connect("127.0.0.1", sp)
none = mk("none"); none.connect("127.0.0.1", sp)
time.sleep(2)
ok(not bad.chans and not none.chans and len(S.chans) == 1, "wrong / missing shared secret rejected")
for n in (S, good, bad, none):
    n.shutdown()

# ---- closed mode (allowlist)
Z = mk("z"); Z.closed = True; zp = m.free_port(); Z.listen(zp)
X = mk("x"); X.connect("127.0.0.1", zp)
ok(wait(lambda: any("allowlist" in e[1] for e in events(Z, "sys"))) and not Z.chans, "closed mode rejects unknown peer without prompting")
asked = []
Z.confirm_cb = lambda fp: asked.append(fp) or True
Z.allow(X.my_fp)
X2 = m.Node(lambda fp: True, app_dir=os.path.join(TMP, "x"), amnesia=True)
X2.ident = X.ident
X2.my_fp = X.my_fp
X2.connect("127.0.0.1", zp)
ok(wait(lambda: Z.chans) and not asked, "allowlisted peer connects, still no prompt")
try:
    Z.allow("not a fingerprint")
    ok(False, "invalid fingerprint rejected")
except ValueError:
    ok(True, "invalid fingerprint rejected")
for n in (Z, X, X2):
    n.shutdown()

# ---- burner identity: new key every time, nothing on disk
b1 = m.Node(None, app_dir=os.path.join(TMP, "burn"), burner=True)
b2 = m.Node(None, app_dir=os.path.join(TMP, "burn"), burner=True)
ok(b1.my_fp != b2.my_fp, "burner identities differ on every start")
ok(not os.path.exists(os.path.join(TMP, "burn")), "burner writes nothing to disk")

# ---- known peers are encrypted when a passphrase is set
kd = os.path.join(TMP, "kn")
K1 = m.Node(lambda fp: True, passphrase="pw-1", app_dir=kd)
kp = m.free_port(); K1.listen(kp)
K2 = mk("k2"); K2.connect("127.0.0.1", kp)
ok(wait(lambda: K1.chans), "persistent node accepts a new peer")
blob = open(os.path.join(kd, "known_peers.json"), "rb").read()
ok(blob.startswith(m.KNOWN_MAGIC) and K2.my_fp.replace(" ", "").encode() not in blob, "known_peers.json is encrypted")
K1.shutdown(); K2.shutdown()
K3 = m.Node(None, passphrase="pw-1", app_dir=kd)
ok(K2.my_fp in K3.known, "encrypted list loads with the right passphrase")
K4 = m.Node(None, passphrase="pw-1", app_dir=kd, amnesia=True)
ok(m.Node.__init__ is not None and K4.known == set(), "amnesia mode loads nothing")

# ---- relay (hub) + cover frames
H, P, Q = mk("h"), mk("p"), mk("q")
hp = m.free_port(); H.listen(hp); H.relay = True
P.connect("127.0.0.1", hp); Q.connect("127.0.0.1", hp)
ok(wait(lambda: len(H.chans) == 2), "hub has two peers")
P.send_text("from P via hub")
ok(wait(lambda: events(Q, "relayed")), "peer behind the hub receives the relayed message")
ev = events(Q, "relayed")[0]
ok(ev[2] == P.my_fp and ev[3] == "from P via hub", "relayed message carries the real origin key")
P.chans[next(iter(P.chans))].send(m.T_COVER, os.urandom(300))
Q.send_text("still alive")
ok(wait(lambda: any(e[2] == "still alive" for e in events(H, "msg"))), "cover frames are ignored, connection keeps working")
P.set_cover(True); ok(P._cover_thread.is_alive(), "cover-traffic thread runs"); P.set_cover(False)
for n in (H, P, Q):
    n.shutdown()

# ---- onion client-auth key formats
pub = A.new_client_auth()
ok(len(pub) == 52 and pub.isalnum() and pub == pub.upper(), "client-auth public key is 52 base32 chars")
A.set_allowed_clients(pub + "\n# comment\n")
ok(A.allowed_clients == [pub], "allowed onion clients parsed")
try:
    A.set_allowed_clients("short")
    ok(False, "bad onion client key rejected")
except ValueError:
    ok(True, "bad onion client key rejected")

# ---- file transfer + resume
F, G = mk("f"), mk("g")
fport = m.free_port(); F.listen(fport); G.connect("127.0.0.1", fport)
ok(wait(lambda: F.chans and G.chans), "file transfer peers connected")
small = os.path.join(TMP, "small:name?.bin")
open(small, "wb").write(os.urandom(3 << 20))
F.send_file(small)
ok(wait(lambda: os.path.isdir(m.DOWNLOAD_DIR) and any(f.endswith(".bin") for f in os.listdir(m.DOWNLOAD_DIR)), 30), "file received")
got = [f for f in os.listdir(m.DOWNLOAD_DIR) if f.endswith(".bin")][0]
ok(got == "small_name_.bin" and sha(os.path.join(m.DOWNLOAD_DIR, got)) == sha(small), "hash equal, file name sanitised")

big = os.path.join(TMP, "big.dat")
with open(big, "wb") as f:
    for _ in range(24):
        f.write(os.urandom(1 << 20))
while F.send_lock.locked():
    time.sleep(0.1)
F.send_file(big)


def part_size():
    pd = os.path.join(m.DOWNLOAD_DIR, ".partial")
    return max([os.path.getsize(os.path.join(pd, f)) for f in os.listdir(pd)] or [0]) if os.path.isdir(pd) else 0


ok(wait(lambda: part_size() > (6 << 20), 60) or os.path.exists(os.path.join(m.DOWNLOAD_DIR, "big.dat")), "transfer in progress")
if not os.path.exists(os.path.join(m.DOWNLOAD_DIR, "big.dat")):
    for ch in list(G.chans.values()):
        ch.sock.close()  # simulate a dropped connection
    wait(lambda: not F.chans and not G.chans, 10)
    while F.send_lock.locked():
        time.sleep(0.1)
    G.connect("127.0.0.1", fport)
    ok(wait(lambda: F.chans and G.chans, 10), "reconnected after interruption")
    F.send_file(big)
    ok(wait(lambda: os.path.exists(os.path.join(m.DOWNLOAD_DIR, "big.dat")), 90), "resumed transfer completes")
    ok(any("resuming" in e[1] for e in events(F, "sys")), "sender reports the resume offset")
ok(sha(os.path.join(m.DOWNLOAD_DIR, "big.dat")) == sha(big), "resumed file hash equal")
F.shutdown(); G.shutdown()

print("all loopback tests passed")
