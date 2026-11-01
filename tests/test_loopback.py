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
while F.send_queue:
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
    while F.send_queue:
        time.sleep(0.1)
    G.connect("127.0.0.1", fport)
    ok(wait(lambda: F.chans and G.chans, 10), "reconnected after interruption")
    F.send_file(big)
    ok(wait(lambda: os.path.exists(os.path.join(m.DOWNLOAD_DIR, "big.dat")), 90), "resumed transfer completes")
    ok(any("resuming" in e[1] for e in events(F, "sys")), "sender reports the resume offset")
ok(sha(os.path.join(m.DOWNLOAD_DIR, "big.dat")) == sha(big), "resumed file hash equal")
F.shutdown(); G.shutdown()

# ---- constant-rate traffic (shaping)
import socket as _socket
import struct as _struct
import threading as _th
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _K


def chan_pair():
    a, b = _socket.socketpair()
    out = {}
    th = _th.Thread(target=lambda: out.update(r=m.handshake(b, _K.generate(), False)))
    th.start()
    ra = m.handshake(a, _K.generate(), True)
    th.join()
    return a, b, m.Channel(a, ra[1]), m.Channel(b, out["r"][1])


# wire view: all frames the same size, on a fixed clock, dummy frames in the silence
a, b, ca, cb = chan_pair()
ca.set_rate(50)
_th.Thread(target=lambda: (ca.send(m.T_MSG, b"hi"), ca.send(m.T_FILE_CHUNK, os.urandom(60000))), daemon=True).start()
b.settimeout(10)
sizes, times = [], []
t_end = time.monotonic() + 2.0
while time.monotonic() < t_end:
    (n,) = _struct.unpack(">I", m.recv_exact(b, 4))
    m.recv_exact(b, n)
    sizes.append(n)
    times.append(time.monotonic())
ca.close()
gaps = sorted(y - x for x, y in zip(times, times[1:]))
med = gaps[len(gaps) // 2]
ok(len(set(sizes)) == 1 and sizes[0] == 1024 + 16, "constant-rate: every frame has exactly the same size")
ok(0.008 < med < 0.045, f"constant-rate: frames on a fixed clock (median gap {med * 1000:.1f} ms for 50/s)")
ok(55 < len(sizes) < 140, f"constant-rate: about 50 frames per second ({len(sizes)} in 2 s)")
ok(m.shape_estimate(1.0).startswith("1.5 KB/s") and "GB per month" in m.shape_estimate(1.0), "traffic estimate is shown")

# reassembly: sizes around the fragment boundary, interleaved senders
a, b, ca, cb = chan_pair()
ca.set_rate(400)
got, errors = [], []
sizes_sent = [0, 1, m.FRAG_DATA - 1, m.FRAG_DATA, m.FRAG_DATA + 1, 5000, 60000, 3 * m.FRAG_DATA]
payloads = [os.urandom(n) for n in sizes_sent]


def rx():
    try:
        while len(got) < len(payloads) * 2:
            typ, data = cb.recv()
            if typ != m.T_COVER:
                got.append((typ, data))
    except Exception as e:
        errors.append(e)


r = _th.Thread(target=rx, daemon=True)
r.start()
t1 = _th.Thread(target=lambda: [ca.send(m.T_MSG, p) for p in payloads])
t2 = _th.Thread(target=lambda: [ca.send(m.T_FILE_CHUNK, p) for p in payloads])
t1.start(); t2.start(); t1.join(60); t2.join(60); r.join(60)
ok(not errors and len(got) == len(payloads) * 2, "fragments from two senders arrive and reassemble")
ok([d for t, d in got if t == m.T_MSG] == payloads and [d for t, d in got if t == m.T_FILE_CHUNK] == payloads,
   "interleaved messages are intact and in order per sender")
# switching off flushes what is queued
ca.send(m.T_MSG, b"last words")
ca.set_rate(0)
deadline = time.time() + 5
last = None
while time.time() < deadline and last is None:
    typ, data = cb.recv()
    if typ == m.T_MSG:
        last = data
ok(last == b"last words", "switching constant-rate off flushes queued data")
ca.send(m.T_MSG, b"plain again")
ok(cb.recv() == (m.T_MSG, b"plain again"), "normal sending works again after switching off")
ca.close(); cb.close()

# whole nodes: only one side shaped, then both
S1, S2 = mk("s1"), mk("s2")
sp1 = m.free_port(); S1.listen(sp1); S1.set_shape(100)
S2.connect("127.0.0.1", sp1)
ok(wait(lambda: S1.chans and S2.chans), "shaped and unshaped node connect")
S1.send_text("shaped hello"); S2.send_text("plain hello")
ok(wait(lambda: events(S2, "msg")) and wait(lambda: events(S1, "msg")), "chat works with one side constant-rate")
S2.set_shape(100)
fpath = os.path.join(TMP, "shaped.bin")
open(fpath, "wb").write(os.urandom(150_000))
while S1.send_queue:
    time.sleep(0.1)
S1.send_file(fpath)
S1.send_text("chat during transfer")
ok(wait(lambda: any(e[2] == "chat during transfer" for e in events(S2, "msg")), 30), "chat is not blocked behind a file transfer")
ok(wait(lambda: os.path.exists(os.path.join(m.DOWNLOAD_DIR, "shaped.bin")), 60), "file arrives over constant-rate traffic")
ok(sha(os.path.join(m.DOWNLOAD_DIR, "shaped.bin")) == sha(fpath), "file hash equal over constant-rate traffic")
S1.shutdown(); S2.shutdown()

# ---- fresh Diffie-Hellman key renewal (ratchet)
def rpair():
    a, b = _socket.socketpair()
    out = {}
    th = _th.Thread(target=lambda: out.update(r=m.handshake(b, _K.generate(), False)))
    th.start()
    ra = m.handshake(a, _K.generate(), True)
    th.join()
    return a, b, m.Channel(a, ra[1], True), m.Channel(b, out["r"][1], False)


def pump(ch, got):
    def run():
        try:
            while True:
                got.append(ch.recv())
        except Exception:
            pass
    _th.Thread(target=run, daemon=True).start()


def keys(ch):
    p = ch.noise.noise_protocol
    return p.cipher_state_encrypt.k, p.cipher_state_decrypt.k


for rate in (0, 80):
    ca, cb = None, None
    a, b, ca, cb = rpair()
    if rate:
        ca.set_rate(rate); cb.set_rate(rate)
    ga, gb = [], []
    pump(ca, ga); pump(cb, gb)
    ca.send(m.T_MSG, b"before"); 
    ok(wait(lambda: (m.T_MSG, b"before") in gb), f"message before renewal arrives (rate {rate})")
    old_a, old_b = keys(ca), keys(cb)
    stop = _th.Event()
    sent = []

    def spam(ch, tag):
        i = 0
        while not stop.is_set():
            try:
                ch.send(m.T_MSG, f"{tag}{i}".encode()); sent.append(f"{tag}{i}".encode()); i += 1
            except Exception:
                return
            time.sleep(0.003 if not rate else 0.02)
    _th.Thread(target=spam, args=(ca, "a"), daemon=True).start()
    _th.Thread(target=spam, args=(cb, "b"), daemon=True).start()
    for _ in range(3):
        time.sleep(0.3)
        ok(ca.ratchet_now(), f"renewal started (rate {rate})")
        ok(wait(lambda: ca._eph is None and cb._pend_rx is None, 15), f"renewal completes while both sides chat (rate {rate})")
    time.sleep(0.5)
    stop.set(); time.sleep(0.5 if not rate else 1.5)
    new_a, new_b = keys(ca), keys(cb)
    ok(new_a[0] != old_a[0] and new_a[1] != old_a[1] and new_b[0] != old_b[0], f"all four keys are new (rate {rate})")
    ok(new_a[0] == new_b[1] and new_a[1] == new_b[0], f"both sides agree on the new keys (rate {rate})")
    ok(ca._ratchets == 3 and cb._ratchets == 3, f"three renewals counted (rate {rate})")
    got = {x[1] for x in ga + gb if x[0] == m.T_MSG}
    mine = {x for x in sent}
    # nothing lost or garbled across the key switches (a few at the very end may still be in flight)
    ok(len(mine - got) <= 3 and not (got - mine - {b"before"}), f"no message lost or corrupted across renewals (rate {rate}); {len(mine)} sent")
    a.close(); b.close(); ca.dead.set(); cb.dead.set()

# misuse is rejected
a, b, ca, cb = rpair()
pump(cb, [])
res = []
th = _th.Thread(target=lambda: res.append(_try(lambda: ca.recv())))
def _try(f):
    try:
        f(); return False
    except ConnectionError:
        return True
# responder tries to start a renewal / DONE without INIT -> initiator side must refuse
cb2 = cb
cb2._send_raw(m.T_RATCH_DONE, bytes(32))
a.settimeout(5)
ok(_try(lambda: ca.recv()), "unexpected DONE is rejected")
a, b, ca, cb = rpair()
cb._send_raw(m.T_RATCH_INIT, os.urandom(32))
a.settimeout(5)
ok(_try(lambda: ca.recv()), "responder-started renewal is rejected")
a, b, ca, cb = rpair()
ca._send_raw(m.T_RATCH_INIT, bytes(32))      # all-zero point: low order, must not be accepted
b.settimeout(5)
ok(_try(lambda: cb.recv()), "low-order public key in renewal is rejected")
a, b, ca, cb = rpair()
ca._send_raw(m.T_RATCH_INIT, b"short")
b.settimeout(5)
ok(_try(lambda: cb.recv()), "malformed renewal is rejected")

# timer-driven renewal
a, b, ca, cb = rpair()
ga, gb = [], []
pump(ca, ga); pump(cb, gb)
ca.start_ratchet(0.4)
ok(wait(lambda: ca._ratchets >= 2 and cb._ratchets >= 2, 10), "timer starts renewals by itself")
ca.send(m.T_MSG, b"after timer")
ok(wait(lambda: (m.T_MSG, b"after timer") in gb), "chat still works after timer renewals")
ca.ratchet_every = 0; ca.dead.set(); cb.dead.set()

# ---- file queue, pause / resume / cancel, speed limit
Q1, Q2 = mk("q1"), mk("q2")
qp = m.free_port()
Q1.listen(qp); Q2.connect("127.0.0.1", qp)
ok(wait(lambda: Q1.chans and Q2.chans), "queue test nodes connected")
shutil_dl = m.DOWNLOAD_DIR
files = []
for i, sz in enumerate((300_000, 200_000, 100_000)):
    fpq = os.path.join(TMP, f"q{i}.bin")
    open(fpq, "wb").write(os.urandom(sz)); files.append(fpq)
for fpq in files:
    Q1.send_file(fpq)
ok(len(Q1.queue_info()) >= 2, "several files wait in the queue")
ok(wait(lambda: all(os.path.exists(os.path.join(shutil_dl, f"q{i}.bin")) for i in range(3)), 30), "queued files all arrive")
order = [os.path.basename(e[2]) for e in events(Q2, "file")]
ok(order == ["q0.bin", "q1.bin", "q2.bin"], f"files arrive in the order they were queued ({order})")
ok(all(sha(os.path.join(shutil_dl, f"q{i}.bin")) == sha(files[i]) for i in range(3)), "queued files intact")
ok(wait(lambda: not Q1.send_queue, 5), "queue empties by itself")

# speed limit
lim = os.path.join(TMP, "lim.bin")
open(lim, "wb").write(os.urandom(400_000))
Q1.set_speed_limit(200_000)
t0 = time.time()
Q1.send_file(lim)
ok(wait(lambda: os.path.exists(os.path.join(shutil_dl, "lim.bin")), 30), "limited transfer completes")
el = time.time() - t0
ok(1.6 < el < 6, f"speed limit slows 400 KB at 200 KB/s to about 2 s (took {el:.1f}s)")
Q1.set_speed_limit(0)

# pause / resume
pz = os.path.join(TMP, "pz.bin")
open(pz, "wb").write(os.urandom(3_000_000))
Q1.set_speed_limit(1_000_000)
Q1.send_file(pz)
def partmax():
    d = os.path.join(shutil_dl, ".partial")
    return max([os.path.getsize(os.path.join(d, f)) for f in os.listdir(d)] or [0]) if os.path.isdir(d) else 0


ok(wait(lambda: partmax() > 200_000, 10), "big transfer started")
Q1.pause_transfers()
time.sleep(0.8)
sz1 = partmax()
time.sleep(1.2)
sz2 = partmax()
ok(sz1 == sz2 and 0 < sz1 < 3_000_000, f"paused transfer sends nothing ({sz1} == {sz2})")
ok(not os.path.exists(os.path.join(shutil_dl, "pz.bin")), "file not complete while paused")
Q1.resume_transfers()
ok(wait(lambda: os.path.exists(os.path.join(shutil_dl, "pz.bin")), 30), "transfer finishes after resume")
ok(sha(os.path.join(shutil_dl, "pz.bin")) == sha(pz), "paused and resumed file intact")

# cancel running + cancel queued, next file still goes through
cx = os.path.join(TMP, "cx.bin"); open(cx, "wb").write(os.urandom(3_000_000))
after = os.path.join(TMP, "after.bin"); open(after, "wb").write(os.urandom(50_000))
gone = os.path.join(TMP, "gone.bin"); open(gone, "wb").write(os.urandom(50_000))
Q1.set_speed_limit(1_000_000)
Q1.send_file(cx); it_gone = Q1.send_file(gone); Q1.send_file(after)
ok(wait(lambda: any(e[0] == "progress" and "cx.bin" in str(e[1]) for e in list(Q1.events.queue)), 10), "cancel test: transfer running")
Q1.cancel_transfer(it_gone["id"])
Q1.cancel_transfer()
Q1.set_speed_limit(0)
ok(wait(lambda: os.path.exists(os.path.join(shutil_dl, "after.bin")), 30), "next file still arrives after a cancel")
ok(not os.path.exists(os.path.join(shutil_dl, "cx.bin")), "cancelled file was not delivered")
ok(not os.path.exists(os.path.join(shutil_dl, "gone.bin")), "file cancelled in the queue was never sent")
ok(wait(lambda: not os.path.isdir(os.path.join(shutil_dl, ".partial")) or not os.listdir(os.path.join(shutil_dl, ".partial")), 5),
   "receiver deleted the partial file after the cancel")
ok(wait(lambda: not Q1.send_queue, 5), "queue empty after cancels")
Q1.shutdown(); Q2.shutdown()

# ---- SOCKS5 proxy for direct connections, IPv6
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import socks_helper
px, hits = socks_helper.start()
P1, P2 = mk("p1"), mk("p2")
pport = m.free_port()
P1.listen(pport)
P2.proxy = px
P2.connect("127.0.0.1", pport)
ok(wait(lambda: P1.chans and P2.chans, 10), "direct connection works through a SOCKS5 proxy")
ok(hits and hits[-1] == ("127.0.0.1", pport), f"the proxy really carried the connection ({hits[-1:]})")
P2.send_text("via proxy")
ok(wait(lambda: any(e[2] == "via proxy" for e in events(P1, "msg"))), "chat works through the proxy")
P1.shutdown(); P2.shutdown()
P3 = mk("p3"); P3.proxy = ("127.0.0.1", m.free_port())     # dead proxy: must fail, never connect directly
P4 = mk("p4"); p4port = m.free_port(); P4.listen(p4port)
P3.connect("127.0.0.1", p4port)
ok(wait(lambda: any("Could not connect" in e[1] for e in events(P3, "sys")), 15) and not P3.chans and not P4.chans,
   "a dead proxy never falls back to a direct connection")
P3.shutdown(); P4.shutdown()

ok(m.split_hostport("[::1]:6000") == ("::1", 6000) and m.split_hostport("[2001:db8::5]", 5555) == ("2001:db8::5", 5555)
   and m.split_hostport("2001:db8::5", 5555) == ("2001:db8::5", 5555) and m.split_hostport("a.b:7") == ("a.b", 7),
   "IPv6 addresses are parsed (bracketed, bare, with port)")
ok(m.clean_host(" [::1] ") == "::1", "brackets are removed before connecting")
try:
    m.split_hostport("[::1]:99999")
    ok(False, "bad port")
except ValueError:
    ok(True, "out of range port is rejected")
import socket as _s
try:
    t6 = _s.socket(_s.AF_INET6); t6.bind(("::1", 0)); t6.close(); have6 = True
except OSError:
    have6 = False
if have6:
    V1, V2 = mk("v1"), mk("v2")
    v6port = m.free_port()
    V1.listen(v6port)
    V2.connect("::1", v6port)
    ok(wait(lambda: V1.chans and V2.chans, 10), "connection over IPv6 (::1) works")
    V3 = mk("v3"); V3.connect("127.0.0.1", v6port)
    ok(wait(lambda: len(V1.chans) == 2, 10), "listener is dual-stack (IPv4 and IPv6 peers at the same time)")
    V1.shutdown(); V2.shutdown(); V3.shutdown()
else:
    print("SKIP IPv6 loopback (no IPv6 on this machine)")

# ---- cover traffic profiles
import random as _rnd
for prof in m.COVER_PROFILES:
    r = _rnd.Random(3)
    eps = [m.cover_plan(prof, r) for _ in range(300)]
    ok(all(w >= 0 and 0 <= n <= m.COVER_MAX and idle > 0 for steps, idle in eps for w, n in steps), f"{prof}: plans are valid")
    ok(m.cover_estimate(prof).startswith("about"), f"{prof}: estimate available")
avg = lambda prof, f: sum(f(m.cover_plan(prof, _rnd.Random(i))) for i in range(300)) / 300
rate = lambda prof: float(m.cover_estimate(prof).split()[1])
ok(rate("stream") > 5 * rate("browse") > 5 * 5 * rate("chat"), "average load: stream >> browse >> chat")
ok(avg("chat", lambda e: e[1]) > 3 * avg("stream", lambda e: e[1]), "chat pauses are far longer than streaming pauses")
ok(max(n for steps, _ in (m.cover_plan("chat", _rnd.Random(i)) for i in range(300)) for _, n in steps) <= 120, "chat messages are tiny")
ok(sum(1 for i in range(300) if len(m.cover_plan("browse", _rnd.Random(i))[0]) >= 9) == 300, "browse: request followed by a burst of replies")

CP, CQ = mk("cp"), mk("cq")
cport = m.free_port(); CP.listen(cport); CQ.connect("127.0.0.1", cport)
ok(wait(lambda: CP.chans and CQ.chans), "cover profile test nodes connected")
got = []
orig_rf = m.Channel._recv_frame
def spy(self):
    typ, data = orig_rf(self)
    if typ == m.T_COVER:
        got.append((time.time(), len(data)))
    return typ, data
m.Channel._recv_frame = spy
try:
    CQ.set_cover(True, "stream")
    ok(wait(lambda: len(got) >= 6, 20), "stream profile produces bursts of dummy frames")
    ok(max(n for _, n in got) >= 20000, "stream dummy frames are large (media-segment like)")
    CQ.set_cover(False)
    time.sleep(0.5); n0 = len(got); time.sleep(3)
    ok(len(got) - n0 <= 1, "turning cover traffic off stops it right away")
    CQ.set_cover(True, "chat")
    got.clear()
    CP.send_text("real message during chat cover")
    ok(wait(lambda: any(e[2] == "real message during chat cover" for e in events(CQ, "msg"))), "real messages still work with cover traffic")
    try:
        CQ.set_cover(True, "nonsense"); ok(False, "unknown profile")
    except ValueError:
        ok(True, "unknown profile is rejected")
    CQ.set_cover(False)
finally:
    m.Channel._recv_frame = orig_rf
CP.shutdown(); CQ.shutdown()

print("all loopback tests passed")
