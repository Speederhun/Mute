"""Tests for android/python/android_bridge.py on the desktop (no Android needed).
Run: python tests/test_android_bridge.py"""
import json
import os
import sys
import tempfile
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "android", "python"))
import mute as m
import android_bridge as ab

TMP = tempfile.mkdtemp(prefix="mute_ab_")


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


class Pump(threading.Thread):
    """Plays the Kotlin side: polls events, auto-answers fingerprint prompts."""

    def __init__(self, bridge, accept=True):
        super().__init__(daemon=True)
        self.b, self.accept, self.events, self.running = bridge, accept, [], True
        self.start()

    def run(self):
        while self.running:
            for ev in json.loads(self.b.poll(100)):
                self.events.append(ev)
                if ev["k"] == "confirm":
                    self.b.answer_confirm(ev["fp"], self.accept)

    def of(self, kind):
        return [e for e in list(self.events) if e["k"] == kind]


def wait(cond, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


# ---- identity helpers
d_a = os.path.join(TMP, "a_data")
ok(ab.identity_state(d_a) == "missing", "no identity before first start")
A = ab.Bridge(d_a, os.path.join(TMP, "a_dl"))
ok(ab.identity_state(d_a) == "plain", "identity created in the app directory")
ok(ab.check_passphrase(d_a, None), "plain identity needs no passphrase")

# ---- encrypted identity
d_enc = os.path.join(TMP, "enc")
E = ab.Bridge(d_enc, os.path.join(TMP, "enc_dl"), passphrase="correct horse")
ok(ab.identity_state(d_enc) == "encrypted", "passphrase encrypts the identity key")
ok(not ab.check_passphrase(d_enc, "wrong") and ab.check_passphrase(d_enc, "correct horse"), "passphrase check")
E.shutdown()

# ---- state JSON
st = json.loads(A.state())
ok(st["fp"] == A.node.my_fp and len(st["words"].split()) == 6, "state has fingerprint and 6 words")

# ---- two bridges talk (fingerprint confirmation goes through answer_confirm)
B = ab.Bridge(os.path.join(TMP, "b_data"), os.path.join(TMP, "b_dl"), burner=True)
pa, pb = Pump(A), Pump(B)
port = m.free_port()
A.start_direct(port)
ok(json.loads(A.state())["listening"], "start_direct listens")
B.connect("127.0.0.1:%d" % port, A.node.my_fp)
ok(wait(lambda: pa.of("confirm") or pa.of("connected")), "new peer triggers a confirm event")
ok(wait(lambda: pa.of("connected") and pb.of("connected")), "both sides connected after confirmation")
c = pa.of("confirm")
ok(c and len(c[0]["words"].split()) == 6, "confirm event carries the 6 words")

A.send_text("szia árvíztűrő")
ok(wait(lambda: pb.of("msg")), "message arrives as JSON event")
ok(pb.of("msg")[0]["text"] == "szia árvíztűrő", "unicode text intact")
fp_b = pa.of("connected")[0]["fp"]
A.name_peer(fp_b, "Bea")
ok(json.loads(A.state())["peers"][0]["name"] == "Bea", "nickname shows in state")

# ---- file transfer into the download dir
src = os.path.join(TMP, "hello.txt")
with open(src, "w") as f:
    f.write("x" * 200000)
A.send_file(src)
ok(wait(lambda: pb.of("file"), 20) and pb.of("file")[0]["ok"], "file received intact")
ok(os.path.getsize(pb.of("file")[0]["path"]) == 200000, "received file has the right size")
ok(pb.of("progress"), "progress events are produced")

# ---- a refused fingerprint prevents the connection
C = ab.Bridge(os.path.join(TMP, "c_data"), os.path.join(TMP, "c_dl"), burner=True)
D = ab.Bridge(os.path.join(TMP, "d_data"), os.path.join(TMP, "d_dl"), burner=True)
pc, pd = Pump(C, accept=False), Pump(D, accept=False)
port2 = m.free_port()
C.start_direct(port2)
D.connect("127.0.0.1:%d" % port2)
time.sleep(3)
ok(not pc.of("connected") and not pd.of("connected"), "rejecting the fingerprint blocks the session")

# ---- tor lookup patch
tor = os.path.join(TMP, "libtor.so")
open(tor, "w").close()
ptd = os.path.join(TMP, "pt")
os.makedirs(ptd)
open(os.path.join(ptd, "liblyrebird.so"), "w").close()
real_find_tor, real_find_pt = m.find_tor, m.find_pt
ab._patch_tor_lookup(tor, ptd)
ok(m.find_tor() == tor, "find_tor points at the bundled binary")
ok(m.find_pt(("lyrebird", "obfs4proxy")) == os.path.join(ptd, "liblyrebird.so"), "find_pt maps lib<name>.so")
ok(m.find_pt(("snowflake-client",)) is None, "missing transport is reported as missing")
m.find_tor, m.find_pt = real_find_tor, real_find_pt

# ---- options: configure() and state()["options"]
def opts(b):
    return json.loads(b.state())["options"]


th = json.loads(ab.themes())
ok(len(th) == 8 and all(k in th["hacker"] for k in m.THEME_ROLES + ("pal",)), "themes come from mute.THEMES")
ok(set(json.loads(ab.cover_profiles())) == set(m.COVER_PROFILES), "cover profiles listed with estimates")
ok(json.loads(ab.shape_labels())[0] == ["off", 0.0], "shape labels listed")
ok("KB/s" in ab.shape_estimate(1.0, True), "shape estimate text")

C.configure(json.dumps({"relay": True, "cover": True, "cover_profile": "chat", "shape": 0.2,
                        "speed_limit_kbs": 64, "ratchet": 300, "proxy": "127.0.0.1:9050",
                        "scrub": False, "amnesia": True}))
o = opts(C)
ok(o["relay"] and o["cover"] and o["cover_profile"] == "chat" and o["shape"] == 0.2, "relay/cover/shape applied")
ok(o["speed_limit_kbs"] == 64 and o["ratchet"] == 300 and o["proxy"] == "127.0.0.1:9050", "limit/ratchet/proxy applied")
ok(not o["scrub"] and o["amnesia"], "scrub and amnesia applied")
C.configure(json.dumps({"cover": False, "shape": 0, "proxy": ""}))
ok(not opts(C)["cover"] and opts(C)["shape"] == 0 and opts(C)["proxy"] == "", "options switch off again")
for bad in ({"shape": 500}, {"cover_profile": "nope"}, {"allowed_clients": "tooshort"}, {"proxy": "h:notaport"}):
    try:
        C.configure(json.dumps(bad))
        ok(False, "bad option accepted: %r" % bad)
    except ValueError:
        ok(True, "bad option rejected: %r" % list(bad))

pub = json.loads(C.configure(json.dumps({"new_client_auth": True})))["options"]["client_auth_pub"]
ok(pub and len(pub) == 52, "onion client auth key is 52 characters")
C.configure(json.dumps({"allowed_clients": pub}))
ok(opts(C)["allowed_clients"] == 1, "allowed onion client keys stored")
C.configure(json.dumps({"bridges": "obfs4 1.2.3.4:443 " + "A" * 40 + " cert=" + "B" * 70 + " iat-mode=0"}))
ok(opts(C)["bridges"] == 1, "bridge line parsed")
C.configure(json.dumps({"bridges": ""}))
ok(opts(C)["bridges"] == 0, "bridges cleared")

# ---- closed mode + shared secret over real connections
E1 = ab.Bridge(os.path.join(TMP, "e1"), os.path.join(TMP, "e1_dl"), burner=True)
E2 = ab.Bridge(os.path.join(TMP, "e2"), os.path.join(TMP, "e2_dl"), burner=True)
p1, p2 = Pump(E1), Pump(E2)
port3 = m.free_port()
E1.configure(json.dumps({"closed": True}))
E1.start_direct(port3)
E2.connect("127.0.0.1:%d" % port3)
time.sleep(2.5)
ok(not p1.of("connected") and not p1.of("confirm"), "closed mode: unknown peer is refused without any prompt")
E1.configure(json.dumps({"allow": E2.node.my_fp}))
E2.connect("127.0.0.1:%d" % port3)
ok(wait(lambda: p1.of("connected")), "closed mode: allowlisted fingerprint connects")
ok(not p1.of("confirm"), "closed mode: no fingerprint prompt for allowlisted peer")

F1 = ab.Bridge(os.path.join(TMP, "f1"), os.path.join(TMP, "f1_dl"), burner=True)
F2 = ab.Bridge(os.path.join(TMP, "f2"), os.path.join(TMP, "f2_dl"), burner=True)
F3 = ab.Bridge(os.path.join(TMP, "f3"), os.path.join(TMP, "f3_dl"), burner=True)
q1, q2, q3 = Pump(F1), Pump(F2), Pump(F3)
port4 = m.free_port()
F1.configure(json.dumps({"psk": "a long shared secret"}))
ok(opts(F1)["psk"], "shared secret is set")
F1.start_direct(port4)
F2.configure(json.dumps({"psk": "a long shared secret"}))
F2.connect("127.0.0.1:%d" % port4)
ok(wait(lambda: q1.of("connected") and q2.of("connected"), 30), "matching shared secret connects")
F3.configure(json.dumps({"psk": "wrong secret"}))
F3.connect("127.0.0.1:%d" % port4)
time.sleep(4)
# XXpsk3 mixes the secret in the last message, so the listening side detects the mismatch and drops
# the session; the connecting side may still reach its fingerprint prompt first.
ok(F3.node.my_fp not in F1.node.chans, "wrong shared secret is refused by the listening side")
ok(any("shared secret mismatch" in e["text"] for e in q1.of("sys")), "listener reports the shared secret mismatch")

# ---- pause / resume / speed limit / folder transfer
F1.configure(json.dumps({"speed_limit_kbs": 0}))
F1.pause_transfers()
ok(opts(F1)["paused"], "transfers can be paused")
F1.resume_transfers()
ok(not opts(F1)["paused"], "transfers can be resumed")
folder = os.path.join(TMP, "mydir")
os.makedirs(os.path.join(folder, "sub"))
for name in ("a.txt", os.path.join("sub", "b.txt")):
    with open(os.path.join(folder, name), "w") as f:
        f.write("data " * 1000)
F1.send_file(folder)
ok(wait(lambda: q2.of("file"), 20) and q2.of("file")[-1]["ok"], "folder arrives as a clean zip")
ok(q2.of("file")[-1]["path"].endswith(".zip"), "received folder is a .zip")
ok(isinstance(json.loads(F1.queue()), list), "queue() returns JSON")

# ---- moat helpers are wired (network is not touched: bad proxy fails fast)
try:
    ab.moat_captcha("obfs4", "127.0.0.1:1")
    ok(False, "moat should have failed")
except Exception as e:
    ok(True, "moat_captcha raises on an unreachable proxy (%s)" % type(e).__name__)

for pmp in (p1, p2, q1, q2, q3):
    pmp.running = False
for b in (E1, E2, F1, F2, F3):
    b.shutdown()

for p in (pa, pb, pc, pd):
    p.running = False
for b in (A, B, C, D):
    b.shutdown()
print("ALL OK")
