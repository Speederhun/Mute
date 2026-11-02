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

for p in (pa, pb, pc, pd):
    p.running = False
for b in (A, B, C, D):
    b.shutdown()
print("ALL OK")
