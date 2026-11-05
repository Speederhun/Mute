"""Voice call tests with a fake microphone/speaker (no sound hardware needed).
Run: python tests/test_voice.py"""
import array
import math
import os
import random
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m

TMP = tempfile.mkdtemp(prefix="mute_voice_")
m.DOWNLOAD_DIR = os.path.join(TMP, "dl")


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


def wait(cond, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.03)
    return False


def mk(name):
    return m.Node(lambda fp: True, app_dir=os.path.join(TMP, name), amnesia=True)


def events(node, kind):
    return [e for e in list(node.events.queue) if e[0] == kind]


def call_states(node):
    return [e[1] for e in events(node, "call")]


def sine(freq, n, phase=0.0, amp=8000):
    s = array.array("h", (int(amp * math.sin(2 * math.pi * freq * (phase + i) / m.CALL_RATE)) for i in range(n)))
    return s.tobytes()


def power(pcm, freq):
    """Goertzel power of one frequency."""
    s = array.array("h"); s.frombytes(pcm)
    w = 2 * math.pi * freq / m.CALL_RATE
    c = 2 * math.cos(w)
    q1 = q2 = 0.0
    for x in s:
        q0 = x + c * q1 - q2
        q2, q1 = q1, q0
    return q1 * q1 + q2 * q2 - c * q1 * q2


class FakeAudio:
    """Stands in for the sound card: plays a tone into the call, records what comes out."""
    instances = []

    def __init__(self, freq):
        self.freq, self.rec, self.stop_ev = freq, bytearray(), threading.Event()
        self.phase = 0
        self.silent = False
        self.stall = 0.0                       # seconds the "sound card" thread sleeps (to starve things)
        FakeAudio.instances.append(self)

    def start(self, on_mic, pull_out):
        def run():
            nxt = time.time()
            while not self.stop_ev.is_set():
                if self.stall > 0:
                    time.sleep(self.stall); self.stall = 0
                chunk = bytes(m.CHUNK_BYTES) if self.silent else sine(self.freq, m.CHUNK_SAMPLES, self.phase)
                self.phase += m.CHUNK_SAMPLES
                on_mic(chunk)
                self.rec += pull_out()
                nxt += 0.02
                time.sleep(max(0, nxt - time.time()))
        self.th = threading.Thread(target=run, daemon=True); self.th.start()

    def stop(self):
        self.stop_ev.set()


def setup_pair(freq_a=600, freq_b=1100):
    A, B = mk("a"), mk("b")
    port = m.free_port(); A.listen(port); B.connect("127.0.0.1", port)
    assert wait(lambda: A.chans and B.chans), "connect"
    fa, fb = FakeAudio(freq_a), FakeAudio(freq_b)
    A.calls.backend_factory = lambda i, o: fa
    B.calls.backend_factory = lambda i, o: fb
    return A, B, fa, fb


# ---------------------------------------------------------------- codec
rnd = random.Random(5)
sig = bytearray()
for i in range(16000):                     # one second of speech-like signal: two tones + noise
    v = 7000 * math.sin(2 * math.pi * 220 * i / 16000) + 3500 * math.sin(2 * math.pi * 1300 * i / 16000) + rnd.gauss(0, 300)
    sig += struct.pack("<h", int(max(-32768, min(32767, v))))
sig = bytes(sig)
enc, pred, idx = m.adpcm_encode(sig)
dec, _, _ = m.adpcm_decode(enc, len(sig) // 2)
a, b = array.array("h"), array.array("h"); a.frombytes(sig); b.frombytes(dec)
sp = sum(x * x for x in a); sn = sum((x - y) ** 2 for x, y in zip(a, b))
snr = 10 * math.log10(sp / sn)
ok(len(enc) == len(sig) // 4, "ADPCM is 4 bits per sample (4:1)")
ok(snr > 15, f"ADPCM round trip keeps the signal (SNR {snr:.1f} dB)")
c = m._AdpcmCodec(); d = m._AdpcmCodec()
pk = c.encode(sine(500, m.CHUNK_SAMPLES * m.PACKET_CHUNKS))
ok(len(pk) + 3 + 5 < 1024, f"an 80 ms packet fits one 1 KB frame ({len(pk)} bytes)")
chunks = d.decode(pk)
ok(len(chunks) == m.PACKET_CHUNKS and all(len(x) == m.CHUNK_BYTES for x in chunks), "packet decodes to four 20 ms chunks")
bad = 0
for _ in range(500):
    junk = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 800)))
    try:
        d.decode(junk)
    except ValueError:
        pass
    except Exception:
        bad += 1
ok(bad == 0, "garbage audio packets only ever raise ValueError")
ok(m.pcm_level(sine(500, 320)) > 4000 and m.pcm_level(bytes(640)) == 0, "level meter distinguishes tone from silence")
if m._opus_module():
    oc = m._OpusCodec()
    ok(len(oc.decode(oc.encode(sine(500, 1280)))) == 4, "Opus round trip")
else:
    print("SKIP Opus (opuslib/libopus not installed): ADPCM is used")

# ---------------------------------------------------------------- full call, both directions
A, B, fa, fb = setup_pair()
t0 = time.time()
A.calls.call(next(iter(A.chans)))
ok(wait(lambda: B.calls.state == "ringing-in"), "callee is told about the incoming call")
ok("incoming" in call_states(B) and "ringing" in call_states(A), "events: incoming / ringing")
B.calls.accept()
ok(wait(lambda: A.calls.active() and B.calls.active()), "call becomes active on both sides")
ok(wait(lambda: len(fa.rec) > 16000 * 2 and len(fb.rec) > 16000 * 2, 15), "audio flows both ways")
tail_b = bytes(fb.rec[-16000:]); tail_a = bytes(fa.rec[-16000:])
ok(power(tail_b, 600) > 20 * power(tail_b, 1100), "B hears A's 600 Hz tone")
ok(power(tail_a, 1100) > 20 * power(tail_a, 600), "A hears B's 1100 Hz tone")
st = A.calls.stats()
ok(st and st["rx"] > 8 and st["tx"] > 8 and st["codec"] in ("adpcm", "opus"), f"stats are kept ({st['tx']} sent, {st['rx']} received, codec {st['codec']})")
ok(st["underruns"] <= 6 and st["bad"] == 0, f"no real stutter on loopback ({st['underruns']} underruns)")
# latency: tone burst start
A.calls.hangup()
ok(wait(lambda: B.calls.state == "idle" and A.calls.state == "idle"), "hangup ends the call on both sides")
ok("ended-remote" in call_states(B) and "ended" in call_states(A), "events: ended / ended-remote")
ok(fa.stop_ev.is_set() and fb.stop_ev.is_set(), "audio devices are released after the call")

# ---------------------------------------------------------------- mute
FakeAudio.instances.clear()
fa, fb = FakeAudio(600), FakeAudio(1100)
A.calls.backend_factory = lambda i, o: fa
B.calls.backend_factory = lambda i, o: fb
A.calls.call(next(iter(A.chans)))
ok(wait(lambda: B.calls.state == "ringing-in"), "second call rings")
B.calls.accept()
ok(wait(lambda: A.calls.active()), "second call active")
time.sleep(1.5)
A.calls.set_muted(True)
ok(wait(lambda: B.calls.remote_muted, 5), "the other side is told you muted")
time.sleep(1.0)
n0 = len(fb.rec); rx0 = B.calls.stats()["rx"]
time.sleep(1.5)
seg = bytes(fb.rec[n0:])
ok(m.pcm_level(seg) < 300, "muted microphone sends silence")
ok(B.calls.stats()["rx"] - rx0 >= 10, "packets keep flowing while muted (muting is not visible on the wire)")
A.calls.set_muted(False)
time.sleep(2.0)
ok(power(bytes(fb.rec[-16000:]), 600) > 20 * power(bytes(fb.rec[-16000:]), 1100), "unmuting brings the voice back")

# ---------------------------------------------------------------- files wait during the call
big = os.path.join(TMP, "during.bin"); open(big, "wb").write(os.urandom(400_000))
A.send_file(big)
time.sleep(2)
ok(not os.path.exists(os.path.join(m.DOWNLOAD_DIR, "during.bin")), "file transfer waits while a call is running")
B.send_text("chat works during a call")
ok(wait(lambda: any(e[2] == "chat works during a call" for e in events(A, "msg"))), "chat messages still go through during a call")
A.calls.hangup()
ok(wait(lambda: os.path.exists(os.path.join(m.DOWNLOAD_DIR, "during.bin")), 30), "the file continues after the call")

# ---------------------------------------------------------------- jitter: the sound card stalls
fa2, fb2 = FakeAudio(600), FakeAudio(1100)
A.calls.backend_factory = lambda i, o: fa2
B.calls.backend_factory = lambda i, o: fb2
A.calls.call(next(iter(A.chans))); wait(lambda: B.calls.state == "ringing-in"); B.calls.accept()
ok(wait(lambda: A.calls.active()), "call for the jitter test")
time.sleep(1.0)
fa2.stall = 0.6                            # A's sender stalls for 0.6 s
time.sleep(2.5)
ok(B.calls.active() and A.calls.active(), "a stall does not end the call")
ok(power(bytes(fb2.rec[-16000:]), 600) > 20 * power(bytes(fb2.rec[-16000:]), 1100), "audio recovers after the stall")
ok(B.calls.stats()["underruns"] >= 1, "the receiver noticed the gap and adapted")

# ---------------------------------------------------------------- hostile peer
def raw_send(node, typ, payload):
    ch = next(iter(node.chans.values()))
    ch.send(typ, payload)


raw_send(A, m.T_AUDIO, os.urandom(900))
raw_send(A, m.T_AUDIO, b"\x00")
raw_send(A, m.T_CALL, b"not json")
raw_send(A, m.T_CALL, b'{"t": 5}')
raw_send(A, m.T_CALL, b'{"t":"accept","codec":"evil"}')
raw_send(A, m.T_CALL, b'{"t":"mute","m":"x"}')
time.sleep(0.5)
B.send_text("still here")
ok(wait(lambda: any(e[2] == "still here" for e in events(A, "msg"))), "garbage audio/signalling does not break the connection")
ok(B.calls.stats()["bad"] >= 2, "bad audio packets are counted and dropped")
B.calls.hangup()
ok(wait(lambda: A.calls.state == "idle"), "call ends")
n_before = len(events(B, "call"))
raw_send(A, m.T_AUDIO, os.urandom(300))
raw_send(A, m.T_CALL, b'{"t":"hangup"}')
raw_send(A, m.T_CALL, b'{"t":"accept","codec":"adpcm"}')
time.sleep(0.5)
ok(B.calls.state == "idle" and len(events(B, "call")) == n_before, "audio or call messages without a call are ignored")

# ---------------------------------------------------------------- reject / busy / no answer / disconnect
A.calls.call(next(iter(A.chans)))
ok(wait(lambda: B.calls.state == "ringing-in"), "ring for reject test")
B.calls.reject()
ok(wait(lambda: A.calls.state == "idle") and "rejected" in call_states(A), "a rejected call is reported to the caller")

A.calls.call(next(iter(A.chans))); wait(lambda: B.calls.state == "ringing-in")
try:
    B.calls.call(next(iter(B.chans))); ok(False, "busy")
except ConnectionError as e:
    ok("Already" in str(e), "you cannot start a call while one is ringing")
A.calls.hangup()
ok(wait(lambda: B.calls.state == "idle") and "missed" in call_states(B), "caller hangs up while ringing -> callee sees a missed call")

C = mk("c")
cport = m.free_port(); C.listen(cport); A.connect("127.0.0.1", cport)
ok(wait(lambda: len(A.chans) == 2), "A also talks to C")
fpc = [fp for fp in A.chans if fp == C.my_fp][0]
A.calls.call(next(iter(B.chans and [fp for fp in A.chans if fp != fpc])))
wait(lambda: B.calls.state == "ringing-in")
B.calls.accept(); wait(lambda: A.calls.active())
C.calls.backend_factory = lambda i, o: FakeAudio(200)
C.calls.call(next(iter(C.chans)))
ok(wait(lambda: "busy" in call_states(C)), "a second caller gets 'busy' while you are in a call")
A.calls.backend_factory = lambda i, o: FakeAudio(300)
B.calls.hangup(); wait(lambda: A.calls.state == "idle")

A.calls.ring_seconds = 1; B.calls.ring_seconds = 5
A.calls.call(next(iter([fp for fp in A.chans if fp != fpc])))
ok(wait(lambda: "noanswer" in call_states(A), 5) and wait(lambda: B.calls.state == "idle", 5), "unanswered call times out on both sides")
A.calls.ring_seconds = m.RING_SECONDS

fa3, fb3 = FakeAudio(600), FakeAudio(1100)
A.calls.backend_factory = lambda i, o: fa3
B.calls.backend_factory = lambda i, o: fb3
A.calls.call(next(iter([fp for fp in A.chans if fp != fpc]))); wait(lambda: B.calls.state == "ringing-in"); B.calls.accept()
ok(wait(lambda: A.calls.active()), "call before disconnect")
for ch in list(B.chans.values()):
    ch.sock.close()
ok(wait(lambda: A.calls.state == "idle" and B.calls.state == "idle", 10) and fa3.stop_ev.is_set(), "a dropped connection ends the call and frees the audio device")
for n in (A, B, C):
    n.shutdown()

# ---------------------------------------------------------------- constant-rate mode
A, B, fa, fb = setup_pair()
A.set_shape(25); B.set_shape(25)
A.calls.call(next(iter(A.chans))); wait(lambda: B.calls.state == "ringing-in"); B.calls.accept()
ok(wait(lambda: A.calls.active() and B.calls.active()), "call works in constant-rate mode")
ok(wait(lambda: len(fb.rec) > 16000 * 4, 20), "audio flows in constant-rate mode")
time.sleep(1)
ok(power(bytes(fb.rec[-16000:]), 600) > 10 * power(bytes(fb.rec[-16000:]), 1100), "constant-rate call carries the voice")
ok(B.calls.stats()["bad"] == 0, "no corrupted audio in constant-rate mode")
A.calls.hangup(); wait(lambda: B.calls.state == "idle")
A.set_shape(5)
try:
    A.calls.call(next(iter(A.chans))); ok(False, "slow shape")
except ConnectionError as e:
    ok("too slow" in str(e), "a constant-rate setting that is too slow for audio is refused with a clear message")
for n in (A, B):
    n.shutdown()

# ---------------------------------------------------------------- no audio hardware
A, B = mk("na"), mk("nb")
port = m.free_port(); A.listen(port); B.connect("127.0.0.1", port); wait(lambda: A.chans and B.chans)
def nohw(i, o):
    raise m.AudioUnavailable("no sound hardware")
A.calls.backend_factory = nohw
try:
    A.calls.call(next(iter(A.chans))); ok(False, "no hw")
except ConnectionError as e:
    ok("no sound hardware" in str(e) and A.calls.state == "idle", "missing audio hardware gives a clear error and no half-started call")
B.calls.backend_factory = nohw
FakeAudio.instances.clear()
A.calls.backend_factory = lambda i, o: FakeAudio(500)
A.calls.call(next(iter(A.chans))); wait(lambda: B.calls.state == "ringing-in")
try:
    B.calls.accept(); ok(False, "accept without hw")
except ConnectionError:
    ok(True, "accepting without a working sound device fails cleanly")
ok(wait(lambda: A.calls.state == "idle" and B.calls.state == "idle"), "both sides are idle again")
for n in (A, B):
    n.shutdown()
# ---------------------------------------------------------------- codec negotiation
A, B, fa, fb = setup_pair()
B.calls.codecs_override = ["adpcm"]
A.calls.call(next(iter(A.chans))); wait(lambda: B.calls.state == "ringing-in"); B.calls.accept()
ok(wait(lambda: A.calls.active() and B.calls.active()), "call between an Opus-capable and an ADPCM-only side")
ok(A.calls.codec == "adpcm" and B.calls.codec == "adpcm", "both sides fall back to the codec they share")
ok(wait(lambda: len(fb.rec) > 16000 * 3, 15) and power(bytes(fb.rec[-16000:]), 600) > 20 * power(bytes(fb.rec[-16000:]), 1100), "audio is fine with the fallback codec")
A.calls.hangup(); wait(lambda: B.calls.state == "idle")
for n in (A, B):
    n.shutdown()

print("all voice tests passed")
