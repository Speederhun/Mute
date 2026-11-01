"""Moat (bridge download) client against a local mock of the service, also through a SOCKS5 proxy.
Run: python tests/test_moat.py"""
import base64
import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mute as m


def ok(cond, msg):
    assert cond, msg
    print("PASS", msg)


JPEG = b"\xff\xd8\xff\xe0fakejpeg"
GOOD = ["obfs4 192.0.2.10:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0",
        "obfs4 192.0.2.11:9001 89ABCDEF0123456789ABCDEF0123456789ABCDEF cert=BBBB iat-mode=0"]
seen = []


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, doc):
        raw = json.dumps(doc).encode()
        self.send_response(code)
        self.send_header("Content-Type", m.MOAT_TYPE)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"null")
        seen.append((self.path, body, self.headers.get("Content-Type")))
        if self.path == "/moat/fetch":
            self.reply(200, {"data": [{"id": "1", "type": "moat-challenge", "version": "0.1.0", "transport": "obfs4",
                                       "image": base64.b64encode(JPEG).decode(), "challenge": "tok123"}]})
        elif self.path == "/moat/check":
            d = body["data"][0]
            if d["solution"] == "right" and d["challenge"] == "tok123":
                self.reply(200, {"data": [{"id": "3", "type": "moat-bridges", "version": "0.1.0", "bridges": GOOD + [
                    "weirdtransport 1.2.3.4:5 AAAA", "obfs4 1.2.3.4:5 AAAA\nBridge evil", "x" * 700]}]})
            else:
                self.reply(200, {"errors": [{"id": "4", "type": "moat-bridges", "version": "0.1.0", "code": 419,
                                             "status": "No you can't", "detail": "The CAPTCHA solution was incorrect."}]})
        elif self.path == "/moat/circumvention/builtin":
            self.reply(200, {"obfs4": GOOD[:1], "snowflake": ["snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"],
                             "meek-azure": ["meek_lite 192.0.2.2:2 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://x.example/ front=y.example"]})
        else:
            self.reply(404, {"errors": [{"detail": "nope"}]})


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
m.MOAT_BASE = f"http://127.0.0.1:{srv.server_address[1]}/moat"

img, ch = m.moat_captcha()
ok(img == JPEG and ch == "tok123", "captcha image and challenge are read")
path, body, ctype = seen[-1]
ok(ctype == m.MOAT_TYPE and body["data"][0]["type"] == "client-transports" and body["data"][0]["supported"] == ["obfs4"],
   "captcha request has the expected JSON:API shape")
bridges = m.moat_solve(ch, " right ")
ok(bridges == GOOD, "correct answer returns only usable, safe bridge lines (unknown transport, injected newline, huge line dropped)")
ok(seen[-1][1]["data"][0]["solution"] == "right" and seen[-1][1]["data"][0]["challenge"] == "tok123", "solution is sent trimmed with its challenge")
try:
    m.moat_solve(ch, "wrong")
    ok(False, "wrong captcha rejected")
except m.MoatError as e:
    ok("Wrong captcha" in str(e), "wrong captcha gives a clear error")
b = m.moat_builtin()
ok(len(b) == 3 and any(x.startswith("snowflake") for x in b) and any(x.startswith("meek_lite") for x in b), "built-in bridges (no captcha) are fetched")
try:
    m._moat_post("nothing")
    ok(False, "http error")
except m.MoatError as e:
    ok("nope" in str(e), "service errors are reported")
m.MOAT_BASE = "http://127.0.0.1:1/moat"
try:
    m.moat_builtin()
    ok(False, "unreachable")
except m.MoatError as e:
    ok("Could not reach" in str(e), "unreachable service gives a friendly error")
m.MOAT_BASE = f"http://127.0.0.1:{srv.server_address[1]}/moat"


# --- through a SOCKS5 proxy (tiny test proxy)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import socks_helper
px, hits = socks_helper.start()
img, ch = m.moat_captcha(proxy=px)
ok(img == JPEG and hits and hits[-1][1] == srv.server_address[1], "bridge download works through a SOCKS5 proxy")
ok(m.parse_proxy("127.0.0.1:9050") == ("127.0.0.1", 9050) and m.parse_proxy("socks5h://localhost:1080") == ("localhost", 1080)
   and m.parse_proxy("") is None, "proxy text is parsed")
print("all moat tests passed")
