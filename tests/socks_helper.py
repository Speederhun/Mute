"""Tiny SOCKS5 proxy (no authentication) for the tests. start() -> ((host, port), hits)
where hits records every (target host, target port) the proxy was asked to reach."""
import socket
import struct
import threading


def _pipe(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    for x in (a, b):
        try:
            x.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def start():
    hits = []
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(8)

    def one(c):
        try:
            c.recv(262)                      # greeting
            c.sendall(b"\x05\x00")
            req = c.recv(262)
            atyp = req[3]
            if atyp == 1:
                host, prt = socket.inet_ntoa(req[4:8]), struct.unpack(">H", req[8:10])[0]
            elif atyp == 4:
                host, prt = socket.inet_ntop(socket.AF_INET6, req[4:20]), struct.unpack(">H", req[20:22])[0]
            else:
                ln = req[4]
                host, prt = req[5:5 + ln].decode(), struct.unpack(">H", req[5 + ln:7 + ln])[0]
            hits.append((host, prt))
            up = socket.create_connection((host, prt), timeout=5)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            threading.Thread(target=_pipe, args=(c, up), daemon=True).start()
            _pipe(up, c)
        except Exception:
            c.close()

    def serve():
        while True:
            c, _ = ls.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return ls.getsockname(), hits
