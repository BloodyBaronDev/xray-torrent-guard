#!/usr/bin/env python3
"""Минимальный HTTP-трекер (BEP 3, compact) для изолированного стенда."""
import time, urllib.parse, socket, struct
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

swarms = {}

def benc(x):
    if isinstance(x, int): return b"i%de" % x
    if isinstance(x, bytes): return b"%d:%s" % (len(x), x)
    if isinstance(x, str): return benc(x.encode())
    if isinstance(x, dict): return b"d" + b"".join(benc(k) + benc(v) for k, v in sorted(x.items())) + b"e"
    raise TypeError(x)

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True, encoding="latin-1")
        ih = q.get("info_hash", [""])[0].encode("latin-1")
        port = int(q.get("port", ["0"])[0])
        ip = self.client_address[0]
        now = time.time()
        peers = swarms.setdefault(ih, {})
        if q.get("event", [""])[0] != "stopped" and port:
            peers[(ip, port)] = now
        live = [p for p, t in peers.items() if now - t < 600 and p != (ip, port)]
        compact = b"".join(socket.inet_aton(a) + struct.pack(">H", p) for a, p in live)
        body = benc({"interval": 30, "peers": compact})
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
        print(f"announce {ip}:{port} peers={len(live)}", flush=True)
    def log_message(self, *a): pass

ThreadingHTTPServer(("0.0.0.0", 6969), H).serve_forever()
