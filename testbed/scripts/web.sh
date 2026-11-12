#!/bin/bash
# Обычные сервисы: 20 HTTP-портов и 60 UDP-эхо.
mkdir -p /srv && dd if=/dev/urandom of=/srv/blob bs=1M count=2 status=none && cd /srv
for p in $(seq 8000 8019); do python3 -m http.server $p >/dev/null 2>&1 & done
python3 - <<'PY'
import socket, selectors
sel = selectors.DefaultSelector()
for p in range(5300, 5360):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", p)); s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
while True:
    for k, _ in sel.select():
        d, a = k.fileobj.recvfrom(2048); k.fileobj.sendto(d, a)
PY
