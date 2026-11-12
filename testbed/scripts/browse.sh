#!/bin/bash
# Обычный пользователь за VPN: HTTP-загрузки и UDP-запросы, без торрентов.
for i in $(seq 60); do ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done
while true; do
  for p in $(seq 8000 8019); do curl -s -o /dev/null --max-time 5 http://${WEB_IP}:$p/blob || true; done
  python3 - "$WEB_IP" <<'PY2'
import socket, sys
for p in range(5300, 5360):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.5)
    try:
        s.sendto(b"ping %d" % p, (sys.argv[1], p)); s.recvfrom(2048)
    except OSError:
        pass
PY2
  sleep 1
done
