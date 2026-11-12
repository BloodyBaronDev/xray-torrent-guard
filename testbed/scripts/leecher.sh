#!/bin/bash
# Качальщик за VPN: ждёт .torrent и качает. Трафик идёт через tun0 клиента.
set -e
for i in $(seq 60); do [ -f /share/payload.torrent ] && ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done
/opt/tb/transmission.sh &
for i in $(seq 30); do transmission-remote -l >/dev/null 2>&1 && break; sleep 0.5; done
transmission-remote -a /share/payload.torrent >/dev/null
echo "leecher started"
wait
