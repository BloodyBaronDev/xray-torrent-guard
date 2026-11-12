#!/bin/bash
# Клиент VPN: Xray (socks → VLESS), tun2socks, весь трафик кроме ноды — в туннель.
set -e
cat > /tmp/client.json <<EOF
{
 "log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": 1080, "protocol": "socks", "settings": {"udp": true}}],
 "outbounds": [{
   "protocol": "vless",
   "settings": {"vnext": [{"address": "${NODE_IP}", "port": 443, "users": [{"id": "${UUID}", "encryption": "none"}]}]},
   "streamSettings": {"network": "${TRANSPORT:-tcp}" $( [ "${TRANSPORT}" = xhttp ] && echo ', "xhttpSettings": {"path": "/x"}' )}
 }]
}
EOF
xray run -c /tmp/client.json &
sleep 1
tun2socks -device tun0 -proxy socks5://127.0.0.1:1080 -loglevel warning &
for i in $(seq 20); do ip link show tun0 >/dev/null 2>&1 && break; sleep 0.5; done
ip link set tun0 up
GW=$(ip route | awk '/default/ {print $3}')
ip route add ${NODE_IP}/32 dev eth0 ${GW:+via $GW} 2>/dev/null || true
ip route replace default dev tun0
# прямой маршрут на всю подсеть стенда перебил бы туннель: напрямую только нода
NET=$(ip route | awk '/dev eth0 proto kernel/ {print $1}')
[ -n "$NET" ] && ip route del $NET dev eth0
# сценарий «на ноде только пиры»: трекер мимо туннеля
[ -n "${BYPASS_IP}" ] && ip route add ${BYPASS_IP}/32 dev eth0 ${GW:+via $GW} 2>/dev/null || true
echo "client tunnel up"
exec sleep infinity
