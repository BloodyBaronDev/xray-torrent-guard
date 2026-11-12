#!/bin/bash
# Нода: VLESS-сервер, выход freedom, access-лог в tmpfs.
set -e
mkdir -p /run/xray
cat > /tmp/node.json <<EOF
{
 "log": {"access": "/run/xray/access.log", "loglevel": "warning"},
 "inbounds": [{
   "port": 443, "protocol": "vless",
   "settings": {"clients": [{"id": "${UUID_ALICE}", "email": "alice@testbed"}, {"id": "${UUID_BOB}", "email": "bob@testbed"}], "decryption": "none"},
   "streamSettings": {"network": "${TRANSPORT:-tcp}" $( [ "${TRANSPORT}" = xhttp ] && echo ', "xhttpSettings": {"path": "/x"}' )},
   "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}
 }],
 "outbounds": [{"protocol": "freedom"}]
}
EOF
exec xray run -c /tmp/node.json
