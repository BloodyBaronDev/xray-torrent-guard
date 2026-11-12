#!/bin/bash
# Запуск transmission-daemon с параметрами сценария.
# ENC: 0 — разрешать открытый, 1 — предпочитать шифрование, 2 — только шифрование
set -e
DIR=/data/cfg; mkdir -p $DIR /data/dl
b() { [ "$1" = 1 ] && echo true || echo false; }
cat > $DIR/settings.json <<EOF
{
 "download-dir": "/data/dl", "incomplete-dir-enabled": false,
 "encryption": ${ENC:-1},
 "dht-enabled": $(b ${DHT:-1}), "utp-enabled": $(b ${UTP:-1}),
 "pex-enabled": true, "lpd-enabled": false,
 "peer-port": ${PEER_PORT:-51413}, "port-forwarding-enabled": false,
 "rpc-enabled": true, "rpc-bind-address": "127.0.0.1", "rpc-authentication-required": false,
 "rpc-whitelist-enabled": false, "rpc-host-whitelist-enabled": false,
 "speed-limit-up-enabled": true, "speed-limit-up": ${UP_KBPS:-100},
 "ratio-limit-enabled": false, "message-level": 2
}
EOF
exec transmission-daemon -f -g $DIR
