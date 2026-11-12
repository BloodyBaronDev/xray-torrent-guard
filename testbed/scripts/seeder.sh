#!/bin/bash
# Сид: генерирует файл, создаёт .torrent с трекером, раздаёт.
set -e
mkdir -p /data/dl /share
# одинаковые данные у всех сидов: детерминированный генератор
[ -f /data/dl/payload.bin ] || python3 -c "import random,sys; sys.stdout.buffer.write(random.Random(1).randbytes(64<<20))" > /data/dl/payload.bin
if [ "${ROLE:-primary}" = primary ]; then
  rm -f /share/payload.torrent
  transmission-create -t http://${TRACKER_IP}:6969/announce -o /share/payload.torrent.tmp /data/dl/payload.bin >/dev/null
  mv /share/payload.torrent.tmp /share/payload.torrent
else
  for i in $(seq 120); do [ -f /share/payload.torrent ] && break; sleep 1; done
fi
/opt/tb/transmission.sh &
for i in $(seq 30); do transmission-remote -l >/dev/null 2>&1 && break; sleep 0.5; done
transmission-remote -a /share/payload.torrent -w /data/dl >/dev/null
echo "seeder ready"
wait
