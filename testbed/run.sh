#!/bin/bash
# Прогон матрицы сценариев на изолированном стенде. Результат — results.md.
# Использование: bash testbed/run.sh [сценарий...]   (по умолчанию все)
set -u
cd "$(dirname "$0")"
DUR=${DUR:-120}
#      имя              ENC DHT UTP TRANSPORT BYPASS_IP  что ожидаем
ALL="
default            1 1 1 tcp   -          трекер+DHT+uTP
xhttp              1 1 1 xhttp -          то же через XHTTP
enc_required       2 0 0 tcp   -          MSE по TCP, HTTP-трекер
peers_plain        0 0 0 tcp   10.77.0.5  только пиры, открытый handshake
peers_utp          1 1 1 tcp   10.77.0.5  только пиры: uTP и DHT
peers_enc          2 0 0 tcp   10.77.0.5  только пиры, только MSE по TCP
"
want="${*:-}"
out=results.md
{
  echo "# Результаты стенда ($(date -u +%Y-%m-%dT%H:%MZ), ${DUR} с на сценарий)"
  echo
  echo "| Сценарий | Условия | Скачано alice | Событий alice | Сигналы | Событий bob (контроль) | kernel_drops |"
  echo "|---|---|---|---|---|---|---|"
} > $out
docker compose build -q || exit 1
while read -r name enc dht utp tr byp desc <&3; do
  [ -z "$name" ] && continue
  [ -n "$want" ] && ! grep -qw "$name" <<<"$want" && continue
  [ "$byp" = "-" ] && byp=""
  echo "== $name: $desc"
  export ENC=$enc DHT=$dht UTP=$utp TRANSPORT=$tr BYPASS_IP=$byp
  docker compose down -v -t 2 >/dev/null 2>&1
  docker compose up -d >/dev/null 2>&1 || { echo "up failed"; docker compose logs --tail 30; continue; }
  sleep "$DUR"
  ev=$(docker compose exec -T node curl -s 127.0.0.1:9090/v1/events)
  health=$(docker compose exec -T node curl -s 127.0.0.1:9090/health)
  prog=$(docker compose exec -T alice transmission-remote -l 2>/dev/null | awk 'NR==2{print $2}')
  a=$(grep -o '"subject":"alice@testbed"' <<<"$ev" | wc -l)
  b=$(grep -o '"subject":"bob@testbed"' <<<"$ev" | wc -l)
  sig=$(grep -o '"reasons":{[^}]*}' <<<"$ev" | sed 's/"reasons"://; s/"//g' | sort -u | tr '\n' ' ')
  drops=$(grep -o '"kernel_drops":[0-9]*' <<<"$health" | cut -d: -f2)
  echo "| $name | $desc (ENC=$enc DHT=$dht uTP=$utp, $tr) | ${prog:-?} | $a | ${sig:-—} | $b | ${drops:-?} |" >> $out
  docker compose logs --no-color xtg > "logs-$name-xtg.txt" 2>&1
  echo "   alice=$a bob=$b progress=${prog:-?} signals=${sig:-none}"
  echo "   health: $health"
done 3<<<"$ALL"
docker compose down -v -t 2 >/dev/null 2>&1
echo; cat $out
