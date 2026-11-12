# Изолированный стенд

Docker-сеть `internal: true` без выхода в интернет. Образы собираются один раз (Alpine,
Xray, tun2socks, Transmission скачиваются при сборке), дальше всё работает офлайн.

```
alice (Transmission) ─ tun0 ─ tun2socks ─ Xray-клиент ─ VLESS ─┐
bob (curl, UDP)      ─ tun0 ─ tun2socks ─ Xray-клиент ─ VLESS ─┤
                                                               node: Xray (freedom) + xtg
                                    сид, трекер, веб-сервер ◄──┘
```

- `alice@testbed` качает 64 МБ у сида; `bob@testbed` — контроль: обычные HTTP и UDP.
- `xtg` работает в сетевом пространстве ноды, читает её access-лог из tmpfs и усекает его.
- Сценарии `peers_*` направляют трекер мимо туннеля: на ноде видно только трафик между
  пирами — так проверяется, что ловится без трекера.

```bash
bash testbed/run.sh                 # все сценарии, ~2 мин каждый
bash testbed/run.sh peers_enc       # один
DUR=300 bash testbed/run.sh         # дольше
```

Итог — `testbed/results.md`, журналы xtg — `testbed/logs-*.txt`.
