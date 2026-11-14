<div align="center">

# 🛡️ Xray Torrent Guard

**Находит BitTorrent на VPN/прокси-ноде — даже шифрованный — и говорит, какой пользователь качает.**

[![Release](https://img.shields.io/github/v/release/BloodyBaronDev/xray-torrent-guard?include_prereleases&label=release)](https://github.com/BloodyBaronDev/xray-torrent-guard/releases)
![Rust](https://img.shields.io/badge/rust-%E2%89%A51.80-orange)
![Linux](https://img.shields.io/badge/platform-linux%20x86__64-blue)
![Size](https://img.shields.io/badge/binary-~350%20KB-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[Быстрый старт](#-быстрый-старт) · [Настройка Xray](#-настройка-xray) · [Обработчики](#-что-делать-с-событиями) · [Результаты](#-результаты) · [API](#-api) · [FAQ](#-faq-и-неполадки)

</div>

---

> **Статус:** release candidate. Проверено на изолированном стенде с реальными клиентами и
> сутки на боевой ноде в режиме наблюдателя (13–14.11.2026, [отчёт](docs/field-test-2026-11.md)).

## Зачем

- Жалобы правообладателей и хостеров приходят на IP ноды, а страдает весь сервис.
- Штатные средства — sniffing `bittorrent` в Xray, торрент-блокер Remnawave, `ipp2p` —
  видят только открытый handshake. Шифрованный BT (MSE/PE), uTP и DHT проходят мимо.
- За relay/CDN у всех клиентов один IP: бан по IP отключает всех. Нужен **пользователь**.

## Как это работает

```
 клиент ──VLESS/Hysteria──▶ Xray ──────────── исходящие пакеты ──▶ интернет
                             │ access.log            │
                             ▼ (кто, куда)           ▼ (что внутри)
                       ┌──────────────── xtg ────────────────┐
                       │ анализатор протоколов + эвристики   │
                       │ оценка риска в окне 60 с            │
                       └──▶ событие {user, score, причины} ──┘
                                │
                    API · webhook · exec → бан, уведомление, лог
```

1. **Свой анализатор протоколов:** BT handshake, MSE/PE, uTP, DHT (bencode KRPC), трекеры
   HTTP/UDP, LSD.
2. **Поведенческие эвристики:** веер UDP-пиров, кандидаты MSE на нестандартных портах.
3. **Оценка риска:** сильный сигнал сразу даёт событие, слабые суммируются в окне.
4. **Привязка к пользователю:** по access-логу Xray пакет к `IP:порт` сопоставляется с
   `email` того, кто открыл соединение.
5. **Открытый выход:** HTTP API, webhook, внешняя команда — бан делаете под свою панель.

Без зависимостей, один статический бинарник ~350 КБ, ~5% CPU и ~4 МБ памяти на боевой ноде.

## 🚀 Быстрый старт

### Одной командой (рекомендуется)

```bash
curl -fsSL https://raw.githubusercontent.com/BloodyBaronDev/xray-torrent-guard/main/deploy/get.sh | sudo sh
```

Скрипт скачивает готовый бинарник последнего релиза, проверяет SHA-256, ставит
systemd-юнит, создаёт `/run/xray` в tmpfs, сам определяет внешний интерфейс и запускает
службу в режиме **наблюдателя** (никого не банит, только пишет события).
Повторный запуск — обновление: настройки в `/etc/default/xtg` не трогаются.
| Переменная | Что делает |
|---|---|
| `XTG_VERSION=v0.1.0` | конкретный релиз вместо последнего |
| `XTG_IFACE=ens3` | интерфейс вместо автоопределения |
| `XTG_START=0` | только установить, не запускать |

```bash
curl -fsSL https://raw.githubusercontent.com/BloodyBaronDev/xray-torrent-guard/main/deploy/get.sh | sudo XTG_IFACE=ens3 sh
```

После установки осталось **одно**: [включить access-лог Xray](#-настройка-xray).

### Из исходников

```bash
git clone https://github.com/BloodyBaronDev/xray-torrent-guard && cd xray-torrent-guard
cargo build --release            # Rust ≥ 1.80
sudo sh deploy/install.sh        # бинарник, юнит, /run/xray
sudoedit /etc/default/xtg
sudo systemctl enable --now xtg
```

### Docker

```bash
docker build -t xtg .            # ~2 МБ, FROM scratch
docker run -d --name xtg --restart always --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN -v /run/xray:/run/xray \
  xtg run --iface eth0 --xray-log /run/xray/access.log --xray-log-max 64M \
          --only-attributed --api 127.0.0.1:9090 --quiet
```

### Проверка

```bash
systemctl status xtg
curl -s 127.0.0.1:9090/health           # packets растёт, xray.lines растёт
curl -s 127.0.0.1:9090/v1/events        # события
journalctl -u xtg -f
```

## 🔧 Настройка Xray

xtg нужен access-лог Xray с `email` пользователей. Держите его в `/run/xray` (tmpfs):
торрент-клиент открывает тысячи соединений, на диске лог быстро вырастет до гигабайт.

### Xray напрямую (systemd)

```json
"log": { "access": "/run/xray/access.log", "loglevel": "warning" }
```

```bash
sudo systemctl restart xray     # файл появится при первом соединении
```

### Remnawave node (Docker)

Смонтируйте `/run/xray` хоста в контейнер ноды — в `docker-compose.yml` ноды:

```yaml
services:
  remnanode:
    volumes:
      - /run/xray:/var/log/xray
```

В профиле ноды в панели:

```json
"log": { "access": "/var/log/xray/access.log", "loglevel": "warning" }
```

Затем `docker compose up -d`. Именно так работает боевая нода из полевого прогона.

### Что важно

- У клиентов должен быть задан `email` — панели ставят туда ID или имя пользователя.
  Без него субъектом станет IP клиента (за relay — один на всех).
- Sniffing с `destOverride` без `"routeOnly": true` подменяет IP на домен — такие строки
  не сопоставить (счётчик `domain_lines` в `/health`). Пиры BT ходят по IP, поэтому
  основной трафик всё равно сопоставляется, но `routeOnly: true` лучше.
- Лог усекает сам xtg (`XTG_LOG_MAX`), logrotate не нужен. Если всё же используете —
  только с `copytruncate`.

## ⚙️ Настройка

Всё в `/etc/default/xtg`, после правки — `sudo systemctl restart xtg`.

```bash
XTG_IFACE=eth0                    # внешний интерфейс ноды
XTG_LOG=/run/xray/access.log      # access-лог Xray
XTG_LOG_MAX=64M                   # усекать лог после стольких прочитанных байт
XTG_API=127.0.0.1:9090            # HTTP API (только localhost!)
XTG_ARGS=                         # обработчик и тонкая настройка, см. ниже
```

| Опция для `XTG_ARGS` | По умолчанию | Смысл |
|---|---|---|
| `--threshold N` | 100 | порог оценки для события |
| `--window S` | 60 | окно суммирования слабых сигналов, с |
| `--fanout N` | 40 | порог веера UDP-пиров в минуту |
| `--cooldown S` | 60 | не чаще одного события на пользователя за S с |
| `--webhook URL` | — | POST события в JSON |
| `--exec CMD` | — | команда на каждое событие |

Юнит работает с минимальными правами: `CAP_NET_RAW` (захват), `CAP_NET_ADMIN` (буфер
приёма), `CAP_DAC_OVERRIDE` (усечение лога), запись только в `/run/xray` и
`/var/lib/xtg`, `MemoryMax=256M`, `CPUQuota=50%`. События сохраняются в
`/var/lib/xtg/events.jsonl` и переживают перезапуск.

## 🎯 Что делать с событиями

> 💡 **Лайфхак:** первые дни держите xtg наблюдателем (`XTG_ARGS=` пустой), смотрите
> `/v1/events` и сверяйте с access-логом. Включайте бан, когда убедитесь, что срабатывания
> настоящие. Поднимите `--cooldown` до 600, чтобы один качальщик не сыпал событиями.

В обработчик приходят переменные `XTG_SUBJECT` (email или IP), `XTG_SUBJECT_KIND`
(`user`/`ip`), `XTG_SCORE`, `XTG_REMOTE`, `XTG_REASONS`, `XTG_EVENT` (весь JSON).

**Уведомление в Telegram:**

```bash
XTG_ARGS="--cooldown 600 --exec '/usr/local/bin/xtg-tg'"
```

```sh
#!/bin/sh
# /usr/local/bin/xtg-tg
curl -s "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
  --data-urlencode chat_id="$TG_CHAT" \
  --data-urlencode text="🧲 торрент: $XTG_SUBJECT ($XTG_REASONS)" >/dev/null
```

**Бан по IP через nftables** (без relay, когда у клиента свой IP):

```bash
nft add table inet xtg
nft add set inet xtg banned '{ type ipv4_addr; timeout 1h; }'
nft add chain inet xtg in '{ type filter hook input priority 0; }'
nft add rule inet xtg in ip saddr @banned drop
XTG_ARGS="--exec 'nft add element inet xtg banned { \$XTG_SUBJECT }'"
```

**Бан пользователя в панели:** `--webhook http://127.0.0.1:8000/xtg` на свой сервис,
который по `subject` отключает пользователя через API панели (Remnawave, Marzban, 3x-ui).
Так работает за relay, где IP у всех один.

## 📊 Результаты

### Что ловится

| Сигнал | Вес | Чем подтверждено |
|---|---|---|
| BT handshake (TCP и внутри uTP) | 100 | юнит + стенд + бой |
| DHT KRPC (с проверкой bencode) | 100 | юнит + pcap + бой |
| HTTP announce/scrape | 100 | юнит + стенд + бой |
| UDP-трекер (BEP 15) | 100 | юнит-тест |
| LSD (BEP 14) | 100 | юнит-тест |
| uTP-заголовок (кроме STUN) | 20/пир, до 100 | юнит + стенд + бой |
| Кандидат MSE/PE (кроме 443, 80, 22…) | 10/пир, до 100 | юнит + стенд + бой |
| Веер UDP ≥ 40 пиров/мин | 50 | юнит-тест |

### Боевая нода, сутки (13–14.11.2026)

VLESS/Reality + Hysteria за relay, ~220 активных пользователей в час, режим наблюдателя.

| | |
|---|---|
| Событий / пользователей | 67 / 3 |
| Подтверждено по логу Xray | 1 из 1 проверяемого (трекер на 6969, десятки пиров) |
| Ложных срабатываний | не найдено |
| Пропусков в проверенном окне (1 ч, 224 польз.) | не найдено |
| Ресурсы | ~5% CPU, ~4 МБ RSS, 0 потерь пакетов после обновления |

Подробно и с ограничениями — [docs/field-test-2026-11.md](docs/field-test-2026-11.md).
Стенд с qBittorrent/Transmission/libtorrent — [testbed/results.md](testbed/results.md),
как воспроизвести — [testbed/README.md](testbed/README.md).

## 📡 API

| Запрос | Ответ |
|---|---|
| `GET /health` | `{"status":"ok","version":"…","packets":N,"xray":{…}}` |
| `GET /v1/events?since=ID` | события с `id > ID` (последние 1000) |
| `GET /v1/subjects` | текущие оценки субъектов |

```json
{"id":1,"ts":1700000001.000000,"type":"torrent_detected","subject":"alice",
 "subject_kind":"user","score":100,"proto":"udp","remote":"87.98.162.88","reasons":{"dht":1}}
```

API без авторизации — слушайте только `127.0.0.1`.

## 🧪 Разбор записи и ручной запуск

```bash
xtg analyze capture.pcap                                   # события в stdout
xtg analyze capture.pcap --xray-log access.log --log-utc-offset +03:00
sudo xtg run --iface wg0 --api 127.0.0.1:9090              # без лога: субъект — IP (TUN/WireGuard)
xtg --help
```

## ❓ FAQ и неполадки

**`/health` — `packets` растёт, а `xray.lines` 0.** Xray не пишет лог в `/run/xray/access.log`:
проверьте `"log"` в конфиге, монтирование для Docker и что Xray перезапущен.

**События с `subject_kind: ip` и IP relay.** У клиентов нет `email` или строка не
сопоставилась (`domain_lines` в `/health` — включите `routeOnly`).

**В журнале «ядро потеряло N пакетов».** Не хватает CPU: проверьте `CPUQuota` в юните и
нагрузку ноды. Буфер приёма уже увеличен через `SO_RCVBUFFORCE`.

**Падает при перезапуске сети.** Захват переживает пропажу интерфейса; если сеть не
вернулась, systemd перезапустит службу (`Restart=always`).

**Два пользователя на одном `IP:порт`.** Берётся тот, чья строка в логе ближе к началу потока.

**Удаление:**

```bash
sudo systemctl disable --now xtg
sudo rm /usr/local/bin/xtg /etc/systemd/system/xtg.service /etc/default/xtg /etc/tmpfiles.d/xtg.conf
sudo rm -rf /var/lib/xtg
```

## Принципы

- Никаких данных пользователей в репозитории и логах по умолчанию.
- Работает на типовой VPS (1 vCPU, 1 ГБ).
- Каждое «ловит/не ловит» подтверждено воспроизводимым тестом.
- Сторонние блокеры — только эталон для сравнения на стенде.

## Лицензия

[MIT](LICENSE)
