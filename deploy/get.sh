#!/bin/sh
# Установка xtg одной командой, без Rust и сборки:
#   curl -fsSL https://raw.githubusercontent.com/BloodyBaronDev/xray-torrent-guard/main/deploy/get.sh | sudo sh
# Переменные: XTG_VERSION (тег релиза, по умолчанию последний), XTG_IFACE (по умолчанию —
# интерфейс маршрута по умолчанию), XTG_START=0 — только установить, не запускать.
set -eu
REPO=BloodyBaronDev/xray-torrent-guard
[ "$(id -u)" = 0 ] || { echo "нужен root: ... | sudo sh"; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "только Linux"; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo "готовый бинарник только для x86_64; соберите из исходников (cargo build --release)"; exit 1; }
command -v systemctl >/dev/null || { echo "нужен systemd; без него используйте Docker-образ"; exit 1; }

if [ -z "${XTG_VERSION:-}" ]; then
  XTG_VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=1" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
fi
[ -n "$XTG_VERSION" ] || { echo "не удалось узнать версию; задайте XTG_VERSION"; exit 1; }
echo "xtg $XTG_VERSION"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
REL="https://github.com/$REPO/releases/download/$XTG_VERSION"
RAW="https://raw.githubusercontent.com/$REPO/$XTG_VERSION/deploy"
curl -fsSL -o "$T/xtg-x86_64-linux-musl" "$REL/xtg-x86_64-linux-musl"
curl -fsSL -o "$T/SHA256SUMS" "$REL/SHA256SUMS"
(cd "$T" && grep ' xtg-x86_64-linux-musl$' SHA256SUMS | sha256sum -c -) \
  || { echo "контрольная сумма не сошлась"; exit 1; }
curl -fsSL -o "$T/xtg.service" "$RAW/xtg.service"
curl -fsSL -o "$T/xtg.default" "$RAW/xtg.default"

systemctl is-active -q xtg 2>/dev/null && WAS_ACTIVE=1 || WAS_ACTIVE=0
install -m 0755 "$T/xtg-x86_64-linux-musl" /usr/local/bin/xtg

XRAY_USER=$(systemctl show -p User --value xray 2>/dev/null || true)
echo "d /run/xray 0750 ${XRAY_USER:-root} root -" > /etc/tmpfiles.d/xtg.conf
systemd-tmpfiles --create /etc/tmpfiles.d/xtg.conf

if [ ! -f /etc/default/xtg ]; then
  IFACE=${XTG_IFACE:-$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')}
  install -m 0644 "$T/xtg.default" /etc/default/xtg
  [ -n "$IFACE" ] && sed -i "s/^XTG_IFACE=.*/XTG_IFACE=$IFACE/" /etc/default/xtg
  echo "создан /etc/default/xtg (интерфейс: ${IFACE:-не определён, впишите вручную})"
else
  echo "/etc/default/xtg уже есть — не трогаю"
fi
install -m 0644 "$T/xtg.service" /etc/systemd/system/xtg.service
systemctl daemon-reload

if [ "$WAS_ACTIVE" = 1 ]; then
  systemctl restart xtg; echo "обновлено и перезапущено"
elif [ "${XTG_START:-1}" = 1 ]; then
  systemctl enable --now xtg
fi

API=$(sed -n 's/^XTG_API=//p' /etc/default/xtg)
cat <<EOF

Готово. Осталось:
 1. Xray должен писать access-лог в /run/xray/access.log (см. README, «Настройка Xray»).
 2. Проверка: curl -s ${API:-127.0.0.1:9090}/health
 3. Обработчик событий (бан, уведомление): XTG_ARGS в /etc/default/xtg, затем systemctl restart xtg
EOF
