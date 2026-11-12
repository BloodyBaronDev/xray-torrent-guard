#!/bin/sh
# Установка xtg на ноду: бинарник, пользователь, каталог лога в tmpfs, systemd.
# Использование: sudo sh deploy/install.sh [путь/к/xtg]
set -eu
BIN=${1:-target/release/xtg}
[ -x "$BIN" ] || { echo "нет бинарника $BIN (cargo build --release)"; exit 1; }
install -m 0755 "$BIN" /usr/local/bin/xtg
# каталог в /run пересоздаётся при загрузке
XRAY_USER=$(systemctl show -p User --value xray 2>/dev/null || true)
XRAY_USER=${XRAY_USER:-root}
echo "d /run/xray 0750 $XRAY_USER root -" > /etc/tmpfiles.d/xtg.conf
systemd-tmpfiles --create /etc/tmpfiles.d/xtg.conf
[ -f /etc/default/xtg ] || install -m 0644 deploy/xtg.default /etc/default/xtg
install -m 0644 deploy/xtg.service /etc/systemd/system/xtg.service
systemctl daemon-reload
cat <<EOF
Готово. Дальше:
 1. В конфиге Xray: "log": {"access": "/run/xray/access.log", "loglevel": "warning"}
    и перезапустите Xray (файл появится при первом соединении).
 2. Проверьте /etc/default/xtg (интерфейс, обработчик событий).
 3. systemctl enable --now xtg && curl -s 127.0.0.1:9090/health
EOF
