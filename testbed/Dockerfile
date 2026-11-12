# Инструменты стенда: Xray, tun2socks, Transmission, Python. Скачиваются при сборке,
# сам стенд работает в сети без выхода в интернет.
FROM alpine:3.20
ARG XRAY_VERSION=25.10.15
ARG TUN2SOCKS_VERSION=2.5.2
RUN apk add --no-cache transmission-daemon transmission-cli transmission-remote transmission-extra python3 curl iproute2 unzip bash tcpdump \
 && curl -fsSL -o /tmp/x.zip https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip \
 && unzip -q /tmp/x.zip xray -d /usr/local/bin \
 && curl -fsSL -o /tmp/t.zip https://github.com/xjasonlyu/tun2socks/releases/download/v${TUN2SOCKS_VERSION}/tun2socks-linux-amd64.zip \
 && unzip -q /tmp/t.zip -d /tmp/t && mv /tmp/t/tun2socks-linux-amd64 /usr/local/bin/tun2socks \
 && chmod +x /usr/local/bin/* && rm -rf /tmp/*
COPY scripts/ /opt/tb/
# на случай checkout с CRLF
RUN sed -i 's/\r$//' /opt/tb/* && chmod +x /opt/tb/*.sh
