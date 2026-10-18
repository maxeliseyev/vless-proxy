#!/usr/bin/env bash
# Готовит тестовый сервер: .env с доменом, файлы для скачивания, конфиги Hysteria 2.
#   bash setup.sh домен
set -eu
cd "$(dirname "$0")"

DOMAIN=${1:-${DOMAIN:-}}
if [ -z "$DOMAIN" ]; then
    echo "использование: bash setup.sh домен" >&2
    exit 1
fi
printf 'DOMAIN=%s\n' "$DOMAIN" >.env

mkdir -p site
if [ ! -f site/10m.bin ]; then
    echo "site/10m.bin ..."
    head -c 10485760 /dev/urandom >site/10m.bin
fi
if [ ! -f site/1g.bin ]; then
    echo "site/1g.bin (около минуты) ..."
    head -c 1073741824 /dev/urandom >site/1g.bin
fi

if [ -f .hy2-password ]; then
    PASSWORD=$(cat .hy2-password)
else
    PASSWORD=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    printf '%s\n' "$PASSWORD" >.hy2-password
    chmod 600 .hy2-password
fi

gen() {
    sed -e "s/__PORT__/$2/" -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__PASSWORD__/$PASSWORD/" -e "s/__IGNORE_BW__/$3/" \
        hysteria.yaml.tmpl >"hy2-$1.yaml"
}
gen brutal 8443 false
gen bbr 8444 true

cat <<MSG

Готово. Дальше:
  docker compose up -d                       # Caddy (HTTP/3 на 443/udp) + iperf3
  docker compose logs caddy | grep -i certificate   # дождаться сертификата
  docker compose --profile hysteria up -d    # Hysteria 2 на 8443 (Brutal) и 8444 (BBR)

Проверка с любой машины:
  curl --http3-only -sI https://$DOMAIN/ | head -1
  iperf3 -u -c $DOMAIN -b 10M -t 10

Ссылки для тестировщиков (H4):
  hysteria2://$PASSWORD@$DOMAIN:8443/?sni=$DOMAIN#brutal
  hysteria2://$PASSWORD@$DOMAIN:8444/?sni=$DOMAIN#bbr
Скрипт тестировщиков:
  bash tspu-trial.sh -n "сеть" -i $DOMAIN:5201 https://$DOMAIN
MSG
