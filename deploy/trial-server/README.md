# Тестовый сервер для испытаний HTTP/3-транспорта

Стадия 1 плана [docs/h3-transport-plan.md](../../docs/h3-transport-plan.md): измерения без нашего кода. На одном VPS поднимаются сайт с HTTP/3 (Caddy), iperf3 и два сервера Hysteria 2. По нему тестировщики прогоняют [scripts/tspu-trial.sh](../../scripts/tspu-trial.sh) и закрывают гипотезы H1, H2, H3, H4, H6; второй такой же VPS у другого хостера даёт H7.

## Что нужно

- VPS с Docker и docker compose, открытые порты: 80/tcp, 443/tcp, 443/udp, 5201/tcp+udp, 8443/udp, 8444/udp.
- Домен (или поддомен) с A-записью на IP VPS. Сертификат Let's Encrypt Caddy получает сам по HTTP-01, поэтому порт 80 должен быть доступен снаружи.

## Запуск

На VPS один раз поднять лимит UDP-буферов, иначе quic-go в Caddy предупреждает и HTTP/3 работает медленнее:

```sh
sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000
printf 'net.core.rmem_max=7500000\nnet.core.wmem_max=7500000\n' | sudo tee /etc/sysctl.d/99-quic.conf
```

```sh
git clone https://github.com/maxeliseyev/vless-proxy.git && cd vless-proxy/deploy/trial-server
bash setup.sh example.ru          # .env, site/10m.bin, site/1g.bin, hy2-brutal.yaml, hy2-bbr.yaml
docker compose up -d              # Caddy + iperf3
docker compose logs -f caddy      # ждать "certificate obtained successfully"
docker compose --profile hysteria up -d
```

Проверки с любой машины (нужен curl с HTTP/3, см. шапку `tspu-trial.sh`):

```sh
curl --http3-only -sI https://example.ru/ | head -1     # HTTP/3 200
curl -sI https://example.ru/ | grep -i alt-svc           # alt-svc: h3=":443"; ma=2592000
iperf3 -u -c example.ru -b 10M -t 10
```

`setup.sh` печатает ссылки `hysteria2://…` для официальных клиентов (H4) и готовую команду для тестировщиков.

## Детали

- HTTP/3 в Caddy включён по умолчанию, заголовок `Alt-Svc` он добавляет сам. Выпускающий центр закреплён на Let's Encrypt, чтобы путь к сертификату в томе `caddy_data` был известен Hysteria.
- Hysteria 2 слушает UDP 8443 (Brutal, когда клиент присылает bandwidth) и UDP 8444 (`ignoreClientBandwidth: true`, то есть BBR). Порт 443/udp занят Caddy, это осознанная разница с продуктивной схемой: H4 проверяет сигнатуру реализации, а не порт. Чужие клиенты и активный пробинг получают через Hysteria тот же сайт (маскировка на `http://caddy:8080`).
- После продления сертификата (раз в 60 дней) Hysteria надо перезапустить: `docker compose --profile hysteria restart`.
- iperf3 на 5201, а не на 443: это «неизвестный UDP на произвольном порту», как у raw-UDP-протоколов.
- Журнал доступа Caddy в JSON: `docker compose exec caddy cat /data/access.log`. Для H8 через неделю смотреть запросы с российских IP, которые не похожи на тестировщиков (другие User-Agent, обход всех страниц, запросы к `/.env`, `/admin` и т. п.).
- Пароль Hysteria хранится в `.hy2-password`, файлы `.env`, `hy2-*.yaml`, `*.bin` и пароль в git не попадают.
