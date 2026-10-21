# Ранбук: VPS для испытаний HTTP/3 (стадия 1)

Пошаговая настройка стенда из [`deploy/trial-server/`](../deploy/trial-server) и прогон гипотез H1, H2, H3, H6 (и H0, если есть зарубежный REALITY-сервер). План и сами гипотезы — в [`h3-transport-plan.md`](h3-transport-plan.md).

Один стенд = один VPS + один домен. Второй VPS у другого хостера даёт H7. Всё остальное делает `scripts/tspu-trial.sh` с машины тестировщика.

## 1. Какой провайдер брать

Главное ограничение: **VPS должен быть физически за границей**. Российская локация для H1/H2/H3/H6 бесполезна — трафик не пересекает границу и ТСПУ его не видит. Именно поэтому уже имеющиеся серверы в московских локациях для этих гипотез не подходят, хотя как рабочие прокси они нормальны.

| Роль | Кто | Локация | Оплата из РФ | Почему |
|---|---|---|---|---|
| Основной стенд | **Aeza** | Амстердам или Франкфурт | карта РФ, СБП, крипта; почасовая | 35–50 мс из Москвы, KVM/NVMe, 1 Гбит/с, почасовой биллинг — легко удалить после тестов |
| Второй стенд для H7 | **PQ Hosting** или **HostVDS** | Амстердам / Кишинёв | карта РФ, СБП, крипта | другой ASN и другая страна — сравнение репутации |
| «Крупный» провайдер для H7 | **Timeweb Cloud**, **RUVDS** или **VDSina EU** | ЕС | карта РФ, СБП | если Hetzner недоступен, это ближайший аналог «известного» ASN |
| Эталон «известного» ASN | **Hetzner** (AS24940) | Falkenstein / Helsinki | **нет**: с 2024 не обслуживает адреса в РФ, карты РФ не принимает | только если есть зарубежная карта и не российский адрес в профиле |

Практический выбор по умолчанию: **Aeza NL** для первого стенда и **PQ Hosting NL/MD** для второго. Этого достаточно, чтобы закрыть H1/H2/H3/H6 и получить осмысленную пару для H7. Hetzner не стоит трудов: без иностранной карты и не российского billing-адреса аккаунт всё равно не заведут, а для H7 важнее не бренд, а разные ASN — запишите ASN в отчёт, и подмена будет видна.

Чего избегать:

- локаций в РФ и «Россия-оптимизированных» площадок, даже если провайдер иностранный;
- OpenVZ (нужен KVM);
- провайдеров, чья DDoS-защита фильтрует или проксирует UDP/443 — тогда H1 упадёт не из-за ТСПУ, а из-за хостера;
- бесплатных и «серых» IP: репутация AS — это как раз то, что проверяет H7;
- CDN/WARP в качестве выхода.

Минимальная конфигурация: 1 vCPU, 1 ГБ RAM (2 ГБ, если хотите держать Hysteria вместе с Caddy), 10–20 ГБ NVMe, порт 1 Гбит/с, 1 ТБ трафика в месяц, Ubuntu 24.04, IPv4. IPv6 можно не заказывать; если он есть, AAAA-запись должна реально работать, иначе `curl` будет пытаться в IPv6 и «морозиться» на ровном месте.

## 2. Домен

Нужен любой домен, которым вы управляете. Подойдёт поддомен: `trial.example.com`.

- A-запись → IPv4 VPS. AAAA — только если IPv6 на VPS рабочий.
- Если домен в Cloudflare, **выключите оранжевое облако** (DNS only). Иначе TLS терминирует Cloudflare, HTTP/3 идёт к Cloudflare, а не к вашему Caddy, и сертификат Let's Encrypt не выпустится по HTTP-01.
- Порт 80 должен быть открыт снаружи: Caddy получает сертификат через HTTP-01.
- Домен лучше нейтральный, не похожий на VPN-панель: его будет видеть ТСПУ и активный пробинг (H8).

Проверка до установки:

```sh
dig +short trial.example.com        # должен вернуть IP VPS
```

## 3. Первый вход и база

```sh
ssh root@203.0.113.10

apt update && apt -y upgrade
apt -y install ca-certificates curl gnupg git jq ufw iperf3
timedatectl set-timezone Europe/Moscow
```

Сразу проверьте, что вход по ключу работает, и только потом отключайте пароль. На облачных Ubuntu настройки часто лежат не в `sshd_config`, а в `sshd_config.d/*.conf`, поэтому смотрите эффективное значение:

```sh
sshd -T | grep -E '^(passwordauthentication|permitrootlogin)'
```

Если `passwordauthentication yes`, поправьте файл, который её включает (обычно `/etc/ssh/sshd_config.d/50-cloud-init.conf`), затем:

```sh
sshd -t && systemctl reload ssh
sshd -T | grep -E '^(passwordauthentication|permitrootlogin)'
```

Docker (официальный репозиторий, не get.docker.com):

```sh
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  >/etc/apt/sources.list.d/docker.list
apt update
apt -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
docker compose version
```

## 4. Firewall

Открыть ровно то, что использует стенд:

| Порт | Зачем |
|---|---|
| 22/tcp | SSH |
| 80/tcp | Let's Encrypt HTTP-01 |
| 443/tcp | сайт и Alt-Svc |
| 443/udp | HTTP/3 (Caddy) |
| 5201/tcp, 5201/udp | iperf3 (H3) |
| 8443/udp, 8444/udp | Hysteria 2 Brutal / BBR (H4) |

```sh
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow 5201/tcp
ufw allow 5201/udp
ufw allow 8443/udp
ufw allow 8444/udp
ufw --force enable
ufw status
```

Важно: **Docker публикует порты через свой iptables и обходит ufw**. Если у провайдера есть cloud firewall / security group (Hetzner, Aeza, Timeweb), настройте те же порты там — это надёжнее. UFW всё равно полезен: он закрывает всё, что не опубликовано контейнерами.

## 5. UDP-буферы для QUIC

Без этого quic-go в Caddy предупреждает и HTTP/3 работает медленнее:

```sh
cat >/etc/sysctl.d/99-quic.conf <<'EOF'
net.core.rmem_max=7500000
net.core.wmem_max=7500000
EOF
sysctl --system
```

TCP congestion control не трогаем: на стенде должен остаться CUBIC, как у Chrome, иначе сравнение h2/h3 в H2 будет нечестным.

## 6. Стенд

```sh
git clone https://github.com/maxeliseyev/vless-proxy.git
cd vless-proxy/deploy/trial-server
bash setup.sh trial.example.com          # .env, 10 МБ и 1 ГБ, конфиги Hysteria
docker compose up -d                     # Caddy + iperf3
docker compose logs -f caddy             # ждать "certificate obtained successfully"
```

Когда сертификат получен:

```sh
docker compose --profile hysteria up -d  # 8443 Brutal, 8444 BBR
docker compose ps
```

`setup.sh` печатает ссылки `hysteria2://…` — они нужны для ручного H4 официальным клиентом. Файлы `.env`, `hy2-*.yaml`, `.hy2-password` и `site/*.bin` в git не попадают.

## 7. Проверка стенда

С машины тестировщика (не с VPS, иначе проверяется loopback):

```sh
# curl с HTTP/3: на macOS ставится brew install curl, бинарник keg-only
# Apple Silicon: /opt/homebrew, Intel: /usr/local
export PATH="/opt/homebrew/opt/curl/bin:$PATH"
curl --version | grep HTTP3

curl --http3-only -sI https://trial.example.com/ | head -1       # HTTP/3 200
curl -sI https://trial.example.com/ | grep -i alt-svc            # alt-svc: h3=":443"
curl -sI https://trial.example.com/10m.bin | head -1             # 200, Content-Length: 10485760
iperf3 -c trial.example.com -p 5201 -t 5                          # TCP
iperf3 -u -c trial.example.com -p 5201 -b 10M -t 10               # UDP, гипотеза H3
```

Если `--http3-only` не проходит, а h2 проходит — это уже результат H1, а не «стенд сломан». Сначала исключите хостерский firewall и проверьте с другой сети.

## 8. Прогон с российской сети

### Выключите TUN и VPN

Это критично. Пока работает `vproxy --tui --tun` (или Happ, или любой системный VPN), вы измеряете не ТСПУ, а свой туннель. Признак: `curl https://ipinfo.io/ip` показывает не российский IP, а скрипт печатает «внешний IP не в России».

Отдельная ловушка: **при включённом TUN ping и `nc` врут**. Sing-box отвечает на ICMP сам, поэтому `ping 192.0.2.1` (TEST-NET, которого не существует) даёт «0% loss», а `nc -z` показывает «порт открыт», хотя пакеты никуда не идут. Для проверки в обход TUN используйте `curl --interface en0` или `ssh -o BindInterface=en0`.

### Что нужно на машине тестировщика

- `curl` с HTTP/3 (скрипт сам найдёт Homebrew-сборку);
- `iperf3` (`brew install iperf3` / `apt install iperf3`);
- `vproxy` — только для H0, путь передаётся через `-b` (для локальной сборки: `-b ./target/debug/vproxy`);
- файл ссылок для H0: две строки на **один и тот же зарубежный REALITY-сервер**, отличаются только `fp`:

```
vless://...&fp=chrome#reality-chrome
vless://...&fp=chrome133#reality-chrome133
```

Если зарубежного REALITY-сервера нет, H0 пропустите. Российские серверы для H0 бессмысленны: соединение до них не пересекает границу. Как проверка того, что обе ссылки и оба отпечатка рабочие, H0 всё равно полезен, но выводов о ТСПУ не даст.

### Запуск

```sh
bash scripts/tspu-trial.sh \
  -n "МТС, мобильная, Москва" \
  -i trial.example.com:5201 \
  -f links.txt \
  -r 3 \
  -o results/
```

- `-r 3` — три прогона с паузой 600 с. Пауза обязательна: заморозка привязана к IP клиента и SNI и живёт 120–600 с.
- `-q` — быстрый прогон без 1 ГБ и долгого соединения; для отчёта не годится, только чтобы проверить, что всё запускается.
- `-k` — не проверять сертификат; только для локальной отладки, в отчёт не идёт.

Скрипт закрывает H1, H2 (10 МБ, 1 ГБ, долгое соединение), H3, H6 и H0. Отчёт — `results/tspu-trial-*.txt`, сырой лог — `*.log`. В отчёт попадает таблица «тест | сеть | время | вердикт | детали»; лог нужен, если что-то пошло не так.

Один прогон = одна сеть. Не смешивайте в одном отчёте Wi-Fi и мобильный, разные регионы и разные операторы.

## 9. H7: второй VPS

Поднимите второй стенд по этому же ранбуку у другого провайдера (другой ASN и, желательно, другая страна), с другим доменом. Затем:

```sh
bash scripts/tspu-trial.sh -n "..." -i trial2.example.com:5201 \
  -f links.txt -r 3 -o results/h7-hoster2 \
  https://trial2.example.com
```

Сравнивайте не «работает/не работает», а вердикты по каждой гипотезе и скорость. В отчёт добавьте IP, ASN и дата-центр обоих VPS — без этого H7 не читается.

## 10. H4: Hysteria 2 вручную

`setup.sh` печатает две ссылки `hysteria2://…` — Brutal (8443) и BBR (8444). Их проверяют официальным клиентом Hysteria на тех же сетях, что и основной прогон:

- подключиться, скачать `10m.bin` и `1g.bin` через SOCKS5-порт клиента, сравнить Brutal и BBR;
- отдельно отметить, есть ли заморозка после N МБ и на каком варианте;
- TUIC в этом стенде нет: если он нужен, это отдельный сервер, и H4 по TUIC проверяется отдельно.

Скрипт `tspu-trial.sh` Hysteria не проверяет — это ручная часть.

## 11. H8: активный пробинг

Через неделю после начала испытаний:

```sh
cd vless-proxy/deploy/trial-server
docker compose exec caddy cat /data/access.log \
  | jq -r '[.ts, .request.remote_ip, .request.uri, (.request.headers."User-Agent"[0] // "-")] | @tsv' \
  | sort | uniq -c | sort -rn | head -50
```

Ищите запросы с российских IP, не похожие на тестировщиков: чужие User-Agent, обход `/`, `/.env`, `/admin`, сканирование путей. Это ответ на вопрос «достаточно ли маскировки сайтом».

## 12. Что считать результатом

Минимальный набор для выводов:

- 3 прогона на сеть, пауза ≥ 10 минут;
- зафиксированы оператор, тип сети, город, время (МСК), IP и ASN VPS;
- есть отчёт и лог;
- TUN/VPN выключены, внешний IP российский;
- для H7 — два разных ASN.

Без этого это не измерение, а «вроде работало».

## 13. Если что-то не работает

| Симптом | Куда смотреть |
|---|---|
| Сертификат не выпускается | 80/tcp закрыт, DNS не указывает на VPS, Cloudflare proxy включён, `docker compose logs caddy` |
| `--http3-only` таймаутит, h2 работает | UDP/443 режет хостер или провайдер; проверьте cloud firewall и `ss -ulpn \| grep 443`; это может быть результатом H1 |
| Hysteria не стартует | `docker compose logs hy2-brutal`; сертификат ещё не выпущен или путь в `hy2-*.yaml` не совпал |
| `docker compose: command not found` | не установлен `docker-compose-plugin` |
| iperf3 без итоговой строки | UDP/5201 закрыт, контейнер `iperf3` не запущен |
| В отчёте внешний IP не РФ | включён TUN/VPN; выключите и перезапустите |
| `10m.bin`/`1g.bin` отдают 404 | не запускали `setup.sh` или том `./site` не смонтирован |
| `curl` без HTTP/3 | `brew install curl`, проверить `curl --version \| grep HTTP3`; скрипт ищет Homebrew-путь сам |
| H0 падает на обеих ссылках | vproxy не в PATH/неверный `-b`, ссылки от разных серверов, порт 18081+ занят |
| H0 «работает», но это ничего не значит | REALITY-сервер в РФ; для H0 нужен зарубежный |

## 14. Убрать за собой

```sh
cd vless-proxy/deploy/trial-server
docker compose --profile hysteria down -v     # контейнеры, сеть и сертификаты
```

Затем удалите A-запись и уничтожьте VPS. При почасовой оплате (Aeza, HostVDS) это стоит копейки, но забытый стенд с 1 ГБ файлом и открытым iperf3 — плохая идея.
