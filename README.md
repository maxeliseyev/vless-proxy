# vproxy

Терминальный VLESS-клиент на Rust для macOS и Linux с **собственной реализацией ядра**: REALITY и XTLS Vision написаны на Rust, а не делегированы xray-core. Один бинарник, локальный SOCKS5/HTTP-прокси или системный VPN через TUN, TUI со статистикой, routing-правила.

Подробный план и история решений: [`ROADMAP.md`](ROADMAP.md).

## Установка

Готовые сборки для macOS (Apple Silicon и Intel) и Linux x86-64 в [GitHub Releases](https://github.com/maxeliseyev/vless-proxy/releases):

```sh
curl -fsSL https://raw.githubusercontent.com/maxeliseyev/vless-proxy/main/install.sh | sh
```

Скрипт определяет платформу, проверяет sha256 и ставит `vproxy` в `/usr/local/bin` (или `~/.local/bin`). Переменные: `VPROXY_VERSION=v0.7.0`, `VPROXY_PREFIX=~/.local/bin`.

Из исходников: `cargo build --release` (нужен Rust stable; rustls берётся из форка [maxeliseyev/rustls](https://github.com/maxeliseyev/rustls/tree/reality-0.23) автоматически).

Для системного режима (TUN) дополнительно нужен [sing-box](https://sing-box.sagernet.org): `brew install sing-box`.

## Быстрый старт

```sh
vproxy
```

При первом запуске vproxy попросит вставить `vless://` ссылку прямо в терминал (кавычки не нужны), проверит её и сохранит в `~/.config/vproxy/server.txt`. Дальше:

```sh
vproxy                      # локальный SOCKS5 на 127.0.0.1:1080
vproxy --tui                # то же с интерфейсом: сервер, соединения, трафик, логи, q для выхода
                            # несколько ссылок в server.txt → список серверов, ↑↓ и Enter переключают на лету,
                            # a добавляет сервер (вставьте ссылку), d удаляет
sudo vproxy --tun           # весь системный трафик через сервер (sing-box TUN)
sudo vproxy --tui --tun     # системный режим с интерфейсом
```

Проверка: `curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org` (локальный режим) или просто `curl https://api.ipify.org` (TUN).

Другие способы указать сервер:

```sh
vproxy -f server.txt                 # ссылка из файла (строки с # игнорируются)
vproxy -u 'vless://...'              # ссылка аргументом, в кавычках
vproxy -c config.toml                # полный TOML-конфиг
vproxy --probe -f server.txt         # один handshake с сервером и отчёт
vproxy --print-tun-config -f server.txt   # показать сгенерированный конфиг sing-box
```

Поддерживаются ссылки с `security=reality|tls|none`, транспортом `type=tcp|ws` (`path`, `host`), `flow=xtls-rprx-vision`, параметрами `pbk`, `sid`, `sni`, `fp`, `spx`, и `#имя` сервера.

Конфиг Xray/Happ в JSON тоже подходит напрямую: `vproxy -c happ.json`. Берутся vless-outbound (адрес, uuid, tcp/ws, tls/reality), порт socks-inbound и правила `routing.rules` (domain/ip/port → direct/proxy/block; geosite/geoip переносятся как rule-set для TUN-режима).

## Конфиг

Пример со всеми секциями: [`config.toml`](config.toml). Самое нужное:

```toml
[inbound]
port = 1080
protocol = "socks5"          # или "http"

[server]                     # то же, что в vless:// ссылке
address = "1.2.3.4"
port = 443
uuid = "..."
security = "reality"
sni = "www.example.com"
reality_public_key = "..."
reality_short_id = "..."
flow = "xtls-rprx-vision"

[routing]                    # первое совпавшее правило побеждает, иначе final
final = "proxy"
[[routing.rules]]
outbound = "direct"          # proxy | direct | block
ip_private = true
[[routing.rules]]
outbound = "direct"
domain_suffix = ["ru", "su"]
[[routing.rules]]
outbound = "direct"
geoip = ["ru"]               # geoip/geosite работают в TUN-режиме (rule-set sing-box)

[tun]
enabled = false              # то же, что --tun; нужен root и sing-box
dns = "8.8.8.8"
dns_via_proxy = true
```

Правила routing имеют семантику sing-box: поля внутри одного правила объединяются по AND, списки по OR. В локальном режиме vproxy сам открывает direct-соединения, в TUN-режиме те же правила транслируются в sing-box.

Автозапуск: примеры в [`docs/launchd/`](docs/launchd) (macOS) и [`docs/systemd/`](docs/systemd) (Linux).

## Что реализовано

Главное достижение проекта: **протокольное ядро Xray перенесено на Rust и работает против боевых серверов без xray-core.**

- **VLESS** поверх TCP/TLS, **WebSocket** (`type=ws`, бинарные фреймы как в Xray) и **XHTTP** (`type=xhttp`: stream-one, stream-up и packet-up по HTTP/2 или HTTP/1.1, поверх REALITY, TLS или без шифрования, с паддингом и заголовками как у Xray): запрос, ленивый ответ, UDP-фреймы, SOCKS5 (`CONNECT`, `UDP ASSOCIATE`) и HTTP (`CONNECT`, обычные запросы) inbound. Импорт конфигов Xray/Happ из JSON и Amnezia VPN (`vpn://` ссылки и `.vpn` файлы с контейнером XRay).
- **REALITY нативно**: X25519 + HKDF auth key, аутентификатор в `session_id` ClientHello (AES-256-GCM), проверка сертификата сервера по HMAC-SHA512, гибридный key share X25519MLKEM768, который требуют современные серверы. Поверх форка rustls с одним хуком в ~75 строк.
- **XTLS Vision нативно**: паддинг на время внутреннего TLS-handshake и прямая пересылка TCP (direct copy) для TLS 1.3 без двойного шифрования. Для этого REALITY-поток ведётся собственным драйвером поверх `rustls::ClientConnection` по одной TLS-записи за раз.
- **TUN-режим** по схеме Happ: sing-box держит интерфейс и отдаёт всё в локальный SOCKS5; конфиг генерируется автоматически и защищён от петель.
- **Routing**: direct / proxy / block по доменам, CIDR, приватным адресам, портам, geoip/geosite.
- **TUI**: сервер и режим, соединения, трафик и скорость, логи; переключение между серверами из `server.txt` без перезапуска (новые соединения идут через выбранный, выбор запоминается), добавление сервера вставкой ссылки (`a`) и удаление (`d`) прямо из интерфейса.
- **MUX (Mux.Cool)**: несколько TCP-сессий в одном VLESS-соединении (`[mux]`, импортируется из Xray JSON); для серверов с Vision не применяется, как и в Xray.
- **DNS**: remote/local, split-правила, кэш с TTL. Таймауты, лимит соединений, graceful shutdown.
- **Проверено**: сквозные тесты против xray-core (локально) и боевого REALITY+Vision сервера: TLS 1.3 цели уходят в direct copy в обе стороны, загрузки совпадают по хэшу, upload и параллельные запросы работают.

`xray-core` остаётся опциональным sidecar только для Vision поверх обычного `security=tls` (`runtime.reality_engine = auto|native|xray`).

## Разработка

```sh
cargo test                   # 99 unit + 5 e2e
cargo clippy --all-targets
```

Модули: `reality` (примитивы протокола), `reality_tls` (rustls-интеграция и драйвер потока), `vision`, `vless`, `routing`, `tun`, `tui`, `runtime` (relay и inbound'ы). Релизы собирает GitHub Actions по тегу `v*`.
