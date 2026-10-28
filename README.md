# Ratatosk

**Ratatosk** — набор инструментов для устойчивого к цензуре доступа в интернет с **собственной реализацией ядра** на Rust: REALITY и XTLS Vision написаны с нуля (а не делегированы xray-core), плюс собственный транспорт QUIC/HTTP-3 с клиентом и сервером. Раньше проект назывался vproxy и был обычным VLESS-клиентом; теперь это шире, чем прокси.

Состав:
- **`vproxy`** — терминальный клиент для macOS/Linux: один бинарник, локальный SOCKS5/HTTP-прокси или системный VPN через TUN, TUI со статистикой, routing-правила.
- **`vproxy-server`** — серверный конец QUIC/HTTP-3-транспорта; обычным HTTP/3-клиентам отдаёт настоящий сайт (см. [docs/h3-transport-plan.md](docs/h3-transport-plan.md)).
- **ядро** (крейт `vproxy-core`) — REALITY, Vision, транспорты, netstack; общее для клиента, сервера и iOS.
- **Ratatosk (iOS)** — приложение на этом ядре, одноимённое зонтичному проекту ([отдельный репозиторий](https://github.com/maxeliseyev/ratatosk-ios)).

Имена бинарников, крейтов и образов (`vproxy`, `vproxy-server`) пока прежние — переименование артефактов под зонтичное имя запланировано отдельным релизом. Подробный план и история решений: [`ROADMAP.md`](ROADMAP.md).

## Установка

Готовые сборки для macOS (Apple Silicon и Intel) и Linux (x86-64 и arm64, glibc и статические musl для Alpine) в [GitHub Releases](https://github.com/maxeliseyev/vless-proxy/releases):

```sh
curl -fsSL https://raw.githubusercontent.com/maxeliseyev/vless-proxy/main/install.sh | sh
```

Скрипт определяет платформу, проверяет sha256 и ставит `vproxy` в `/usr/local/bin` (или `~/.local/bin`). Переменные: `VPROXY_VERSION=v0.12.0`, `VPROXY_PREFIX=~/.local/bin`.

Docker (образ `ghcr.io/maxeliseyev/vproxy`, linux/amd64 и linux/arm64, слушает `0.0.0.0:1080` внутри контейнера):

```sh
docker run -d --name vproxy -p 127.0.0.1:1080:1080 -v "$PWD/server.txt:/data/server.txt:ro" ghcr.io/maxeliseyev/vproxy
docker run -d --name vproxy -p 127.0.0.1:1080:1080 ghcr.io/maxeliseyev/vproxy -s 'https://provider/sub/token'
docker build -t vproxy .      # собрать самому (Alpine, статический musl)
```

Из исходников: `cargo build --release` (нужен Rust stable; rustls берётся из форка [maxeliseyev/rustls](https://github.com/maxeliseyev/rustls/tree/reality-0.23) автоматически и раз в неделю синхронизируется с upstream `rel-0.23`). Системный режим (`--tun`) встроен в бинарник — внешних зависимостей вроде sing-box больше не нужно.

## Быстрый старт

```sh
vproxy
```

При первом запуске vproxy попросит вставить `vless://` ссылку прямо в терминал (кавычки не нужны), проверит её и сохранит в `~/.config/vproxy/server.txt`. Дальше:

```sh
vproxy                      # локальный SOCKS5 на 127.0.0.1:1080
vproxy --tui                # то же с интерфейсом: сервер, соединения, трафик, логи, q для выхода
                            # несколько ссылок в server.txt → список серверов, ↑↓ и Enter переключают на лету,
                            # a добавляет сервер (вставьте ссылку), d удаляет,
                            # p замеряет задержку всех серверов, b переключает на самый быстрый,
                            # u обновляет список из подписки
sudo vproxy --tun           # весь системный трафик через сервер (встроенный TUN, macOS/Linux)
sudo vproxy --tui --tun     # системный режим с интерфейсом
sudo vproxy --tun --split-ru  # .ru .su .рф — напрямую, мимо прокси (сплит-туннелинг)
```

Проверка: `curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org` (локальный режим) или просто `curl https://api.ipify.org` (TUN).

### В фоне

Чтобы vproxy работал после закрытия терминала и поднимался при входе или загрузке, он ставится как сервис (launchd на macOS, systemd на Linux):

```sh
vproxy service install -f server.txt            # локальный прокси, агент пользователя
sudo vproxy service install --tun -f server.txt # системный VPN, демон с root
vproxy service status | logs | uninstall        # с --tun для системного
```

Пути к бинарнику и конфигу записываются в сервис абсолютными. Логи: `~/Library/Logs/vproxy.log` или `/var/log/vproxy.log` на macOS, `journalctl -u vproxy` на Linux.

Подписка провайдера (страница с base64-списком ссылок, как у 3x-ui, Marzban, Remnawave):

```sh
vproxy -s 'https://provider/sub/token'   # список сохраняется в ~/.config/vproxy/server.txt (или в файл из -f)
vproxy --refresh                         # обновить список из подписки и выйти
```

Дальше достаточно `vproxy` или `vproxy --tui`: список обновляется сам, когда он старше интервала провайдера (`profile-update-interval`, по умолчанию 24 ч), клавиша `u` в TUI обновляет вручную. В заголовке файла хранятся URL, название, время обновления и трафик (`subscription-userinfo`), выбранный сервер помечается `# active:`, а ссылки после строки `# manual` (добавленные через `a` или дописанные руками) при обновлении сохраняются. Ссылки других протоколов (vmess, trojan, ss) пропускаются.

Другие способы указать сервер:

```sh
vproxy -f server.txt                 # ссылка из файла (строки с # игнорируются)
vproxy -u 'vless://...'              # ссылка аргументом, в кавычках
vproxy -c config.toml                # полный TOML-конфиг
vproxy --probe -f server.txt         # один handshake с сервером и отчёт
vproxy --ping -f server.txt          # задержка handshake для всех серверов списка
vproxy --split-ru                    # .ru .su .рф direct (= --direct-zone ru,su,рф)
vproxy --direct-zone ru,su,рф,cn     # свой список зон, которые идут мимо прокси
```

Поддерживаются ссылки с `security=reality|tls|none`, транспортом `type=tcp|ws|xhttp` (`path`, `host`, `mode`, `extra`), `flow=xtls-rprx-vision`, параметрами `pbk`, `sid`, `sni`, `fp` (`chrome` по умолчанию, `none` отключает имитацию), `spx`, `alpn`, и `#имя` сервера.

Конфиг Xray/Happ в JSON тоже подходит напрямую: `vproxy -c happ.json`. Берутся vless-outbound (адрес, uuid, tcp/ws, tls/reality), порт socks-inbound и правила `routing.rules` (domain/ip/port → direct/proxy/block; `geosite`/`geoip` разбираются, но пока не применяются — для зон по доменам есть `direct_suffix`).

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
direct_suffix = ["ru", "su", "рф"]  # сплит-туннелинг: эти зоны идут напрямую (= --split-ru)
[[routing.rules]]
outbound = "direct"          # proxy | direct | block
ip_private = true
[[routing.rules]]
outbound = "direct"
domain_suffix = ["ru", "su"]

[tun]
enabled = false              # то же, что --tun; нужен root
dns = "8.8.8.8"
dns_via_proxy = true
```

Правила routing имеют семантику sing-box: поля внутри одного правила объединяются по AND, списки по OR. `direct_suffix` добавляется как правило `direct` после ваших (явное правило побеждает); `.рф` сопоставляется с punycode `xn--p1ai`. Направление direct/proxy работает одинаково в локальном и в TUN-режиме.

Автозапуск: примеры в [`docs/launchd/`](docs/launchd) (macOS) и [`docs/systemd/`](docs/systemd) (Linux).

## Что реализовано

Главное достижение проекта: **протокольное ядро Xray перенесено на Rust и работает против боевых серверов без xray-core.**

- **VLESS** поверх TCP/TLS, **WebSocket** (`type=ws`, бинарные фреймы как в Xray) и **XHTTP** (`type=xhttp`: stream-one, stream-up и packet-up по HTTP/2 или HTTP/1.1, поверх REALITY, TLS или без шифрования, с паддингом и заголовками как у Xray): запрос, ленивый ответ, UDP-фреймы, SOCKS5 (`CONNECT`, `UDP ASSOCIATE`) и HTTP (`CONNECT`, обычные запросы) inbound. Импорт конфигов Xray/Happ из JSON и Amnezia VPN (`vpn://` ссылки и `.vpn` файлы с контейнером XRay).
- **REALITY нативно**: X25519 + HKDF auth key, аутентификатор в `session_id` ClientHello (AES-256-GCM), проверка сертификата сервера по HMAC-SHA512, гибридный key share X25519MLKEM768, который требуют современные серверы. Поверх форка rustls с двумя хуками.
- **Отпечаток TLS как у Chrome** (`fp=chrome`, включён по умолчанию для REALITY, TLS, WS и XHTTP): ClientHello пересобирается по профилю uTLS `HelloChrome_155` (Chrome stable с октября 2026): набор и порядок шифров, 17 расширений в случайном порядке, GREASE в шести местах, GREASE ECH, ALPS, SCT, session ticket, ML-DSA в signature_algorithms и `trust_anchors` со списком корней Chrome. JA4 `t13d1517h2_8daaf6152771_cb7bf5808d99`, проверить можно командой `cargo run --example fingerprint`. Прежняя форма Chrome 133 (её, по данным разработчиков Xray, ТСПУ выделяет и ограничивает) доступна как `fp=chrome133` для сравнения. Отключается `fp=none`.
- **XTLS Vision нативно**: паддинг на время внутреннего TLS-handshake и прямая пересылка TCP (direct copy) для TLS 1.3 без двойного шифрования. Для этого REALITY-поток ведётся собственным драйвером поверх `rustls::ClientConnection` по одной TLS-записи за раз.
- **TUN-режим** нативный, в одном процессе: собственный netstack + FakeDNS держат системный интерфейс и маршрутизацию, без sidecar и без внешних зависимостей (macOS/Linux; direct-соединения выходят через физический интерфейс).
- **Routing** и **сплит-туннелинг**: direct / proxy / block по доменам (суффикс/ключевое слово, включая IDN/punycode), CIDR, приватным адресам и портам; `direct_suffix` / `--split-ru` пускают зону `.ru` `.su` `.рф` напрямую мимо прокси.
- **TUI**: сервер и режим, соединения, трафик и скорость, лог с прокруткой (PgUp/PgDn, Home/End; свежие строки всегда видны) и его копия в `~/.config/vproxy/vproxy.log` с ротацией (5 MiB × 3, путь задаёт `--log-file`, `none` отключает); переключение между серверами из `server.txt` без перезапуска (новые соединения идут через выбранный, выбор запоминается), добавление сервера вставкой ссылки (`a`) и удаление (`d`) прямо из интерфейса; задержка handshake по каждому серверу (замер при старте и по `p`), `b` переключает на самый быстрый.
- **MUX (Mux.Cool)**: несколько TCP-сессий в одном VLESS-соединении (`[mux]`, импортируется из Xray JSON); для серверов с Vision не применяется, как и в Xray.
- **DNS**: remote/local, split-правила, кэш с TTL. Таймауты, лимит соединений, graceful shutdown.
- **Проверено**: сквозные тесты против xray-core (локально) и боевого REALITY+Vision сервера: TLS 1.3 цели уходят в direct copy в обе стороны, загрузки совпадают по хэшу, upload и параллельные запросы работают.

`xray-core` остаётся опциональным sidecar только для Vision поверх обычного `security=tls` (`runtime.reality_engine = auto|native|xray`).

## Безопасность

- Сервер аутентифицируется до отправки чего-либо: REALITY проверяет сертификат по auth key и рвёт соединение при любом несовпадении (без отката на обычный PKI), `security=tls` всегда проверяет сертификат по системным и webpki корням, опции вроде `allowInsecure` нет.
- Ссылки и подписки считаются недоверенными: `vpn://` не может задать адрес inbound или правила routing, числа из `extra` XHTTP ограничены, имена серверов и `profile-title` очищаются от управляющих символов.
- `server.txt` и `service.txt` содержат UUID и токен подписки, поэтому пишутся с правами `0600` в каталоге `0700`; в логах URL подписки показывается без пути. Ссылка в `-u` и URL в `-s` видны в `ps`, для постоянной работы лучше файл или `service install`.
- Если inbound слушает не loopback (`-l 0.0.0.0`, Docker), это открытый прокси для всех, кто дотягивается до порта: `direct`-соединения к приватным и loopback адресам в этом режиме отклоняются (и после DNS-резолва), чтобы контейнер не стал мостом в сеть хоста. Публиковать порт стоит только как `-p 127.0.0.1:1080:1080` или внутри доверенной сети.
- Отказ `accept()` при нехватке дескрипторов не роняет процесс, лимит открытых файлов поднимается при старте; UDP-ассоциация держит не более 128 целей.
- `sudo vproxy --tun` и root-сервис поднимают TUN в самом процессе vproxy, без запуска сторонних бинарников. Опциональный sidecar xray-core (только для Vision поверх обычного TLS) запускается из обычных путей — vproxy предупредит, если бинарник доступен на запись не только root. Зависимости проверяются `cargo audit` в CI.

## Разработка

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked
cargo fmt --all --check
```

Cargo workspace разделён на [ядро](crates/core/), [CLI-клиент](crates/cli/),
[сервер](crates/server/) и [FFI для iOS](crates/ffi/).
Границы пакетов, команды сборки и новые пути описаны в
[docs/architecture.md](docs/architecture.md). Конкретный продуктивный сайт
ведётся отдельно от публичного кода сервера. Релизы собирает GitHub Actions
по тегу `v*`.

Текущий статус и точка продолжения работы:
[checkpoint-2026-10-26.md](docs/checkpoint-2026-10-26.md).
