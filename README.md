# vproxy

Терминальный VLESS-клиент на Rust для macOS и Linux с **собственной реализацией ядра**: REALITY и XTLS Vision написаны на Rust, а не делегированы xray-core. Один бинарник, локальный SOCKS5/HTTP-прокси или системный VPN через TUN, TUI со статистикой, routing-правила.

Подробный план и история решений: [`ROADMAP.md`](ROADMAP.md).

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

Из исходников: `cargo build --release` (нужен Rust stable; rustls берётся из форка [maxeliseyev/rustls](https://github.com/maxeliseyev/rustls/tree/reality-0.23) автоматически). Форк раз в неделю сливается с upstream `rel-0.23` workflow'ом `rustls fork sync`: он прогоняет тесты rustls и vproxy, обновляет `rev` в `Cargo.toml`, а конфликт слияния или выход rustls 0.24 превращает в issue.

Для системного режима (TUN) дополнительно нужен [sing-box](https://sing-box.sagernet.org). Его ставит сам vproxy:

```sh
vproxy install-sing-box              # Homebrew на macOS, официальный репозиторий sing-box на deb/rpm/Arch,
                                     # иначе релиз с GitHub в ~/.config/vproxy/bin; --download принудительно скачивает
```

Без Homebrew на macOS команда предложит поставить и его. При `sudo vproxy --tun` без sing-box vproxy тоже предложит установку. Свой бинарник указывается `--sing-box /path` или `tun.sing_box_path` в TOML.

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
sudo vproxy --tun           # весь системный трафик через сервер (sing-box TUN)
sudo vproxy --tui --tun     # системный режим с интерфейсом
```

Проверка: `curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org` (локальный режим) или просто `curl https://api.ipify.org` (TUN).

### В фоне

Чтобы vproxy работал после закрытия терминала и поднимался при входе или загрузке, он ставится как сервис (launchd на macOS, systemd на Linux):

```sh
vproxy service install -f server.txt            # локальный прокси, агент пользователя
sudo vproxy service install --tun -f server.txt # системный VPN, демон с root
vproxy service status | logs | uninstall        # с --tun для системного
```

Пути к бинарнику, конфигу и sing-box записываются в сервис абсолютными. Логи: `~/Library/Logs/vproxy.log` или `/var/log/vproxy.log` на macOS, `journalctl -u vproxy` на Linux.

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
vproxy --print-tun-config -f server.txt   # показать сгенерированный конфиг sing-box
```

Поддерживаются ссылки с `security=reality|tls|none`, транспортом `type=tcp|ws|xhttp` (`path`, `host`, `mode`, `extra`), `flow=xtls-rprx-vision`, параметрами `pbk`, `sid`, `sni`, `fp` (`chrome` по умолчанию, `none` отключает имитацию), `spx`, `alpn`, и `#имя` сервера.

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
- **REALITY нативно**: X25519 + HKDF auth key, аутентификатор в `session_id` ClientHello (AES-256-GCM), проверка сертификата сервера по HMAC-SHA512, гибридный key share X25519MLKEM768, который требуют современные серверы. Поверх форка rustls с двумя хуками.
- **Отпечаток TLS как у Chrome** (`fp=chrome`, включён по умолчанию для REALITY, TLS, WS и XHTTP): ClientHello пересобирается по профилю uTLS `HelloChrome_133`, который шлёт сам Xray: набор и порядок шифров, 16 расширений в случайном порядке, GREASE в пяти местах, GREASE ECH, ALPS, SCT, session ticket. JA4 совпадает с Chrome (`t13d1516h2_8daaf6152771_d8a2da3f94cd`), проверить можно командой `cargo run --example fingerprint`. Отключается `fp=none`.
- **XTLS Vision нативно**: паддинг на время внутреннего TLS-handshake и прямая пересылка TCP (direct copy) для TLS 1.3 без двойного шифрования. Для этого REALITY-поток ведётся собственным драйвером поверх `rustls::ClientConnection` по одной TLS-записи за раз.
- **TUN-режим** по схеме Happ: sing-box держит интерфейс и отдаёт всё в локальный SOCKS5; конфиг генерируется автоматически и защищён от петель.
- **Routing**: direct / proxy / block по доменам, CIDR, приватным адресам, портам, geoip/geosite.
- **TUI**: сервер и режим, соединения, трафик и скорость, логи; переключение между серверами из `server.txt` без перезапуска (новые соединения идут через выбранный, выбор запоминается), добавление сервера вставкой ссылки (`a`) и удаление (`d`) прямо из интерфейса; задержка handshake по каждому серверу (замер при старте и по `p`), `b` переключает на самый быстрый.
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
- `sudo vproxy --tun` и root-сервис запускают sing-box/xray из обычных путей, в том числе Homebrew (`/opt/homebrew/bin` принадлежит пользователю): vproxy предупредит, если бинарник доступен на запись не только root. Зависимости проверяются `cargo audit` в CI.

## Разработка

```sh
cargo test                   # 99 unit + 5 e2e
cargo clippy --all-targets
```

Структура `src/`: `config/` (TOML, ссылки, списки серверов, подписки, импорт Xray и Amnezia), `protocol/` (VLESS, REALITY, Vision, Mux.Cool, отпечаток Chrome), `transport/` (TLS, WebSocket, XHTTP), `inbound/` (SOCKS5, HTTP), `proxy/` (relay, routing, DNS, счётчики), `system/` (TUN через sing-box, установка sing-box, сервисы, xray-sidecar), `ui/` (TUI); `main.rs` только разбирает аргументы. Релизы собирает GitHub Actions по тегу `v*`.
