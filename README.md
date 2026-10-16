# vproxy

Терминальный VLESS-клиент на Rust для macOS/Linux без лишнего GUI. Проект строится как **reusable core library + тонкая CLI-обёртка**, чтобы один и тот же сетевой core можно было использовать и как локальный прокси в терминале, и позже встроить в другое приложение.

## Что делает проект

`vproxy` поднимает локальный inbound-прокси, принимает клиентские соединения, устанавливает удалённую VLESS-сессию до сервера и дальше проксирует трафик в обе стороны.

Подробный план развития проекта: [`ROADMAP.md`](ROADMAP.md).

Базовый pipeline:

`local client -> SOCKS5/HTTP inbound -> TCP/TLS -> VLESS request -> relay`

## Что уже реализовано

- **TLS transport** через `rustls` + `tokio-rustls`
- **VLESS framing**
  - request/response header для TCP
  - length-prefixed UDP frames поверх stream transport
- **SOCKS5 inbound**
  - `CONNECT`
  - `UDP ASSOCIATE`
- **HTTP inbound**
  - `CONNECT` для HTTPS-туннелей
  - обычные HTTP proxy requests для `http://...`
- **async relay** через Tokio
- **TOML-конфиг** с валидацией
- **vless:// URL parser** для быстрого запуска без конфига
- **Native REALITY transport** (Rust, без xray-core)
  - клиентская часть протокола REALITY портирована из Xray-core: auth key через X25519 + HKDF, аутентификатор в `session_id` ClientHello (AES-256-GCM), проверка сертификата сервера по HMAC-SHA512
  - работает поверх форка `rustls` с одним хуком (`ClientConfig::session_id_hook`), см. `[patch.crates-io]` в `Cargo.toml`
  - принимает `vless://` ссылки с `security=reality`, параметры `pbk`, `sid`, `sni`, `fp`, `spx`
  - `vproxy --probe` делает один handshake и показывает результат
- **Native XTLS Vision** (`flow=xtls-rprx-vision`, `xtls-rprx-vision-udp443`)
  - порт `proxy/proxy.go` из Xray-core: паддинг на время внутреннего TLS handshake, затем прямая пересылка TCP (direct copy) для TLS 1.3 без двойного шифрования
  - для TLS 1.2 и не-TLS трафика паддинг завершается командой End, трафик идёт через внешний TLS как обычно
  - REALITY-поток ведётся собственным драйвером поверх `rustls::ClientConnection` по одной TLS-записи за раз, поэтому момент переключения на raw-копирование известен точно
  - UDP на порт 443 отклоняется (как в Xray), чтобы QUIC упал на TCP; `-udp443` разрешает
- **xray-core sidecar** остаётся только для Vision поверх обычного `security=tls`
- **минимальная DNS policy**
  - `remote` resolve по умолчанию
  - опциональный `local` resolve через system DNS
  - выбор IPv4/IPv6 стратегии
- **library-first структура**
  - `src/lib.rs` — reusable core
  - `src/runtime.rs` — runtime и `ProxyClient`
  - `src/main.rs` — CLI wrapper

## Архитектура

### `config`

Загружает и валидирует конфиг. Сейчас поддерживаются:

- `inbound.protocol = "socks5"`
- `inbound.protocol = "http"`
- `server.security = "tls"`
- `server.security = "none"` при `use_tls = false`

### `tls`

Отвечает за TLS client-side transport. Trust store собирается из:

- системных сертификатов
- `webpki-roots`

### `vless`

Сериализует VLESS request header и читает response header. Сам VLESS здесь рассматривается как лёгкая transport-обёртка поверх TCP без отдельного шифрования внутри протокола.

### `dns`

Минимальный DNS layer, который пока не пытается быть отдельным DNS engine:

- по умолчанию домены сохраняются как domain target и резолвятся на remote side
- при `dns.mode = "local"` домен резолвится локально через system DNS
- `dns.strategy` управляет выбором IPv4/IPv6 адреса

### `runtime`

Главная reusable-часть проекта:

- `ProxyClient` устанавливает outbound VLESS-сессию к целевому адресу
- `serve(...)` поднимает локальный inbound и dispatch-ит его по протоколу

Это уже готовит проект к встраиванию в другие приложения: CLI не содержит внутри себя сетевую логику, а использует ту же библиотеку, которую позже можно будет оборачивать в iOS bridge/FFI.

### `reality` и `reality_tls`

`reality` содержит чистые примитивы протокола REALITY (без I/O), проверенные на векторах, сгенерированных Go-криптографией из Xray-core. `reality_tls` встраивает их в rustls: своя X25519 key-exchange группа (чтобы знать секрет key share), хук на `session_id` первого ClientHello и `ServerCertVerifier`, который принимает только сертификат, подписанный HMAC от выведенного auth key. Для этого используется форк rustls ([maxeliseyev/rustls](https://github.com/maxeliseyev/rustls), ветка `reality-0.23`) с патчем в ~75 строк.

### `vision` и `vless::VlessStream`

`vision` — чистая машина состояний XTLS Vision (паддинг, распаковка, классификатор TLS-трафика), покрытая тестами, включая обмен клиент/сервер между двумя экземплярами. `VlessStream` применяет её к сессии: отправляет заголовок запроса вместе с первыми данными клиента (или с пустым паддинг-блоком через 500 мс, как Xray), лениво читает заголовок ответа и переключает транспорт в direct-режим по команде пира.

### `xray_sidecar`

`xray-core` как sidecar-процесс нужен только для Vision поверх `security = "tls"` (REALITY + Vision работают нативно). Переключатель `runtime.reality_engine`:

- `auto` (default) — нативно; sidecar только для Vision поверх plain TLS
- `native` — всегда нативно; Vision поверх plain TLS отклоняется
- `xray` — всегда sidecar для REALITY/Vision

### `socks5` и `http`

Локальные inbound-модули только принимают запрос от локального клиента, извлекают target host/port и передают управление reusable runtime.

## Конфиг

Пример базового конфига:

```toml
[inbound]
address = "127.0.0.1"
port = 1080
protocol = "socks5" # или "http"

[server]
address = "example.com"
port = 443
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
use_tls = true
security = "tls"

[dns]
mode = "remote"          # или "local"
strategy = "prefer_ipv4" # prefer_ipv4 | prefer_ipv6 | ipv4_only | ipv6_only

[runtime]
connect_timeout_secs = 10
read_timeout_secs = 300
write_timeout_secs = 60
idle_timeout_secs = 600
max_connections = 1024
```

Для незашифрованного транспорта:

```toml
[server]
address = "example.com"
port = 1234
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
use_tls = false
security = "none"
```

Для REALITY:

```toml
[server]
address = "194.87.235.91"
port = 443
uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
security = "reality"
encryption = "none"
sni = "www.intel.com"
fingerprint = "chrome"
reality_public_key = "T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8"
reality_short_id = "b59cfeedfabf9f"
flow = "xtls-rprx-vision"
spider_x = "/"

[runtime]
reality_engine = "auto"
xray_path = "xray"
```

### Runtime параметры

Секция `[runtime]` управляет стабильностью и производительностью:

- `connect_timeout_secs` (default: 10) — таймаут подключения к серверу
- `read_timeout_secs` (default: 300) — таймаут чтения из сокета (5 мин)
- `write_timeout_secs` (default: 60) — таймаут записи в сокет (1 мин)
- `idle_timeout_secs` (default: 600) — таймаут бездействия (10 мин)
- `max_connections` (default: 1024) — лимит одновременных соединений
- `reality_engine` (default: `auto`) — `auto` / `native` / `xray`, см. раздел `xray_sidecar`
- `xray_path` (default: `xray`) — путь к `xray-core` для sidecar mode (сейчас нужен только для Vision)

### DNS кэш

Секция `[dns.cache]` управляет кэшированием DNS-запросов:

```toml
[dns.cache]
enabled = true          # включить/выключить кэш
max_entries = 1000      # максимум записей в кэше
ttl_secs = 300          # TTL по умолчанию (5 мин)
min_ttl_secs = 30       # минимальный TTL
max_ttl_secs = 3600     # максимальный TTL (1 час)
```

Кэш уменьшает нагрузку на system DNS и ускоряет повторные запросы.

### DNS правила (Split DNS)

Секция `[[dns.rules]]` позволяет настроить split DNS — разные домены резолвить по-разному:

```toml
[dns]
mode = "remote"
strategy = "prefer_ipv4"

[dns.cache]
enabled = true
max_entries = 1000
ttl_secs = 300

# Российские домены — локально
[[dns.rules]]
domain_suffix = ".ru"
resolve = "local"

# Китайские домены — локально
[[dns.rules]]
domain_suffix = ".cn"
resolve = "local"

# Конкретный домен — локально
[[dns.rules]]
domain = "example.com"
resolve = "local"

# Всё остальное — remote (по умолчанию)
```

**Параметры правила:**
- `domain_suffix` — суффикс домена (например, `.ru` для всех .ru доменов)
- `domain` — точное совпадение домена
- `domain_keyword` — ключевое слово в домене
- `resolve` — куда отправлять: `local` или `remote`

**Приоритет:** первое совпавшее правило выигрывает.

## Запуск

### Через vless:// ссылку

Быстрый запуск без создания конфига:

```bash
# Использовать vless:// URL напрямую
cargo run -- --url 'vless://uuid@host:port?security=tls'

# С кастомным inbound портом (default: 1080)
cargo run -- --url 'vless://...' --inbound-port 8080

# С проверкой конфига и verbose-логами
cargo run -- --url 'vless://...' --check-config --verbose
```

Формат vless:// URL:
```
vless://uuid@host:port?security=tls&sni=example.com#remark
```

Параметры:
- `security` — `tls`, `reality`, или `none`
- `sni` — SNI для TLS/REALITY
- `encryption` — тип шифрования (default: `none`)
- `pbk` — PUBLIC_KEY для REALITY
- `sid` — SHORT_ID для REALITY (до 16 hex символов, чётное количество)
- `fp` — fingerprint для REALITY (например `chrome`)
- `flow` — flow для REALITY/Vision (сейчас поддерживается `xtls-rprx-vision`)
- `spx` — spiderX для REALITY
- Fragment (`#remark`) — название сервера (отображается в логах)

Примеры URL:
```bash
# TLS сервер
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@server.com:443?security=tls

# REALITY / Vision сервер
vless://uuid@host:port?type=tcp&security=reality&encryption=none&pbk=PUBLIC_KEY&sid=SHORT_ID&sni=www.example.com&fp=chrome&spx=%2F&flow=xtls-rprx-vision

# С кастомным SNI
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@server.com:443?security=tls&sni=cdn.example.com

# Без шифрования
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@server.com:1234?security=none

# С remark
vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@server.com:443?security=tls#My%20Server
```

### Через TOML конфиг

Проверить конфиг:

```bash
cargo run -- --check-config
```

Запустить с verbose-логами:

```bash
cargo run -- --verbose
```

Указать свой конфиг:

```bash
cargo run -- --config ./config.toml
```

После сборки:

```bash
cargo build --release
./target/release/vproxy --config ./config.toml --verbose
```

### Команды CLI

```
vproxy - terminal VLESS client

Usage:
  vproxy [OPTIONS] [config-path|vless://...]

Options:
  -c, --config <PATH>       Path to TOML config
  -u, --url <VLESS_URL>     VLESS subscription URL (vless://...)
  -p, --inbound-port <PORT> Local inbound port (default: 1080)
  -v, --verbose             Enable debug logging
      --check-config        Validate config and exit
  -h, --help                Show this help
```

## Фоновый запуск

Сейчас внутри приложения нет отдельного daemon-режима. Для Unix-подобного окружения предполагается использовать обычные системные механизмы:

- `nohup`
- `systemd`
- `launchd`
- supervisor/containers

То есть текущая задача проекта — надёжный сетевой core и CLI foreground-режим, а не собственная daemonization-обвязка внутри процесса.

## Почему проект уже готовится к iOS

Хотя текущая цель — нормальный терминальный клиент, структура уже сделана так, чтобы потом не переписывать core заново:

- протокольная логика живёт в библиотеке
- CLI — отдельный тонкий слой
- `ProxyClient` можно оборачивать в FFI/API-границу позже

Следующий шаг в сторону iOS — не перенос CLI-кода, а добавление безопасного bridge-слоя над уже существующим Rust core.

## Текущее состояние и ограничения

Проект уже закрывает основной MVP-path:

- локальный inbound
- подключение к VLESS server
- relay трафика

Пока ещё не реализованы:

- полноценный DNS engine / cache / DNS rules
- MUX
- XTLS Vision поверх обычного `security = "tls"` (сейчас только REALITY)
- мимикрия ClientHello под браузерный отпечаток (uTLS-style)
- встроенный FFI-safe API для Swift/Objective-C
- production-oriented service management внутри самого приложения

## Разработка

Форматирование и тесты:

```bash
cargo fmt
cargo test --quiet
```

На текущем этапе тесты покрывают:

- валидацию конфига
- DNS policy / IP strategy selection
- SOCKS5 handshake
- HTTP request parsing/rewrite
- VLESS framing
- e2e flows:
  - SOCKS5 TCP
  - HTTP CONNECT
  - HTTP proxy request
  - SOCKS5 UDP ASSOCIATE
