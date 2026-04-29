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

### `socks5` и `http`

Локальные inbound-модули только принимают запрос от локального клиента, извлекают target host/port и передают управление reusable runtime.

## Конфиг

Пример:

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

## Запуск

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
- XTLS/REALITY и другие расширения
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
