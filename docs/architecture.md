# Устройство репозитория

Корень — Cargo workspace. Основные части собираются независимо:

| Каталог | Cargo-пакет | Ответственность |
|---|---|---|
| `crates/core` | `vproxy-core` | Конфигурация, VLESS/REALITY/Vision/Mux, транспорты, h3-клиент, routing, DNS, SOCKS5/HTTP, userspace netstack |
| `crates/cli` | `vproxy` | Бинарник `vproxy`, TUI, журнал, сигналы desktop-приложения, службы, TUN через sing-box и xray-sidecar |
| `crates/server` | `vproxy-server` | Сервер QUIC-транспорта, аутентификация и соединения с целями |
| `crates/ffi` | `vproxy-ffi` | C ABI и Swift-обёртки для Ratatosk, staticlib и заголовки |

CLI, сервер и FFI зависят от `vproxy-core`. Ядро не зависит от них,
не включает TUI, не устанавливает службы и не запускает внешние процессы.
Нативные локальные inbound-протоколы остаются в ядре, чтобы ими могли
пользоваться разные оболочки.

`serve_with_shutdown` предоставляет локальные слушатели с сигналом завершения
от вызывающего приложения. CLI управляет системными сигналами и sidecar-процессами.
Для простого нативного запуска в ядре остаются `serve` и `serve_with_server`;
они отклоняют конфигурации, требующие desktop-процессов.

## Команды

```sh
cargo build -p vproxy                     # target/debug/vproxy
cargo run -p vproxy -- --help
cargo build -p vproxy-server              # target/debug/vproxy-server
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked
cargo fmt --all --check

cargo build -p vproxy-core --lib --target aarch64-apple-ios
cargo build -p vproxy-ffi --target aarch64-apple-ios
scripts/build-xcframework.sh
```

`cargo build` и `cargo test` без `-p` выбирают ядро и CLI. Для всех четырёх
пакетов нужен `--workspace`. Примеры сетевого ядра лежат в
`crates/core/examples` и запускаются через `cargo run -p vproxy-core --example …`.
Интеграционные тесты лежат рядом со своим пакетом в его `tests/`.

Версия CLI и ядра задаётся в `[workspace.package]` корневого `Cargo.toml`.
Форк rustls и профили сборки также задаются только в корне. Имена бинарников,
`libvproxy_ffi.a`, C API `ratatosk_*` и `RatatoskCore.xcframework` сохранены.
Rust-импорт ядра теперь называется `vproxy_core`, например:

```rust
use vproxy_core::{Config, ProxyClient};
```

## Развёртывание и содержимое сайта

`deploy/trial-server` содержит общий измерительный стенд. Его текстовая
страница — тестовый пример; она не является продуктивным сайтом.

Конкретный сайт, его медиапоток, оформление и параметры продуктивного
развёртывания ведутся в отдельном закрытом репозитории. Публичный сервер
получает контент из внешнего HTTP-backend; его код и Docker-образ не должны
включать продуктивную страницу или адрес видеокамеры. Измерительный стенд
и серверные e2e-тесты используют нейтральный тестовый контент.

Локальные закрытые материалы можно держать в отдельном checkout под `private/`:
этот каталог исключён из Git и Docker-контекста. Закрытый репозиторий не
публикуется автоматически вместе с этим workspace.

## Миграция путей

В документах, описывающих предыдущие этапы, встречаются исторические пути:

| Ранее | Теперь |
|---|---|
| `src/config`, `src/protocol`, `src/transport`, `src/h3`, `src/proxy`, `src/inbound`, `src/netstack` | `crates/core/src/…` |
| `src/main.rs`, `src/ui`, `src/system`, `src/logging.rs` | `crates/cli/src/…` |
| `server/` | `crates/server/` |
| `ffi/` | `crates/ffi/` |
| `tests/`, `examples/` | `crates/core/tests/`, `crates/core/examples/` |

Внешнему Xcode-проекту, который читает заголовки и Swift-файлы из исходников,
нужно обновить пути на `crates/ffi/include` и `crates/ffi/swift`. Путь готового
XCFramework остаётся `target/RatatoskCore.xcframework`.
