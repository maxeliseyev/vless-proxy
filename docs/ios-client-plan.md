# План: iOS-клиент на ядре vproxy

Статус: этап 0 сделан 2026-10-24, остальное план. Цель: VPN-приложение для iPhone, которое использует то же Rust-ядро, что и CLI (REALITY, Vision, Mux, XHTTP, WS, routing, подписки), без xray-core и sing-box.

## 1. Чем iOS отличается от desktop

| Desktop vproxy | iOS |
|---|---|
| TUN через sing-box (отдельный процесс) | Процессы запускать нельзя: ни sing-box, ни xray-core |
| Локальный SOCKS5/HTTP inbound | Не нужен, пакеты приходят прямо в наш код |
| TUI, CLI, systemd/launchd | SwiftUI-приложение плюс системный VPN-профиль |
| Память не ограничена (около 14 МБ в работе) | Packet Tunnel extension ограничен примерно 50 МБ, при превышении система его убивает |

Не хватает одной большой части: TCP/IP-стека в userspace, который заменит sing-box. Остальное переиспользуется.

## 2. Архитектура

```
┌──────────── iOS App (SwiftUI) ─────────────┐
│ серверы, ссылка/QR, подписки, подключение, │
│ статистика, пинг                           │
│        NETunnelProviderManager             │
└───────┬───────────── App Group ────────────┘
        │ sendProviderMessage (stats, switch, ping)
┌───────▼──── Packet Tunnel Extension ───────┐
│ Swift: NEPacketTunnelProvider              │
│   packetFlow.readPackets ──► FFI ──┐       │
│   packetFlow.writePackets ◄─ FFI ◄─┤       │
│ ┌──────────── Rust ────────────────▼─────┐ │
│ │ netstack: IP-пакеты → TCP/UDP-потоки   │ │  новое
│ │ FakeDNS: домен → фейковый IP           │ │  новое
│ │ ProxyClient::open_tcp / open_udp       │ │  есть
│ │ routing, Mux, REALITY/Vision, XHTTP    │ │  есть
│ └────────────────────────────────────────┘ │
└────────────────────────────────────────────┘
```

- **Шов с ядром.** `ProxyClient::open_tcp(address, port)` и `open_udp` (`src/proxy/runtime.rs`) уже принимают цель и сами выбирают proxy, direct или block. Стек только достаёт потоки из пакетов и вызывает их.
- **Сетевой стек.** Готовый крейт, не свой. Кандидаты: `ipstack` (на нём tun2proxy) и `netstack-smoltcp`. Выбор после прототипа на нагрузке и памяти.
- **DNS.** FakeDNS: туннель отдаёт системе свой DNS-адрес, стек отвечает фейковыми IP и помнит домен. Routing работает по доменам, на сервер уходит домен.
- **FFI.** UniFFI или C ABI через cbindgen. API: `start(config, packet_callback)`, `push_packets`, `stop`, `stats`, `switch_server`, `ping`. Сборка в `.xcframework` для `aarch64-apple-ios` и `aarch64-apple-ios-sim`.
- **Рантайм.** tokio на 1–2 потоках, Mux включён, чтобы держаться в лимите памяти.
- **Desktop.** Тот же netstack может заменить sing-box на macOS и Linux и убрать сайдкар (около 43 МБ).

## 3. Этапы

0. **Сделано.** Cargo features: `cli = tui + desktop` по умолчанию; `tui` включает ratatui, crossterm и `ui`; `desktop` включает `system` (sing-box, xray-core, установщик, службы), tempfile и tar. Бинарь требует `cli`. `cargo build --lib --no-default-features --target aarch64-apple-ios` собирается, aws-lc-rs и форк rustls тоже. Без `desktop` конфиг с xray-сайдкаром или TUN через sing-box отклоняется понятной ошибкой. CI-джоб `ios-core` проверяет это на каждом push.
1. **Rust netstack + FakeDNS.** Проверять на macOS через настоящий utun вместо sing-box, iPhone не нужен.
2. **FFI-крейт `vproxy-ffi`** и скрипт сборки xcframework.
3. **Xcode-проект.** Приложение и Packet Tunnel extension, минимальный UI.
4. **Доводка на устройстве.** Память под Instruments, Wi-Fi ↔ LTE (пересоздание соединений и Mux), сон и пробуждение, on-demand, kill switch (`includeAllNetworks`).
5. **Распространение.**

## 4. Риски

- **Аккаунт.** Нужен платный Apple Developer Program: Network Extension на бесплатном аккаунте не работает. Для своих устройств хватает dev- или Ad Hoc-сборки.
- **App Store.** Правило App Review 5.4: VPN-приложения публикует организация, а не частное лицо. Apple убирает VPN-приложения из российского App Store по требованию РКН. Пути: свои устройства, TestFlight, витрины других стран. Решить до этапа 5.
- **Память около 50 МБ.** Главный технический риск, мерить с первого прототипа.
- **Смена сети.** Долгие REALITY-соединения рвутся при переходе Wi-Fi ↔ LTE.
