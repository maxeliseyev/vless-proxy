# vproxy — CLI-клиент

Бинарник `vproxy`, терминальный интерфейс, журнал, службы и системный
TUN-режим (`--tun`, нативный in-process netstack на macOS; xray-core
используется как sidecar только для XTLS Vision поверх plain TLS).
Использует независимый `vproxy-core`.

```sh
cargo run -p vproxy -- --help
cargo build -p vproxy --release
```

См. [использование клиента](../../README.md) и
[архитектуру workspace](../../docs/architecture.md).
