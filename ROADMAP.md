# vproxy roadmap

Этот документ фиксирует общий план проекта, уже принятые архитектурные решения и порядок следующих итераций, чтобы не потерять контекст по мере роста codebase.

## 1. Цель проекта

`vproxy` — это терминальный VLESS-клиент на Rust для macOS/Linux без тяжёлого GUI, который:

- можно запускать как локальный прокси в CLI
- можно развивать как reusable Rust core
- можно позже встроить в другое приложение, включая iOS-клиент

### Что это значит на практике

- **Сейчас приоритет — сильный networking core**, а не UI и не FFI.
- **CLI — это оболочка над core**, а не центр архитектуры.
- **iOS-путь не отменён**, но он должен опираться на уже стабилизированный Rust runtime.

## 2. Что уже сделано

### Завершённые milestones

1. **Базовый TCP/TLS VLESS path**
   - Есть подключение к remote server по TCP/TLS.
   - Есть корректный VLESS request/response lifecycle.
   - Есть bidirectional relay для TCP-трафика.
   - **Комментарий:** это был минимально необходимый рабочий каркас, без которого всё остальное не имеет смысла.

2. **Нормализация CLI и конфига**
   - Добавлены валидация `protocol/security`.
   - Добавлены `--verbose`, `--check-config`, `--config`.
   - Исправлены ранние ошибки в handshake/runtime flow.
   - **Комментарий:** важно было сначала сделать поведение предсказуемым, прежде чем расширять функциональность.

3. **Library-first архитектура**
   - Вынесен reusable core в `src/lib.rs`.
   - `src/runtime.rs` содержит runtime и `ProxyClient`.
   - `src/main.rs` оставлен тонкой CLI-обёрткой.
   - **Комментарий:** это ключевое решение для будущего iOS embedding и вообще для роста проекта без переписывания всего заново.

4. **Локальные inbound-протоколы**
   - SOCKS5 `CONNECT`
   - HTTP proxy:
     - `CONNECT`
     - обычные HTTP proxy requests
   - **Комментарий:** это закрывает наиболее практичный локальный client-facing слой для desktop/terminal использования.

 5. **UDP milestone**
    - Добавлен VLESS UDP framing поверх stream transport.
    - Добавлен SOCKS5 `UDP ASSOCIATE`.
    - Добавлена runtime-маршрутизация UDP datagram'ов в отдельные VLESS UDP-сессии по целевому адресу.
    - **Комментарий:** это важный шаг от "игрушечного TCP-only proxy" к более полноценному клиенту.

 6. **Документация проекта**
    - README отражает текущее устройство проекта.
    - **Комментарий:** без актуальной документации быстро теряется понимание, где MVP уже закрыт, а где ещё нет.

 7. **vless:// URL support**
    - Добавлен парсер vless:// ссылок
    - Поддержка TLS, REALITY, none security
    - Параметры: `pbk`, `sid`, `sni`, `flow`, `encryption`
    - Автогенерация конфига из URL
    - **Комментарий:** упрощает запуск — не нужно создавать конфиг вручную.

 8. **Runtime hardening**
    - Таймауты: connect, read, write, idle
    - Graceful shutdown (SIGINT/SIGTERM)
    - Лимит соединений (`max_connections`)
    - Защита от зависаний
    - **Комментарий:** превращает рабочий прототип в production-ready инструмент.

 9. **DNS rules + cache**
    - Split DNS: правила для доменов (suffix, exact, keyword)
    - DNS cache с TTL, eviction, лимитами
    - Настройка через `[dns.rules]` и `[dns.cache]`
    - **Комментарий:** уменьшает DNS-запросы и позволяет гибко управлять резолвингом.

 10. **REALITY transport (sidecar)**
     - Поддержка `vless://` REALITY/Vision параметров: `pbk`, `sid`, `sni`, `fp`, `flow`, `spx`
     - Подключение через `xray-core` sidecar для `security=reality` / `xtls-rprx-vision`
     - **Комментарий:** это дало рабочий transport для реальных ссылок до появления нативной реализации.

 24. **Установка sing-box и фоновый сервис (2026-10-18)**
     - `src/singbox.rs`: поиск бинарника (`--sing-box`/`tun.sing_box_path`, `~/.config/vproxy/bin`, PATH, Homebrew, системные префиксы, бандл Happ; под sudo ищется и дом реального пользователя); `vproxy install-sing-box`: Homebrew на macOS (без него предлагает поставить Homebrew), официальный скрипт репозитория sing-box на deb/rpm/Arch, иначе релиз с GitHub под ОС/CPU в `~/.config/vproxy/bin` (`--download` принудительно); `--tun` без sing-box предлагает установку на месте
     - `src/service.rs`: `vproxy service install|uninstall|status|logs [--tun]` генерирует launchd plist (агент пользователя или системный демон) или systemd unit (user или system с root и CAP_NET_ADMIN), пишет абсолютные пути к бинарнику, конфигу и sing-box, запускает и включает автозапуск; логи в файл без ANSI
     - проверено: загрузка релиза в scratch-HOME и запуск `sing-box version`; цикл install → status → слушающий порт → uninstall для launchd-агента

 23. **XHTTP-транспорт (2026-10-17)**
     - `src/xhttp.rs` на hyper 1.x (`client::conn::http1/http2` поверх наших TLS/REALITY-потоков): stream-one (один POST, тело запроса = uplink, тело ответа = downlink), stream-up (GET + потоковый POST), packet-up (GET + POST-пакеты с seq, батчинг до 1 МБ, интервал 30 мс); по HTTP/1.1 только packet-up на отдельном соединении для upload
     - URL/заголовки как у Xray: `/path/` + session id (uuid) + seq, `Referer` с `x_padding` 100–1000 X, `Content-Type: application/grpc` на потоковых запросах, кастомные `headers`; из `extra`/`xhttpSettings` читаются mode, headers, noGRPCHeader, xPaddingBytes, scMaxEachPostBytes, scMinPostsIntervalMs, uplinkHTTPMethod (downloadSettings, нестандартные placement и obfs-паддинг пока нет)
     - HTTP-версия: REALITY → HTTP/2 (prior knowledge), TLS → по ALPN (`alpn` в ссылке/TOML), без шифрования → HTTP/1.1; auto-режим как у Xray: stream-one с REALITY, иначе packet-up
     - конфиг: `transport = "xhttp"`, `path`/`host` (алиасы `ws_path`/`ws_host`), `xhttp_mode`, `xhttp_extra`; ссылки `type=xhttp&path&host&mode&extra&alpn`; импорт Xray JSON `xhttpSettings`
     - проверено на локальном xray-core 26.7.28: все три режима по REALITY+HTTP/2 и packet-up по plain HTTP/1.1, загрузки по хэшу и эхо 3×1 МБ

 22. **Импорт Amnezia VPN (2026-10-17)**
     - `src/amnezia_import.rs`: `vpn://` = base64url от `qCompress` (4 байта длины + zlib) над JSON сервера Amnezia; из контейнера `amnezia-xray` берётся `xray.last_config` (обычный клиентский JSON xray-core) и идёт через `xray_import`
     - `vpn://` принимается везде, где `vless://` (аргумент, `-u`, `-f`, `server.txt`, первый запуск, `a` в TUI); `-c file.vpn` читает сырой qCompress, base64 или plain JSON, как сам клиент Amnezia
     - full-access (admin) конфиг без `last_config` и конфиги без XRay-контейнера отклоняются с пояснением; проверено на ссылке, собранной независимо (Python zlib) из боевого WS-конфига, включая `--probe`

 21. **MUX / Mux.Cool (2026-10-16)**
     - `src/mux.rs`: фреймы (New/Keep/End/KeepAlive, DATA/ERROR), `MuxManager` (concurrency, 128 сессий на соединение, закрытие через 16 с простоя, retire при смене сервера), `MuxStream` как AsyncRead/AsyncWrite; VLESS-запрос `Mux` без адреса, как в Xray
     - соединение ведётся одной задачей (один waker на оба направления); relay переписан так, что направления продвигаются независимо (иначе mux-сессии блокировали друг друга)
     - попутно: `RealityStream::poll_read` больше не сбрасывает TLS-вывод в сокет (при split по задачам это глушило waker писателя)
     - проверено: e2e-тест с mock-сервером (две сессии в одном соединении), локальный xray-core (эхо 5×2 МБ, 6 параллельных загрузок), боевой WS+TLS сервер (4 параллельные загрузки, upload 1 МБ)

 20. **Добавление и удаление серверов в TUI (2026-10-16)**
     - `ServerList::add_link`/`remove`: ссылка дописывается в файл ссылок / вычищается из него, остальные строки (комментарии, чужие строки) не трогаются; последний сервер и активный удалить нельзя
     - TUI: `a` открывает строку ввода (bracketed paste, Enter/Esc), `d` спрашивает `y/n`; проверено в pty: вставка, дубликат, отказ для активного, подтверждение, файл

 19. **Переключение серверов в TUI (2026-10-16)**
     - `src/servers.rs`: список серверов из файла ссылок (невалидные строки пропускаются с warning), выбранный записывается первым
     - `runtime::ActiveServer`: активный сервер в `RwLock`, `ProxyClient` берёт снимок на каждое соединение; `swap` валидирует и отвергает серверы, которым нужен sidecar
     - TUI: панель серверов (появляется при ≥2), ↑↓/jk и Enter; listener и sing-box не перезапускаются, старые соединения доживают
     - e2e-тест: первое соединение к A, после `swap` — к B, sidecar-сервер отвергается; живая проверка в pty на двух боевых серверах

 18. **WebSocket-транспорт и импорт Xray JSON (2026-10-16)**
     - `src/ws.rs`: WS поверх TLS или TCP через tokio-tungstenite (без его TLS), бинарные фреймы, адаптер AsyncRead/AsyncWrite; `type=ws` + `path`/`host` в ссылках, `server.transport`/`ws_path`/`ws_host` в TOML
     - `src/xray_import.rs`: `vproxy -c happ.json` — vless-outbound, socks-inbound, `routing.rules` (domain:/full:/keyword:/geosite:, geoip:, cidr, порты)
     - попутно найден и исправлен старый баг: `security=tls` падал с паникой rustls (две крипто-фичи в сборке), теперь провайдер задан явно, есть регрессионный тест
     - проверено на боевом WS+TLS сервере: upgrade, трафик, 2 МБ по хэшу, upload; e2e-тест WS с mock-сервером

 17. **Первый запуск без аргументов (2026-10-16)**
     - поиск ссылки: `./server.txt` → `~/.config/vproxy/config.toml` → `~/.config/vproxy/server.txt`
     - интерактивный запрос `vless://` ссылки со stdin (без shell-кавычек), валидация, до трёх попыток, сохранение в `~/.config/vproxy/server.txt`
     - без терминала (launchd/systemd) — понятная ошибка вместо зависания
     - README переписан компактно: установка, быстрый старт, конфиг, достижения; релиз v0.3.0

 16. **Релизы и установка (2026-10-16)**
     - `.github/workflows/ci.yml`: fmt, clippy, тесты на ubuntu и macos
     - `.github/workflows/release.yml`: по тегу `v*` сборки macOS arm64, macOS x86_64 (кросс с arm64-раннера), Linux x86_64; tar.gz + sha256 в GitHub Release
     - `install.sh`: определяет платформу, качает последний релиз, проверяет sha256, ставит в `/usr/local/bin` или `~/.local/bin`
     - `vproxy --version`, версия 0.2.0

 15. **Routing-правила (2026-10-16)**
     - `src/routing.rs`: `[routing]` с семантикой sing-box (AND внутри правила, OR в списках, первое совпадение); direct/proxy/block по domain*, ip_cidr, ip_private, port
     - runtime: `OutboundStream`/`UdpOutbound` — direct TCP и UDP мимо сервера, block → отказ
     - `tun.rs`: трансляция 1:1 в sing-box плюс `geoip`/`geosite` как remote rule-set; `block` → `action: reject`; проверено `sing-box check`
     - e2e-тест: direct-правило не касается VLESS-сервера
     - **Комментарий:** geoip/geosite локально не реализованы намеренно: в локальном режиме это редко нужно, а в TUN их делает sing-box.

 14. **Минимальный TUI (2026-10-16)**
     - `src/stats.rs`: счётчики соединений/байт/ошибок, хуки в runtime (TCP relay и UDP-сессии)
     - `src/tui.rs`: ratatui, шапка (сервер, security/flow/sni, engine, TUN, uptime), трафик со скоростью, панель логов через перехват tracing, `q` → graceful shutdown через SIGINT
     - `server.remark` из `#fragment` ссылки показывается как имя сервера
     - **Комментарий:** интерфейс намеренно без управления конфигом; переключение серверов и правил — отдельный этап.

 13. **TUN-режим и service/ops (2026-10-16)**
     - `src/tun.rs`: генератор конфига sing-box (tun-inbound → socks-outbound на наш inbound) и sidecar-процесс, живущий вместе с сервером; `--tun`, `--print-tun-config`, секция `[tun]`
     - защита от петли: process_name (vproxy, sing-box, xray) и адрес сервера → direct, их DNS → direct; остальной DNS через туннель по умолчанию
     - конфиг проверен `sing-box check` (1.12.12); живой запуск требует root и выключенного Happ (два TUN не уживутся)
     - `docs/launchd/*.plist` и `docs/systemd/vproxy.service` как примеры автозапуска
     - логи переведены в stderr, stdout только для данных
     - **Комментарий:** ровно схема Happ, без собственного TUN-стека; покрывает пункт 3 из раздела 4.

 12. **Native XTLS Vision (2026-10-16)**
     - `src/vision.rs`: порт `VisionWriter`/`VisionReader`/`XtlsPadding`/`XtlsUnpadding`/`XtlsFilterTls` из `proxy/proxy.go`
     - `RealityStream` переписан как собственный драйвер поверх `rustls::ClientConnection`, кормит его по одной TLS-записи, поэтому байты после команды Direct не теряются (у Xray это `unsafe`-доступ к `input`/`rawInput` в `tls.Conn`)
     - `VlessStream`: заголовок запроса уходит вместе с первыми данными или пустым паддинг-блоком через 500 мс, как у Xray
     - `flow` кодируется в addons как protobuf; UDP/443 отклоняется без `-udp443`
     - проверено против локального xray-core 26.7.28: TLS 1.3 → direct copy в обе стороны (5 МБ, хэш совпал, ~7 МБ/с), TLS 1.2 → путь End (upload 300 КБ и download 2 МБ, хэши совпали)
     - добавлена гибридная группа X25519MLKEM768 (`aws-lc-rs` ML-KEM-768 + свой X25519): актуальный REALITY-сервер отвергает ClientHello без неё, а для auth key берёт X25519-share, который rustls шлёт вторым
     - проверено на боевом сервере пользователя: handshake, 5 МБ download с совпавшим хэшем, upload, параллельные запросы
     - **Комментарий:** sidecar теперь нужен только для Vision поверх plain TLS. При включённом Happ его TUN заворачивает трафик vproxy в свой же туннель до того же сервера, и сервер такие соединения не аутентифицирует — для тестов vproxy нужно выводить из TUN (или выключать Happ).

 11. **Native REALITY (2026-10-16)**
     - `src/reality.rs`: примитивы протокола, тесты на векторах из Go-криптографии Xray-core
     - форк rustls ([maxeliseyev/rustls](https://github.com/maxeliseyev/rustls), ветка `reality-0.23`) с хуком `ClientConfig::session_id_hook`
     - `src/reality_tls.rs`: X25519 key share, session-id hook, HMAC-проверка сертификата, `RealityConnector`
     - `runtime.reality_engine = auto | native | xray`, `vproxy --probe`
     - проверено сквозным тестом против локального xray-core 26.7.28 REALITY-сервера
     - попутно исправлен deadlock: VLESS response header читается лениво (`vless::VlessStream`), как его шлёт Xray
     - **Комментарий:** решение принято осознанно — проект должен быть своим ядром, а не конфиг-генератором для xray-core.

## 3. Архитектурные решения, которые уже считаются принятыми

### 3.1 Library-first

Core логика должна жить в библиотеке, а не в бинарнике.

- менять transport/protocol/runtime нужно прежде всего в library layer
- CLI должен оставаться thin wrapper

**Почему:** это одновременно помогает и тестированию, и будущему встраиванию в iOS/другие клиенты.

### 3.2 Daemonization не делаем внутри приложения прямо сейчас

Для background/service mode пока достаточно системных механизмов:

- `systemd`
- `launchd`
- `nohup`
- контейнеры / supervisor

**Почему:** собственный daemon-mode внутри процесса сейчас даст меньше пользы, чем развитие сетевого core.

### 3.3 Не распыляемся рано на “всё как у Xray”

Анализ mature клиентов вроде **Xray-core** и **sing-box** полезен как ориентир, но мы не должны пытаться сразу повторить весь их scope.

**Почему:** у них есть огромные подсистемы routing/DNS/TUN/service/mobile integration, но для нашего проекта важен правильный порядок роста, а не копирование всего стека.

## 4. Что показал анализ open-source клиентов

Сравнение с **Xray-core** и **sing-box** показало, что у зрелых клиентов обычно есть ещё такие крупные блоки:

1. **DNS engine**
2. **routing/policy engine**
3. **TUN / transparent proxy mode**
4. **service management**
5. **mobile integration surface**
6. **MUX и transport extensions**

### Главный вывод

Этот анализ **не изменил immediate roadmap**, а только подтвердил правильный порядок:

- UDP действительно нужно было делать следующим
- после UDP логично идти в DNS + e2e + runtime hardening
- в routing/TUN/FFI/MUX пока рано лезть до стабилизации core semantics

## 5. Приоритетный roadmap дальше

Ниже — порядок следующих этапов после текущего UDP milestone.

### Этап 1. Минимальный DNS path / resolver policy

Что нужно сделать:

- определить, как клиент резолвит доменные имена
- решить, когда трафик идёт как domain target, а когда нужен локальный resolve
- добавить хотя бы минимально управляемое поведение для DNS-сценариев

Комментарии:

- после появления UDP это становится особенно важным
- без DNS часть практических сценариев будет работать нестабильно или непредсказуемо
- здесь не нужен сразу “умный DNS engine как у sing-box”, нужен сначала аккуратный минимальный слой

### Статус

Закрыто в минимальном виде:

- `remote resolve` оставлен default-поведением
- добавлен опциональный `local resolve` через system DNS
- добавлена policy выбора IPv4/IPv6 адреса

Что **ещё не закрыто** в DNS-теме:

- отдельный DNS engine
- DNS cache
- DNS rules / split DNS
- выделенный DNS inbound/outbound слой

### Этап 2. E2E / интеграционные тесты

Что нужно сделать:

- тесты реального проксирования через локальный inbound
- отдельные сценарии для:
  - SOCKS5 TCP
  - HTTP CONNECT
  - HTTP proxy request
  - SOCKS5 UDP
- mock VLESS server/test harness для проверки framing и relay поведения

Комментарии:

- сейчас tests хорошо покрывают codec/framing, но этого мало для уверенности в whole-flow
- это особенно важно перед следующими более крупными изменениями в runtime

### Статус

Закрыто:

- добавлен integration harness с реальным `serve(...)`
- добавлен mock VLESS server для end-to-end сценариев
- покрыты:
  - SOCKS5 TCP
  - HTTP CONNECT
  - HTTP proxy request
  - SOCKS5 UDP ASSOCIATE

### Этап 3. Runtime hardening

Что нужно сделать:

- таймауты
- graceful shutdown
- предсказуемое закрытие association/session
- лимиты соединений и защиты от зависаний
- более ясные логи и ошибки

Комментарии:

- это превращает рабочий прототип в более production-like инструмент
- делать это лучше после e2e-тестов, чтобы было на что опираться при рефакторинге

### Этап 4. Конфиг следующего уровня

Что нужно сделать:

- аккуратно расширить конфиг под новые runtime-функции
- не превращать конфиг сразу в копию sing-box/xray
- оставить его компактным и понятным

Комментарии:

- хороший конфиг должен расти вместе с возможностями core
- слишком ранняя универсализация только усложнит проект

### Этап 5. MUX и transport extensions

Что нужно сделать:

- оценить, нужен ли MUX реально под целевые сценарии
- после этого уже решать, добавлять ли его в core

Комментарии:

- это не следующий шаг
- MUX полезен, но не настолько базовый, как DNS/e2e/runtime hardening

### Этап 6. Service/ops слой

Что нужно сделать:

- описать нормальные варианты фонового запуска
- возможно добавить примеры под `systemd` и `launchd`

Комментарии:

- это полезно практически, но не должно тормозить развитие сетевого ядра

## 6. Что сознательно откладывается

### FFI-safe слой для iOS

Сделать позже, после стабилизации core API.

Почему откладываем:

- иначе придётся фиксировать слишком ранний API
- текущая library-first архитектура уже готовит почву
- сначала нужно стабилизировать поведение runtime, DNS и e2e semantics

### Routing engine

Полноценные rules/policies пока не приоритет.

Почему откладываем:

- это большой отдельный пласт логики
- без стабильного core и tests он даст больше сложности, чем пользы

### TUN mode

Пока не делаем.

Почему откладываем:

- это уже шаг к VPN-like продукту
- текущая цель проекта — terminal/local proxy client

### XTLS/REALITY и расширенные transport-режимы

**REALITY и XTLS Vision реализованы нативно (milestones 11–12).**

Что уже закрыто:
- нативный REALITY handshake в Rust runtime (`reality.rs` + `reality_tls.rs` + форк rustls)
- нативный Vision (`vision.rs` + `VlessStream`): паддинг, direct copy для TLS 1.3, End-путь для TLS 1.2
- `vless://` URLs с `security=reality`, параметры `pbk`, `sid`, `sni`, `fp`, `spx`, `flow`
- `xray-core` sidecar остаётся только для Vision поверх plain TLS

**Следующие шаги именно в этом порядке:**
1. **Vision поверх plain TLS** — нужен тот же record-драйвер для `security = "tls"` (сейчас там tokio-rustls), после чего sidecar можно убрать совсем.
2. **Отпечаток ClientHello.** REALITY-сервер его не проверяет, но пересылает наш ClientHello на `dest` и зеркалит размеры ответа. rustls шлёт не-браузерный hello (свой набор шифров, случайный порядок расширений, без GREASE). Делать только если DPI или конкретные `dest` начнут ломать соединение.
3. Поддерживать патч rustls маленьким, чтобы переносить его на новые 0.23.x одной командой.

## 7. Отдельная ветка: путь к iOS

Когда core будет стабилизирован, путь к iOS выглядит так:

1. зафиксировать устойчивый library API
2. добавить lifecycle/cancellation surface
3. сделать FFI-safe boundary
4. решить, нужен ли:
   - только embedded outbound path
   - или полноценная интеграция с NetworkExtension/TUN

### Важный комментарий

Путь к iOS **не должен ломать terminal-first архитектуру**. Наоборот, iOS слой должен использовать тот же core, что уже используется CLI.

## 8. Критерий “логического конца” для первой большой версии

Можно считать, что первоначальная идея доведена до зрелого состояния, когда есть:

- TCP и UDP path
- локальные SOCKS5 и HTTP inbound
- корректный конфиг
- e2e tests
- базовый DNS path + rules + cache
- устойчивый runtime (таймауты, shutdown, лимиты)
- vless:// URL support
- базовая REALITY поддержка
- понятная документация и сценарии запуска

Это ещё не “полный аналог Xray/sing-box”, но уже сильный самостоятельный terminal VLESS client.

## 9. Короткая памятка по ближайшему следующему шагу

Если продолжать прямо отсюда, следующий практический milestone:

1. **xhttp: downloadSettings / xmux (переиспользование HTTP/2-соединений)** если понадобится на реальном сервере; grpc только если появится реальный конфиг
2. **UDP поверх MUX (xudp)** если понадобится

Именно в таком порядке.
