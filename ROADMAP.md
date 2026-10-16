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

1. **Живая проверка `--tun`** под sudo при выключенном Happ (sing-box из Homebrew или из бандла Happ)
2. **Routing-правила** (domain/geoip → direct/proxy) — сейчас только bypass-списки в `[tun]`; у Happ это шаблоны `routing.rules`
3. **MUX / transport extensions** only if still justified
3. **MUX / transport extensions** only if still justified

Именно в таком порядке.
