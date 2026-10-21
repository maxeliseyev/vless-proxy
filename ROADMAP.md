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

 33. **Набор для измерений за ТСПУ (2026-10-19, стадия 1 плана `docs/h3-transport-plan.md`)**
    - `deploy/trial-server/`: Caddy с HTTP/3 на 443/udp и настоящим сертификатом, файлы 10 МБ и 1 ГБ, журнал доступа для H8, iperf3 на 5201, Hysteria 2 в двух вариантах (Brutal на 8443, BBR на 8444) с маскировкой на тот же сайт; `setup.sh домен` генерирует `.env`, файлы, конфиги и ссылки `hysteria2://`.
    - `scripts/tspu-trial.sh` для тестировщиков (bash 3.2+, macOS/Linux/WSL): один прогон = TCP h2 с Alt-Svc, H1 QUIC handshake, H2 10 МБ и 1 ГБ по HTTP/3 с детектором заморозки (меньше 2 КБ/с за 20 с), долгое соединение 50 КБ/с, H6 четыре параллельных QUIC-соединения с проверкой заморозки через 10/130/310 с, H3 iperf3 UDP, H0 vproxy с двумя REALITY-ссылками (`fp=chrome`/`fp=chrome133`) через SOCKS; curl с HTTP/3 ищется сам (Homebrew keg-only), внешний IP и страна через ipinfo, прокси-переменные снимаются, отчёт в формате таблицы со страницы испытаний плюс сырой лог.
    - `docs/trial-server-runbook.md`: выбор провайдера и локации (зарубежный VPS, разные ASN для H7), домен и DNS-only, базовая настройка Ubuntu, firewall с оговоркой про Docker, UDP-буферы, запуск стенда, проверка с тестировщика, прогон H1/H2/H3/H6/H0, лог для H8 и разбор типовых сбоев.
    - Проверено локально: нативный Caddy на loopback (Docker Desktop на macOS не доставляет UDP на localhost, на Linux-VPS такой проблемы нет), iperf3, REALITY-сервер.

32. **Отпечаток Chrome 155 (2026-10-18, стадия 0 плана `docs/h3-transport-plan.md`)**
     - По данным разработчиков Xray (issue #7131, 13.10.2026) ТСПУ давно целится в отпечаток Chrome 133 и ограничивает число соединений с ним; наш `fp=chrome` был именно HelloChrome_133.
     - `fp=chrome` теперь uTLS `HelloChrome_155`: в signature_algorithms добавлены GREASE и ML-DSA-44/65/87 (12 значений), появилось расширение `trust_anchors` (0xca34, draft-ietf-tls-trust-anchor-ids) с 28 идентификаторами Chrome Root Store, 17 расширений в случайном порядке, JA4 `t13d1517h2_…`. Старая форма сохранена как `fp=chrome133` для A/B-сравнений тестировщиками (гипотеза H0).
     - Форк rustls (rev `7df70d14`): `trust_anchors` в CertificateEntry игнорируется так же, как SCT, иначе сервер, выбравший цепочку по нашему списку, ронял бы handshake `UnknownCertificateExtension`; в EncryptedExtensions неизвестные расширения rustls и так складывает в `unknown_extensions`.
     - `cargo run --example fingerprint -- chrome <host>` делает handshake и `GET /` к любому хосту, чтобы проверять приём новой формы реальными серверами.

 31. **Поддержание форка rustls в актуальном состоянии (2026-10-18)**
     - Форк `maxeliseyev/rustls` (ветка `reality-0.23`, 6 коммитов поверх upstream `rel-0.23`) надо двигать за upstream: 0.23.x выходит примерно раз в месяц, в том числе с security-фиксами, а `cargo audit` видит только номер версии из форка.
     - Workflow `rustls fork sync` (`.github/workflows/rustls-sync.yml`, по понедельникам 06:00 UTC и вручную) вызывает `.github/scripts/rustls-sync.sh`: fetch upstream `rel-0.23`, merge в `reality-0.23` (merge, а не rebase, чтобы все когда-либо запинённые `rev` оставались доступны), полный `cargo test -p rustls --all-features --all-targets`, push форка через deploy-ключ (секрет `RUSTLS_FORK_DEPLOY_KEY`, ключ с правом записи только на репозиторий форка), затем bump `rev` в `Cargo.toml`, `cargo update -p rustls`, fmt/clippy/тесты vproxy и коммит в `main`. Конфликт слияния, любой другой сбой и выход rustls 0.24 становятся issue в vproxy (0.24 один раз: патчи придётся переносить на новую ветку вручную).
     - Скрипт запускается и локально: `DRY_RUN=1 .github/scripts/rustls-sync.sh` ничего не пушит и не коммитит. Проверены все три пути: `none` (текущее состояние), `bump` (копия vproxy с устаревшим `rev`), `merge` (копия форка, откаченная на v/0.23.45: 29 upstream-коммитов слились без конфликтов, включая `client/hs.rs`).
     - Ограничение: коммит бота в `main` не запускает `ci.yml` (GITHUB_TOKEN не триггерит workflow), поэтому Linux-проверки делает сам sync-job, а macOS-прогон случится при следующем ручном push.

 30. **Проверка безопасности ядра и поверхности атаки (2026-10-18, v0.11.0 → main)**
     - Два независимых ревью: криптографическое ядро (REALITY/Vision/VLESS/Mux/отпечаток, хуки форка rustls) и остальная поверхность (inbound, импорт ссылок, подписки, system-слой, supply chain). В ядре критичных проблем нет: REALITY seal байт-в-байт как `reality.go`, проверка сертификата fail-closed (чужой сертификат, TLS 1.2, HRR, resumption → обрыв, VLESS не отправляется), парсеры без паник и неограниченного роста.
     - Исправлено: ошибка `accept()` (EMFILE) больше не завершает процесс, лимит открытых файлов поднимается до hard limit при старте (launchd даёт 256); таймаут SOCKS5/HTTP handshake ограничен 30 с; UDP-ассоциация держит не более 128 целей с выкидыванием по idle 120 с; `vpn://` ссылка не может задать адрес inbound и правила routing; числа из `extra` XHTTP ограничены (паддинг ≤ 64 KiB, интервал ≤ 60 с); при inbound не на loopback (`-l 0.0.0.0`, Docker) `direct` к приватным/loopback адресам отклоняется, причём после DNS-резолва, а IP-литерал в SOCKS-домене считается IP; файлы с учётными данными (`server.txt`, `service.txt`) пишутся 0600 в каталог 0700; URL подписки в логах и ошибках без пути/токена; UUID больше не попадает в ключ mux-соединения (в логах); заголовок `profile-title` и имена серверов очищаются от управляющих символов (перенос строки в title позволял провайдеру дописывать строки файла); `%`-кодирование в ссылках декодируется как UTF-8; DNS `domain_suffix` только по границе метки; в systemd-юните экранируются `%` и `$`; `install.sh` не ставит бинарник без `.sha256`; права workflow выданы по job'ам; `cargo audit` в CI (обновлены h2 и quinn-proto); форк rustls принимает SCT в CertificateEntry (мы его объявляем в Chrome-профиле); TCP+TLS объявляет ALPN `h2,http/1.1` как Xray; после перехода записи в direct вывод rustls (KeyUpdate/alert) не попадает в поток; mux не копит `End`-ответы без ограничения; root предупреждается о sing-box/xray, доступных на запись другим пользователям.
     - Сознательно не сделано: spider-поведение Xray при чужом сертификате (мы просто рвём соединение, это заметно активному проберу, но безопасно); `pqv` (ML-DSA-65) проверка сервера; запуск root-сервиса только из root-owned бинарников (сломало бы Homebrew-сценарий); ALPS-ответ сервера (rustls не шлёт ClientEncryptedExtensions, затрагивает только BoringSSL-серверы с ALPS, которых среди VLESS-серверов нет).

 29. **Сборки arm64/musl и Docker-образ (2026-10-18)**
     - release.yml: `linux-arm64` (нативно на `ubuntu-22.04-arm`), `linux-x86_64-musl` и `linux-arm64-musl` (musl-tools, статические бинарники); job `docker` собирает multi-arch образ `ghcr.io/maxeliseyev/vproxy:<ver>` и `:latest` из musl-бинарников (`.github/docker/Dockerfile`)
     - корневой `Dockerfile` собирает из исходников на `rust:1-alpine` (aws-lc-sys под musl: build-base, cmake, perl); образ на `alpine` с `ca-certificates`, слушает `0.0.0.0:1080`, конфиг через `/data/server.txt`, `-s URL` или `-u`
     - `-l/--listen <ADDR>` для адреса inbound (в контейнере `0.0.0.0`), пробрасывается и в `service install`; `install.sh` понимает arm64 и выбирает musl на Alpine / без glibc (`VPROXY_LIBC=musl` принудительно)

 28. **Структура исходников (2026-10-18)**
     - `src/` разложен по слоям: `config/` (+ `import/`), `protocol/` (+ `reality/`), `transport/`, `inbound/`, `proxy/`, `system/`, `ui/`; публичные типы для CLI и тестов реэкспортируются из `lib.rs`; история файлов сохранена через `git mv`

 27. **Подписки (2026-10-18)**
     - `src/subscription.rs`: загрузка по URL (reqwest, UA `vproxy/<ver>`), тело base64 (std/url-safe, с паддингом и без, с переносами) или plain, берутся `vless://` и `vpn://`, остальные протоколы считаются пропущенными; заголовки `subscription-userinfo`, `profile-title` (в т.ч. `base64:`), `profile-update-interval`
     - файл ссылок с заголовком `# subscription/title/updated/interval/traffic/active` и секцией `# manual` (маркер пишется всегда, чтобы дописанные руками ссылки переживали обновление); для управляемого файла выбор сервера пишется в `# active:`, порядок не меняется
     - `-s URL` (в `-f` или `~/.config/vproxy/server.txt`), `--refresh`, автообновление при старте если список старше интервала (ошибка сети не мешает запуску), `u` в TUI с фоновой загрузкой и перезамером задержек
     - проверено на локальном фейковом сервере подписки с реальными ссылками: `-s`, автообновление, `--refresh`, сохранение ручной ссылки, `u` в pty

 26. **Ping и автовыбор сервера (2026-10-18)**
     - `runtime::measure_handshake` / `ping_servers`: полный transport handshake (TCP + TLS/REALITY/WS/XHTTP) с таймаутом, соединение сразу закрывается, без VLESS-трафика
     - TUI: колонка задержки в списке, замер всех серверов параллельно при старте и по `p`, `b` переключает на самый быстрый; результаты старых раундов отбрасываются; `--ping` печатает таблицу, отсортированную по задержке
     - проверено в pty на двух боевых серверах и одном недоступном адресе

 25. **Отпечаток TLS как у Chrome (2026-10-18)**
     - форк rustls: `ClientConfig::client_hello_rewriter` — хук получает закодированный ClientHello и отдаёт замену; байты идут в сеть и в transcript, список предложенных шифров и расширений перечитывается из них (ответы на ALPS/ECH не «unsolicited»), добавленный GREASE ECH переводит статус ECH в Grease; применяется до `session_id_hook`, который теперь работает по байтам; не применяется при resumption
     - `src/fingerprint.rs`: профиль uTLS `HelloChrome_133` (его шлёт Xray 26.x): 16 шифров с GREASE, 16 расширений + 2 GREASE, порядок случайный на соединение и одинаковый для HRR, GREASE в cipher/group/ext1/ext2/version, GREASE ECH как у BoringSSL, ALPS (17613), SCT, session ticket, renegotiation_info, compress_certificate brotli (включена фича rustls `brotli`); random, session id, key shares, SNI и ALPN rustls сохраняются; `fp=none` отключает; при отпечатке resumption выключен
     - проверено: JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd` (Chrome) и по нашему расчёту, и у tls.peet.ws (`examples/fingerprint.rs`); REALITY-аутентификация с локальным xray и боевым сервером, WS+TLS — без изменений

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
