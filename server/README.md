# vproxy-server

Сервер h3-транспорта vproxy (QUIC, свой протокол): план и причины в [docs/h3-transport-plan.md](../docs/h3-transport-plan.md). Прототип, стадия 2.

Что умеет сейчас: QUIC v1 + TLS 1.3 с сертификатом домена из файлов, ALPN `h3`, аутентификация токеном от uuid, привязанным к TLS-сессии, TCP-цели как потоки одного соединения, отказ в доступе к приватным адресам. Не умеет пока: UDP, отдачу сайта чужим клиентам (их соединение просто закрывается с `H3_NO_ERROR`), ACME.

```toml
# server.toml
listen = "0.0.0.0:8445"
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key = "/etc/letsencrypt/live/example.com/privkey.pem"
users = ["00000000-0000-0000-0000-000000000000"]
# allow_private = false
```

```sh
cargo build --release -p vproxy-server
target/release/vproxy-server -c server.toml        # -v для подробного лога
```

Ссылка для клиента: `h3://<uuid>@example.com:8445?sni=example.com#name` — подходит для `vproxy`, файла ссылок и подписок.
