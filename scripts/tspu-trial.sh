#!/usr/bin/env bash
# tspu-trial.sh: один прогон испытаний HTTP/3-транспорта из сети за ТСПУ.
#
#   bash tspu-trial.sh -n "МТС, мобильная, Новосибирск" https://домен
#
# Что проверяет (номера гипотез из docs/h3-transport-plan.md):
#   H1  QUIC на UDP/443 к домену проходит (curl --http3-only), рядом TCP h2
#   H2  поток по HTTP/3: 10 МБ, затем файл 1 ГБ до 5 минут; стоп < 2 КБ/с за 20 с = заморозка
#   --  долгое соединение: 10 МБ со скоростью 50 КБ/с (около 200 с) по одному QUIC-соединению
#   H6  4 параллельных QUIC-соединения, потом проверка, не заморозило ли домен
#   H3  iperf3 UDP 10 Мбит/с 60 с (-i host:port), «неизвестный UDP» против QUIC
#   H0  vproxy с двумя REALITY-ссылками (-f): fp=chrome и fp=chrome133, 10 МБ через прокси
#
# Нужен curl с HTTP/3 (строка Features в `curl --version` содержит HTTP3):
#   macOS: brew install curl (скрипт сам найдёт /opt/homebrew/opt/curl/bin/curl)
#   Linux: curl 8.x с ngtcp2/quiche, например статическая сборка github.com/stunnel/static-curl
#   Windows: WSL, либо curl.se/windows (в нём HTTP/3 есть) из Git Bash
# Без такого curl тесты HTTP/3 пропускаются, H0 и H3 работают.
#
# Один запуск = один прогон. Между прогонами пауза не меньше 10 минут (-r 3 делает
# три прогона с паузой сам). Отчёт и сырой лог кладутся в текущую папку.

set -u

VERSION=1
NETWORK=""
LINKS=""
VPROXY_BIN=""
IPERF=""
ROUNDS=1
OUT="."
QUICK=0
INSECURE=0
SMALL="${SMALL:-/10m.bin}"
BIG="${BIG:-/1g.bin}"
BIG_CAP="${BIG_CAP:-300}"
PAUSE="${PAUSE:-600}"
PROXY_PORT="${PROXY_PORT:-18080}"

usage() {
    cat <<USAGE
Использование: bash tspu-trial.sh [параметры] https://домен [https://домен2 ...]

  -n "сеть"      оператор, моб/провод, регион (спросит, если не задано)
  -f файл        файл ссылок vless:// для H0: две строки на один сервер, fp=chrome и fp=chrome133
  -b путь        бинарник vproxy (по умолчанию ищется в PATH, ./vproxy, ./target/release/vproxy)
  -i host:port   сервер iperf3 для H3 (UDP)
  -r N           число прогонов, между ними пауза ${PAUSE} с (по умолчанию 1)
  -o папка       куда писать отчёт и лог (по умолчанию текущая)
  -q             быстрый прогон: без файла 1 ГБ и без долгого соединения
  -k             не проверять сертификат (только для локальной отладки)
  -h             эта справка

Второй домен (другой хостер) даёт пару для H7: тесты прогоняются для каждого.
USAGE
}

while getopts "n:f:b:i:r:o:qkh" opt; do
    case $opt in
        n) NETWORK=$OPTARG ;;
        f) LINKS=$OPTARG ;;
        b) VPROXY_BIN=$OPTARG ;;
        i) IPERF=$OPTARG ;;
        r) ROUNDS=$OPTARG ;;
        o) OUT=$OPTARG ;;
        q) QUICK=1 ;;
        k) INSECURE=1 ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

if [ $# -eq 0 ] && [ -z "$LINKS" ]; then
    usage
    exit 1
fi

DOMAINS=""
for d in "$@"; do
    d=${d%/}
    case $d in
        http://*|https://*) ;;
        *) d="https://$d" ;;
    esac
    DOMAINS="$DOMAINS $d"
done

# ---------------------------------------------------------------- helpers

STAMP=$(date '+%Y%m%d-%H%M%S')
mkdir -p "$OUT"
REPORT="$OUT/tspu-trial-$STAMP.txt"
LOG="$OUT/tspu-trial-$STAMP.log"
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t tspu)
VPROXY_PID=""

cleanup() {
    [ -n "$VPROXY_PID" ] && kill "$VPROXY_PID" 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

say() { printf '%s\n' "$*" | tee -a "$REPORT"; }
note() { printf '%s\n' "$*"; }
raw() { printf '%s\n' "$*" >>"$LOG"; }
msk() { TZ=Europe/Moscow date '+%Y-%m-%d %H:%M'; }
ms() { awk "BEGIN{printf \"%.0f\", ${1:-0} * 1000}"; }
mb() { awk "BEGIN{printf \"%.1f\", ${1:-0} / 1048576}"; }
mbs() { awk "BEGIN{printf \"%.2f\", ${1:-0} / 1048576}"; }
secs() { awk "BEGIN{printf \"%.1f\", ${1:-0}}"; }

find_curl() {
    local c
    for c in "${CURL:-}" /opt/homebrew/opt/curl/bin/curl /usr/local/opt/curl/bin/curl "$(command -v curl 2>/dev/null)"; do
        [ -n "$c" ] && [ -x "$c" ] || continue
        if "$c" --version 2>/dev/null | grep -q HTTP3; then
            printf '%s' "$c"
            return
        fi
    done
    command -v curl 2>/dev/null || true
}

CURL_BIN=$(find_curl)
if [ -z "$CURL_BIN" ]; then
    echo "curl не найден" >&2
    exit 1
fi
H3_CURL=0
"$CURL_BIN" --version | grep -q HTTP3 && H3_CURL=1
CURL_VERSION=$("$CURL_BIN" --version | head -1 | awk '{print $2}')
INSECURE_FLAG=""
[ "$INSECURE" = 1 ] && INSECURE_FLAG="-k"

# fetch MODE URL [curl args...]
# Печатает одну строку: код выхода|текст ошибки|версия http|код|время handshake|время всего|байт|байт в с|ip
fetch() {
    local mode=$1 url=$2 proto
    shift 2
    case $mode in
        h3) proto=--http3-only ;;
        h2) proto=--http2 ;;
        h1) proto=--http1.1 ;;
    esac
    "$CURL_BIN" $proto -sS -o /dev/null $INSECURE_FLAG --max-time "${MAXTIME:-15}" "$@" \
        -w '%{exitcode}|%{errormsg}|%{http_version}|%{http_code}|%{time_appconnect}|%{time_total}|%{size_download}|%{speed_download}|%{remote_ip}' \
        "$url" 2>>"$LOG"
    printf '\n'
}

# Разбор строки fetch в переменные R_*
parse() {
    IFS='|' read -r R_EXIT R_ERR R_VER R_CODE R_HS R_TOTAL R_BYTES R_SPEED R_IP <<EOF2
$1
EOF2
    raw "  curl: $1"
}

# Вердикт для короткого запроса (handshake + маленький ответ)
verdict_probe() {
    if [ "$R_EXIT" = 0 ]; then
        case $R_CODE in
            2*|3*|404) printf 'ok' ;;
            *) printf 'fail' ;;
        esac
    elif [ "$R_EXIT" = 28 ]; then
        printf 'timeout'
    else
        printf 'fail'
    fi
}

# Вердикт для загрузки: ok / cap (упёрлись в лимит времени) / freeze / fail
verdict_download() {
    local cap=$1
    if [ "$R_EXIT" = 0 ]; then
        case $R_CODE in
            2*) printf 'ok' ;;
            *) printf 'fail' ;;
        esac
    elif [ "$R_EXIT" = 28 ]; then
        if [ "$R_BYTES" = 0 ] || [ "${R_BYTES:-0}" -eq 0 ] 2>/dev/null; then
            printf 'timeout'
        elif awk "BEGIN{exit !($R_TOTAL >= $cap - 2)}"; then
            printf 'cap'
        else
            printf 'freeze'
        fi
    else
        printf 'fail'
    fi
}

details_download() {
    local v=$1
    case $v in
        ok) printf '%s МБ за %s с, %s МБ/с' "$(mb "$R_BYTES")" "$(secs "$R_TOTAL")" "$(mbs "$R_SPEED")" ;;
        cap) printf 'лимит %s с: %s МБ, %s МБ/с, заморозки нет' "$(secs "$R_TOTAL")" "$(mb "$R_BYTES")" "$(mbs "$R_SPEED")" ;;
        freeze) printf 'встало после %s МБ на %s с (средняя %s МБ/с)' "$(mb "$R_BYTES")" "$(secs "$R_TOTAL")" "$(mbs "$R_SPEED")" ;;
        timeout) printf 'ни байта за %s с (чёрная дыра?)' "$(secs "$R_TOTAL")" ;;
        *) printf 'curl %s: %s (код %s, %s МБ)' "$R_EXIT" "${R_ERR:-ответ не 2xx}" "$R_CODE" "$(mb "$R_BYTES")" ;;
    esac
}

# Строка отчёта в формате таблицы со страницы испытаний
row() {
    # row ТЕСТ ВЕРДИКТ ДЕТАЛИ
    say "$1 | $NETWORK | $(msk) | $2 | $3"
}

port_open() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# ---------------------------------------------------------------- environment

if [ -z "$NETWORK" ]; then
    if [ -t 0 ]; then
        printf 'Сеть (оператор, моб/провод, регион): '
        read -r NETWORK
    fi
    [ -n "$NETWORK" ] || NETWORK="не указана"
fi

for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; do
    if [ -n "${!v:-}" ]; then
        note "ВНИМАНИЕ: в окружении задан $v, он снят на время прогона"
        unset "$v"
    fi
done

if [ -n "$LINKS" ]; then
    if [ -z "$VPROXY_BIN" ]; then
        for c in "$(command -v vproxy 2>/dev/null)" ./vproxy ./target/release/vproxy; do
            [ -n "$c" ] && [ -x "$c" ] && { VPROXY_BIN=$c; break; }
        done
    fi
    if [ -z "$VPROXY_BIN" ] || [ ! -x "$VPROXY_BIN" ]; then
        echo "vproxy не найден, укажите -b путь/к/vproxy" >&2
        exit 1
    fi
    if [ ! -r "$LINKS" ]; then
        echo "файл ссылок $LINKS не читается" >&2
        exit 1
    fi
fi

OS=$(uname -s)
case $OS in
    Darwin) OS="macOS $(sw_vers -productVersion 2>/dev/null)" ;;
    Linux) OS="Linux $(. /etc/os-release 2>/dev/null && printf '%s' "$PRETTY_NAME")" ;;
esac

say "=== Испытания HTTP/3-транспорта, скрипт v$VERSION ==="
say "Дата (МСК): $(msk)"
say "Сеть: $NETWORK"
say "ОС: $OS; curl $CURL_VERSION, HTTP/3: $([ $H3_CURL = 1 ] && echo да || echo нет)"
[ -n "$LINKS" ] && say "vproxy: $("$VPROXY_BIN" --version 2>/dev/null | head -1)"

INFO=$("$CURL_BIN" -s --max-time 6 https://ipinfo.io/json 2>>"$LOG" || true)
if [ -n "$INFO" ]; then
    field() { printf '%s' "$INFO" | sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
    PUB_IP=$(field ip); PUB_ORG=$(field org); PUB_COUNTRY=$(field country); PUB_CITY=$(field city)
    say "Внешний IP: $PUB_IP ($PUB_ORG, $PUB_COUNTRY, $PUB_CITY)"
    if [ "$PUB_COUNTRY" != "RU" ]; then
        say "ВНИМАНИЕ: внешний IP не в России. Если включён VPN или прокси, выключите и запустите снова."
    fi
else
    say "Внешний IP: не удалось узнать (ipinfo.io недоступен)"
fi
[ $H3_CURL = 1 ] || say "ВНИМАНИЕ: у curl нет HTTP/3, тесты H1/H2/H6 будут пропущены (см. шапку скрипта)"

# ---------------------------------------------------------------- tests

probe_h3() {
    # probe_h3 BASE → вердикт в PV, R_* заполнены (не через $(...), иначе R_* теряются)
    parse "$(MAXTIME=15 fetch h3 "$1/")"
    PV=$(verdict_probe)
}

test_domain() {
    local base=$1 host v alt r
    host=${base#*://}
    say ""
    say "--- $base ---"

    # TCP: h2 с alt-svc
    parse "$(MAXTIME=15 fetch h2 "$base/")"
    v=$(verdict_probe)
    alt=$("$CURL_BIN" -sI $INSECURE_FLAG --max-time 15 --http2 "$base/" 2>>"$LOG" | tr -d '\r' | grep -i '^alt-svc:' | sed 's/^[Aa]lt-[Ss]vc: *//' | head -1)
    row "TCP" "$v" "h$R_VER код $R_CODE, TLS $(ms "$R_HS") мс, всего $(ms "$R_TOTAL") мс, ip $R_IP, alt-svc: ${alt:-нет}${R_ERR:+, $R_ERR}"

    if [ $H3_CURL != 1 ]; then
        row "H1" "skip" "curl без HTTP/3"
        return
    fi

    # H1: QUIC handshake
    probe_h3 "$base"
    v=$PV
    row "H1" "$v" "h$R_VER код $R_CODE, QUIC handshake $(ms "$R_HS") мс, всего $(ms "$R_TOTAL") мс${R_ERR:+, $R_ERR}"
    if [ "$v" != ok ]; then
        row "H2" "skip" "H1 не прошёл"
        row "H6" "skip" "H1 не прошёл"
        return
    fi

    # H2: 10 МБ по h3 и по h2
    parse "$(MAXTIME=120 fetch h3 "$base$SMALL" --speed-limit 2000 --speed-time 20)"
    v=$(verdict_download 120)
    row "H2" "$v" "h3 ${SMALL#/}: $(details_download "$v")"
    parse "$(MAXTIME=120 fetch h2 "$base$SMALL" --speed-limit 2000 --speed-time 20)"
    v=$(verdict_download 120)
    row "H2" "$v" "h2 ${SMALL#/} (TCP для сравнения): $(details_download "$v")"

    if [ $QUICK = 1 ]; then
        row "H2" "skip" "файл 1 ГБ и долгое соединение пропущены (-q)"
    else
        note "  файл ${BIG#/} по HTTP/3, до $BIG_CAP с ..."
        parse "$(MAXTIME=$BIG_CAP fetch h3 "$base$BIG" --speed-limit 2000 --speed-time 20)"
        v=$(verdict_download "$BIG_CAP")
        row "H2" "$v" "h3 ${BIG#/}: $(details_download "$v")"

        note "  долгое соединение: ${SMALL#/} на 50 КБ/с, около 200 с ..."
        parse "$(MAXTIME=600 fetch h3 "$base$SMALL" --limit-rate 50k --speed-limit 1000 --speed-time 30)"
        v=$(verdict_download 600)
        row "H2" "$v" "h3 долгое соединение 50 КБ/с: $(details_download "$v")"
    fi

    # H6: 4 параллельных QUIC-соединения, потом проверка заморозки
    note "  4 параллельных QUIC-соединения ..."
    local i ok=0
    for i in 1 2 3 4; do
        (MAXTIME=60 fetch h3 "$base$SMALL" --speed-limit 2000 --speed-time 20 >"$TMP/par.$i") &
    done
    wait
    local par=""
    for i in 1 2 3 4; do
        parse "$(cat "$TMP/par.$i")"
        v=$(verdict_download 60)
        [ "$v" = ok ] && ok=$((ok + 1))
        par="$par $v($(mb "$R_BYTES")МБ)"
    done
    sleep 10
    probe_h3 "$base"
    v=$PV
    if [ "$v" = ok ]; then
        row "H6" "ok" "4 соединения:$par; через 10 с домен отвечает, handshake $(ms "$R_HS") мс"
    else
        note "  домен не отвечает после параллельных соединений, жду 120 с ..."
        sleep 120
        probe_h3 "$base"
        v=$PV
        if [ "$v" = ok ]; then
            row "H6" "freeze" "4 соединения:$par; через 10 с не отвечал, через 130 с отпустило"
        else
            note "  всё ещё не отвечает, жду ещё 180 с ..."
            sleep 180
            probe_h3 "$base"
            v=$PV
            if [ "$v" = ok ]; then
                row "H6" "freeze" "4 соединения:$par; не отвечал 130 с, через 310 с отпустило"
            else
                row "H6" "freeze" "4 соединения:$par; не отвечает и через 310 с ($R_ERR)"
            fi
        fi
    fi
}

test_iperf() {
    local host=${IPERF%:*} port=${IPERF##*:} out line
    if ! command -v iperf3 >/dev/null 2>&1; then
        row "H3" "skip" "iperf3 не установлен (brew install iperf3 / apt install iperf3)"
        return
    fi
    [ "$port" = "$host" ] && port=5201
    note "  iperf3 UDP 10 Мбит/с, 60 с ..."
    out=$(iperf3 -u -c "$host" -p "$port" -b 10M -t 60 2>&1 </dev/null)
    raw "$out"
    line=$(printf '%s\n' "$out" | grep -E 'receiver' | tail -1)
    if [ -n "$line" ]; then
        # ... 0.00-60.00 sec  71.5 MBytes  10.0 Mbits/sec  0.025 ms  12/51680 (0.023%)  receiver
        local rate loss jitter
        rate=$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /bits\/sec/) print $(i-1)" "$i}')
        jitter=$(printf '%s' "$line" | awk '{for(i=1;i<=NF;i++) if($i=="ms") print $(i-1)" ms"}')
        loss=$(printf '%s' "$line" | sed -n 's/.* \([0-9]*\/[0-9]* ([^)]*)\).*/\1/p')
        local pct
        pct=$(printf '%s' "$loss" | sed -n 's/.*(\([0-9.]*\)%.*/\1/p')
        local v=ok
        awk "BEGIN{exit !(${pct:-0} > 5)}" && v=slow
        awk "BEGIN{exit !(${pct:-0} > 50)}" && v=fail
        row "H3" "$v" "UDP 10 Мбит/с 60 с: принято $rate, потери $loss, джиттер $jitter"
    else
        line=$(printf '%s\n' "$out" | grep -i 'error' | head -1)
        row "H3" "fail" "${line:-нет итоговой строки iperf3, см. лог}"
    fi
}

test_vproxy() {
    local base=$1 n=0 line fp name port
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            ''|'#'*) continue ;;
        esac
        n=$((n + 1))
        fp=$(printf '%s' "$line" | sed -n 's/.*[?&]fp=\([^&#]*\).*/\1/p')
        [ -n "$fp" ] || fp=chrome
        name=$(printf '%s' "$line" | sed -n 's/.*#\(.*\)$/\1/p')
        port=$((PROXY_PORT + n))
        printf '%s\n' "$line" >"$TMP/link.$n"
        note "  vproxy ссылка $n (fp=$fp${name:+, $name}) на порту $port ..."
        "$VPROXY_BIN" -f "$TMP/link.$n" -p "$port" </dev/null >"$TMP/vproxy.$n.log" 2>&1 &
        VPROXY_PID=$!
        local w=0
        while [ $w -lt 100 ] && ! port_open "$port"; do
            sleep 0.1
            w=$((w + 1))
        done
        if ! port_open "$port"; then
            row "H0" "fail" "fp=$fp: vproxy не открыл порт $port за 10 с, см. лог"
            cat "$TMP/vproxy.$n.log" >>"$LOG"
            kill "$VPROXY_PID" 2>/dev/null
            VPROXY_PID=""
            continue
        fi
        # первый запрос = REALITY handshake + маленький ответ
        parse "$(MAXTIME=20 fetch h1 https://www.google.com/generate_204 -x "socks5h://127.0.0.1:$port")"
        local v d
        v=$(verdict_probe)
        d="google 204 через прокси: код $R_CODE за $(ms "$R_TOTAL") мс${R_ERR:+, $R_ERR}"
        if [ "$v" = ok ] && [ -n "$base" ]; then
            parse "$(MAXTIME=120 fetch h2 "$base$SMALL" -x "socks5h://127.0.0.1:$port" --speed-limit 2000 --speed-time 20)"
            v=$(verdict_download 120)
            d="$d; ${SMALL#/} через прокси: $(details_download "$v")"
        fi
        row "H0" "$v" "fp=$fp${name:+ ($name)}: $d"
        kill "$VPROXY_PID" 2>/dev/null
        wait "$VPROXY_PID" 2>/dev/null
        VPROXY_PID=""
        raw "--- vproxy $n (fp=$fp) ---"
        grep -E 'handshake|JA4|ERROR|WARN|error' "$TMP/vproxy.$n.log" >>"$LOG"
        sleep 5
    done <"$LINKS"
    [ $n -gt 0 ] || row "H0" "skip" "в файле $LINKS нет ссылок"
}

run_round() {
    local d
    for d in $DOMAINS; do
        test_domain "$d"
    done
    if [ -n "$IPERF" ]; then
        say ""
        test_iperf
    fi
    if [ -n "$LINKS" ]; then
        say ""
        say "--- vproxy, REALITY (H0) ---"
        test_vproxy "${DOMAINS# }"
    fi
}

round=1
while [ "$round" -le "$ROUNDS" ]; do
    say ""
    say "=== Прогон $round из $ROUNDS, $(msk) ==="
    run_round
    if [ "$round" -lt "$ROUNDS" ]; then
        left=$PAUSE
        while [ "$left" -gt 0 ]; do
            note "  пауза между прогонами: осталось $left с"
            sleep 60
            left=$((left - 60))
        done
    fi
    round=$((round + 1))
done

say ""
say "=== Конец. Отчёт: $REPORT, лог для разбора ошибок: $LOG ==="
note ""
note "Скопируйте содержимое $REPORT в ответ. Если что-то не сработало, приложите и $LOG."
