#!/bin/sh
# vproxy on OpenWrt: a transparent, whole-LAN anti-censorship router.
#
# Routes every device on the router's LAN through the h3/QUIC transport to the
# exit server, with DNS resolved inside the tunnel (no leak). Chain:
#
#   LAN device -> tun -> sing-box -> SOCKS -> vproxy -> h3/QUIC -> exit server
#
# vproxy speaks our transport and offers a local SOCKS5 inbound; sing-box is the
# TUN + routing + DNS layer (sing-box's own DoH runs over the proxy, since raw
# UDP DNS over SOCKS is unreliable). Requires an aarch64 or x86_64 OpenWrt
# device (the aws-lc-rs crypto core has no MIPS/ARMv7 build) with ~20 MB free on
# /overlay and the default OpenWrt package feeds reachable.
#
# Usage, on the router (or over ssh):
#   sh install.sh 'h3://<uuid>@<host>:443?sni=<host>#label'
# Re-running is safe (idempotent); it reconfigures in place.
#
# Env overrides: VPROXY_VERSION (default below), SERVER_IP (skip DNS lookup),
# SOCKS_PORT (default 1080), REPO (GitHub owner/repo of the release).
set -eu

VPROXY_VERSION="${VPROXY_VERSION:-0.18.4}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
REPO="${REPO:-maxeliseyev/vless-proxy}"

LINK="${1:-$(cat /etc/vproxy/link 2>/dev/null || true)}"
[ -n "$LINK" ] || { echo "usage: sh install.sh 'h3://<uuid>@<host>:443?sni=<host>#label'" >&2; exit 1; }

# --- parse the exit host out of the link ------------------------------------
HOST=$(printf '%s' "$LINK" | sed -E 's#^[a-z0-9]+://[^@]*@([^:/?#]+).*#\1#')
[ -n "$HOST" ] && [ "$HOST" != "$LINK" ] || { echo "cannot parse host from link" >&2; exit 1; }
echo ">> exit host: $HOST  (vproxy $VPROXY_VERSION)"

# --- arch guard + release asset name ----------------------------------------
ARCH=$(uname -m)
case "$ARCH" in
  aarch64) ASSET=arm64 ;;
  x86_64)  ASSET=x86_64 ;;
  *) echo "unsupported arch '$ARCH' — the crypto core builds only on aarch64/x86_64" >&2; exit 1 ;;
esac

# --- dependencies (sing-box, tun, curl) -------------------------------------
echo ">> installing dependencies"
if command -v apk >/dev/null 2>&1; then
  apk update >/dev/null 2>&1 || true
  apk add sing-box kmod-tun curl >/dev/null
else
  opkg update >/dev/null 2>&1 || true
  opkg install sing-box kmod-tun curl >/dev/null
fi
modprobe tun 2>/dev/null || true
[ -e /dev/net/tun ] || { echo "no /dev/net/tun after loading kmod-tun" >&2; exit 1; }

# --- vproxy binary (from the GitHub release, if not already this version) ---
if ! /usr/bin/vproxy --version 2>/dev/null | grep -q "$VPROXY_VERSION"; then
  TGZ="vproxy-linux-${ASSET}-musl.tar.gz"
  URL="https://github.com/$REPO/releases/download/v${VPROXY_VERSION}/$TGZ"
  echo ">> downloading $URL"
  curl -fsSL -o "/tmp/$TGZ" "$URL"
  tar xzf "/tmp/$TGZ" -C /tmp
  install -m 0755 "/tmp/vproxy-linux-${ASSET}-musl/vproxy" /usr/bin/vproxy
  rm -rf "/tmp/$TGZ" "/tmp/vproxy-linux-${ASSET}-musl"
fi
echo ">> vproxy: $(/usr/bin/vproxy --version)"

# --- link + pin the exit host so vproxy resolves it WITHOUT the tunnel ------
# (otherwise vproxy's own DNS for the exit host is pulled into the tunnel it is
# trying to build -> deadlock). The pin + the route rule keep its QUIC direct.
mkdir -p /etc/vproxy
printf '%s\n' "$LINK" > /etc/vproxy/link
chmod 600 /etc/vproxy/link

IP="${SERVER_IP:-}"
if [ -z "$IP" ]; then
  IP=$(nslookup "$HOST" 2>/dev/null | sed -n '/^Name:/,$p' | awk '/[Aa]ddress/{print $NF}' | grep -Eo '^[0-9]+(\.[0-9]+){3}$' | head -1)
fi
[ -n "$IP" ] || { echo "cannot resolve $HOST — re-run with SERVER_IP=<ip>" >&2; exit 1; }
sed -i "/[[:space:]]$HOST\$/d" /etc/hosts 2>/dev/null || true
echo "$IP $HOST" >> /etc/hosts
echo ">> pinned $HOST -> $IP in /etc/hosts"

# --- vproxy procd service (SOCKS5 on loopback) ------------------------------
cat > /etc/init.d/vproxy <<INIT
#!/bin/sh /etc/rc.common
# vproxy h3 client — local SOCKS5 inbound; sing-box routes the LAN into it.
USE_PROCD=1
START=95
STOP=10
PROG=/usr/bin/vproxy

start_service() {
    procd_open_instance
    procd_set_param command "\$PROG" -f /etc/vproxy/link -l 127.0.0.1 -p $SOCKS_PORT
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_set_param env HOME=/root
    procd_close_instance
}
INIT
chmod 0755 /etc/init.d/vproxy
/etc/init.d/vproxy enable

# --- sing-box config: tun + DNS-hijack (DoH over the proxy) + routing -------
mkdir -p /etc/sing-box
cat > /etc/sing-box/config.json <<CFG
{
  "log": { "level": "warn", "output": "/tmp/sb.log", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" }
    ],
    "final": "remote",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["172.19.0.1/30"],
      "auto_route": true,
      "strict_route": true,
      "stack": "gvisor"
    }
  ],
  "outbounds": [
    { "type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": $SOCKS_PORT },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_cidr": ["$IP/32"], "outbound": "direct" },
      { "ip_is_private": true, "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
CFG
sing-box check -c /etc/sing-box/config.json

# sing-box must run as root for TUN/auto_route (the packaged default is a
# low-priv user, which cannot set up the tunnel).
uci set sing-box.main.user='root'
uci set sing-box.main.enabled='1'
uci set sing-box.main.conffile='/etc/sing-box/config.json'
uci commit sing-box
/etc/init.d/sing-box enable

# --- firewall: allow LAN clients to be forwarded into the tunnel -----------
# tun0 is unzoned by default and fw4's forward policy is drop, so forwarded
# LAN traffic to it is rejected (the router's own traffic still works). Put
# tun0 in its own zone (masq + MSS clamp) and allow lan -> proxy forwarding.
uci -q delete firewall.proxy || true
uci set firewall.proxy='zone'
uci set firewall.proxy.name='proxy'
uci set firewall.proxy.input='ACCEPT'
uci set firewall.proxy.output='ACCEPT'
uci set firewall.proxy.forward='ACCEPT'
uci set firewall.proxy.masq='1'
uci set firewall.proxy.mtu_fix='1'
uci add_list firewall.proxy.device='tun0'
uci -q delete firewall.lan_proxy || true
uci set firewall.lan_proxy='forwarding'
uci set firewall.lan_proxy.src='lan'
uci set firewall.lan_proxy.dest='proxy'
uci commit firewall

# At boot fw4 starts before sing-box creates tun0, so the zone binds to nothing
# until a reload. Reload fw4 whenever tun0 appears.
mkdir -p /etc/hotplug.d/net
cat > /etc/hotplug.d/net/99-proxy-fw <<'HP'
#!/bin/sh
[ "$ACTION" = "add" ] && { [ "$INTERFACE" = "tun0" ] || [ "$DEVICE" = "tun0" ]; } && fw4 reload
HP
chmod 0755 /etc/hotplug.d/net/99-proxy-fw

# --- (re)start, vproxy first so sing-box's SOCKS outbound has a listener ----
echo ">> starting services"
/etc/init.d/vproxy restart
sleep 2
/etc/init.d/sing-box restart
sleep 6
fw4 reload >/dev/null 2>&1 || true   # bind the proxy zone now that tun0 exists

echo
echo ">> done. Checking the exit:"
OUT=$(curl -s --max-time 20 https://ipinfo.io/json 2>/dev/null || true)
echo "$OUT" | grep -E '"ip"|"city"|"country"' || echo "   (no answer yet — give it a few seconds and retry: curl -s https://ipinfo.io/json)"
echo
echo "All LAN traffic now exits through $HOST. To stop: /etc/init.d/sing-box stop"
