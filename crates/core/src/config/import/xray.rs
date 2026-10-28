//! Import an Xray-core / Happ JSON client config as a vproxy [`Config`].
//!
//! Only what vproxy can act on is taken: the first `vless` outbound (its
//! address, user, transport and security), the first `socks` inbound port and
//! the `routing.rules` that map to our rule model. DNS, policy, stats and
//! metrics sections are ignored.

use crate::config::{
    Config, DnsCacheConfig, DnsConfig, InboundConfig, MuxConfig, RoutingConfig, RoutingRule,
    RuntimeConfig, ServerConfig, TunConfig,
};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::path::Path;
use tracing::warn;
use uuid::Uuid;

pub fn load(path: &Path, inbound_port: Option<u16>) -> Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    from_json(&text, inbound_port).with_context(|| format!("while importing {}", path.display()))
}

pub fn from_json(text: &str, inbound_port: Option<u16>) -> Result<Config> {
    let root: Value = serde_json::from_str(text).context("not valid JSON")?;
    let outbound = root["outbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|o| o["protocol"] == "vless")
        .max_by_key(|o| if o["tag"] == "proxy" { 1 } else { 0 })
        .ok_or_else(|| anyhow::anyhow!("no vless outbound in the Xray config"))?;

    let vnext = &outbound["settings"]["vnext"][0];
    let address = str_field(&vnext["address"]).context("outbound vnext.address")?;
    let port = vnext["port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .context("outbound vnext.port")?;
    let user = &vnext["users"][0];
    let uuid: Uuid = str_field(&user["id"])
        .context("outbound user id")?
        .parse()
        .context("outbound user id is not a UUID")?;
    let flow = opt_str(&user["flow"]);
    let encryption = opt_str(&user["encryption"]).unwrap_or_else(|| "none".to_string());

    let stream = &outbound["streamSettings"];
    let network = opt_str(&stream["network"]).unwrap_or_else(|| "tcp".to_string());
    let security = opt_str(&stream["security"]).unwrap_or_else(|| "none".to_string());
    let transport = match network.as_str() {
        "tcp" | "raw" => "tcp",
        "ws" | "websocket" => "ws",
        "xhttp" | "splithttp" => "xhttp",
        other => bail!("transport network {other:?} is not supported (tcp, ws and xhttp are)"),
    };
    let (ws_path, ws_host, xhttp_mode, xhttp_extra) = match transport {
        "ws" => {
            let ws = &stream["wsSettings"];
            let host = opt_str(&ws["host"]).or_else(|| opt_str(&ws["headers"]["Host"]));
            (opt_str(&ws["path"]), host, None, None)
        }
        "xhttp" => {
            let x = if stream["xhttpSettings"].is_object() {
                &stream["xhttpSettings"]
            } else {
                &stream["splithttpSettings"]
            };
            let extra = x
                .as_object()
                .filter(|o| !o.is_empty())
                .map(|_| x.to_string());
            (
                opt_str(&x["path"]),
                opt_str(&x["host"]),
                opt_str(&x["mode"]),
                extra,
            )
        }
        _ => (None, None, None, None),
    };
    let alpn = tls_alpn(&stream["tlsSettings"]["alpn"]);

    let tls = &stream["tlsSettings"];
    let reality = &stream["realitySettings"];
    let (sni, fingerprint) = match security.as_str() {
        "tls" => (opt_str(&tls["serverName"]), opt_str(&tls["fingerprint"])),
        "reality" => (
            opt_str(&reality["serverName"]),
            opt_str(&reality["fingerprint"]),
        ),
        _ => (None, None),
    };
    let security = match security.as_str() {
        "tls" | "reality" | "none" => security,
        "" => "none".to_string(),
        other => bail!("security {other:?} is not supported"),
    };

    let server = ServerConfig {
        remark: opt_str(&root["remarks"]).or_else(|| opt_str(&outbound["tag"])),
        address,
        port,
        uuid,
        use_tls: security != "none",
        security: security.clone(),
        encryption,
        sni,
        fingerprint: fingerprint.filter(|f| !f.is_empty()),
        reality_public_key: opt_str(&reality["publicKey"]),
        reality_short_id: opt_str(&reality["shortId"]),
        flow: flow.filter(|f| !f.is_empty()),
        spider_x: opt_str(&reality["spiderX"]),
        transport: transport.to_string(),
        ws_path,
        ws_host,
        alpn,
        xhttp_mode,
        xhttp_extra,
    };

    let socks = root["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|i| i["protocol"] == "socks");
    let inbound = InboundConfig {
        address: socks
            .and_then(|i| opt_str(&i["listen"]))
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        port: inbound_port
            .or_else(|| {
                socks
                    .and_then(|i| i["port"].as_u64())
                    .and_then(|p| u16::try_from(p).ok())
            })
            .unwrap_or(1080),
        protocol: "socks5".to_string(),
    };

    let config = Config {
        server,
        inbound,
        dns: DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![],
            cache: DnsCacheConfig::default(),
        },
        runtime: RuntimeConfig::default_values(),
        tun: TunConfig::default(),
        routing: import_routing(&root["routing"]),
        mux: import_mux(&outbound["mux"]),
    };
    config.validate()?;
    Ok(config)
}

/// `tlsSettings.alpn` (array or string) → comma separated list.
fn tls_alpn(v: &Value) -> Option<String> {
    let list: Vec<String> = match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Value::String(s) => s.split(',').map(|x| x.trim().to_string()).collect(),
        _ => Vec::new(),
    };
    let list: Vec<String> = list.into_iter().filter(|x| !x.is_empty()).collect();
    (!list.is_empty()).then(|| list.join(","))
}

/// Xray outbound `mux` → `[mux]`.
fn import_mux(mux: &Value) -> MuxConfig {
    let mut out = MuxConfig::default();
    if mux["enabled"].as_bool() == Some(true) {
        out.enabled = true;
        if let Some(c) = mux["concurrency"].as_i64() {
            out.concurrency = c;
        }
    }
    out
}

/// Xray `routing.rules` → `[routing]`. Rules bound to inbound tags (DNS/metrics
/// plumbing) and conditions we cannot express are skipped with a warning.
fn import_routing(routing: &Value) -> RoutingConfig {
    let mut out = RoutingConfig {
        final_outbound: "proxy".to_string(),
        rules: Vec::new(),
        direct_suffix: Vec::new(),
    };
    for (i, rule) in routing["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        if !rule["inboundTag"].is_null() {
            continue;
        }
        let outbound = match rule["outboundTag"].as_str() {
            Some("direct") => "direct",
            Some("proxy") => "proxy",
            Some("block") => "block",
            other => {
                warn!("xray import: rule {i}: unsupported outboundTag {other:?}, skipped");
                continue;
            }
        };
        let mut r = RoutingRule {
            outbound: outbound.to_string(),
            ..Default::default()
        };
        for d in str_list(&rule["domain"]) {
            if let Some(x) = d.strip_prefix("geosite:") {
                r.geosite.push(x.to_string());
            } else if let Some(x) = d.strip_prefix("domain:") {
                r.domain_suffix.push(x.to_string());
            } else if let Some(x) = d.strip_prefix("full:") {
                r.domain.push(x.to_string());
            } else if let Some(x) = d.strip_prefix("keyword:") {
                r.domain_keyword.push(x.to_string());
            } else if d.starts_with("regexp:") || d.starts_with("ext:") {
                warn!("xray import: rule {i}: domain pattern {d:?} not supported, skipped");
            } else {
                // Xray: a bare string is a substring match.
                r.domain_keyword.push(d);
            }
        }
        for ip in str_list(&rule["ip"]) {
            if ip == "geoip:private" {
                r.ip_private = true;
            } else if let Some(x) = ip.strip_prefix("geoip:") {
                r.geoip.push(x.to_string());
            } else if ip.starts_with("ext:") {
                warn!("xray import: rule {i}: ip pattern {ip:?} not supported, skipped");
            } else {
                r.ip_cidr.push(ip);
            }
        }
        if let Some(port) = rule["port"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| rule["port"].as_u64().map(|p| p.to_string()))
        {
            for part in port.split(',') {
                match part.trim().parse::<u16>() {
                    Ok(p) => r.port.push(p),
                    Err(_) => {
                        warn!("xray import: rule {i}: port {part:?} (ranges unsupported), skipped")
                    }
                }
            }
        }
        let empty = r.domain.is_empty()
            && r.domain_suffix.is_empty()
            && r.domain_keyword.is_empty()
            && r.ip_cidr.is_empty()
            && !r.ip_private
            && r.port.is_empty()
            && r.geoip.is_empty()
            && r.geosite.is_empty();
        if empty {
            warn!("xray import: rule {i}: no usable conditions, skipped");
            continue;
        }
        out.rules.push(r);
    }
    out
}

fn str_field(v: &Value) -> Result<String> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("missing or not a string"))
}

fn opt_str(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned).filter(|s| !s.is_empty())
}

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::Array(items) => items
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAPP_WS: &str = r#"{
      "inbounds": [
        {"listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": {"udp": true}, "tag": "socks"},
        {"listen": "127.0.0.1", "port": 10809, "protocol": "http", "tag": "http"}
      ],
      "outbounds": [
        {"protocol": "vless", "tag": "proxy",
         "settings": {"vnext": [{"address": "nearsky.example", "port": 443,
            "users": [{"encryption": "none", "id": "00000000-0000-0000-0000-000000000001", "level": 8}]}]},
         "streamSettings": {"network": "ws", "security": "tls",
            "tlsSettings": {"alpn": [], "fingerprint": "", "serverName": "nearsky.example"},
            "wsSettings": {"headers": {"Host": "nearsky.example"}, "path": "/ygrouke6xa"}}},
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"}
      ],
      "remarks": "nearsky-vless",
      "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
        {"inboundTag": ["metrics_in"], "outboundTag": "metrics_out"},
        {"inboundTag": ["socks"], "outboundTag": "proxy", "port": "53"},
        {"ip": ["geoip:private"], "outboundTag": "direct"},
        {"domain": ["geosite:category-ru", "domain:yandex.ru", "full:exact.ru", "sber"], "outboundTag": "direct"},
        {"ip": ["geoip:ru", "10.0.0.0/8"], "outboundTag": "direct", "port": "80,443"},
        {"domain": ["regexp:.*ads.*"], "outboundTag": "block"}
      ]}
    }"#;

    #[test]
    fn imports_happ_ws_tls_config() {
        let c = from_json(HAPP_WS, None).unwrap();
        assert_eq!(c.server.address, "nearsky.example");
        assert_eq!(c.server.port, 443);
        assert_eq!(c.server.security, "tls");
        assert_eq!(c.server.transport, "ws");
        assert_eq!(c.server.ws_path.as_deref(), Some("/ygrouke6xa"));
        assert_eq!(c.server.ws_host.as_deref(), Some("nearsky.example"));
        assert_eq!(c.server.sni.as_deref(), Some("nearsky.example"));
        assert_eq!(c.server.remark.as_deref(), Some("nearsky-vless"));
        assert!(c.server.fingerprint.is_none());
        assert_eq!(c.inbound.port, 10808);
        assert_eq!(from_json(HAPP_WS, Some(1080)).unwrap().inbound.port, 1080);

        let rules = &c.routing.rules;
        assert_eq!(
            rules.len(),
            3,
            "inbound-tag rules and the regexp-only rule are skipped"
        );
        assert!(rules[0].ip_private && rules[0].outbound == "direct");
        assert_eq!(rules[1].geosite, vec!["category-ru"]);
        assert_eq!(rules[1].domain_suffix, vec!["yandex.ru"]);
        assert_eq!(rules[1].domain, vec!["exact.ru"]);
        assert_eq!(rules[1].domain_keyword, vec!["sber"]);
        assert_eq!(rules[2].geoip, vec!["ru"]);
        assert_eq!(rules[2].ip_cidr, vec!["10.0.0.0/8"]);
        assert_eq!(rules[2].port, vec![80, 443]);
    }

    #[test]
    fn imports_xhttp_stream_settings() {
        let json = r#"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"x.example","port":443,
          "users":[{"id":"9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d","encryption":"none"}]}]},
          "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"cdn.example","alpn":["h2","http/1.1"]},
            "xhttpSettings":{"path":"/api","host":"cdn.example","mode":"packet-up","noGRPCHeader":true}}}]}"#;
        let c = from_json(json, Some(1080)).unwrap();
        assert_eq!(c.server.transport, "xhttp");
        assert_eq!(c.server.ws_path.as_deref(), Some("/api"));
        assert_eq!(c.server.ws_host.as_deref(), Some("cdn.example"));
        assert_eq!(c.server.xhttp_mode.as_deref(), Some("packet-up"));
        assert_eq!(c.server.alpn.as_deref(), Some("h2,http/1.1"));
        assert!(c
            .server
            .xhttp_extra
            .as_deref()
            .unwrap()
            .contains("noGRPCHeader"));
        c.validate().unwrap();
    }

    #[test]
    fn rejects_unsupported_transport() {
        let json = HAPP_WS.replace(r#""network": "ws""#, r#""network": "grpc""#);
        assert!(from_json(&json, None).is_err());
    }
}
