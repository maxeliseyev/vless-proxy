//! System-wide (TUN) mode, built the way Happ does it: a `sing-box` sidecar
//! owns the TUN interface and forwards everything to vproxy's local SOCKS5
//! inbound. vproxy has no TUN stack of its own.
//!
//! The generated sing-box config must not create a loop: vproxy's own
//! connection to the VLESS server (and sing-box's, and xray-core's when the
//! sidecar engine is in use) is routed `direct` by process name and by the
//! server address, and those processes resolve DNS directly as well.

use crate::config::{Config, InboundProtocol};
use crate::proxy::routing::Outbound;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::Builder;
use tokio::process::Command;
use tokio::sync::watch;
use tracing::{info, warn};

/// Process names whose traffic bypasses the tunnel (plus our own executable).
const BYPASS_PROCESSES: [&str; 2] = ["sing-box", "xray"];

/// Name of the running executable, as sing-box's `process_name` sees it.
pub fn current_process_name() -> Option<String> {
    std::env::current_exe()
        .ok()?
        .file_name()?
        .to_str()
        .map(str::to_owned)
}

/// Render the sing-box configuration for `config`.
pub fn build_sing_box_config(config: &Config, self_name: Option<&str>) -> Result<Value> {
    if !matches!(config.inbound_protocol()?, InboundProtocol::Socks5) {
        bail!("TUN mode needs inbound.protocol = \"socks5\" (sing-box forwards to a SOCKS5 proxy)");
    }
    let tun = &config.tun;

    let mut processes: Vec<String> = BYPASS_PROCESSES.iter().map(|s| s.to_string()).collect();
    if let Some(name) = self_name {
        if !processes.iter().any(|p| p == name) {
            processes.insert(0, name.to_string());
        }
    }

    let dns_direct = json!({
        "type": "udp",
        "tag": "dns-direct",
        "server": tun.dns,
        "server_port": 53,
        "detour": "direct"
    });
    let dns_proxy = json!({
        "type": "udp",
        "tag": "dns-proxy",
        "server": tun.dns,
        "server_port": 53,
        "detour": "proxy"
    });
    let dns_final = if tun.dns_via_proxy {
        "dns-proxy"
    } else {
        "dns-direct"
    };
    let dns_servers = if tun.dns_via_proxy {
        vec![dns_direct, dns_proxy]
    } else {
        vec![dns_direct]
    };

    let mut route_rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "process_name": processes, "outbound": "direct" }),
    ];
    match config.server.address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            route_rules.push(json!({ "ip_cidr": [format!("{ip}/32")], "outbound": "direct" }))
        }
        Ok(IpAddr::V6(ip)) => {
            route_rules.push(json!({ "ip_cidr": [format!("{ip}/128")], "outbound": "direct" }))
        }
        Err(_) => {
            route_rules.push(json!({ "domain": [config.server.address], "outbound": "direct" }))
        }
    }
    if !tun.bypass_domains.is_empty() {
        route_rules.push(json!({ "domain_suffix": tun.bypass_domains, "outbound": "direct" }));
    }
    if !tun.bypass_cidrs.is_empty() {
        route_rules.push(json!({ "ip_cidr": tun.bypass_cidrs, "outbound": "direct" }));
    }

    // [routing] rules, 1:1 (same AND/OR semantics as sing-box).
    let mut rule_sets: Vec<Value> = Vec::new();
    for rule in &config.routing.rules {
        let outbound = Outbound::parse(&rule.outbound)?;
        let mut r = serde_json::Map::new();
        if !rule.domain.is_empty() {
            r.insert("domain".into(), json!(rule.domain));
        }
        if !rule.domain_suffix.is_empty() {
            r.insert("domain_suffix".into(), json!(rule.domain_suffix));
        }
        if !rule.domain_keyword.is_empty() {
            r.insert("domain_keyword".into(), json!(rule.domain_keyword));
        }
        if !rule.ip_cidr.is_empty() {
            r.insert("ip_cidr".into(), json!(rule.ip_cidr));
        }
        if rule.ip_private {
            r.insert("ip_is_private".into(), json!(true));
        }
        if !rule.port.is_empty() {
            r.insert("port".into(), json!(rule.port));
        }
        let mut tags: Vec<String> = Vec::new();
        for g in &rule.geoip {
            let tag = format!("geoip-{g}");
            if !rule_sets.iter().any(|s| s["tag"] == tag) {
                rule_sets.push(json!({
                    "type": "remote", "tag": tag, "format": "binary",
                    "url": format!("https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{g}.srs"),
                    "download_detour": "proxy"
                }));
            }
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        for g in &rule.geosite {
            let tag = format!("geosite-{g}");
            if !rule_sets.iter().any(|s| s["tag"] == tag) {
                rule_sets.push(json!({
                    "type": "remote", "tag": tag, "format": "binary",
                    "url": format!("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{g}.srs"),
                    "download_detour": "proxy"
                }));
            }
            if !tags.contains(&tag) {
                tags.push(tag);
            }
        }
        if !tags.is_empty() {
            r.insert("rule_set".into(), json!(tags));
        }
        match outbound {
            Outbound::Block => {
                r.insert("action".into(), json!("reject"));
            }
            other => {
                r.insert("outbound".into(), json!(other.as_str()));
            }
        }
        route_rules.push(Value::Object(r));
    }
    let final_outbound = if config.routing.final_outbound.trim().is_empty() {
        Outbound::Proxy
    } else {
        Outbound::parse(&config.routing.final_outbound)?
    };

    Ok(json!({
        "log": { "level": if tun.log_level.is_empty() { "warn" } else { tun.log_level.as_str() }, "timestamp": true },
        "dns": {
            "servers": dns_servers,
            "rules": [
                { "process_name": processes, "server": "dns-direct" }
            ],
            "final": dns_final
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": [tun.address],
            "mtu": tun.mtu,
            "auto_route": true,
            "strict_route": tun.strict_route,
            "stack": tun.stack
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "proxy",
                "server": config.inbound.address,
                "server_port": config.inbound.port,
                "udp_fragment": true,
                "domain_resolver": { "server": "dns-direct", "strategy": "prefer_ipv4" }
            },
            {
                "type": "direct",
                "tag": "direct",
                "domain_resolver": { "server": "dns-direct", "strategy": "prefer_ipv4" }
            }
        ],
        "route": {
            "auto_detect_interface": true,
            "final": final_outbound.as_str(),
            "rule_set": rule_sets,
            "rules": route_rules
        }
    }))
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Spawn sing-box with a generated config and keep it alive until `shutdown`
/// fires or the process exits. Creating a TUN interface needs root.
pub async fn run(config: Arc<Config>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    if !is_root() {
        bail!("TUN mode creates a network interface and must run as root (sudo vproxy --tun ...)");
    }
    let rendered = build_sing_box_config(config.as_ref(), current_process_name().as_deref())?;
    let mut temp = Builder::new()
        .prefix("vproxy-singbox-")
        .suffix(".json")
        .tempfile()
        .context("Failed to create temporary sing-box config")?;
    serde_json::to_writer_pretty(temp.as_file_mut(), &rendered)?;
    temp.as_file_mut().flush()?;

    // Let the local inbound come up first.
    tokio::time::sleep(Duration::from_millis(300)).await;
    info!(
        "Starting sing-box TUN sidecar ({}) -> socks5 {}",
        config.tun.sing_box_path,
        config.inbound.endpoint()
    );
    crate::system::singbox::warn_if_unsafe_for_root(
        std::path::Path::new(&config.tun.sing_box_path),
        "sing-box",
    );
    let mut child = Command::new(&config.tun.sing_box_path)
        .arg("run")
        .arg("-c")
        .arg(temp.path())
        .arg("--disable-color")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "Failed to start sing-box binary `{}` for TUN mode. {}",
                config.tun.sing_box_path,
                crate::system::singbox::not_found_hint()
            )
        })?;

    tokio::select! {
        status = child.wait() => {
            let status = status?;
            bail!("sing-box TUN sidecar exited with status {status}");
        }
        _ = shutdown.changed() => {
            info!("Stopping sing-box TUN sidecar");
            // SIGTERM lets sing-box remove its routes and DNS settings;
            // tokio's kill() would be SIGKILL.
            if let Some(pid) = child.id() {
                // SAFETY: plain syscall on a pid we own.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
            }
            match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    warn!("sing-box did not exit after SIGTERM, killing it");
                    let _ = child.kill().await;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::url::VlessUrl;
    use crate::config::Config;

    fn cfg(url: &str) -> Config {
        let mut c = Config::from_vless_url(&VlessUrl::parse(url).unwrap(), 1080);
        c.tun.enabled = true;
        c
    }

    #[test]
    fn routes_self_and_server_direct_to_avoid_loops() {
        let config =
            cfg("vless://00000000-0000-0000-0000-000000000000@195.60.237.42:443?security=tls");
        let v = build_sing_box_config(&config, Some("vproxy")).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        let text = v.to_string();
        assert!(text.contains(r#""process_name":["vproxy","sing-box","xray"]"#));
        assert!(rules
            .iter()
            .any(|r| r["ip_cidr"] == json!(["195.60.237.42/32"]) && r["outbound"] == "direct"));
        assert_eq!(v["route"]["final"], "proxy");
        assert_eq!(v["route"]["rule_set"].as_array().unwrap().len(), 0);
        assert_eq!(v["outbounds"][0]["server_port"], 1080);
        assert_eq!(v["dns"]["rules"][0]["server"], "dns-direct");
        assert_eq!(v["dns"]["final"], "dns-proxy");
    }

    #[test]
    fn domain_server_is_bypassed_by_name_and_dns_can_stay_direct() {
        let mut config =
            cfg("vless://00000000-0000-0000-0000-000000000000@vpn.example.com:443?security=tls");
        config.tun.dns_via_proxy = false;
        config.tun.bypass_domains = vec!["lan".into()];
        config.tun.bypass_cidrs = vec!["192.168.0.0/16".into()];
        let v = build_sing_box_config(&config, None).unwrap();
        let rules = v["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["domain"] == json!(["vpn.example.com"])));
        assert!(rules.iter().any(|r| r["domain_suffix"] == json!(["lan"])));
        assert!(rules
            .iter()
            .any(|r| r["ip_cidr"] == json!(["192.168.0.0/16"])));
        assert_eq!(v["dns"]["final"], "dns-direct");
        assert_eq!(v["dns"]["servers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn requires_socks5_inbound() {
        let mut config =
            cfg("vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls");
        config.inbound.protocol = "http".to_string();
        assert!(build_sing_box_config(&config, None).is_err());
    }

    #[test]
    fn translates_routing_rules_and_rule_sets() {
        use crate::config::RoutingRule;
        let mut config =
            cfg("vless://00000000-0000-0000-0000-000000000000@1.2.3.4:443?security=tls");
        config.routing.final_outbound = "direct".into();
        config.routing.rules = vec![
            RoutingRule {
                outbound: "proxy".into(),
                geoip: vec!["ru".into()],
                geosite: vec!["category-ru".into(), "category-ru".into()],
                ..Default::default()
            },
            RoutingRule {
                outbound: "block".into(),
                domain_suffix: vec!["ads.example".into()],
                port: vec![80, 443],
                ..Default::default()
            },
            RoutingRule {
                outbound: "direct".into(),
                ip_private: true,
                ..Default::default()
            },
        ];
        let v = build_sing_box_config(&config, Some("vproxy")).unwrap();
        assert_eq!(v["route"]["final"], "direct");
        let sets = v["route"]["rule_set"].as_array().unwrap();
        assert_eq!(sets.len(), 2, "duplicate geosite tag collapsed");
        assert!(sets.iter().any(
            |s| s["tag"] == "geoip-ru" && s["url"].as_str().unwrap().ends_with("geoip-ru.srs")
        ));
        let rules = v["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(
            |r| r["rule_set"] == json!(["geoip-ru", "geosite-category-ru"])
                && r["outbound"] == "proxy"
        ));
        assert!(rules
            .iter()
            .any(|r| r["domain_suffix"] == json!(["ads.example"])
                && r["port"] == json!([80, 443])
                && r["action"] == "reject"));
        assert!(rules
            .iter()
            .any(|r| r["ip_is_private"] == true && r["outbound"] == "direct"));
    }
}
