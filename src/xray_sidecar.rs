use crate::config::{Config, InboundProtocol, TransportSecurity};
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::sync::Arc;
use tempfile::Builder;
use tokio::process::Command;
use tracing::info;

pub fn should_use(config: &Config) -> Result<bool> {
    config.needs_xray_sidecar()
}

pub async fn run(config: Arc<Config>) -> Result<()> {
    let rendered = build_config_json(config.as_ref())?;
    let mut temp = Builder::new()
        .prefix("vproxy-xray-")
        .suffix(".json")
        .tempfile()
        .context("Failed to create temporary xray config")?;
    serde_json::to_writer_pretty(temp.as_file_mut(), &rendered)
        .context("Failed to write xray config JSON")?;
    temp.as_file_mut().flush()?;

    info!(
        "Starting xray-core sidecar for {}:{} using {}",
        config.server.address, config.server.port, config.runtime.xray_path
    );

    let mut child = Command::new(&config.runtime.xray_path)
        .arg("run")
        .arg("-c")
        .arg(temp.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| {
            format!(
                "Failed to start xray-core binary `{}` for REALITY/Vision transport",
                config.runtime.xray_path
            )
        })?;

    let status = child.wait().await?;
    if !status.success() {
        bail!("xray-core sidecar exited with status {status}");
    }

    Ok(())
}

pub(crate) fn build_config_json(config: &Config) -> Result<Value> {
    if !matches!(config.transport_security()?, TransportSecurity::Reality) {
        bail!("xray-core sidecar is currently only used for REALITY transport");
    }

    let inbound = match config.inbound_protocol()? {
        InboundProtocol::Socks5 => json!({
            "listen": config.inbound.address,
            "port": config.inbound.port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": true
            }
        }),
        InboundProtocol::Http => json!({
            "listen": config.inbound.address,
            "port": config.inbound.port,
            "protocol": "http",
            "settings": {}
        }),
    };

    let mut user = Map::new();
    user.insert("id".to_string(), json!(config.server.uuid.to_string()));
    user.insert("encryption".to_string(), json!(config.server.encryption));
    if let Some(flow) = &config.server.flow {
        user.insert("flow".to_string(), json!(flow));
    }

    let settings = json!({
        "vnext": [{
            "address": config.server.address,
            "port": config.server.port,
            "users": [Value::Object(user)]
        }]
    });

    let stream_settings = json!({
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
            "show": false,
            "serverName": config.server.tls_server_name(),
            "fingerprint": config.server.reality_fingerprint(),
            "publicKey": config.server.reality_public_key.as_deref().unwrap_or(""),
            "shortId": config.server.reality_short_id.as_deref().unwrap_or(""),
            "spiderX": config.server.reality_spider_x()
        }
    });

    Ok(json!({
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [inbound],
        "outbounds": [{
            "protocol": "vless",
            "settings": settings,
            "streamSettings": stream_settings
        }]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsCacheConfig, DnsConfig, InboundConfig, RuntimeConfig, ServerConfig};
    use uuid::Uuid;

    fn base_reality_config() -> Config {
        Config {
            server: ServerConfig {
                address: "194.87.235.91".to_string(),
                port: 443,
                uuid: Uuid::parse_str("1b71598d-e3cd-4cf0-8c99-d1ce08ad4881").unwrap(),
                use_tls: true,
                security: "reality".to_string(),
                encryption: "none".to_string(),
                sni: Some("www.intel.com".to_string()),
                fingerprint: Some("chrome".to_string()),
                reality_public_key: Some("T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8".to_string()),
                reality_short_id: Some("b59cfeedfabf9f".to_string()),
                flow: Some("xtls-rprx-vision".to_string()),
                spider_x: Some("/".to_string()),
                transport: "tcp".to_string(),
                ws_path: None,
                ws_host: None,
                remark: None,
            },
            inbound: InboundConfig {
                address: "127.0.0.1".to_string(),
                port: 1080,
                protocol: "socks5".to_string(),
            },
            dns: DnsConfig {
                mode: "remote".to_string(),
                strategy: "prefer_ipv4".to_string(),
                rules: vec![],
                cache: DnsCacheConfig::default(),
            },
            runtime: RuntimeConfig {
                connect_timeout_secs: 10,
                read_timeout_secs: 300,
                write_timeout_secs: 60,
                idle_timeout_secs: 600,
                max_connections: 1024,
                xray_path: "xray".to_string(),
                reality_engine: "auto".to_string(),
            },
            tun: Default::default(),
            routing: Default::default(),
            mux: Default::default(),
        }
    }

    #[test]
    fn builds_xray_config_for_reality_vision() {
        let config = base_reality_config();
        let rendered = build_config_json(&config).unwrap();

        assert_eq!(rendered["inbounds"][0]["protocol"], "socks");
        assert_eq!(rendered["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            rendered["outbounds"][0]["streamSettings"]["security"],
            "reality"
        );
        assert_eq!(
            rendered["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "www.intel.com"
        );
        assert_eq!(
            rendered["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"],
            "T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8"
        );
        assert_eq!(
            rendered["outbounds"][0]["streamSettings"]["realitySettings"]["shortId"],
            "b59cfeedfabf9f"
        );
        assert_eq!(
            rendered["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"],
            "/"
        );
        assert_eq!(
            rendered["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }
}
