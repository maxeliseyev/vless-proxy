//! Amnezia VPN share formats: `vpn://` links, `.vpn` files and the JSON they
//! decode to. The payload is base64url (no padding) of Qt `qCompress`
//! output: a 4-byte big-endian uncompressed length followed by a zlib
//! stream. Inside is Amnezia's server description; its `amnezia-xray`
//! container carries a stock Xray client config as the `xray.last_config`
//! string, which goes through the regular Xray JSON import.

use crate::config::import::xray;
use crate::config::Config;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;
use std::io::Read;
use std::path::Path;

pub const LINK_PREFIX: &str = "vpn://";
const XRAY_CONTAINER: &str = "amnezia-xray";

pub fn is_link(text: &str) -> bool {
    text.trim_start().starts_with(LINK_PREFIX)
}

/// A `vpn://` link as a config; `inbound_port` is the local port to listen on.
pub fn from_link(link: &str, inbound_port: u16) -> Result<Config> {
    let payload = link
        .trim()
        .strip_prefix(LINK_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("not a vpn:// link"))?;
    let bytes = decode_base64(payload).context("vpn:// link is not valid base64")?;
    let json = q_uncompress(&bytes).context("vpn:// link payload is not qCompress data")?;
    let root: Value = serde_json::from_slice(&json).context("vpn:// link does not hold JSON")?;
    from_json(&root, Some(inbound_port))
}

/// A `.vpn` file: plain JSON, raw qCompress bytes, or base64 of them (with
/// or without the `vpn://` prefix), the same cases the Amnezia client accepts.
pub fn load_file(path: &Path, inbound_port: Option<u16>) -> Result<Config> {
    let data = std::fs::read(path).with_context(|| format!("Cannot read {}", path.display()))?;
    let root = decode_payload(&data)
        .with_context(|| format!("{} is not an Amnezia config", path.display()))?;
    from_json(&root, inbound_port).with_context(|| format!("while importing {}", path.display()))
}

/// Decode file or QR contents in any of Amnezia's encodings.
pub fn decode_payload(data: &[u8]) -> Result<Value> {
    if let Ok(root) = serde_json::from_slice::<Value>(data) {
        if root.is_object() {
            return Ok(root);
        }
    }
    if let Ok(json) = q_uncompress(data) {
        return serde_json::from_slice(&json).context("decompressed data is not JSON");
    }
    let text = std::str::from_utf8(data).context("not UTF-8")?;
    let text = text.trim().strip_prefix(LINK_PREFIX).unwrap_or(text.trim());
    let bytes = decode_base64(text).context("not base64")?;
    let json = q_uncompress(&bytes).context("base64 payload is not qCompress data")?;
    serde_json::from_slice(&json).context("decompressed data is not JSON")
}

/// Amnezia server JSON → config of its Xray container.
pub fn from_json(root: &Value, inbound_port: Option<u16>) -> Result<Config> {
    let containers = root["containers"].as_array().cloned().unwrap_or_default();
    let is_xray = |c: &Value| c["container"] == XRAY_CONTAINER;
    let container = containers
        .iter()
        .find(|c| is_xray(c) && root["defaultContainer"] == XRAY_CONTAINER)
        .or_else(|| containers.iter().find(|c| is_xray(c)))
        .ok_or_else(|| {
            let names: Vec<&str> = containers
                .iter()
                .filter_map(|c| c["container"].as_str())
                .collect();
            if names.is_empty() {
                anyhow::anyhow!("Amnezia config has no containers (protocols)")
            } else {
                anyhow::anyhow!(
                    "Amnezia config has no XRay container, only: {} (vproxy speaks VLESS only)",
                    names.join(", ")
                )
            }
        })?;
    let last_config = &container["xray"]["last_config"];
    let text = match last_config {
        Value::String(s) if !s.trim().is_empty() => s.clone(),
        Value::Object(_) => last_config.to_string(),
        _ => bail!(
            "Amnezia config carries no Xray client config (last_config). \
             Export a connection config for the XRay protocol from the Amnezia app, \
             not the full-access (admin) config"
        ),
    };
    let mut config = xray::from_json(&text, inbound_port)
        .context("Xray client config inside the Amnezia config")?;
    if config.server.remark.as_deref().is_none_or(str::is_empty) {
        if let Some(description) = root["description"]
            .as_str()
            .filter(|d| !d.trim().is_empty())
        {
            config.server.remark = Some(description.trim().to_string());
        }
    }
    Ok(config)
}

fn decode_base64(text: &str) -> Result<Vec<u8>> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let text = text.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .map_err(Into::into)
}

/// Qt `qUncompress`: 4-byte big-endian expected length, then a zlib stream.
fn q_uncompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 6 {
        bail!("too short");
    }
    let expected = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if expected > 64 * 1024 * 1024 {
        bail!("declared size too large");
    }
    let mut out = Vec::with_capacity(expected);
    flate2::read::ZlibDecoder::new(&data[4..])
        .take(expected as u64 + 1)
        .read_to_end(&mut out)
        .context("zlib")?;
    if out.len() != expected {
        bail!(
            "decompressed size {} does not match header {expected}",
            out.len()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Qt `qCompress`.
    fn q_compress(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u32).to_be_bytes().to_vec();
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(8));
        enc.write_all(data).unwrap();
        out.extend_from_slice(&enc.finish().unwrap());
        out
    }

    const CLIENT_JSON: &str = r#"{
      "inbounds": [{"listen": "127.0.0.1", "port": 10808, "protocol": "socks"}],
      "outbounds": [{
        "protocol": "vless",
        "settings": {"vnext": [{"address": "203.0.113.7", "port": 443,
          "users": [{"id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
          "realitySettings": {"fingerprint": "chrome", "serverName": "www.googletagmanager.com",
            "publicKey": "Mkpry4Un0Ka6RkyokWUIKYWVCuugce3hdEU7dLn6yD4", "shortId": "0123456789abcdef"}}
      }]
    }"#;

    fn amnezia_json(last_config: Option<&str>) -> Value {
        let mut xray = serde_json::Map::new();
        xray.insert("port".into(), Value::String("443".into()));
        if let Some(c) = last_config {
            xray.insert("last_config".into(), Value::String(c.to_string()));
        }
        serde_json::json!({
            "containers": [
                {"container": "amnezia-awg", "awg": {"port": "55424"}},
                {"container": "amnezia-xray", "xray": xray}
            ],
            "defaultContainer": "amnezia-xray",
            "description": "My Amnezia box",
            "hostName": "203.0.113.7"
        })
    }

    fn link(root: &Value) -> String {
        let compressed = q_compress(root.to_string().as_bytes());
        format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(compressed))
    }

    #[test]
    fn decodes_a_vpn_link_into_the_xray_container() {
        let config = from_link(&link(&amnezia_json(Some(CLIENT_JSON))), 1080).unwrap();
        assert_eq!(config.server.address, "203.0.113.7");
        assert_eq!(config.server.port, 443);
        assert_eq!(config.server.security, "reality");
        assert_eq!(config.server.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(
            config.server.sni.as_deref(),
            Some("www.googletagmanager.com")
        );
        assert_eq!(
            config.server.reality_short_id.as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(config.server.remark.as_deref(), Some("My Amnezia box"));
        assert_eq!(config.inbound.port, 1080);
        config.validate().unwrap();
    }

    #[test]
    fn vpn_files_in_every_encoding() {
        let root = amnezia_json(Some(CLIENT_JSON));
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("raw.vpn");
        std::fs::write(&raw, q_compress(root.to_string().as_bytes())).unwrap();
        let text = dir.path().join("link.vpn");
        std::fs::write(&text, format!("{}\n", link(&root))).unwrap();
        let plain = dir.path().join("plain.vpn");
        std::fs::write(&plain, root.to_string()).unwrap();
        for path in [raw, text, plain] {
            let config = load_file(&path, None).unwrap();
            assert_eq!(config.server.address, "203.0.113.7");
            assert_eq!(config.inbound.port, 10808, "{}", path.display());
        }
    }

    #[test]
    fn full_access_config_without_client_config_is_explained() {
        let err = from_link(&link(&amnezia_json(None)), 1080)
            .unwrap_err()
            .to_string();
        assert!(err.contains("last_config"), "{err}");

        let mut root = amnezia_json(Some(CLIENT_JSON));
        root["containers"].as_array_mut().unwrap().remove(1);
        root["defaultContainer"] = Value::String("amnezia-awg".into());
        let err = from_link(&link(&root), 1080).unwrap_err().to_string();
        assert!(err.contains("amnezia-awg"), "{err}");

        assert!(from_link("vpn://not*base64", 1080).is_err());
        assert!(from_link("vpn://AAAA", 1080).is_err());
    }
}
