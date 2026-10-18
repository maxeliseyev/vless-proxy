use anyhow::{bail, Result};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct VlessUrl {
    pub uuid: Uuid,
    pub host: String,
    pub port: u16,
    pub security: String,
    pub sni: Option<String>,
    pub fingerprint: Option<String>,
    pub encryption: String,
    pub remark: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub flow: Option<String>,
    pub spider_x: Option<String>,
    /// `tcp`, `ws` or `xhttp`
    pub transport: String,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub alpn: Option<String>,
    /// XHTTP `mode` and `extra` (JSON) parameters.
    pub xhttp_mode: Option<String>,
    pub xhttp_extra: Option<String>,
}

impl VlessUrl {
    pub fn parse(url: &str) -> Result<Self> {
        let url = url.trim();

        if !url.starts_with("vless://") {
            bail!("URL must start with vless://");
        }

        let without_scheme = &url[8..];

        let (auth_with_host, fragment) = match without_scheme.split_once('#') {
            Some((base, frag)) => (base, Some(url_decode(frag))),
            None => (without_scheme, None),
        };

        let (auth, host_port) = match auth_with_host.split_once('@') {
            Some((a, b)) => (a, b),
            None => bail!("URL must contain user info (uuid@host:port)"),
        };

        let uuid = Uuid::parse_str(auth).map_err(|e| anyhow::anyhow!("Invalid UUID: {}", e))?;

        let (host, port) = parse_host_port(host_port)?;

        let mut params = HashMap::new();
        if let Some((_, query)) = host_port.split_once('?') {
            for pair in query.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    params.insert(url_decode(key), url_decode(value));
                }
            }
        }

        let transport = match params.get("type").map(|t| t.to_ascii_lowercase()) {
            None => "tcp".to_string(),
            Some(t) if t == "tcp" || t == "raw" => "tcp".to_string(),
            Some(t) if t == "ws" || t == "websocket" => "ws".to_string(),
            Some(t) if t == "xhttp" || t == "splithttp" => "xhttp".to_string(),
            Some(t) => bail!("Transport type={t} is not supported (tcp, ws and xhttp are)"),
        };
        let ws_path = params.get("path").cloned().filter(|p| !p.is_empty());
        let ws_host = params.get("host").cloned().filter(|h| !h.is_empty());
        let alpn = params.get("alpn").cloned().filter(|a| !a.is_empty());
        let (xhttp_mode, xhttp_extra) = if transport == "xhttp" {
            (
                params.get("mode").cloned().filter(|m| !m.is_empty()),
                params
                    .get("extra")
                    .cloned()
                    .filter(|e| !e.trim().is_empty()),
            )
        } else {
            (None, None)
        };

        let security = params
            .get("security")
            .cloned()
            .unwrap_or_else(|| "none".to_string());
        let sni = params
            .get("sni")
            .cloned()
            .or_else(|| params.get("host").cloned());
        let fingerprint = params.get("fp").cloned();
        let encryption = params
            .get("encryption")
            .cloned()
            .unwrap_or_else(|| "none".to_string());
        let reality_public_key = params.get("pbk").cloned();
        let reality_short_id = params.get("sid").cloned();
        let flow = params.get("flow").cloned();
        let spider_x = params.get("spx").cloned();

        Ok(VlessUrl {
            uuid,
            host,
            port,
            security,
            sni,
            fingerprint,
            encryption,
            remark: fragment
                .map(|f| crate::config::sanitize_name(&f))
                .filter(|f| !f.is_empty()),
            reality_public_key,
            reality_short_id,
            flow,
            spider_x,
            transport,
            ws_path,
            ws_host,
            alpn,
            xhttp_mode,
            xhttp_extra,
        })
    }

    pub fn use_tls(&self) -> bool {
        matches!(self.security.as_str(), "tls" | "reality")
    }
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let input = input.split('?').next().unwrap_or(input);
    let input = input.strip_suffix('/').unwrap_or(input);

    if input.starts_with('[') {
        let end_bracket = input
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("Invalid IPv6 format"))?;
        let host = &input[1..end_bracket];
        let rest = &input[end_bracket + 1..];

        if rest.is_empty() || !rest.starts_with(':') {
            bail!("Port required after IPv6 address");
        }

        let port: u16 = rest[1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid port"))?;

        Ok((host.to_string(), port))
    } else {
        let last_colon = input
            .rfind(':')
            .ok_or_else(|| anyhow::anyhow!("Port required"))?;

        let host = &input[..last_colon];
        let port: u16 = input[last_colon + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid port"))?;

        Ok((host.to_string(), port))
    }
}

fn url_decode(input: &str) -> String {
    // Percent-escapes are bytes of UTF-8 (`%D0%9C` is one Cyrillic letter),
    // so decode into bytes first.
    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 && hex.is_ascii() {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    bytes.push(byte);
                    continue;
                }
            }
            bytes.push(b'%');
            bytes.extend_from_slice(hex.as_bytes());
        } else if c == '+' {
            bytes.push(b' ');
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remark_is_utf8_decoded_and_sanitized() {
        let parsed = VlessUrl::parse(
            "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@h.example:443?security=none#%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0%20%231",
        )
        .unwrap();
        assert_eq!(parsed.remark.as_deref(), Some("Москва #1"));

        let parsed = VlessUrl::parse(
            "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@h.example:443?security=none#a%1b%5b31mb%0ac",
        )
        .unwrap();
        assert_eq!(parsed.remark.as_deref(), Some("a [31mb c"));

        let parsed = VlessUrl::parse(
            "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@h.example:443?security=none#%0a",
        )
        .unwrap();
        assert_eq!(parsed.remark, None);
    }

    #[test]
    fn parses_xhttp_parameters() {
        let u = VlessUrl::parse("vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@h.example:443?type=xhttp&security=reality&pbk=k&sid=ab&sni=s.example&path=%2Fapi&host=c.example&mode=stream-up&alpn=h2&extra=%7B%22noGRPCHeader%22%3Atrue%7D#x").unwrap();
        assert_eq!(u.transport, "xhttp");
        assert_eq!(u.ws_path.as_deref(), Some("/api"));
        assert_eq!(u.ws_host.as_deref(), Some("c.example"));
        assert_eq!(u.xhttp_mode.as_deref(), Some("stream-up"));
        assert_eq!(u.alpn.as_deref(), Some("h2"));
        assert_eq!(u.xhttp_extra.as_deref(), Some(r#"{"noGRPCHeader":true}"#));
    }

    #[test]
    fn parses_basic_tls_url() {
        let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:443?security=tls&encryption=none";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(
            parsed.uuid.to_string(),
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        );
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.security, "tls");
        assert!(parsed.use_tls());
    }

    #[test]
    fn parses_url_with_remark() {
        let url =
            "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:443?security=tls#My%20Server";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(parsed.remark, Some("My Server".to_string()));
    }

    #[test]
    fn parses_url_with_sni() {
        let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:443?security=tls&sni=cdn.example.com";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(parsed.sni, Some("cdn.example.com".to_string()));
    }

    #[test]
    fn parses_plain_url() {
        let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com:1234?security=none";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(parsed.security, "none");
        assert!(!parsed.use_tls());
    }

    #[test]
    fn parses_ipv6_url() {
        let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@[2001:db8::1]:443?security=tls";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn rejects_invalid_uuid() {
        let url = "vless://invalid-uuid@example.com:443";
        assert!(VlessUrl::parse(url).is_err());
    }

    #[test]
    fn rejects_missing_port() {
        let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@example.com";
        assert!(VlessUrl::parse(url).is_err());
    }

    #[test]
    fn rejects_non_vless_scheme() {
        let url = "http://example.com";
        assert!(VlessUrl::parse(url).is_err());
    }

    #[test]
    fn parses_reality_vision_url() {
        let url = "vless://1b71598d-e3cd-4cf0-8c99-d1ce08ad4881@194.87.235.91:443/?type=tcp&encryption=none&security=reality&pbk=T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8&fp=chrome&sni=www.intel.com&sid=b59cfeedfabf9f&spx=%2F&flow=xtls-rprx-vision#2ei7r2pe";
        let parsed = VlessUrl::parse(url).unwrap();

        assert_eq!(parsed.host, "194.87.235.91");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.security, "reality");
        assert_eq!(parsed.encryption, "none");
        assert_eq!(parsed.sni.as_deref(), Some("www.intel.com"));
        assert_eq!(parsed.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(
            parsed.reality_public_key.as_deref(),
            Some("T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8")
        );
        assert_eq!(parsed.reality_short_id.as_deref(), Some("b59cfeedfabf9f"));
        assert_eq!(parsed.spider_x.as_deref(), Some("/"));
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.remark.as_deref(), Some("2ei7r2pe"));
    }

    #[test]
    fn parses_ws_tls_url() {
        let url = VlessUrl::parse("vless://34ba3996-ef86-49b9-a481-d782b4ec7923@nearsky.example:443?type=ws&security=tls&path=%2Fygrouke6xa&host=cdn.example&sni=nearsky.example#ws-server").unwrap();
        assert_eq!(url.transport, "ws");
        assert_eq!(url.ws_path.as_deref(), Some("/ygrouke6xa"));
        assert_eq!(url.ws_host.as_deref(), Some("cdn.example"));
        assert_eq!(url.sni.as_deref(), Some("nearsky.example"));
        assert!(url.use_tls());
        assert!(
            VlessUrl::parse("vless://34ba3996-ef86-49b9-a481-d782b4ec7923@h:443?type=grpc")
                .is_err()
        );
        let tcp =
            VlessUrl::parse("vless://34ba3996-ef86-49b9-a481-d782b4ec7923@h:443?security=tls")
                .unwrap();
        assert_eq!(tcp.transport, "tcp");
    }
}
