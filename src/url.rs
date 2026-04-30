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
    pub encryption: String,
    pub remark: Option<String>,
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

        let security = params
            .get("security")
            .cloned()
            .unwrap_or_else(|| "none".to_string());
        let sni = params
            .get("sni")
            .cloned()
            .or_else(|| params.get("host").cloned());
        let encryption = params
            .get("encryption")
            .cloned()
            .unwrap_or_else(|| "none".to_string());

        Ok(VlessUrl {
            uuid,
            host,
            port,
            security,
            sni,
            encryption,
            remark: fragment,
        })
    }

    pub fn use_tls(&self) -> bool {
        matches!(self.security.as_str(), "tls" | "reality")
    }
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let input = input.split('?').next().unwrap_or(input);

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
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
