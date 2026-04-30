use crate::url::VlessUrl;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundProtocol {
    Socks5,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolveMode {
    Remote,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsIpStrategy {
    PreferIpv4,
    PreferIpv6,
    Ipv4Only,
    Ipv6Only,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub inbound: InboundConfig,
    #[serde(default = "default_dns_config")]
    pub dns: DnsConfig,
    #[serde(default = "default_runtime_config")]
    pub runtime: RuntimeConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub uuid: Uuid,
    #[serde(default = "default_tls")]
    pub use_tls: bool,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundConfig {
    pub address: String,
    pub port: u16,
    #[serde(default = "socks5")]
    pub protocol: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    #[serde(default = "default_dns_strategy")]
    pub strategy: String,
    #[serde(default)]
    pub rules: Vec<DnsRule>,
    #[serde(default)]
    pub cache: DnsCacheConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsCacheConfig {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_cache_ttl")]
    pub ttl_secs: u64,
    #[serde(default = "default_cache_min_ttl")]
    pub min_ttl_secs: u64,
    #[serde(default = "default_cache_max_ttl")]
    pub max_ttl_secs: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_entries: default_cache_max_entries(),
            ttl_secs: default_cache_ttl(),
            min_ttl_secs: default_cache_min_ttl(),
            max_ttl_secs: default_cache_max_ttl(),
        }
    }
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_max_entries() -> usize {
    1000
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_cache_min_ttl() -> u64 {
    30
}

fn default_cache_max_ttl() -> u64 {
    3600
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsRule {
    pub domain: Option<String>,
    pub domain_suffix: Option<String>,
    pub domain_keyword: Option<String>,
    #[serde(default = "default_rule_resolve")]
    pub resolve: String,
}

fn default_rule_resolve() -> String {
    "local".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_write_timeout")]
    pub write_timeout_secs: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        connect_timeout_secs: default_connect_timeout(),
        read_timeout_secs: default_read_timeout(),
        write_timeout_secs: default_write_timeout(),
        idle_timeout_secs: default_idle_timeout(),
        max_connections: default_max_connections(),
    }
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_read_timeout() -> u64 {
    300
}

fn default_write_timeout() -> u64 {
    60
}

fn default_idle_timeout() -> u64 {
    600
}

fn default_max_connections() -> usize {
    1024
}

fn default_tls() -> bool {
    true
}

fn default_security() -> String {
    "tls".to_string()
}

fn socks5() -> String {
    "socks5".to_string()
}

fn default_dns_config() -> DnsConfig {
    DnsConfig {
        mode: default_dns_mode(),
        strategy: default_dns_strategy(),
        rules: vec![],
        cache: DnsCacheConfig::default(),
    }
}

fn default_dns_mode() -> String {
    "remote".to_string()
}

fn default_dns_strategy() -> String {
    "prefer_ipv4".to_string()
}

impl Config {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn server_addr(&self) -> String {
        self.server.endpoint()
    }

    pub fn inbound_addr(&self) -> String {
        self.inbound.endpoint()
    }

    pub fn transport_security(&self) -> Result<TransportSecurity> {
        self.server.transport_security()
    }

    pub fn inbound_protocol(&self) -> Result<InboundProtocol> {
        self.inbound.protocol_kind()
    }

    pub fn dns_resolve_mode(&self) -> Result<DnsResolveMode> {
        self.dns.resolve_mode()
    }

    pub fn dns_ip_strategy(&self) -> Result<DnsIpStrategy> {
        self.dns.ip_strategy()
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.server.port == 0 {
            bail!("Server port must be 1-65535");
        }
        if self.inbound.port == 0 {
            bail!("Inbound port must be 1-65535");
        }
        if self.server.address.trim().is_empty() {
            bail!("Server address must not be empty");
        }
        if self.inbound.address.trim().is_empty() {
            bail!("Inbound address must not be empty");
        }

        self.server.transport_security()?;
        self.inbound.protocol_kind()?;
        self.dns.resolve_mode()?;
        self.dns.ip_strategy()?;

        Ok(())
    }
}

impl ServerConfig {
    pub fn endpoint(&self) -> String {
        format_host_port(&self.address, self.port)
    }

    pub fn transport_security(&self) -> Result<TransportSecurity> {
        match self.security.trim().to_ascii_lowercase().as_str() {
            "tls" => {
                if !self.use_tls {
                    bail!("security = \"tls\" requires use_tls = true");
                }
                Ok(TransportSecurity::Tls)
            }
            "reality" => Ok(TransportSecurity::Reality),
            "none" | "plain" => {
                if self.use_tls {
                    bail!("security = \"none\" requires use_tls = false");
                }
                Ok(TransportSecurity::None)
            }
            other => bail!("Unsupported server.security value: {other}"),
        }
    }
}

impl InboundConfig {
    pub fn endpoint(&self) -> String {
        format_host_port(&self.address, self.port)
    }

    pub fn protocol_kind(&self) -> Result<InboundProtocol> {
        match self.protocol.trim().to_ascii_lowercase().as_str() {
            "socks5" => Ok(InboundProtocol::Socks5),
            "http" => Ok(InboundProtocol::Http),
            other => bail!("Unsupported inbound.protocol value: {other}"),
        }
    }
}

impl DnsConfig {
    pub fn resolve_mode(&self) -> Result<DnsResolveMode> {
        match self.mode.trim().to_ascii_lowercase().as_str() {
            "remote" => Ok(DnsResolveMode::Remote),
            "local" => Ok(DnsResolveMode::Local),
            other => bail!("Unsupported dns.mode value: {other}"),
        }
    }

    pub fn ip_strategy(&self) -> Result<DnsIpStrategy> {
        match self.strategy.trim().to_ascii_lowercase().as_str() {
            "prefer_ipv4" => Ok(DnsIpStrategy::PreferIpv4),
            "prefer_ipv6" => Ok(DnsIpStrategy::PreferIpv6),
            "ipv4_only" => Ok(DnsIpStrategy::Ipv4Only),
            "ipv6_only" => Ok(DnsIpStrategy::Ipv6Only),
            other => bail!("Unsupported dns.strategy value: {other}"),
        }
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

impl Config {
    pub fn from_vless_url(url: &VlessUrl, inbound_port: u16) -> Self {
        let server = ServerConfig {
            address: url.host.clone(),
            port: url.port,
            uuid: url.uuid,
            use_tls: url.use_tls(),
            security: url.security.clone(),
            reality_public_key: url.reality_public_key.clone(),
            reality_short_id: url.reality_short_id.clone(),
        };

        let inbound = InboundConfig {
            address: "127.0.0.1".to_string(),
            port: inbound_port,
            protocol: "socks5".to_string(),
        };

        let dns = DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![],
            cache: DnsCacheConfig::default(),
        };

        let runtime = RuntimeConfig {
            connect_timeout_secs: default_connect_timeout(),
            read_timeout_secs: default_read_timeout(),
            write_timeout_secs: default_write_timeout(),
            idle_timeout_secs: default_idle_timeout(),
            max_connections: default_max_connections(),
        };

        Config {
            server,
            inbound,
            dns,
            runtime,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            server: ServerConfig {
                address: "example.com".to_string(),
                port: 443,
                uuid: Uuid::nil(),
                use_tls: true,
                security: "tls".to_string(),
                reality_public_key: None,
                reality_short_id: None,
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
                connect_timeout_secs: default_connect_timeout(),
                read_timeout_secs: default_read_timeout(),
                write_timeout_secs: default_write_timeout(),
                idle_timeout_secs: default_idle_timeout(),
                max_connections: default_max_connections(),
            },
        }
    }

    #[test]
    fn accepts_valid_tls_config() {
        let config = base_config();

        assert_eq!(
            config.server.transport_security().unwrap(),
            TransportSecurity::Tls
        );
        assert_eq!(
            config.inbound.protocol_kind().unwrap(),
            InboundProtocol::Socks5
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_default_dns_policy() {
        let config = base_config();

        assert_eq!(config.dns.resolve_mode().unwrap(), DnsResolveMode::Remote);
        assert_eq!(config.dns.ip_strategy().unwrap(), DnsIpStrategy::PreferIpv4);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_unsupported_inbound_protocol() {
        let mut config = base_config();
        config.inbound.protocol = "bogus".to_string();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("Unsupported inbound.protocol value"));
    }

    #[test]
    fn rejects_mismatched_tls_settings() {
        let mut config = base_config();
        config.server.use_tls = false;

        let error = config.server.transport_security().unwrap_err().to_string();
        assert!(error.contains("requires use_tls = true"));
    }

    #[test]
    fn rejects_unsupported_dns_mode() {
        let mut config = base_config();
        config.dns.mode = "bogus".to_string();

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("Unsupported dns.mode value"));
    }

    #[test]
    fn accepts_local_dns_policy() {
        let mut config = base_config();
        config.dns.mode = "local".to_string();
        config.dns.strategy = "ipv6_only".to_string();

        assert_eq!(config.dns.resolve_mode().unwrap(), DnsResolveMode::Local);
        assert_eq!(config.dns.ip_strategy().unwrap(), DnsIpStrategy::Ipv6Only);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_plain_security_when_tls_disabled() {
        let mut config = base_config();
        config.server.use_tls = false;
        config.server.security = "none".to_string();

        assert_eq!(
            config.server.transport_security().unwrap(),
            TransportSecurity::None
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn accepts_http_inbound_protocol() {
        let mut config = base_config();
        config.inbound.protocol = "http".to_string();

        assert_eq!(
            config.inbound.protocol_kind().unwrap(),
            InboundProtocol::Http
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn formats_ipv6_endpoints_with_brackets() {
        let mut config = base_config();
        config.server.address = "2001:db8::10".to_string();

        assert_eq!(config.server.endpoint(), "[2001:db8::10]:443");
    }

    #[test]
    fn accepts_default_runtime_config() {
        let config = base_config();

        assert_eq!(config.runtime.connect_timeout_secs, 10);
        assert_eq!(config.runtime.read_timeout_secs, 300);
        assert_eq!(config.runtime.write_timeout_secs, 60);
        assert_eq!(config.runtime.idle_timeout_secs, 600);
        assert_eq!(config.runtime.max_connections, 1024);
    }

    #[test]
    fn accepts_custom_runtime_config() {
        let mut config = base_config();
        config.runtime.connect_timeout_secs = 5;
        config.runtime.read_timeout_secs = 120;
        config.runtime.max_connections = 500;

        assert_eq!(config.runtime.connect_timeout_secs, 5);
        assert_eq!(config.runtime.read_timeout_secs, 120);
        assert_eq!(config.runtime.max_connections, 500);
    }
}
