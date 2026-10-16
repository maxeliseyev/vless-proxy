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
    #[serde(default)]
    pub tun: TunConfig,
}

/// System-wide mode through a `sing-box` TUN sidecar (see `tun.rs`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TunConfig {
    pub enabled: bool,
    pub sing_box_path: String,
    /// Interface address, CIDR.
    pub address: String,
    pub mtu: u32,
    /// `mixed` | `system` | `gvisor`
    pub stack: String,
    pub strict_route: bool,
    /// Upstream DNS used for everything caught by the tunnel.
    pub dns: String,
    /// Send DNS queries through the proxy (true) or directly (false).
    pub dns_via_proxy: bool,
    /// Domain suffixes / CIDRs that must not go through the proxy.
    pub bypass_domains: Vec<String>,
    pub bypass_cidrs: Vec<String>,
    pub log_level: String,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sing_box_path: "sing-box".to_string(),
            address: "172.18.0.1/30".to_string(),
            mtu: 1500,
            stack: "mixed".to_string(),
            strict_route: true,
            dns: "8.8.8.8".to_string(),
            dns_via_proxy: true,
            bypass_domains: Vec::new(),
            bypass_cidrs: Vec::new(),
            log_level: "warn".to_string(),
        }
    }
}

impl TunConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.sing_box_path.trim().is_empty() {
            bail!("tun.sing_box_path must not be empty");
        }
        if !self.address.contains('/') {
            bail!("tun.address must be an interface address in CIDR form, e.g. 172.18.0.1/30");
        }
        if !(576..=65535).contains(&self.mtu) {
            bail!("tun.mtu must be between 576 and 65535");
        }
        if !matches!(self.stack.as_str(), "mixed" | "system" | "gvisor") {
            bail!("tun.stack must be \"mixed\", \"system\" or \"gvisor\"");
        }
        if self.dns.parse::<std::net::IpAddr>().is_err() {
            bail!("tun.dns must be an IP address");
        }
        Ok(())
    }
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
    #[serde(default = "default_encryption")]
    pub encryption: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
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
    #[serde(default = "default_xray_path")]
    pub xray_path: String,
    /// How REALITY connections are made: `auto` (native Rust unless the flow
    /// needs XTLS Vision, which still requires xray-core), `native` or `xray`.
    #[serde(default = "default_reality_engine")]
    pub reality_engine: String,
}

/// `server.flow` values understood natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisionFlow {
    /// `xtls-rprx-vision`: UDP to port 443 is rejected so QUIC falls back to TCP.
    Vision,
    /// `xtls-rprx-vision-udp443`: same, but UDP/443 is allowed through.
    VisionUdp443,
}

impl VisionFlow {
    pub fn allows_udp443(self) -> bool {
        matches!(self, VisionFlow::VisionUdp443)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityEngine {
    Auto,
    Native,
    Xray,
}

fn default_runtime_config() -> RuntimeConfig {
    RuntimeConfig {
        connect_timeout_secs: default_connect_timeout(),
        read_timeout_secs: default_read_timeout(),
        write_timeout_secs: default_write_timeout(),
        idle_timeout_secs: default_idle_timeout(),
        max_connections: default_max_connections(),
        xray_path: default_xray_path(),
        reality_engine: default_reality_engine(),
    }
}

fn default_reality_engine() -> String {
    "auto".to_string()
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

fn default_xray_path() -> String {
    "xray".to_string()
}

fn default_tls() -> bool {
    true
}

fn default_security() -> String {
    "tls".to_string()
}

fn default_encryption() -> String {
    "none".to_string()
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

    /// Whether this configuration must be served by the xray-core sidecar.
    ///
    /// REALITY itself is handled natively; XTLS Vision (`flow = xtls-rprx-vision`)
    /// is not implemented in Rust yet and still needs xray-core.
    pub fn needs_xray_sidecar(&self) -> Result<bool> {
        let reality = matches!(
            self.server.transport_security()?,
            TransportSecurity::Reality
        );
        let vision = self.server.vision_flow()?.is_some();
        match self.runtime.reality_engine()? {
            RealityEngine::Xray => Ok(reality || vision),
            // Native REALITY and Vision; Vision over plain TLS still needs xray-core.
            RealityEngine::Auto => Ok(vision && !reality),
            RealityEngine::Native => {
                if vision && !reality {
                    bail!(
                        "XTLS Vision over security = \"tls\" is not supported natively; \
                         use security = \"reality\" or runtime.reality_engine = \"xray\""
                    );
                }
                Ok(false)
            }
        }
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
        self.server.validate_transport_settings()?;
        self.inbound.protocol_kind()?;
        self.dns.resolve_mode()?;
        self.needs_xray_sidecar()?;
        self.tun.validate()?;
        if self.tun.enabled && !matches!(self.inbound.protocol_kind()?, InboundProtocol::Socks5) {
            bail!("tun.enabled requires inbound.protocol = \"socks5\"");
        }
        self.dns.ip_strategy()?;
        self.runtime.validate()?;

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

    pub fn validate_transport_settings(&self) -> Result<()> {
        if self.encryption.trim().to_ascii_lowercase() != "none" {
            bail!("Only server.encryption = \"none\" is currently supported");
        }

        if self.flow.is_some() && !matches!(self.transport_security()?, TransportSecurity::Reality)
        {
            bail!("server.flow is only supported with security = \"reality\"");
        }

        self.vision_flow()?;

        match self.transport_security()? {
            TransportSecurity::Tls | TransportSecurity::None => Ok(()),
            TransportSecurity::Reality => {
                if !self.use_tls {
                    bail!("security = \"reality\" requires use_tls = true");
                }

                let public_key = self
                    .reality_public_key
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("REALITY requires server.reality_public_key"))?;
                if public_key.trim().is_empty() {
                    bail!("REALITY public key must not be empty");
                }

                let short_id = self
                    .reality_short_id
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("REALITY requires server.reality_short_id"))?;
                validate_reality_short_id(short_id)?;

                let sni = self.tls_server_name();
                if sni.trim().is_empty() {
                    bail!("REALITY requires server.sni or a non-empty server.address");
                }

                Ok(())
            }
        }
    }

    pub fn tls_server_name(&self) -> &str {
        self.sni.as_deref().unwrap_or(&self.address)
    }

    pub fn needs_xray_sidecar(&self) -> Result<bool> {
        Ok(
            matches!(self.transport_security()?, TransportSecurity::Reality)
                || self.vision_flow()?.is_some(),
        )
    }

    /// Parsed `server.flow`; `None` for no flow control.
    pub fn vision_flow(&self) -> Result<Option<VisionFlow>> {
        match self.flow.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(crate::vision::FLOW_VISION) => Ok(Some(VisionFlow::Vision)),
            Some(crate::vision::FLOW_VISION_UDP443) => Ok(Some(VisionFlow::VisionUdp443)),
            Some(other) => bail!("Unsupported server.flow value: {other}"),
        }
    }

    pub fn reality_fingerprint(&self) -> &str {
        self.fingerprint.as_deref().unwrap_or("chrome")
    }

    pub fn reality_spider_x(&self) -> &str {
        self.spider_x.as_deref().unwrap_or("/")
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

impl RuntimeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.connect_timeout_secs == 0 {
            bail!("runtime.connect_timeout_secs must be > 0");
        }
        if self.read_timeout_secs == 0 {
            bail!("runtime.read_timeout_secs must be > 0");
        }
        if self.write_timeout_secs == 0 {
            bail!("runtime.write_timeout_secs must be > 0");
        }
        if self.idle_timeout_secs == 0 {
            bail!("runtime.idle_timeout_secs must be > 0");
        }
        if self.max_connections == 0 {
            bail!("runtime.max_connections must be > 0");
        }
        if self.xray_path.trim().is_empty() {
            bail!("runtime.xray_path must not be empty");
        }
        self.reality_engine()?;
        Ok(())
    }

    pub fn reality_engine(&self) -> Result<RealityEngine> {
        match self.reality_engine.to_ascii_lowercase().as_str() {
            "auto" => Ok(RealityEngine::Auto),
            "native" => Ok(RealityEngine::Native),
            "xray" => Ok(RealityEngine::Xray),
            other => bail!(
                "runtime.reality_engine must be \"auto\", \"native\" or \"xray\", got {other:?}"
            ),
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

fn validate_reality_short_id(short_id: &str) -> Result<()> {
    if short_id.is_empty() {
        bail!("REALITY short ID must not be empty");
    }
    if short_id.len() > 16 {
        bail!("REALITY short ID must be at most 16 hex chars");
    }
    if short_id.len() % 2 != 0 {
        bail!("REALITY short ID must contain an even number of hex chars");
    }
    if !short_id.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("REALITY short ID must be hexadecimal");
    }
    Ok(())
}

impl Config {
    pub fn from_vless_url(url: &VlessUrl, inbound_port: u16) -> Self {
        let server = ServerConfig {
            address: url.host.clone(),
            port: url.port,
            uuid: url.uuid,
            use_tls: url.use_tls(),
            security: url.security.clone(),
            encryption: url.encryption.clone(),
            sni: url.sni.clone(),
            fingerprint: url.fingerprint.clone(),
            reality_public_key: url.reality_public_key.clone(),
            reality_short_id: url.reality_short_id.clone(),
            flow: url.flow.clone(),
            spider_x: url.spider_x.clone(),
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
            xray_path: default_xray_path(),
            reality_engine: default_reality_engine(),
        };

        Config {
            server,
            inbound,
            dns,
            runtime,
            tun: TunConfig::default(),
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
                encryption: "none".to_string(),
                sni: None,
                fingerprint: None,
                reality_public_key: None,
                reality_short_id: None,
                flow: None,
                spider_x: None,
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
                xray_path: default_xray_path(),
                reality_engine: default_reality_engine(),
            },
            tun: TunConfig::default(),
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
        assert_eq!(config.runtime.xray_path, "xray");
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

    #[test]
    fn accepts_reality_transport_settings() {
        let mut config = base_config();
        config.server.security = "reality".to_string();
        config.server.encryption = "none".to_string();
        config.server.sni = Some("www.intel.com".to_string());
        config.server.fingerprint = Some("chrome".to_string());
        config.server.reality_public_key =
            Some("T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8".to_string());
        config.server.reality_short_id = Some("b59cfeedfabf9f".to_string());
        config.server.flow = Some("xtls-rprx-vision".to_string());
        config.server.spider_x = Some("/".to_string());

        assert_eq!(
            config.server.transport_security().unwrap(),
            TransportSecurity::Reality
        );
        assert!(config.server.needs_xray_sidecar().unwrap());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_reality_short_id() {
        let mut config = base_config();
        config.server.security = "reality".to_string();
        config.server.reality_public_key = Some("key".to_string());
        config.server.reality_short_id = Some("xyz".to_string());

        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("REALITY short ID"));
    }

    #[test]
    fn builds_config_from_reality_url() {
        let url = VlessUrl::parse("vless://1b71598d-e3cd-4cf0-8c99-d1ce08ad4881@194.87.235.91:443/?type=tcp&encryption=none&security=reality&pbk=T7Rcq-PPtLm4PGQgW5IxLI9CUdH8sSDqo_tGiFPtXD8&fp=chrome&sni=www.intel.com&sid=b59cfeedfabf9f&spx=%2F&flow=xtls-rprx-vision#2ei7r2pe").unwrap();
        let config = Config::from_vless_url(&url, 1080);

        assert_eq!(config.server.address, "194.87.235.91");
        assert_eq!(config.server.sni.as_deref(), Some("www.intel.com"));
        assert_eq!(config.server.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(config.server.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(config.server.spider_x.as_deref(), Some("/"));
        assert_eq!(
            config.server.reality_short_id.as_deref(),
            Some("b59cfeedfabf9f")
        );
    }
}
