//! Reusable VLESS client core with a thin terminal CLI wrapper.
//!
//! The library boundary is intentionally kept below the CLI layer:
//! - `runtime::ProxyClient` exposes reusable outbound connection setup.
//! - `runtime::serve` hosts the local SOCKS5 listener for terminal usage.
//!
//! This keeps protocol/TLS logic inside Rust so a future iOS bridge can wrap the core without
//! depending on command-line parsing or stdout-oriented startup code.

pub mod config;
pub mod dns;
pub mod dns_cache;
pub mod http;
pub mod reality;
pub mod reality_tls;
pub mod runtime;
pub mod socks5;
pub mod tls;
pub mod url;
pub mod vision;
pub mod vless;
pub mod xray_sidecar;

pub use config::{
    Config, DnsCacheConfig, DnsConfig, DnsIpStrategy, DnsResolveMode, InboundConfig,
    InboundProtocol, RuntimeConfig, ServerConfig, TransportSecurity,
};
pub use dns_cache::DnsCache;
pub use reality::RealityClient;
pub use runtime::{serve, ProxyClient};
pub use url::VlessUrl;
