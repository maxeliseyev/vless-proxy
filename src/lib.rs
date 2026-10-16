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
pub mod mux;
pub mod reality;
pub mod reality_tls;
pub mod routing;
pub mod runtime;
pub mod servers;
pub mod socks5;
pub mod stats;
pub mod tls;
pub mod tui;
pub mod tun;
pub mod url;
pub mod vision;
pub mod vless;
pub mod ws;
pub mod xray_import;
pub mod xray_sidecar;

pub use config::{
    Config, DnsCacheConfig, DnsConfig, DnsIpStrategy, DnsResolveMode, InboundConfig,
    InboundProtocol, MuxConfig, RoutingConfig, RoutingRule, RuntimeConfig, ServerConfig, Transport,
    TransportSecurity, TunConfig,
};
pub use dns_cache::DnsCache;
pub use reality::RealityClient;
pub use runtime::{serve, serve_with_server, ActiveServer, ProxyClient};
pub use servers::{ServerEntry, ServerList};
pub use url::VlessUrl;
