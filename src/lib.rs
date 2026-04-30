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
pub mod http;
pub mod runtime;
pub mod socks5;
pub mod tls;
pub mod url;
pub mod vless;

pub use config::{
    Config, DnsConfig, DnsIpStrategy, DnsResolveMode, InboundConfig, InboundProtocol,
    RuntimeConfig, ServerConfig, TransportSecurity,
};
pub use dns::ResolverPolicy;
pub use runtime::{serve, ProxyClient};
pub use url::VlessUrl;
