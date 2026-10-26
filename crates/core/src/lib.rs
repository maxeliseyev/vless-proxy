//! Shared networking core: configuration, protocols, transports, routing,
//! local proxy listeners and the userspace network stack.
//!
//! CLI, terminal UI, host services and external processes live in the
//! `vproxy` package; the server and C ABI are separate workspace members.

pub mod config;
pub mod h3;
pub mod inbound;
pub mod netstack;
pub mod protocol;
pub mod proxy;
pub mod transport;

pub use config::servers::{ServerEntry, ServerList};
pub use config::url::VlessUrl;
pub use config::{
    Config, DnsCacheConfig, DnsConfig, DnsIpStrategy, DnsResolveMode, InboundConfig,
    InboundProtocol, MuxConfig, RoutingConfig, RoutingRule, RuntimeConfig, ServerConfig, Transport,
    TransportSecurity, TunConfig,
};
pub use protocol::reality::RealityClient;
pub use proxy::dns_cache::DnsCache;
pub use proxy::runtime::{serve, serve_with_server, ActiveServer, ProxyClient};
