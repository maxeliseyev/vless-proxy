//! vproxy: a VLESS client core with a terminal CLI on top.
//!
//! Layout:
//! - [`config`]: TOML config, `vless://`/`vpn://` links, server lists,
//!   subscriptions, importers for Xray and Amnezia configs.
//! - [`protocol`]: VLESS framing, REALITY, XTLS Vision, Mux.Cool and the
//!   Chrome-shaped ClientHello.
//! - [`transport`]: TLS, WebSocket and XHTTP carriers.
//! - [`inbound`]: the local SOCKS5 and HTTP listeners.
//! - [`proxy`]: the relay, routing, DNS, counters and the `serve` entry point.
//! - [`system`]: TUN mode (sing-box), installing sing-box, services, the
//!   xray-core sidecar.
//! - [`logging`]: the size-capped, rotating log file behind the TUI.
//! - [`ui`]: the terminal UI.
//!
//! The CLI (`main.rs`) only parses arguments and wires these together, so
//! the library can be embedded without it.

pub mod config;
pub mod inbound;
pub mod logging;
pub mod protocol;
pub mod proxy;
pub mod system;
pub mod transport;
pub mod ui;

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
