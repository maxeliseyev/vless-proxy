//! Integration with the host: TUN mode via sing-box, installing sing-box,
//! running as a service, the xray-core sidecar fallback.

pub mod service;
pub mod singbox;
pub mod tun;
pub mod xray_sidecar;
