//! Integration with the host: native TUN mode (macOS), running as a service,
//! the xray-core sidecar fallback.

pub mod service;
pub mod sidecar;
pub mod tun_native;
pub mod xray_sidecar;
