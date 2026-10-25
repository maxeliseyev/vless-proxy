//! The h3 transport: one QUIC connection to our own server (`vproxy-server`),
//! every TCP target a bidirectional stream on it. The plan and the reasons
//! are in docs/h3-transport-plan.md.
//!
//! On the wire it is QUIC v1 with TLS 1.3, ALPN `h3` and the server's real
//! certificate. After the handshake the client opens a unidirectional stream
//! that only carries its [`wire::AuthToken`]; the server serves nothing
//! before that token checks out. Each further stream is one TCP target: a
//! [`wire::encode_target`] header from the client, one status byte back, then
//! the bytes of the connection both ways. UDP flows are QUIC datagrams on
//! the same connection, framed as [`wire`] describes.

pub mod client;
pub mod wire;

pub use client::{H3Client, H3Stream, H3UdpReceiver, H3UdpSender, H3UdpSession};
