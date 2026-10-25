//! Client side of the h3 transport: one QUIC connection per server, opened
//! on first use and again after it dies, never two handshakes at once.

use super::wire::{self, Status, ALPN, AUTH_LABEL, TOKEN_LEN};
use crate::protocol::vless::Address;
use anyhow::{anyhow, Context, Result};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, info};
use uuid::Uuid;

/// Without traffic for this long the connection is gone (both ends agree on
/// the smaller of their values)...
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// ...so it is pinged this often while it should stay up.
const KEEP_ALIVE: Duration = Duration::from_secs(10);

pub struct H3Client {
    host: String,
    port: u16,
    server_name: String,
    uuid: Uuid,
    config: quinn::ClientConfig,
    /// The live connection, if any. Held across a handshake, which makes
    /// concurrent callers wait for it instead of dialing their own.
    conn: Mutex<Option<quinn::Connection>>,
    handshakes: AtomicU64,
}

impl H3Client {
    /// A client for `host:port` presenting `server_name` in TLS, trusting
    /// the system's roots and Mozilla's.
    pub fn new(host: &str, port: u16, server_name: &str, uuid: Uuid) -> Result<Self> {
        Self::with_roots(
            host,
            port,
            server_name,
            uuid,
            crate::transport::tls::system_root_store(),
        )
    }

    /// Like [`H3Client::new`], trusting only `roots` (tests, private CAs).
    pub fn with_roots(
        host: &str,
        port: u16,
        server_name: &str,
        uuid: Uuid,
        roots: rustls::RootCertStore,
    ) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("rustls provider does not support TLS 1.3")?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow!("QUIC client config: {e}"))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("30 s fits a VarInt")))
            .keep_alive_interval(Some(KEEP_ALIVE));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            host: host.to_string(),
            port,
            server_name: server_name.to_string(),
            uuid,
            config,
            conn: Mutex::new(None),
            handshakes: AtomicU64::new(0),
        })
    }

    /// QUIC handshakes made so far: one per connection.
    pub fn handshakes(&self) -> u64 {
        self.handshakes.load(Ordering::Relaxed)
    }

    /// Open a stream to `address:port` through the server. Returns once the
    /// stream exists; whether the server reached the target shows on the
    /// first read.
    pub async fn open_tcp(&self, address: &Address, port: u16) -> Result<H3Stream> {
        let header = wire::encode_target(address, port)?;
        let conn = self.connection().await?;
        let (mut send, recv) = conn.open_bi().await.context("h3: open stream")?;
        send.write_all(&header).await.context("h3: send target")?;
        Ok(H3Stream {
            send,
            recv,
            status: None,
        })
    }

    /// The live connection, dialing (and authenticating) a new one if there
    /// is none or it has closed.
    pub async fn connection(&self) -> Result<quinn::Connection> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(conn.clone());
        }
        let conn = self.dial().await?;
        *slot = Some(conn.clone());
        Ok(conn)
    }

    async fn dial(&self) -> Result<quinn::Connection> {
        let addr = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("h3: resolve {}", self.host))?
            .next()
            .ok_or_else(|| anyhow!("h3: {} has no address", self.host))?;
        // A new socket (and source port) per connection, like a browser.
        let bind: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid address")
        } else {
            "[::]:0".parse().expect("valid address")
        };
        let endpoint = quinn::Endpoint::client(bind).context("h3: UDP socket")?;
        self.handshakes.fetch_add(1, Ordering::Relaxed);
        let conn = endpoint
            .connect_with(self.config.clone(), addr, &self.server_name)?
            .await
            .with_context(|| format!("h3: QUIC handshake with {addr}"))?;

        let mut exporter = [0u8; TOKEN_LEN];
        conn.export_keying_material(&mut exporter, AUTH_LABEL, b"")
            .map_err(|_| anyhow!("h3: TLS exporter unavailable"))?;
        let token = wire::auth_token(&self.uuid, &exporter);
        // Not waited on: the server reads the token before any other stream.
        let mut auth = conn.open_uni().await.context("h3: open auth stream")?;
        auth.write_all(&token).await.context("h3: send auth")?;
        auth.finish().context("h3: send auth")?;
        info!("h3: connected to {} ({addr})", self.server_name);
        debug!("h3: rtt {:?}", conn.rtt());
        Ok(conn)
    }
}

/// One TCP connection through the server. Reads begin with the server's
/// status byte, which is checked and then hidden.
pub struct H3Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    status: Option<Status>,
}

impl AsyncRead for H3Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.status.is_none() {
            let mut byte = [0u8; 1];
            let mut first = ReadBuf::new(&mut byte);
            ready!(Pin::new(&mut self.recv).poll_read(cx, &mut first))?;
            if first.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "h3: stream closed before the server's answer",
                )));
            }
            let status = Status::from_byte(byte[0]).unwrap_or(Status::BadRequest);
            if status != Status::Connected {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("h3: target {}", status.describe()),
                )));
            }
            self.status = Some(status);
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for H3Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // The trait's, not quinn's inherent poll_write (other error type).
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
