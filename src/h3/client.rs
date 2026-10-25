//! Client side of the h3 transport: one QUIC connection per server, opened
//! on first use and again after it dies, never two handshakes at once. TCP
//! targets are streams on it, UDP flows are datagram sessions.

use super::wire::{self, Status, ALPN, AUTH_LABEL, TOKEN_LEN};
use crate::protocol::vless::Address;
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Without traffic for this long the connection is gone (both ends agree on
/// the smaller of their values)...
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// ...so it is pinged this often while it should stay up.
const KEEP_ALIVE: Duration = Duration::from_secs(10);

/// UDP payload size of QUIC packets from the start, Chrome's value. The
/// quinn default (1200) leaves no room for a 1200-byte inner QUIC Initial in
/// a datagram; path MTU discovery raises it further where the path allows.
pub const INITIAL_MTU: u16 = 1350;

/// Datagrams waiting for a slow UDP flow before newer ones are dropped.
const SESSION_QUEUE: usize = 256;

/// Where a connection's incoming datagrams go: session id to its flow.
type Sessions = Arc<std::sync::Mutex<HashMap<u64, mpsc::Sender<Bytes>>>>;

/// A connection, its socket and the routing of its datagrams.
#[derive(Clone)]
struct Live {
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    conn: quinn::Connection,
    sessions: Sessions,
    next_session: Arc<AtomicU64>,
    /// Whether fragmenting for the datagram limit was logged yet; once
    /// per connection, it would flood the log otherwise.
    fragments_logged: Arc<AtomicBool>,
}

pub struct H3Client {
    host: String,
    port: u16,
    server_name: String,
    uuid: Uuid,
    config: quinn::ClientConfig,
    /// The live connection, if any. Held across a handshake, which makes
    /// concurrent callers wait for it instead of dialing their own.
    conn: Mutex<Option<Live>>,
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
            .keep_alive_interval(Some(KEEP_ALIVE))
            .initial_mtu(INITIAL_MTU);
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

    /// A UDP flow to `address:port` through the server, as QUIC datagrams.
    /// It ends (`recv` gives `None`) when the connection does.
    pub async fn open_udp(&self, address: &Address, port: u16) -> Result<H3UdpSession> {
        let live = self.live().await?;
        if live.conn.max_datagram_size().is_none() {
            bail!("h3: the server does not take datagrams");
        }
        let id = live.next_session.fetch_add(1, Ordering::Relaxed);
        let target: Arc<[u8]> = wire::encode_target(address, port)?.into();
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        live.sessions
            .lock()
            .expect("h3 sessions lock poisoned")
            .insert(id, tx);
        Ok(H3UdpSession {
            sender: H3UdpSender {
                conn: live.conn,
                id,
                target,
                packet: Arc::default(),
                fragments_logged: live.fragments_logged,
            },
            receiver: H3UdpReceiver {
                rx,
                id,
                sessions: live.sessions,
            },
        })
    }

    /// The network under us changed (Wi-Fi to cellular, say): move the live
    /// connection to a new socket, so it carries on over the new path (QUIC
    /// connection migration) instead of dying by idle timeout.
    pub async fn network_changed(&self) {
        let slot = self.conn.lock().await;
        let Some(live) = slot.as_ref().filter(|l| l.conn.close_reason().is_none()) else {
            return;
        };
        let moved = std::net::UdpSocket::bind(unspecified(live.remote))
            .and_then(|socket| live.endpoint.rebind(socket));
        match moved {
            Ok(()) => info!("h3: network changed, connection moved to a new socket"),
            Err(e) => warn!("h3: network changed, cannot move the connection: {e}"),
        }
    }

    /// The live connection, dialing (and authenticating) a new one if there
    /// is none or it has closed.
    pub async fn connection(&self) -> Result<quinn::Connection> {
        Ok(self.live().await?.conn)
    }

    async fn live(&self) -> Result<Live> {
        let mut slot = self.conn.lock().await;
        if let Some(live) = slot.as_ref().filter(|l| l.conn.close_reason().is_none()) {
            return Ok(live.clone());
        }
        let (endpoint, remote, conn) = self.dial().await?;
        let sessions = Sessions::default();
        tokio::spawn(dispatch(conn.clone(), sessions.clone()));
        let live = Live {
            endpoint,
            remote,
            conn,
            sessions,
            next_session: Arc::new(AtomicU64::new(0)),
            fragments_logged: Arc::default(),
        };
        *slot = Some(live.clone());
        Ok(live)
    }

    async fn dial(&self) -> Result<(quinn::Endpoint, SocketAddr, quinn::Connection)> {
        let addr = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .with_context(|| format!("h3: resolve {}", self.host))?
            .next()
            .ok_or_else(|| anyhow!("h3: {} has no address", self.host))?;
        // A new socket (and source port) per connection, like a browser.
        let endpoint = quinn::Endpoint::client(unspecified(addr)).context("h3: UDP socket")?;
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
        // The address only at debug: the shared log masks names, not IPs.
        info!(
            "h3: connected to {}, datagrams up to {} bytes",
            self.server_name,
            conn.max_datagram_size().unwrap_or(0)
        );
        debug!("h3: {addr}, rtt {:?}", conn.rtt());
        Ok((endpoint, addr, conn))
    }
}

/// Any local address of `remote`'s family, any port.
fn unspecified(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    }
}

/// Hand each datagram of `conn` to its session (joining fragments) until
/// the connection ends, then end every session.
async fn dispatch(conn: quinn::Connection, sessions: Sessions) {
    let mut defrag = wire::Defragger::default();
    while let Ok(datagram) = conn.read_datagram().await {
        let Some((id, payload)) = defrag.push(datagram) else {
            continue;
        };
        let flow = sessions
            .lock()
            .expect("h3 sessions lock poisoned")
            .get(&id)
            .cloned();
        if let Some(flow) = flow {
            // A full queue drops the datagram, as a congested link would.
            let _ = flow.try_send(payload);
        }
    }
    sessions.lock().expect("h3 sessions lock poisoned").clear();
}

/// One UDP flow through the server; split it to send and receive at once.
pub struct H3UdpSession {
    sender: H3UdpSender,
    receiver: H3UdpReceiver,
}

impl H3UdpSession {
    pub fn into_split(self) -> (H3UdpSender, H3UdpReceiver) {
        (self.sender, self.receiver)
    }
}

#[derive(Clone)]
pub struct H3UdpSender {
    conn: quinn::Connection,
    id: u64,
    /// The session's target header, at the front of every datagram body.
    target: Arc<[u8]>,
    /// Number of the next fragmented packet.
    packet: Arc<AtomicU16>,
    fragments_logged: Arc<AtomicBool>,
}

impl H3UdpSender {
    /// Send one UDP payload, in fragments when it does not fit the path's
    /// datagram limit. Fails for a payload too big even for those (the
    /// caller drops it, as a too-small MTU would) and when the connection
    /// is gone.
    pub fn send(&self, payload: &[u8]) -> Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| anyhow!("h3: datagrams unavailable"))?;
        let packet = self.packet.fetch_add(1, Ordering::Relaxed);
        let datagrams = wire::datagrams(self.id, &self.target, payload, max, packet)
            .map_err(|e| anyhow!("h3: UDP payload of {} bytes: {e}", payload.len()))?;
        if datagrams.len() > 1 && !self.fragments_logged.swap(true, Ordering::Relaxed) {
            info!("h3: datagram limit {max} bytes, larger UDP payloads go in fragments");
        }
        for datagram in datagrams {
            self.conn
                .send_datagram(datagram)
                .map_err(|e| anyhow!("h3: send datagram: {e}"))?;
        }
        Ok(())
    }
}

pub struct H3UdpReceiver {
    rx: mpsc::Receiver<Bytes>,
    id: u64,
    sessions: Sessions,
}

impl H3UdpReceiver {
    /// The next payload from the target; `None` once the connection is gone.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}

impl Drop for H3UdpReceiver {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.id);
        }
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
