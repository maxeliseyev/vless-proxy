//! `vproxy-server`: the server end of the h3 transport (see `vproxy_core::h3`
//! and docs/h3-transport-plan.md). A QUIC endpoint with the domain's real
//! certificate; a client that proves its account with the auth token gets
//! each of its streams relayed to the TCP target it names.
//!
//! Prototype scope: certificate from files; TCP as streams, UDP as QUIC
//! datagrams (fragmented where the path needs it), one UDP socket per
//! client session. Ordinary HTTP/3 clients receive content from the
//! operator-configured HTTP backend, deployed separately from this binary.

mod admin;
mod http3;
mod stats;

pub use admin::{fetch as fetch_stats, DEFAULT_SOCKET as DEFAULT_ADMIN_SOCKET};
pub use stats::{AccountSnapshot, Snapshot, Stats};

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vproxy_core::h3::wire::{self, Status, ALPN};
use vproxy_core::protocol::vless::Address;

/// The account allow-list, swappable at runtime so a reload (SIGHUP in the
/// binary) can replace it without dropping live connections. Read once per
/// new connection, so a reload takes effect for the next connection; existing
/// sessions carry on (adding a user is seamless, a removed user keeps its
/// current session until it ends).
pub type Accounts = Arc<RwLock<Arc<[Uuid]>>>;

/// A new connection has this long to present its token, a new stream to
/// name its target, a target to accept the TCP connection.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Without any traffic for this long a connection is dropped (clients ping
/// every 10 s while they want it).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// A UDP session nobody sent on for this long is closed, as in vproxy.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// UDP sessions per connection; the least recently used goes first.
const MAX_UDP_SESSIONS: usize = 256;

/// Same as the client's, so datagrams fit from the first packet.
const INITIAL_MTU: u16 = vproxy_core::h3::client::INITIAL_MTU;

/// `server.toml`:
///
/// ```toml
/// listen = "0.0.0.0:443"
/// cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
/// key = "/etc/letsencrypt/live/example.com/privkey.pem"
/// users = ["00000000-0000-0000-0000-000000000000"]
/// ```
#[derive(Debug, Deserialize)]
pub struct Settings {
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub users: Vec<Uuid>,
    /// Relay to loopback and private networks too. Off: a client must not
    /// reach the server's own services or its LAN through it.
    #[serde(default)]
    pub allow_private: bool,
    /// Internal HTTP origin serving independently deployed public content.
    /// Without it, ordinary HTTP/3 requests receive a neutral 404 response.
    #[serde(default)]
    pub site_backend: Option<String>,
    /// Local Unix socket for live stats (`vproxy-server --stats`/`--tui`).
    /// Defaults to [`admin::DEFAULT_SOCKET`]; set to "" to turn it off.
    #[serde(default)]
    pub admin: Option<String>,
}

impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let settings: Settings =
            toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        if settings.users.is_empty() {
            bail!("{}: users is empty", path.display());
        }
        Ok(settings)
    }
}

pub struct Server {
    endpoint: quinn::Endpoint,
    users: Accounts,
    allow_private: bool,
    site: Option<http3::Site>,
    stats: Arc<Stats>,
    admin: Option<PathBuf>,
}

impl Server {
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let certs = CertificateDer::pem_file_iter(&settings.cert)
            .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
            .map_err(|e| anyhow!("{}: {e}", settings.cert.display()))?;
        let key = PrivateKeyDer::from_pem_file(&settings.key)
            .map_err(|e| anyhow!("{}: {e}", settings.key.display()))?;
        let mut server = Self::bind(
            settings.listen,
            certs,
            key,
            settings.users.clone(),
            settings.allow_private,
        )?;
        if let Some(backend) = &settings.site_backend {
            server = server.with_site_backend(backend)?;
        }
        // On by default; `admin = ""` turns it off.
        server.admin = match settings.admin.as_deref() {
            Some("") => None,
            Some(path) => Some(PathBuf::from(path)),
            None => Some(PathBuf::from(admin::DEFAULT_SOCKET)),
        };
        Ok(server)
    }

    pub fn bind(
        listen: SocketAddr,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        users: Vec<Uuid>,
        allow_private: bool,
    ) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("rustls provider does not support TLS 1.3")?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("certificate and key do not match")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| anyhow!("QUIC server config: {e}"))?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("30 s fits a VarInt")))
            .initial_mtu(INITIAL_MTU);
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, listen)
            .with_context(|| format!("listen on {listen}/udp"))?;
        Ok(Self {
            endpoint,
            users: Arc::new(RwLock::new(users.into())),
            allow_private,
            site: None,
            stats: Arc::new(Stats::new()),
            admin: None,
        })
    }

    /// Serve ordinary HTTP/3 requests from an independently deployed HTTP
    /// origin, e.g. `http://caddy:8080`. The client cannot select the origin.
    pub fn with_site_backend(mut self, backend: &str) -> Result<Self> {
        self.site = Some(http3::Site::new(backend)?);
        Ok(self)
    }

    /// Serve live stats on this local Unix socket instead of the default.
    pub fn with_admin(mut self, path: PathBuf) -> Self {
        self.admin = Some(path);
        self
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// A handle to the account allow-list, so the binary can hot-reload it on
    /// SIGHUP (`*handle.write() = Arc::from(new_users)`) without a restart.
    /// Take it before [`Server::run`], which consumes the server.
    pub fn accounts(&self) -> Accounts {
        self.users.clone()
    }

    /// Accept connections until the endpoint is closed.
    pub async fn run(self) -> Result<()> {
        info!("listening on {}/udp", self.local_addr()?);
        let stats = self.stats.clone();
        if let Some(path) = self.admin.clone() {
            let stats = stats.clone();
            tokio::spawn(async move {
                if let Err(e) = admin::serve(&path, stats).await {
                    warn!("admin socket: {e:#}");
                }
            });
        }
        let shared = Arc::new(Shared {
            users: self.users,
            allow_private: self.allow_private,
            site: self.site,
            stats,
        });
        while let Some(incoming) = self.endpoint.accept().await {
            let shared = shared.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                if let Err(e) = shared.connection(incoming).await {
                    debug!("{remote}: {e:#}");
                }
            });
        }
        Ok(())
    }
}

struct Shared {
    users: Accounts,
    allow_private: bool,
    site: Option<http3::Site>,
    stats: Arc<Stats>,
}

impl Shared {
    async fn connection(self: Arc<Self>, incoming: quinn::Incoming) -> Result<()> {
        let remote = incoming.remote_address();
        let conn = incoming.await.context("handshake")?;
        // Snapshot the allow-list for this connection (a reload swaps it for
        // the next one, without disturbing connections already up).
        let users = self.users.read().expect("accounts lock poisoned").clone();
        let (user, transport) = http3::Transport::classify(conn.clone(), &users).await?;
        let Some(user) = user else {
            debug!("{remote}: serving HTTP/3");
            self.stats.site_request();
            return http3::serve(transport, self.site.clone()).await;
        };
        drop(transport);
        let tag = account_tag(&user);
        self.stats.conn_open(&tag);
        info!("{remote}: connected as {tag}");
        tokio::spawn(self.clone().datagrams(conn.clone()));
        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(stream) => stream,
                Err(e) => {
                    info!("{remote} ({tag}): closed: {e}");
                    break;
                }
            };
            let this = self.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                if let Err(e) = this.stream(send, recv).await {
                    debug!("{remote} ({tag}): {e:#}");
                }
            });
        }
        self.stats.conn_close(&tag);
        Ok(())
    }

    /// One TCP target: read its header, connect, answer with the status
    /// byte, then relay until both sides are done.
    async fn stream(&self, mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
        let (address, port) = match timeout(HEADER_TIMEOUT, wire::read_target(&mut recv)).await {
            Ok(Ok(target)) => target,
            Ok(Err(e)) => return refuse(send, Status::BadRequest, e.to_string()).await,
            Err(_) => return refuse(send, Status::BadRequest, "no header".into()).await,
        };
        let target = match self.connect(&address, port).await {
            Ok(target) => target,
            Err((status, why)) => {
                return refuse(send, status, format!("{address}:{port}: {why}")).await
            }
        };
        debug!("relay to {address}:{port}");
        send.write_all(&[Status::Connected as u8]).await?;
        let mut client = tokio::io::join(recv, send);
        let mut target = target;
        self.stats.stream_open();
        // Bytes are tallied when the stream ends (client->target = up).
        let relayed = tokio::io::copy_bidirectional(&mut client, &mut target).await;
        let (up, down) = relayed.as_ref().copied().unwrap_or((0, 0));
        self.stats.stream_close(up, down);
        relayed?;
        Ok(())
    }

    async fn connect(&self, address: &Address, port: u16) -> Result<TcpStream, (Status, String)> {
        let allowed = self.resolve(address, port).await?;
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(allowed.as_slice())).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err((Status::Unreachable, e.to_string())),
            Err(_) => Err((Status::Timeout, "connect timed out".into())),
        }
    }

    /// Addresses of a target the policy lets us reach.
    async fn resolve(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<Vec<SocketAddr>, (Status, String)> {
        let candidates: Vec<SocketAddr> = match address {
            Address::Ipv4(ip) => vec![SocketAddr::new((*ip).into(), port)],
            Address::Ipv6(ip) => vec![SocketAddr::new((*ip).into(), port)],
            Address::Domain(name) => tokio::net::lookup_host((name.as_str(), port))
                .await
                .map_err(|e| (Status::Unreachable, e.to_string()))?
                .collect(),
        };
        let allowed: Vec<SocketAddr> = candidates
            .into_iter()
            .filter(|addr| self.allow_private || is_public(addr.ip()))
            .collect();
        if allowed.is_empty() {
            return Err((Status::Refused, "no public address".into()));
        }
        Ok(allowed)
    }

    /// The UDP side of a connection: datagrams in, one UDP socket per
    /// session to its target, replies back as datagrams, until the
    /// connection ends.
    async fn datagrams(self: Arc<Self>, conn: quinn::Connection) {
        let mut sessions: HashMap<u64, UdpSession> = HashMap::new();
        // Sessions whose target the policy refused: not looked up again.
        let mut refused: HashSet<u64> = HashSet::new();
        let mut defrag = wire::Defragger::default();
        let mut sweep = tokio::time::interval(Duration::from_secs(30));
        loop {
            let datagram = tokio::select! {
                datagram = conn.read_datagram() => match datagram {
                    Ok(datagram) => datagram,
                    Err(_) => break,
                },
                _ = sweep.tick() => {
                    sessions.retain(|_, s| {
                        let keep = s.last.elapsed() < UDP_IDLE;
                        if !keep {
                            s.task.abort();
                        }
                        keep
                    });
                    continue;
                }
            };
            let Some((id, body)) = defrag.push(datagram) else {
                continue;
            };
            let Ok((address, port, payload)) = wire::parse_target(&body) else {
                continue;
            };
            if refused.contains(&id) {
                continue;
            }
            if !sessions.contains_key(&id) {
                if sessions.len() >= MAX_UDP_SESSIONS {
                    let oldest = sessions.iter().min_by_key(|(_, s)| s.last).map(|(k, _)| *k);
                    if let Some(session) = oldest.and_then(|k| sessions.remove(&k)) {
                        session.task.abort();
                    }
                }
                match self.open_udp(&conn, id, &address, port).await {
                    Ok(session) => {
                        debug!("udp to {address}:{port}");
                        sessions.insert(id, session);
                    }
                    Err((status, why)) => {
                        warn!("udp {}: {address}:{port}: {why}", status.describe());
                        refused.insert(id);
                        continue;
                    }
                }
            }
            let session = sessions.get_mut(&id).expect("just inserted");
            session.last = Instant::now();
            if session.socket.send(payload).await.is_ok() {
                session
                    .bytes_up
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
        }
        for session in sessions.values() {
            session.task.abort();
        }
    }

    /// A UDP socket connected to the target, its replies sent back to the
    /// client as datagrams of session `id`.
    async fn open_udp(
        &self,
        conn: &quinn::Connection,
        id: u64,
        address: &Address,
        port: u16,
    ) -> Result<UdpSession, (Status, String)> {
        let target = self.resolve(address, port).await?[0];
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0".parse().expect("valid address")
        } else {
            "[::]:0".parse().expect("valid address")
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| (Status::Unreachable, e.to_string()))?;
        socket
            .connect(target)
            .await
            .map_err(|e| (Status::Unreachable, e.to_string()))?;
        let socket = Arc::new(socket);
        let reader = socket.clone();
        let conn = conn.clone();
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let down = bytes_down.clone();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let mut packet: u16 = 0;
            'recv: while let Ok(n) = reader.recv(&mut buf).await {
                down.fetch_add(n as u64, Ordering::Relaxed);
                let Some(max) = conn.max_datagram_size() else {
                    break;
                };
                packet = packet.wrapping_add(1);
                // Too big even for fragments: dropped, like a lost IP fragment.
                let Ok(datagrams) = wire::datagrams(id, &[], &buf[..n], max, packet) else {
                    continue;
                };
                for datagram in datagrams {
                    match conn.send_datagram(datagram) {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => continue 'recv,
                        Err(_) => break 'recv,
                    }
                }
            }
        });
        self.stats.udp_open();
        Ok(UdpSession {
            socket,
            last: Instant::now(),
            task,
            stats: self.stats.clone(),
            bytes_up,
            bytes_down,
        })
    }
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    last: Instant,
    task: JoinHandle<()>,
    stats: Arc<Stats>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.task.abort();
        self.stats.udp_close(
            self.bytes_up.load(Ordering::Relaxed),
            self.bytes_down.load(Ordering::Relaxed),
        );
    }
}

async fn refuse(mut send: quinn::SendStream, status: Status, why: String) -> Result<()> {
    warn!("{}: {why}", status.describe());
    send.write_all(&[status as u8]).await?;
    send.finish()?;
    Ok(())
}

/// Not loopback, private, link-local, CGNAT or otherwise not the internet.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_multicast()
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(v4) => is_public(v4.into()),
            None => {
                let first = ip.segments()[0];
                !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80)
            }
        },
    }
}

/// Short, non-secret tag of an account for the log.
fn account_tag(uuid: &Uuid) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(uuid.as_bytes())[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_internet_addresses_are_public() {
        for ip in ["93.184.216.34", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
