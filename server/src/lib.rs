//! `vproxy-server`: the server end of the h3 transport (see `vproxy::h3`
//! and docs/h3-transport-plan.md). A QUIC endpoint with the domain's real
//! certificate; a client that proves its account with the auth token gets
//! each of its streams relayed to the TCP target it names.
//!
//! Prototype scope: certificate from files, TCP only. A connection whose
//! token does not check out is closed with `H3_NO_ERROR`; serving the site
//! to such clients over HTTP/3 comes later.

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use uuid::Uuid;
use vproxy::h3::wire::{self, Status, ALPN, AUTH_LABEL, H3_NO_ERROR, TOKEN_LEN};
use vproxy::protocol::vless::Address;

/// A new connection has this long to present its token, a new stream to
/// name its target, a target to accept the TCP connection.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Without any traffic for this long a connection is dropped (clients ping
/// every 10 s while they want it).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
    users: Arc<[Uuid]>,
    allow_private: bool,
}

impl Server {
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let certs = CertificateDer::pem_file_iter(&settings.cert)
            .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
            .map_err(|e| anyhow!("{}: {e}", settings.cert.display()))?;
        let key = PrivateKeyDer::from_pem_file(&settings.key)
            .map_err(|e| anyhow!("{}: {e}", settings.key.display()))?;
        Self::bind(
            settings.listen,
            certs,
            key,
            settings.users.clone(),
            settings.allow_private,
        )
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
        transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("30 s fits a VarInt")));
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, listen)
            .with_context(|| format!("listen on {listen}/udp"))?;
        Ok(Self {
            endpoint,
            users: users.into(),
            allow_private,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Accept connections until the endpoint is closed.
    pub async fn run(self) -> Result<()> {
        info!("listening on {}/udp", self.local_addr()?);
        let shared = Arc::new(Shared {
            users: self.users,
            allow_private: self.allow_private,
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
    users: Arc<[Uuid]>,
    allow_private: bool,
}

impl Shared {
    async fn connection(self: Arc<Self>, incoming: quinn::Incoming) -> Result<()> {
        let remote = incoming.remote_address();
        let conn = incoming.await.context("handshake")?;
        let Some(user) = self.authenticate(&conn).await else {
            info!("{remote}: not authenticated, closing");
            conn.close(H3_NO_ERROR.into(), b"");
            return Ok(());
        };
        let tag = account_tag(&user);
        info!("{remote}: connected as {tag}");
        loop {
            let (send, recv) = match conn.accept_bi().await {
                Ok(stream) => stream,
                Err(e) => {
                    info!("{remote} ({tag}): closed: {e}");
                    return Ok(());
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
    }

    /// The account whose token arrives on the first unidirectional stream.
    async fn authenticate(&self, conn: &quinn::Connection) -> Option<Uuid> {
        let mut exporter = [0u8; TOKEN_LEN];
        conn.export_keying_material(&mut exporter, AUTH_LABEL, b"")
            .ok()?;
        let read = async {
            let mut recv = conn.accept_uni().await.ok()?;
            let mut token = [0u8; TOKEN_LEN];
            recv.read_exact(&mut token).await.ok()?;
            Some(token)
        };
        let token = timeout(AUTH_TIMEOUT, read).await.ok()??;
        self.users
            .iter()
            .find(|user| wire::token_matches(user, &exporter, &token))
            .copied()
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
        tokio::io::copy_bidirectional(&mut client, &mut target).await?;
        Ok(())
    }

    async fn connect(&self, address: &Address, port: u16) -> Result<TcpStream, (Status, String)> {
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
        match timeout(CONNECT_TIMEOUT, TcpStream::connect(allowed.as_slice())).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err((Status::Unreachable, e.to_string())),
            Err(_) => Err((Status::Timeout, "connect timed out".into())),
        }
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
