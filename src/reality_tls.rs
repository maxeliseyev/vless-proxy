//! Native REALITY transport: the primitives from [`crate::reality`] wired into
//! rustls through three extension points.
//!
//! * A [`SupportedKxGroup`] for X25519 that keeps the ephemeral secret so the
//!   REALITY auth key can be derived from it (rustls never exposes the key
//!   share secret itself).
//! * A [`ClientHelloSessionIdHook`] (vproxy patch to rustls) that replaces the
//!   session id of the initial ClientHello with the sealed authenticator.
//! * A [`ServerCertVerifier`] that accepts only a certificate bound to the
//!   derived auth key.
//!
//! All three share per-connection state through a [`ConnectionSlot`].

use crate::reality::{
    seal_session_id, session_id_plaintext, unix_time_now, RealityClient, RealityHandshake,
    RealityStream,
};
use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientHelloSessionIdHook, Resumption};
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, NamedGroup, SignatureScheme};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::debug;
use x25519_dalek::{PublicKey, StaticSecret};

/// ALPN offered to the server. Matches what browsers (and Xray's uTLS
/// fingerprints) send, so the REALITY server can forward unauthenticated
/// clients to the real site transparently.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

type Slot = Arc<Mutex<Option<RealityHandshake>>>;

/// Per-connection state shared between the hook and the verifier.
#[derive(Clone, Default)]
struct ConnectionSlot {
    handshake: Slot,
    verified: Arc<AtomicBool>,
}

impl fmt::Debug for ConnectionSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionSlot")
            .field("verified", &self.verified.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

/// Secrets of key shares that have been generated but not yet consumed by the
/// session-id hook, keyed by their public key. `SupportedKxGroup` instances
/// must be `'static`, so this registry is how a stateless group hands the
/// secret to the per-connection hook.
static PENDING_KEY_SHARES: Mutex<Vec<([u8; 32], [u8; 32])>> = Mutex::new(Vec::new());

fn register_key_share(public: [u8; 32], secret: [u8; 32]) {
    PENDING_KEY_SHARES
        .lock()
        .expect("key share registry poisoned")
        .push((public, secret));
}

fn take_key_share(public: &[u8; 32]) -> Option<[u8; 32]> {
    let mut pending = PENDING_KEY_SHARES
        .lock()
        .expect("key share registry poisoned");
    let idx = pending.iter().position(|(p, _)| p == public)?;
    Some(pending.swap_remove(idx).1)
}

#[derive(Debug)]
struct RealityX25519;

static REALITY_X25519: RealityX25519 = RealityX25519;

impl SupportedKxGroup for RealityX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        register_key_share(public, secret.to_bytes());
        Ok(Box::new(RealityKeyExchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct RealityKeyExchange {
    secret: StaticSecret,
    public: [u8; 32],
}

impl ActiveKeyExchange for RealityKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl Drop for RealityKeyExchange {
    fn drop(&mut self) {
        // Normally the hook already consumed it; this covers aborted handshakes.
        let _ = take_key_share(&self.public);
    }
}

fn reality_provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let base = rustls::crypto::aws_lc_rs::default_provider();
            Arc::new(CryptoProvider {
                kx_groups: vec![&REALITY_X25519],
                ..base
            })
        })
        .clone()
}

// ---------------------------------------------------------------------------
// Session id hook
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SessionIdHook {
    client: RealityClient,
    slot: ConnectionSlot,
}

impl ClientHelloSessionIdHook for SessionIdHook {
    fn session_id(
        &self,
        client_random: &[u8; 32],
        key_share_public: Option<&[u8]>,
        raw_client_hello: &[u8],
    ) -> Option<[u8; 32]> {
        let public: [u8; 32] = key_share_public?.try_into().ok()?;
        let secret = take_key_share(&public)?;
        let mut handshake = self.client.begin_with_secret(secret);
        let auth_key = handshake.derive_auth_key(client_random);
        let plaintext = session_id_plaintext(
            self.client.client_version(),
            unix_time_now(),
            self.client.short_id(),
        );
        let sealed =
            seal_session_id(&auth_key, client_random, &plaintext, raw_client_hello).ok()?;
        *self.slot.handshake.lock().expect("handshake slot poisoned") = Some(handshake);
        Some(sealed)
    }
}

// ---------------------------------------------------------------------------
// Certificate verification
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RealityVerifier {
    slot: ConnectionSlot,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RealityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let guard = self.slot.handshake.lock().expect("handshake slot poisoned");
        let handshake = guard
            .as_ref()
            .ok_or_else(|| Error::General("REALITY: session id hook did not run".into()))?;
        match handshake.verify_server_certificate(end_entity) {
            Ok(true) => {
                self.slot.verified.store(true, Ordering::SeqCst);
                Ok(ServerCertVerified::assertion())
            }
            Ok(false) => Err(Error::General(
                "REALITY: received real certificate (potential MITM or redirection)".into(),
            )),
            Err(e) => Err(Error::General(format!("REALITY: {e}"))),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Connector
// ---------------------------------------------------------------------------

/// Summary of a completed REALITY handshake, for logs and `--probe`.
#[derive(Debug, Clone)]
pub struct RealityConnectionInfo {
    pub server_name: String,
    pub alpn: Option<String>,
    pub cipher_suite: String,
}

pub struct RealityConnector {
    client: RealityClient,
}

impl RealityConnector {
    pub fn new(client: RealityClient) -> Self {
        Self { client }
    }

    /// Run the REALITY handshake over an established transport.
    pub async fn connect<IO>(&self, io: IO) -> Result<RealityStream<IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let slot = ConnectionSlot::default();
        let provider = reality_provider();

        let verifier = Arc::new(RealityVerifier {
            slot: slot.clone(),
            algorithms: provider.signature_verification_algorithms,
        });
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("rustls provider does not support TLS 1.3")?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.enable_sni = true;
        config.alpn_protocols = ALPN.iter().map(|p| p.to_vec()).collect();
        config.session_id_hook = Some(Arc::new(SessionIdHook {
            client: self.client.clone(),
            slot: slot.clone(),
        }));

        let server_name = ServerName::try_from(self.client.server_name().to_string())
            .with_context(|| {
                format!("Invalid REALITY server name: {}", self.client.server_name())
            })?;

        debug!("REALITY handshake with SNI {}", self.client.server_name());
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = connector
            .connect(server_name, io)
            .await
            .context("REALITY handshake failed")?;

        if !slot.verified.load(Ordering::SeqCst) {
            bail!("REALITY handshake completed without certificate verification");
        }

        Ok(RealityStream::new(stream))
    }
}

pub fn connection_info<IO>(stream: &RealityStream<IO>, server_name: &str) -> RealityConnectionInfo
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (_, conn) = stream.get_ref().get_ref();
    RealityConnectionInfo {
        server_name: server_name.to_string(),
        alpn: conn
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        cipher_suite: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_share_registry_hands_secret_to_hook_once() {
        let kx = REALITY_X25519.start().unwrap();
        let public: [u8; 32] = kx.pub_key().try_into().unwrap();
        let secret = take_key_share(&public).expect("registered on start");
        assert_eq!(
            PublicKey::from(&StaticSecret::from(secret)).to_bytes(),
            public
        );
        assert!(take_key_share(&public).is_none(), "consumed exactly once");
        drop(kx);
    }

    #[test]
    fn dropped_key_share_is_removed_from_registry() {
        let kx = REALITY_X25519.start().unwrap();
        let public: [u8; 32] = kx.pub_key().try_into().unwrap();
        drop(kx);
        assert!(take_key_share(&public).is_none());
    }

    #[test]
    fn key_exchange_matches_x25519_dalek() {
        let kx = REALITY_X25519.start().unwrap();
        let public: [u8; 32] = kx.pub_key().try_into().unwrap();
        let peer = StaticSecret::random_from_rng(OsRng);
        let expected = peer.diffie_hellman(&PublicKey::from(public));
        let shared = kx.complete(PublicKey::from(&peer).as_bytes()).unwrap();
        assert_eq!(shared.secret_bytes(), expected.as_bytes());
    }

    #[test]
    fn key_exchange_rejects_bad_peer_key() {
        let kx = REALITY_X25519.start().unwrap();
        assert!(kx.complete(&[0u8; 31]).is_err());
        let kx = REALITY_X25519.start().unwrap();
        assert!(
            kx.complete(&[0u8; 32]).is_err(),
            "all-zero point is non-contributory"
        );
    }
}
