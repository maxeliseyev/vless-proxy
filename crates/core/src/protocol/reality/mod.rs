//! REALITY client-side primitives.
//!
//! This is a port of the client half of the REALITY protocol as implemented in
//! Xray-core (`transport/internet/reality/reality.go`) and validated by the
//! server in XTLS/REALITY (`tls.go`). Everything here is pure computation with
//! no I/O, so it can be unit-tested against vectors produced by the Go
//! reference primitives and later wired into a TLS stack.
//!
//! Protocol summary (client side):
//!
//! 1. The client builds a normal TLS 1.3 ClientHello with an X25519 key share.
//! 2. `shared = X25519(client_key_share_secret, server_reality_public_key)`.
//! 3. `auth_key = HKDF-SHA256(ikm = shared, salt = client_random[..20], info = "REALITY", len = 32)`.
//! 4. The 32-byte legacy `session_id` field is replaced by
//!    `AES-256-GCM(auth_key).seal(nonce = client_random[20..], plaintext = 16 bytes, aad = raw ClientHello with session_id zeroed)`
//!    where the plaintext is `version[3] || 0 || unix_time_be[4] || short_id[8]`.
//! 5. The server proves itself by sending a certificate whose Ed25519 public key
//!    `P` satisfies `cert.signature == HMAC-SHA512(auth_key, P)`.

pub mod tls;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::prelude::*;

/// Byte offset of the `legacy_session_id` payload inside a ClientHello
/// handshake message: 4 (handshake header) + 2 (version) + 32 (random) + 1 (length).
pub const SESSION_ID_OFFSET: usize = 39;
pub const SESSION_ID_LEN: usize = 32;
pub const CLIENT_RANDOM_LEN: usize = 32;
pub const SHORT_ID_LEN: usize = 8;

/// Version bytes advertised in the session id. Servers may enforce
/// `minClientVer` / `maxClientVer` against this, so we advertise a recent
/// Xray-core release (`core.Version_x/y/z`).
pub const DEFAULT_CLIENT_VERSION: [u8; 3] = [26, 10, 10];

const HKDF_INFO: &[u8] = b"REALITY";

/// Static REALITY parameters for one server, parsed from `vless://` / config strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealityClient {
    server_name: String,
    public_key: [u8; 32],
    short_id: [u8; SHORT_ID_LEN],
    client_version: [u8; 3],
}

impl RealityClient {
    /// `public_key` is the server's X25519 key in base64 (URL-safe or standard,
    /// with or without padding). `short_id` is 0..=16 hex chars.
    pub fn new(server_name: impl Into<String>, public_key: &str, short_id: &str) -> Result<Self> {
        Ok(Self {
            server_name: server_name.into(),
            public_key: parse_public_key(public_key)?,
            short_id: parse_short_id(short_id)?,
            client_version: DEFAULT_CLIENT_VERSION,
        })
    }

    pub fn with_client_version(mut self, version: [u8; 3]) -> Self {
        self.client_version = version;
        self
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn short_id(&self) -> &[u8; SHORT_ID_LEN] {
        &self.short_id
    }

    pub fn client_version(&self) -> [u8; 3] {
        self.client_version
    }

    /// Start a handshake with a fresh X25519 key share.
    pub fn begin(&self) -> RealityHandshake {
        RealityHandshake::new(self.clone(), StaticSecret::random_from_rng(OsRng))
    }

    /// Start a handshake with a caller-provided key share secret (tests, or when
    /// the TLS stack hands us the key it will use).
    pub fn begin_with_secret(&self, secret: [u8; 32]) -> RealityHandshake {
        RealityHandshake::new(self.clone(), StaticSecret::from(secret))
    }
}

/// Per-connection handshake state: the X25519 key share the TLS layer must
/// advertise, plus the derived authentication key once the client random is known.
pub struct RealityHandshake {
    client: RealityClient,
    secret: StaticSecret,
    auth_key: Option<AuthKey>,
}

impl std::fmt::Debug for RealityHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityHandshake")
            .field("client", &self.client)
            .field("auth_key_derived", &self.auth_key.is_some())
            .finish_non_exhaustive()
    }
}

impl RealityHandshake {
    fn new(client: RealityClient, secret: StaticSecret) -> Self {
        Self {
            client,
            secret,
            auth_key: None,
        }
    }

    /// Public half of the key share, to be placed in the ClientHello `key_share` extension.
    pub fn key_share_public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Regular TLS ECDH against the server's `key_share`, for the TLS key schedule.
    pub fn tls_shared_secret(&self, server_key_share: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&PublicKey::from(*server_key_share))
            .to_bytes()
    }

    /// Derive the REALITY auth key from this key share and the ClientHello random.
    pub fn derive_auth_key(&mut self, client_random: &[u8; CLIENT_RANDOM_LEN]) -> AuthKey {
        let shared = self
            .secret
            .diffie_hellman(&PublicKey::from(self.client.public_key))
            .to_bytes();
        let key = derive_auth_key(&shared, client_random);
        self.auth_key = Some(key.clone());
        key
    }

    pub fn auth_key(&self) -> Option<&AuthKey> {
        self.auth_key.as_ref()
    }

    /// Fill in the session id of a serialized ClientHello handshake message in place.
    ///
    /// `raw_hello` must be the full handshake message (starting with the 0x01
    /// type byte) carrying a 32-byte session id. `derive_auth_key` must have been
    /// called with the random embedded in this hello.
    pub fn seal_client_hello(&self, raw_hello: &mut [u8], unix_time: u32) -> Result<()> {
        let auth_key = self
            .auth_key
            .as_ref()
            .context("REALITY: auth key not derived yet")?;
        let plaintext =
            session_id_plaintext(self.client.client_version, unix_time, &self.client.short_id);
        seal_client_hello(auth_key, &plaintext, raw_hello)
    }

    /// REALITY certificate check. `Ok(true)` means the server is ours.
    /// `Ok(false)` means a well-formed but foreign certificate: the caller
    /// aborts the handshake (vproxy never falls back to PKI or sends VLESS
    /// to such a peer; Xray would spider the site instead).
    pub fn verify_server_certificate(&self, cert_der: &[u8]) -> Result<bool> {
        let auth_key = self
            .auth_key
            .as_ref()
            .context("REALITY: auth key not derived yet")?;
        verify_server_certificate(auth_key, cert_der)
    }
}

/// HKDF-derived key that authenticates both the ClientHello and the server certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthKey([u8; 32]);

impl AuthKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthKey(..)")
    }
}

/// `HKDF-SHA256(ikm = shared, salt = client_random[..20], info = "REALITY")` -> 32 bytes.
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    client_random: &[u8; CLIENT_RANDOM_LEN],
) -> AuthKey {
    let hk = Hkdf::<Sha256>::new(Some(&client_random[..20]), shared_secret);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO, &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    AuthKey(out)
}

/// The 16 plaintext bytes carried in the session id.
pub fn session_id_plaintext(
    version: [u8; 3],
    unix_time: u32,
    short_id: &[u8; SHORT_ID_LEN],
) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..3].copy_from_slice(&version);
    out[3] = 0; // reserved
    out[4..8].copy_from_slice(&unix_time.to_be_bytes());
    out[8..].copy_from_slice(short_id);
    out
}

/// Encrypt the session id plaintext. `raw_hello_zeroed` is the complete
/// ClientHello handshake message with its session id bytes set to zero; it is
/// bound to the ciphertext as AEAD additional data.
pub fn seal_session_id(
    auth_key: &AuthKey,
    client_random: &[u8; CLIENT_RANDOM_LEN],
    plaintext: &[u8; 16],
    raw_hello_zeroed: &[u8],
) -> Result<[u8; SESSION_ID_LEN]> {
    let cipher = Aes256Gcm::new_from_slice(&auth_key.0).expect("32-byte AES-256 key");
    let nonce = Nonce::from_slice(&client_random[20..]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: raw_hello_zeroed,
            },
        )
        .map_err(|_| anyhow::anyhow!("REALITY: AES-GCM seal failed"))?;
    let mut out = [0u8; SESSION_ID_LEN];
    out.copy_from_slice(&sealed);
    Ok(out)
}

/// Zero the session id in `raw_hello`, seal it, and write the ciphertext back.
pub fn seal_client_hello(
    auth_key: &AuthKey,
    plaintext: &[u8; 16],
    raw_hello: &mut [u8],
) -> Result<()> {
    let (random, _) = split_client_hello(raw_hello)?;
    let random: [u8; CLIENT_RANDOM_LEN] = random.try_into().expect("validated length");
    raw_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);
    let sealed = seal_session_id(auth_key, &random, plaintext, raw_hello)?;
    raw_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].copy_from_slice(&sealed);
    Ok(())
}

/// Validate the fixed layout of a ClientHello handshake message and return
/// `(client_random, session_id)` views into it.
pub fn split_client_hello(raw_hello: &[u8]) -> Result<(&[u8], &[u8])> {
    if raw_hello.len() < SESSION_ID_OFFSET + SESSION_ID_LEN {
        bail!("REALITY: ClientHello too short ({} bytes)", raw_hello.len());
    }
    if raw_hello[0] != 0x01 {
        bail!("REALITY: not a ClientHello handshake message");
    }
    let body_len = u32::from_be_bytes([0, raw_hello[1], raw_hello[2], raw_hello[3]]) as usize;
    if body_len + 4 != raw_hello.len() {
        bail!("REALITY: ClientHello length mismatch");
    }
    if raw_hello[SESSION_ID_OFFSET - 1] as usize != SESSION_ID_LEN {
        bail!("REALITY: ClientHello must carry a 32-byte session id");
    }
    Ok((
        &raw_hello[6..6 + CLIENT_RANDOM_LEN],
        &raw_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN],
    ))
}

/// Check that `cert_der` is the server's REALITY certificate: an Ed25519 leaf
/// whose signature value equals `HMAC-SHA512(auth_key, raw_ed25519_public_key)`.
///
/// Returns `Ok(false)` for a parseable certificate that does not match; the
/// caller treats that as a failed handshake.
pub fn verify_server_certificate(auth_key: &AuthKey, cert_der: &[u8]) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("REALITY: cannot parse server certificate: {e}"))?;
    let spki = cert.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 {
        return Ok(false);
    }
    let public_key = &spki.subject_public_key.data;
    if public_key.len() != 32 {
        return Ok(false);
    }
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(&auth_key.0).expect("HMAC accepts any key length");
    mac.update(public_key);
    let expected = mac.finalize().into_bytes();
    Ok(expected.as_slice() == cert.signature_value.data.as_ref())
}

pub fn unix_time_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

fn parse_public_key(public_key: &str) -> Result<[u8; 32]> {
    let trimmed = public_key.trim().trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .with_context(|| format!("Invalid REALITY public key: {public_key}"))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("REALITY public key must be 32 bytes, got {}", bytes.len()))?;
    Ok(key)
}

fn parse_short_id(short_id: &str) -> Result<[u8; SHORT_ID_LEN]> {
    let trimmed = short_id.trim();
    if !trimmed.len().is_multiple_of(2) || trimmed.len() > SHORT_ID_LEN * 2 {
        bail!("REALITY short ID must be 0..=16 hex chars, got {trimmed:?}");
    }
    let bytes =
        hex::decode(trimmed).with_context(|| format!("Invalid REALITY short ID: {short_id}"))?;
    let mut out = [0u8; SHORT_ID_LEN];
    out[..bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    //! Vectors generated with Go's crypto/ecdh, crypto/hkdf, crypto/aes+cipher.GCM,
    //! crypto/hmac+sha512 and crypto/x509, i.e. the exact primitives Xray-core uses.
    use super::*;
    use aes_gcm::aead::Payload;

    const CLIENT_PRIV: &str = "11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea";
    const CLIENT_PUB: &str = "e52b940ad182cfed595624daaaa892f68f14d52c49ae9016b6ab870e080e8300";
    const SERVER_PUB: &str = "f676b0801cd4bafea80f71854b43a9135ada65b975a13241d4949d962ed87e7b";
    const SHARED: &str = "83a8ab57d2108645c30f3e331eea3470291b5a3952540689be4f39fc188a5b67";
    const RANDOM: &str = "a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b7279";
    const AUTH_KEY: &str = "cfe0a971df560cfe66843b383809903b1b2f0c631c0b519f8b105cb76cc8c0c2";
    const TIMESTAMP: u32 = 1792200000;
    const SHORT_ID: &str = "b59cfeedfabf9f";
    const PLAIN: &str = "1a0a0a006ad2cd40b59cfeedfabf9f00";
    const HELLO_ZEROED: &str = "0100007f0303a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727920000000000000000000000000000000000000000000000000000000000000000030373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cd";
    const SESSION_ID: &str = "d42308ccae8c83daa0222126378f4464d616d50069e03226fae60b50e5c72e4a";
    const HELLO_SEALED: &str = "0100007f0303a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727920d42308ccae8c83daa0222126378f4464d616d50069e03226fae60b50e5c72e4a30373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cd";
    const CERT_DER: &str = "3081d0308183a003020102020101300506032b657030123110300e060355040313077265616c697479301e170d3233313131343232313332305a170d3330303331373137343634305a30123110300e060355040313077265616c697479302a300506032b6570032100ae8c223a43bcba4c09575681c9a1660a4bff05a04d2abcba82640fe7eacf49a7300506032b6570034100bfbdb2b72ddbf82d6a56fbedafd7d6ad5286c200be0c9f4cfe9934469ee7ce82b3659d80aba8b9e6452b42600e1fa7bcaa1a2953cc6318fbeab879e0c7dbd541";
    const CERT_BAD_DER: &str = "3081d0308183a003020102020101300506032b657030123110300e060355040313077265616c697479301e170d3233313131343232313332305a170d3330303331373137343634305a30123110300e060355040313077265616c697479302a300506032b6570032100ae8c223a43bcba4c09575681c9a1660a4bff05a04d2abcba82640fe7eacf49a7300506032b6570034100bfbdb2b72ddbf82d6a56fbedafd7d6ad5286c200be0c9f4cfe9934469ee7ce82b3659d80aba8b9e6452b42600e1fa7bcaa1a2953cc6318fbeab879e0c7dbd540";

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn arr<const N: usize>(s: &str) -> [u8; N] {
        h(s).as_slice().try_into().unwrap()
    }

    fn client() -> RealityClient {
        RealityClient::new(
            "www.example.com",
            &URL_SAFE_NO_PAD.encode(h(SERVER_PUB)),
            SHORT_ID,
        )
        .unwrap()
    }

    #[test]
    fn x25519_key_share_matches_go() {
        let hs = client().begin_with_secret(arr(CLIENT_PRIV));
        assert_eq!(hs.key_share_public(), arr::<32>(CLIENT_PUB));
        assert_eq!(hs.tls_shared_secret(&arr(SERVER_PUB)), arr::<32>(SHARED));
    }

    #[test]
    fn auth_key_matches_go_hkdf() {
        let key = derive_auth_key(&arr(SHARED), &arr(RANDOM));
        assert_eq!(key.as_bytes(), &arr::<32>(AUTH_KEY));

        let mut hs = client().begin_with_secret(arr(CLIENT_PRIV));
        assert_eq!(hs.derive_auth_key(&arr(RANDOM)), key);
    }

    #[test]
    fn session_id_plaintext_layout() {
        let plain = session_id_plaintext(DEFAULT_CLIENT_VERSION, TIMESTAMP, client().short_id());
        assert_eq!(plain, arr::<16>(PLAIN));
    }

    #[test]
    fn seal_session_id_matches_go_aes_gcm() {
        let key = AuthKey::from_bytes(arr(AUTH_KEY));
        let sealed = seal_session_id(&key, &arr(RANDOM), &arr(PLAIN), &h(HELLO_ZEROED)).unwrap();
        assert_eq!(sealed, arr::<32>(SESSION_ID));
    }

    #[test]
    fn seal_client_hello_in_place_end_to_end() {
        let mut hs = client().begin_with_secret(arr(CLIENT_PRIV));
        let mut hello = h(HELLO_ZEROED);
        // Pre-fill the session id with garbage: the sealer must zero it before computing the AAD.
        hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0xEE);

        hs.derive_auth_key(&arr(RANDOM));
        hs.seal_client_hello(&mut hello, TIMESTAMP).unwrap();
        assert_eq!(hello, h(HELLO_SEALED));
    }

    #[test]
    fn server_can_open_session_id_with_zeroed_hello_as_aad() {
        // Mirrors XTLS/REALITY tls.go: the server zeroes the session id, then
        // AES-GCM-opens the ciphertext with the zeroed hello as AAD.
        let sealed = h(HELLO_SEALED);
        let (random, session_id) = split_client_hello(&sealed).unwrap();
        let ciphertext = session_id.to_vec();
        let mut zeroed = sealed.clone();
        zeroed[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN].fill(0);

        let cipher = Aes256Gcm::new_from_slice(&h(AUTH_KEY)).unwrap();
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &ciphertext,
                    aad: &zeroed,
                },
            )
            .unwrap();
        assert_eq!(plain, h(PLAIN));
        assert_eq!(&plain[..3], &DEFAULT_CLIENT_VERSION);
        assert_eq!(
            u32::from_be_bytes(plain[4..8].try_into().unwrap()),
            TIMESTAMP
        );
        assert_eq!(&plain[8..], client().short_id());
    }

    #[test]
    fn seal_rejects_malformed_hello() {
        let key = AuthKey::from_bytes(arr(AUTH_KEY));
        let plain = arr::<16>(PLAIN);

        let mut short = vec![0x01, 0, 0, 10];
        short.extend_from_slice(&[0u8; 10]);
        assert!(seal_client_hello(&key, &plain, &mut short).is_err());

        let mut wrong_type = h(HELLO_ZEROED);
        wrong_type[0] = 0x02;
        assert!(seal_client_hello(&key, &plain, &mut wrong_type).is_err());

        let mut bad_len = h(HELLO_ZEROED);
        bad_len[3] ^= 1;
        assert!(seal_client_hello(&key, &plain, &mut bad_len).is_err());

        let mut empty_sid = h(HELLO_ZEROED);
        empty_sid[SESSION_ID_OFFSET - 1] = 0;
        assert!(seal_client_hello(&key, &plain, &mut empty_sid).is_err());
    }

    #[test]
    fn verifies_reality_certificate_signature() {
        let key = AuthKey::from_bytes(arr(AUTH_KEY));
        assert!(verify_server_certificate(&key, &h(CERT_DER)).unwrap());
        assert!(!verify_server_certificate(&key, &h(CERT_BAD_DER)).unwrap());

        let other = AuthKey::from_bytes([7u8; 32]);
        assert!(!verify_server_certificate(&other, &h(CERT_DER)).unwrap());

        assert!(verify_server_certificate(&key, b"not a certificate").is_err());
    }

    #[test]
    fn handshake_verifies_certificate_after_key_derivation() {
        let mut hs = client().begin_with_secret(arr(CLIENT_PRIV));
        assert!(hs.verify_server_certificate(&h(CERT_DER)).is_err());
        hs.derive_auth_key(&arr(RANDOM));
        assert!(hs.verify_server_certificate(&h(CERT_DER)).unwrap());
    }

    #[test]
    fn parses_public_key_in_any_base64_flavour() {
        let raw = h(SERVER_PUB);
        let url = URL_SAFE_NO_PAD.encode(&raw);
        let std_padded = base64::engine::general_purpose::STANDARD.encode(&raw);
        for enc in [url.as_str(), std_padded.as_str()] {
            assert_eq!(
                RealityClient::new("x", enc, "").unwrap().public_key(),
                &arr::<32>(SERVER_PUB)
            );
        }
        assert!(RealityClient::new("x", "dG9vc2hvcnQ", "").is_err());
        assert!(RealityClient::new("x", "!!!", "").is_err());
    }

    #[test]
    fn short_id_is_zero_padded_to_eight_bytes() {
        assert_eq!(
            RealityClient::new("x", &URL_SAFE_NO_PAD.encode(h(SERVER_PUB)), "")
                .unwrap()
                .short_id(),
            &[0u8; 8]
        );
        assert_eq!(
            RealityClient::new("x", &URL_SAFE_NO_PAD.encode(h(SERVER_PUB)), "ab")
                .unwrap()
                .short_id(),
            &[0xab, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            client().short_id(),
            &[0xb5, 0x9c, 0xfe, 0xed, 0xfa, 0xbf, 0x9f, 0x00]
        );
        let pk = URL_SAFE_NO_PAD.encode(h(SERVER_PUB));
        assert!(RealityClient::new("x", &pk, "abc").is_err());
        assert!(RealityClient::new("x", &pk, "0011223344556677889").is_err());
        assert!(RealityClient::new("x", &pk, "zz").is_err());
    }
}
