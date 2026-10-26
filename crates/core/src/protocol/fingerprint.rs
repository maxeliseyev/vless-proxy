//! TLS ClientHello shaped like Chrome's, so the handshake does not stand out
//! from browser traffic (JA3/JA4 and friends). This is the client side of
//! what Xray does with uTLS `fp=chrome`. The default profile is uTLS
//! `HelloChrome_155` (Chrome stable since October 2026); `HelloChrome_133`
//! stays available as `fp=chrome133` for side-by-side comparisons, since
//! TSPU is reported to single out that older shape.
//!
//! rustls builds its own hello; our fork hands the encoded bytes to a
//! [`ClientHelloRewriter`] and sends what it returns. The rewriter keeps the
//! fields that carry cryptographic state (random, session id, key shares,
//! ALPN, SNI) and replaces the rest: Chrome's cipher suite list, its set of
//! extensions in a per-connection random order (Chrome shuffles them since
//! version 110), GREASE values in the places BoringSSL puts them, a GREASE
//! ECH extension, ALPS, SCT and session ticket requests, and for Chrome 155
//! ML-DSA signature algorithms plus the `trust_anchors` list of the Chrome
//! Root Store. Extensions rustls does not implement are advertised only;
//! servers do not select them.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use rustls::client::ClientHelloRewriter;
use std::collections::HashMap;
use std::sync::Arc;

const EXT_SERVER_NAME: u16 = 0;
const EXT_STATUS_REQUEST: u16 = 5;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SCT: u16 = 18;
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
const EXT_COMPRESS_CERTIFICATE: u16 = 27;
const EXT_SESSION_TICKET: u16 = 35;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_COOKIE: u16 = 44;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_ALPS: u16 = 17613; // application_settings, new code point
const EXT_TRUST_ANCHORS: u16 = 0xca34; // draft-ietf-tls-trust-anchor-ids
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 0x0039;

const X25519MLKEM768: u16 = 0x11ec;
const X25519: u16 = 0x001d;
const SECP256R1: u16 = 0x0017;
const SECP384R1: u16 = 0x0018;

/// Chrome's cipher suites (GREASE first).
const CIPHER_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

/// Chrome's classic signature algorithms (Chrome 133 sends exactly these).
const SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// rsa_pkcs1_sha1: Chrome appends it to the QUIC signature-algorithms list.
const RSA_PKCS1_SHA1: u16 = 0x0201;

/// ML-DSA-44/65/87, which Chrome 155 lists first (after a GREASE value).
const MLDSA_SIGNATURE_ALGORITHMS: [u16; 3] = [0x0904, 0x0905, 0x0906];

/// Chrome Root Store trust anchor IDs advertised by Chrome 155.0.8059.40, in
/// the lexicographic order Chrome uses (uTLS `chrome155TrustAnchorIDs`).
const TRUST_ANCHOR_IDS: [&[u8]; 28] = [
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0f],
];

/// `trust_anchors` extension body: a u16-length list of u8-length IDs.
fn trust_anchors_body() -> Vec<u8> {
    let list_len: usize = TRUST_ANCHOR_IDS.iter().map(|id| 1 + id.len()).sum();
    let mut out = Vec::with_capacity(2 + list_len);
    out.extend_from_slice(&(list_len as u16).to_be_bytes());
    for id in TRUST_ANCHOR_IDS {
        out.push(id.len() as u8);
        out.extend_from_slice(id);
    }
    out
}

/// Which Chrome release to imitate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// uTLS `HelloChrome_133` (Chrome 133 to 154; what Xray sent until
    /// October 2026).
    Chrome133,
    /// uTLS `HelloChrome_155`: adds GREASE and ML-DSA to the signature
    /// algorithms and the `trust_anchors` extension.
    Chrome155,
}

/// Which browser to look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    /// Current Chrome (155).
    Chrome,
    /// The previous Chrome shape, for A/B comparisons (`fp=chrome133`).
    Chrome133,
    /// Send what rustls builds.
    None,
}

impl Fingerprint {
    /// `fp=` / `server.fingerprint` value. Anything Xray would hand to uTLS
    /// (chrome, firefox, safari, ios, android, edge, 360, qq, random,
    /// randomized) becomes current Chrome: that is the only browser
    /// implemented, and the one almost every link asks for. `chrome133`
    /// (also `chrome-133`, `chrome_133`) selects the previous shape. `none`,
    /// `rustls`, `raw` and `go` disable shaping.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("none") | Some("rustls") | Some("raw") | Some("go") | Some("golang") => {
                Fingerprint::None
            }
            Some("chrome133") | Some("chrome-133") | Some("chrome_133") => Fingerprint::Chrome133,
            _ => Fingerprint::Chrome,
        }
    }

    /// A fresh rewriter for one connection (its random choices are made
    /// once, so a HelloRetryRequest hello keeps the same shape).
    pub fn rewriter(self) -> Option<Arc<dyn ClientHelloRewriter>> {
        match self {
            Fingerprint::Chrome => Some(Arc::new(ChromeHello::new(Profile::Chrome155))),
            Fingerprint::Chrome133 => Some(Arc::new(ChromeHello::new(Profile::Chrome133))),
            Fingerprint::None => None,
        }
    }
}

/// Per-connection random choices of a Chrome hello.
#[derive(Debug)]
pub struct ChromeHello {
    profile: Profile,
    grease_cipher: u16,
    grease_group: u16,
    grease_ext1: u16,
    grease_ext2: u16,
    grease_version: u16,
    grease_sigalg: u16,
    /// Extension order: lower rank first.
    ranks: HashMap<u16, u32>,
    ech: Vec<u8>,
}

/// A GREASE value `0x?a?a` (RFC 8701) from a random byte.
fn grease(byte: u8) -> u16 {
    let v = ((byte & 0xf0) | 0x0a) as u16;
    v | (v << 8)
}

impl Default for ChromeHello {
    fn default() -> Self {
        Self::new(Profile::Chrome155)
    }
}

impl ChromeHello {
    pub fn new(profile: Profile) -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(profile, seed)
    }

    /// Deterministic variant (tests).
    pub fn from_seed(profile: Profile, seed: [u8; 32]) -> Self {
        let mut rng = StdRng::from_seed(seed);
        let grease_cipher = grease(rng.gen());
        let grease_group = grease(rng.gen());
        let grease_ext1 = grease(rng.gen());
        let mut grease_ext2 = grease(rng.gen());
        if grease_ext2 == grease_ext1 {
            grease_ext2 ^= 0x1010;
        }
        let grease_version = grease(rng.gen());
        let grease_sigalg = grease(rng.gen());
        let mut ranks = HashMap::new();
        for ext in [
            EXT_SERVER_NAME,
            EXT_STATUS_REQUEST,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_ALPN,
            EXT_SCT,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_COMPRESS_CERTIFICATE,
            EXT_SESSION_TICKET,
            EXT_SUPPORTED_VERSIONS,
            EXT_COOKIE,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_KEY_SHARE,
            EXT_ALPS,
            EXT_TRUST_ANCHORS,
            EXT_ECH,
            EXT_RENEGOTIATION_INFO,
            EXT_QUIC_TRANSPORT_PARAMS,
        ] {
            ranks.insert(ext, rng.gen());
        }
        let ech = grease_ech(&mut rng);
        Self {
            profile,
            grease_cipher,
            grease_group,
            grease_ext1,
            grease_ext2,
            grease_version,
            grease_sigalg,
            ranks,
            ech,
        }
    }
}

/// BoringSSL's GREASE ECH: outer type, HKDF-SHA256/AES-128-GCM, random
/// config id, a 32-byte "encapsulated key" and a random payload whose length
/// is one of Chrome's four choices plus the AEAD tag.
fn grease_ech(rng: &mut StdRng) -> Vec<u8> {
    let payload_len = [128u16, 160, 192, 224][rng.gen_range(0..4)] + 16;
    let mut out = Vec::with_capacity(12 + 32 + 2 + payload_len as usize);
    out.push(0); // ECHClientHello type: outer
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // kdf HKDF-SHA256
    out.extend_from_slice(&0x0001u16.to_be_bytes()); // aead AES-128-GCM
    out.push(rng.gen()); // config id
    out.extend_from_slice(&32u16.to_be_bytes());
    let mut enc = [0u8; 32];
    rng.fill_bytes(&mut enc);
    out.extend_from_slice(&enc);
    out.extend_from_slice(&payload_len.to_be_bytes());
    let mut payload = vec![0u8; payload_len as usize];
    rng.fill_bytes(&mut payload);
    out.extend_from_slice(&payload);
    out
}

/// Parsed ClientHello body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHello {
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl ParsedHello {
    /// Parse an encoded ClientHello handshake message (4-byte header included).
    pub fn parse(raw: &[u8]) -> Option<Self> {
        if raw.len() < 4 || raw[0] != 1 {
            return None;
        }
        let len = u32::from_be_bytes([0, raw[1], raw[2], raw[3]]) as usize;
        let body = raw.get(4..4 + len)?;
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Option<&[u8]> {
            let s = body.get(*p..*p + n)?;
            *p += n;
            Some(s)
        };
        let version = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?);
        let random: [u8; 32] = take(&mut p, 32)?.try_into().ok()?;
        let sid_len = take(&mut p, 1)?[0] as usize;
        let session_id = take(&mut p, sid_len)?.to_vec();
        let cs_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
        let cipher_suites = be_u16s(take(&mut p, cs_len)?).collect();
        let comp_len = take(&mut p, 1)?[0] as usize;
        let compression = take(&mut p, comp_len)?.to_vec();
        let mut extensions = Vec::new();
        if p < body.len() {
            let ext_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().ok()?) as usize;
            let exts = take(&mut p, ext_len)?;
            let mut q = 0usize;
            while q + 4 <= exts.len() {
                let typ = u16::from_be_bytes([exts[q], exts[q + 1]]);
                let l = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
                let data = exts.get(q + 4..q + 4 + l)?.to_vec();
                extensions.push((typ, data));
                q += 4 + l;
            }
        }
        Some(Self {
            version,
            random,
            session_id,
            cipher_suites,
            compression,
            extensions,
        })
    }

    pub fn extension(&self, typ: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, d)| d.as_slice())
    }

    /// Encode as a handshake message with header.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(2048);
        body.extend_from_slice(&self.version.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(self.session_id.len() as u8);
        body.extend_from_slice(&self.session_id);
        body.extend_from_slice(&((self.cipher_suites.len() * 2) as u16).to_be_bytes());
        for cs in &self.cipher_suites {
            body.extend_from_slice(&cs.to_be_bytes());
        }
        body.push(self.compression.len() as u8);
        body.extend_from_slice(&self.compression);
        let mut exts = Vec::with_capacity(1500);
        for (typ, data) in &self.extensions {
            exts.extend_from_slice(&typ.to_be_bytes());
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(data);
        }
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut out = Vec::with_capacity(body.len() + 4);
        out.push(1);
        out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&body);
        out
    }
}

/// Big-endian u16 values of a byte slice (a trailing odd byte is ignored).
fn be_u16s(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    out.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for v in values {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

impl ChromeHello {
    /// Build the Chrome-shaped hello from what rustls produced.
    pub fn shape(&self, original: &ParsedHello, retry: bool) -> Option<ParsedHello> {
        if original.extension(EXT_PRE_SHARED_KEY).is_some()
            || original.extension(EXT_EARLY_DATA).is_some()
        {
            return None; // resumption: the binder covers the exact bytes
        }
        let mut cipher_suites = Vec::with_capacity(16);
        cipher_suites.push(self.grease_cipher);
        cipher_suites.extend_from_slice(&CIPHER_SUITES);

        let mut exts: Vec<(u16, Vec<u8>)> = Vec::with_capacity(18);
        if let Some(sni) = original.extension(EXT_SERVER_NAME) {
            exts.push((EXT_SERVER_NAME, sni.to_vec()));
        }
        exts.push((EXT_EXTENDED_MASTER_SECRET, Vec::new()));
        exts.push((EXT_RENEGOTIATION_INFO, vec![0x00]));
        exts.push((
            EXT_SUPPORTED_GROUPS,
            u16_list(&[
                self.grease_group,
                X25519MLKEM768,
                X25519,
                SECP256R1,
                SECP384R1,
            ]),
        ));
        exts.push((EXT_EC_POINT_FORMATS, vec![0x01, 0x00]));
        exts.push((EXT_SESSION_TICKET, Vec::new()));
        if let Some(alpn) = original.extension(EXT_ALPN) {
            exts.push((EXT_ALPN, alpn.to_vec()));
        }
        exts.push((EXT_STATUS_REQUEST, vec![0x01, 0x00, 0x00, 0x00, 0x00]));
        let sigalgs = match self.profile {
            Profile::Chrome133 => u16_list(&SIGNATURE_ALGORITHMS),
            Profile::Chrome155 => {
                let mut all = Vec::with_capacity(12);
                all.push(self.grease_sigalg);
                all.extend_from_slice(&MLDSA_SIGNATURE_ALGORITHMS);
                all.extend_from_slice(&SIGNATURE_ALGORITHMS);
                u16_list(&all)
            }
        };
        exts.push((EXT_SIGNATURE_ALGORITHMS, sigalgs));
        exts.push((EXT_SCT, Vec::new()));
        if let Some(shares) = original.extension(EXT_KEY_SHARE) {
            // Keep rustls's shares (they hold the key exchange state); a
            // one-byte GREASE share goes first, as in Chrome's first hello.
            let body = shares.get(2..)?;
            let mut data = Vec::with_capacity(shares.len() + 5);
            if !retry {
                data.extend_from_slice(&self.grease_group.to_be_bytes());
                data.extend_from_slice(&1u16.to_be_bytes());
                data.push(0);
            }
            data.extend_from_slice(body);
            let mut ext = Vec::with_capacity(data.len() + 2);
            ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext.extend_from_slice(&data);
            exts.push((EXT_KEY_SHARE, ext));
        }
        exts.push((EXT_PSK_KEY_EXCHANGE_MODES, vec![0x01, 0x01]));
        exts.push((
            EXT_SUPPORTED_VERSIONS,
            vec![
                6,
                (self.grease_version >> 8) as u8,
                self.grease_version as u8,
                0x03,
                0x04,
                0x03,
                0x03,
            ],
        ));
        exts.push((EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]));
        exts.push((EXT_ALPS, vec![0x00, 0x03, 0x02, b'h', b'2']));
        if self.profile == Profile::Chrome155 {
            exts.push((EXT_TRUST_ANCHORS, trust_anchors_body()));
        }
        exts.push((EXT_ECH, self.ech.clone()));
        if let Some(cookie) = original.extension(EXT_COOKIE) {
            exts.push((EXT_COOKIE, cookie.to_vec()));
        }
        exts.sort_by_key(|(typ, _)| self.ranks.get(typ).copied().unwrap_or(u32::MAX));
        exts.insert(0, (self.grease_ext1, Vec::new()));
        exts.push((self.grease_ext2, vec![0x00]));

        Some(ParsedHello {
            version: 0x0303,
            random: original.random,
            session_id: original.session_id.clone(),
            cipher_suites,
            compression: vec![0x00],
            extensions: exts,
        })
    }

    /// Build a Chrome-QUIC-shaped hello. Unlike [`ChromeHello::shape`], this
    /// keeps the `quic_transport_parameters` extension quinn produced (RFC
    /// 9001 requires it) and uses Chrome's QUIC extension set (uQUIC
    /// `QUICChrome_146`): ALPS and ALPN are `h3`, the cipher list is the three
    /// TLS 1.3 suites with no GREASE suite, GREASE ECH is kept, and the
    /// TCP-only extensions are dropped. The transport-parameter
    /// contents, the QUIC version and the Initial packet layout stay quinn's,
    /// so this shapes the handshake's TLS layer only (see docs; the uQUIC
    /// `QUICChrome` presets are the reference).
    pub fn shape_quic(&self, original: &ParsedHello, retry: bool) -> Option<ParsedHello> {
        if original.extension(EXT_PRE_SHARED_KEY).is_some()
            || original.extension(EXT_EARLY_DATA).is_some()
        {
            return None; // resumption: the binder covers the exact bytes
        }
        // The three TLS 1.3 suites Chrome offers over QUIC (no GREASE suite).
        let cipher_suites = vec![0x1301, 0x1302, 0x1303];

        let mut exts: Vec<(u16, Vec<u8>)> = Vec::with_capacity(12);
        // Required by RFC 9001: carry quinn's transport parameters through.
        let qtp = original.extension(EXT_QUIC_TRANSPORT_PARAMS)?;
        exts.push((EXT_QUIC_TRANSPORT_PARAMS, qtp.to_vec()));
        if let Some(sni) = original.extension(EXT_SERVER_NAME) {
            exts.push((EXT_SERVER_NAME, sni.to_vec()));
        }
        exts.push((
            EXT_SUPPORTED_GROUPS,
            u16_list(&[
                self.grease_group,
                X25519MLKEM768,
                X25519,
                SECP256R1,
                SECP384R1,
            ]),
        ));
        if let Some(alpn) = original.extension(EXT_ALPN) {
            exts.push((EXT_ALPN, alpn.to_vec()));
        }
        // Chrome's classic signature algorithms plus rsa_pkcs1_sha1 (uQUIC).
        let mut sigalgs = SIGNATURE_ALGORITHMS.to_vec();
        sigalgs.push(RSA_PKCS1_SHA1);
        exts.push((EXT_SIGNATURE_ALGORITHMS, u16_list(&sigalgs)));
        if let Some(shares) = original.extension(EXT_KEY_SHARE) {
            // Keep rustls's shares (the key exchange state); a one-byte GREASE
            // share goes first, as in Chrome's first hello.
            let body = shares.get(2..)?;
            let mut data = Vec::with_capacity(shares.len() + 5);
            if !retry {
                data.extend_from_slice(&self.grease_group.to_be_bytes());
                data.extend_from_slice(&1u16.to_be_bytes());
                data.push(0);
            }
            data.extend_from_slice(body);
            let mut ext = Vec::with_capacity(data.len() + 2);
            ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext.extend_from_slice(&data);
            exts.push((EXT_KEY_SHARE, ext));
        }
        exts.push((EXT_PSK_KEY_EXCHANGE_MODES, vec![0x01, 0x01]));
        exts.push((
            EXT_SUPPORTED_VERSIONS,
            vec![
                4,
                (self.grease_version >> 8) as u8,
                self.grease_version as u8,
                0x03,
                0x04,
            ],
        ));
        exts.push((EXT_COMPRESS_CERTIFICATE, vec![0x02, 0x00, 0x02]));
        exts.push((EXT_ALPS, vec![0x00, 0x03, 0x02, b'h', b'3']));
        // GREASE ECH, which Chrome 133+ sends over QUIC too (uQUIC
        // `QUICChrome_146` `BoringGREASEECH`). The same per-connection value as
        // the TCP shape; it is advertised only, never selected.
        exts.push((EXT_ECH, self.ech.clone()));
        if let Some(cookie) = original.extension(EXT_COOKIE) {
            exts.push((EXT_COOKIE, cookie.to_vec()));
        }
        exts.sort_by_key(|(typ, _)| self.ranks.get(typ).copied().unwrap_or(u32::MAX));
        exts.insert(0, (self.grease_ext1, Vec::new()));
        exts.push((self.grease_ext2, vec![0x00]));

        Some(ParsedHello {
            version: 0x0303,
            random: original.random,
            session_id: original.session_id.clone(),
            cipher_suites,
            compression: vec![0x00],
            extensions: exts,
        })
    }
}

impl ClientHelloRewriter for ChromeHello {
    fn rewrite(&self, raw_client_hello: &[u8], retry: bool) -> Option<Vec<u8>> {
        let original = ParsedHello::parse(raw_client_hello)?;
        // QUIC carries the transport-parameters extension; its presence marks
        // the handshake as QUIC and selects the QUIC shape.
        if original.extension(EXT_QUIC_TRANSPORT_PARAMS).is_some() {
            let shaped = self.shape_quic(&original, retry)?.encode();
            tracing::debug!("ClientHello shaped like Chrome (QUIC)");
            return Some(shaped);
        }
        let shaped = self.shape(&original, retry)?.encode();
        if let Some(ja4) = ja4(&shaped) {
            tracing::debug!("ClientHello shaped like Chrome (JA4 {ja4})");
        }
        Some(shaped)
    }
}

/// JA4 fingerprint of an encoded ClientHello over TCP, per the FoxIO spec:
/// `t13d1516h2_<ciphers>_<extensions+sigalgs>`.
pub fn ja4(raw: &[u8]) -> Option<String> {
    ja4_inner(raw, 't')
}

/// JA4 fingerprint of a ClientHello carried in a QUIC Initial: identical to
/// [`ja4`] but with the `q` transport prefix (FoxIO: first byte is `q` for
/// QUIC, `t` for TCP). JA4 sorts the cipher and extension lists, so the
/// per-connection GREASE and shuffle do not change it — a Chrome-QUIC shape
/// hashes to Chrome's QUIC JA4 regardless of the random order.
pub fn ja4_quic(raw: &[u8]) -> Option<String> {
    ja4_inner(raw, 'q')
}

fn ja4_inner(raw: &[u8], transport: char) -> Option<String> {
    use sha2::{Digest, Sha256};
    let hello = ParsedHello::parse(raw)?;
    let is_grease = |v: u16| v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff);
    let versions: Vec<u16> = hello
        .extension(EXT_SUPPORTED_VERSIONS)
        .map(|d| {
            be_u16s(d.get(1..).unwrap_or(&[]))
                .filter(|v| !is_grease(*v))
                .collect()
        })
        .unwrap_or_default();
    let version = match versions.iter().max().copied().unwrap_or(hello.version) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        _ => "10",
    };
    let sni = if hello.extension(EXT_SERVER_NAME).is_some() {
        "d"
    } else {
        "i"
    };
    let ciphers: Vec<u16> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let ext_types: Vec<u16> = hello
        .extensions
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease(*t))
        .collect();
    let alpn = hello
        .extension(EXT_ALPN)
        .and_then(|d| {
            let l = *d.get(2)? as usize;
            let first = d.get(3..3 + l)?;
            Some(format!(
                "{}{}",
                *first.first()? as char,
                *first.last()? as char
            ))
        })
        .unwrap_or_else(|| "00".to_string());
    let a = format!(
        "{transport}{version}{sni}{:02}{:02}{alpn}",
        ciphers.len().min(99),
        ext_types.len().min(99)
    );
    let mut sorted_ciphers = ciphers.clone();
    sorted_ciphers.sort_unstable();
    let b_input = sorted_ciphers
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut sorted_exts: Vec<u16> = ext_types
        .iter()
        .copied()
        .filter(|t| *t != EXT_SERVER_NAME && *t != EXT_ALPN)
        .collect();
    sorted_exts.sort_unstable();
    let sigalgs = hello
        .extension(EXT_SIGNATURE_ALGORITHMS)
        .map(|d| {
            be_u16s(d.get(2..).unwrap_or(&[]))
                .filter(|v| !is_grease(*v))
                .map(|v| format!("{v:04x}"))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    let c_input = format!(
        "{}_{}",
        sorted_exts
            .iter()
            .map(|t| format!("{t:04x}"))
            .collect::<Vec<_>>()
            .join(","),
        sigalgs
    );
    let hash12 = |s: &str| {
        let h = Sha256::digest(s.as_bytes());
        h.iter().map(|b| format!("{b:02x}")).collect::<String>()[..12].to_string()
    };
    Some(format!("{a}_{}_{}", hash12(&b_input), hash12(&c_input)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hello of the shape rustls sends for REALITY: SNI, groups, sigalgs,
    /// ALPN, key shares (hybrid + X25519), versions, PSK modes.
    fn rustls_like_hello() -> ParsedHello {
        let mut key_share = Vec::new();
        let mut entries = Vec::new();
        entries.extend_from_slice(&X25519MLKEM768.to_be_bytes());
        entries.extend_from_slice(&1216u16.to_be_bytes());
        entries.extend(std::iter::repeat_n(0xabu8, 1216));
        entries.extend_from_slice(&X25519.to_be_bytes());
        entries.extend_from_slice(&32u16.to_be_bytes());
        entries.extend(std::iter::repeat_n(0xcdu8, 32));
        key_share.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        key_share.extend_from_slice(&entries);
        let mut sni = vec![0, 0, 0, 0, 0];
        sni.extend_from_slice(b"intel.com");
        let l = (sni.len() - 2) as u16;
        sni[0..2].copy_from_slice(&l.to_be_bytes());
        sni[3..5].copy_from_slice(&(l - 3).to_be_bytes());
        ParsedHello {
            version: 0x0303,
            random: [7u8; 32],
            session_id: vec![9u8; 32],
            cipher_suites: vec![0x1301, 0x1302, 0x1303],
            compression: vec![0],
            extensions: vec![
                (EXT_SERVER_NAME, sni),
                (EXT_SUPPORTED_GROUPS, u16_list(&[X25519MLKEM768, X25519])),
                (EXT_SIGNATURE_ALGORITHMS, u16_list(&[0x0403, 0x0804])),
                (
                    EXT_ALPN,
                    vec![
                        0, 11, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
                    ],
                ),
                (EXT_KEY_SHARE, key_share),
                (EXT_SUPPORTED_VERSIONS, vec![2, 3, 4]),
                (EXT_PSK_KEY_EXCHANGE_MODES, vec![1, 1]),
            ],
        }
    }

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a && (v >> 8) == (v & 0xff)
    }

    #[test]
    fn hello_round_trips_through_the_parser() {
        let h = rustls_like_hello();
        assert_eq!(ParsedHello::parse(&h.encode()).unwrap(), h);
    }

    #[test]
    fn shaped_hello_matches_chrome_155() {
        let chrome = ChromeHello::from_seed(Profile::Chrome155, [3u8; 32]);
        let original = rustls_like_hello();
        let raw = chrome.rewrite(&original.encode(), false).unwrap();
        let h = ParsedHello::parse(&raw).unwrap();

        assert_eq!(h.random, original.random);
        assert_eq!(h.session_id, original.session_id);
        assert_eq!(h.cipher_suites.len(), 16);
        assert!(is_grease(h.cipher_suites[0]));
        assert_eq!(&h.cipher_suites[1..], &CIPHER_SUITES);

        let types: Vec<u16> = h.extensions.iter().map(|(t, _)| *t).collect();
        assert!(is_grease(types[0]) && is_grease(*types.last().unwrap()));
        assert_ne!(types[0], *types.last().unwrap());
        assert_eq!(h.extensions[0].1, Vec::<u8>::new());
        assert_eq!(h.extensions.last().unwrap().1, vec![0u8]);
        let non_grease: Vec<u16> = types.iter().copied().filter(|t| !is_grease(*t)).collect();
        assert_eq!(non_grease.len(), 17, "{non_grease:?}");
        for t in [
            EXT_TRUST_ANCHORS,
            EXT_SERVER_NAME,
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SUPPORTED_GROUPS,
            EXT_EC_POINT_FORMATS,
            EXT_SESSION_TICKET,
            EXT_ALPN,
            EXT_STATUS_REQUEST,
            EXT_SIGNATURE_ALGORITHMS,
            EXT_SCT,
            EXT_KEY_SHARE,
            EXT_PSK_KEY_EXCHANGE_MODES,
            EXT_SUPPORTED_VERSIONS,
            EXT_COMPRESS_CERTIFICATE,
            EXT_ALPS,
            EXT_ECH,
        ] {
            assert!(non_grease.contains(&t), "missing extension {t:#x}");
        }

        // key shares: GREASE(1 byte), then rustls's two shares untouched
        let ks = h.extension(EXT_KEY_SHARE).unwrap();
        assert!(is_grease(u16::from_be_bytes([ks[2], ks[3]])));
        assert_eq!(&ks[4..7], &[0, 1, 0]);
        assert_eq!(&ks[7..], &original.extension(EXT_KEY_SHARE).unwrap()[2..]);
        let groups = h.extension(EXT_SUPPORTED_GROUPS).unwrap();
        assert!(is_grease(u16::from_be_bytes([groups[2], groups[3]])));
        let versions = h.extension(EXT_SUPPORTED_VERSIONS).unwrap();
        assert!(is_grease(u16::from_be_bytes([versions[1], versions[2]])));
        assert_eq!(&versions[3..], &[3, 4, 3, 3]);
        let ech = h.extension(EXT_ECH).unwrap();
        assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]);
        assert_eq!(u16::from_be_bytes([ech[6], ech[7]]), 32);
        let payload_len = u16::from_be_bytes([ech[40], ech[41]]);
        assert!([144, 176, 208, 240].contains(&payload_len));
        assert_eq!(ech.len(), 42 + payload_len as usize);

        // signature algorithms: GREASE, ML-DSA-44/65/87, then the classic eight
        let sigalgs: Vec<u16> =
            be_u16s(&h.extension(EXT_SIGNATURE_ALGORITHMS).unwrap()[2..]).collect();
        assert_eq!(sigalgs.len(), 12);
        assert!(is_grease(sigalgs[0]));
        assert_eq!(&sigalgs[1..4], &MLDSA_SIGNATURE_ALGORITHMS);
        assert_eq!(&sigalgs[4..], &SIGNATURE_ALGORITHMS);

        // trust_anchors: 28 IDs, u16 list length, u8 per ID
        let tai = h.extension(EXT_TRUST_ANCHORS).unwrap();
        assert_eq!(tai.len(), 186);
        assert_eq!(u16::from_be_bytes([tai[0], tai[1]]), 184);
        assert_eq!(&tai[2..8], &[5, 0x82, 0xdf, 0x13, 0x02, 0x01]);

        // JA4 of a fresh Chrome 155 TCP hello, captured live from real
        // Chrome 155.0.0.0 on tls.peet.ws (its own capture was a resumption
        // hello with pre_shared_key, t13d1518h2_..._e2d80978ab2e; dropping
        // that extension — which our rewriter never adds — gives this).
        let ja4 = ja4(&raw).unwrap();
        assert_eq!(ja4, "t13d1517h2_8daaf6152771_cb7bf5808d99", "{ja4}");

        // the same connection keeps its order on a retry, minus the GREASE share
        let again = ParsedHello::parse(&chrome.rewrite(&original.encode(), true).unwrap()).unwrap();
        let again_types: Vec<u16> = again.extensions.iter().map(|(t, _)| *t).collect();
        assert_eq!(again_types, types);
        assert_eq!(
            &again.extension(EXT_KEY_SHARE).unwrap()[2..4],
            &X25519MLKEM768.to_be_bytes()
        );

        // different connections differ in order and GREASE
        let other = ChromeHello::from_seed(Profile::Chrome155, [4u8; 32]);
        let other_types: Vec<u16> =
            ParsedHello::parse(&other.rewrite(&original.encode(), false).unwrap())
                .unwrap()
                .extensions
                .iter()
                .map(|(t, _)| *t)
                .collect();
        assert_ne!(other_types, types);
    }

    #[test]
    fn chrome_133_profile_keeps_the_old_shape() {
        let chrome = ChromeHello::from_seed(Profile::Chrome133, [3u8; 32]);
        let raw = chrome
            .rewrite(&rustls_like_hello().encode(), false)
            .unwrap();
        let h = ParsedHello::parse(&raw).unwrap();
        let non_grease: Vec<u16> = h
            .extensions
            .iter()
            .map(|(t, _)| *t)
            .filter(|t| !is_grease(*t))
            .collect();
        assert_eq!(non_grease.len(), 16, "{non_grease:?}");
        assert!(h.extension(EXT_TRUST_ANCHORS).is_none());
        let sigalgs: Vec<u16> =
            be_u16s(&h.extension(EXT_SIGNATURE_ALGORITHMS).unwrap()[2..]).collect();
        assert_eq!(sigalgs, SIGNATURE_ALGORITHMS);
        // the JA4 Chrome 133 reports on tls.peet.ws
        assert_eq!(ja4(&raw).unwrap(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
    }

    #[test]
    fn resumption_hellos_are_left_alone() {
        let mut h = rustls_like_hello();
        h.extensions.push((EXT_PRE_SHARED_KEY, vec![0; 40]));
        assert!(ChromeHello::from_seed(Profile::Chrome155, [1u8; 32])
            .rewrite(&h.encode(), false)
            .is_none());
    }

    #[test]
    fn fingerprint_names() {
        assert_eq!(Fingerprint::parse(None), Fingerprint::Chrome);
        assert_eq!(Fingerprint::parse(Some("chrome")), Fingerprint::Chrome);
        assert_eq!(Fingerprint::parse(Some("firefox")), Fingerprint::Chrome);
        assert_eq!(
            Fingerprint::parse(Some("chrome133")),
            Fingerprint::Chrome133
        );
        assert_eq!(
            Fingerprint::parse(Some("Chrome-133")),
            Fingerprint::Chrome133
        );
        assert_eq!(Fingerprint::parse(Some("none")), Fingerprint::None);
        assert_eq!(Fingerprint::parse(Some("rustls")), Fingerprint::None);
    }

    /// A hello of the shape quinn/rustls sends for QUIC: empty session id, an
    /// ALPN of `h3`, and the quic_transport_parameters extension.
    fn rustls_like_quic_hello() -> ParsedHello {
        let mut h = rustls_like_hello();
        h.session_id = Vec::new();
        h.extensions
            .retain(|(t, _)| *t != EXT_ALPN && *t != EXT_SERVER_NAME);
        let mut sni = vec![0, 0, 0, 0, 0];
        sni.extend_from_slice(b"intel.com");
        let l = (sni.len() - 2) as u16;
        sni[0..2].copy_from_slice(&l.to_be_bytes());
        sni[3..5].copy_from_slice(&(l - 3).to_be_bytes());
        h.extensions.push((EXT_SERVER_NAME, sni));
        h.extensions.push((EXT_ALPN, vec![0, 3, 2, b'h', b'3']));
        // Opaque transport parameters, as quinn encodes them.
        h.extensions
            .push((EXT_QUIC_TRANSPORT_PARAMS, vec![0x01, 0x02, 0x03, 0x04]));
        h
    }

    #[test]
    fn shaped_quic_hello_matches_chrome() {
        let chrome = ChromeHello::from_seed(Profile::Chrome155, [5u8; 32]);
        let original = rustls_like_quic_hello();
        let raw = chrome.rewrite(&original.encode(), false).unwrap();
        let h = ParsedHello::parse(&raw).unwrap();

        // The three TLS 1.3 suites, no GREASE suite (unlike the TCP shape).
        assert_eq!(h.cipher_suites, vec![0x1301, 0x1302, 0x1303]);
        assert!(h.session_id.is_empty());

        // The transport parameters survive untouched: the handshake needs them.
        assert_eq!(
            h.extension(EXT_QUIC_TRANSPORT_PARAMS),
            Some([0x01, 0x02, 0x03, 0x04].as_slice())
        );
        // ALPS is h3, not h2.
        assert_eq!(
            h.extension(EXT_ALPS),
            Some([0, 3, 2, b'h', b'3'].as_slice())
        );

        let types: Vec<u16> = h.extensions.iter().map(|(t, _)| *t).collect();
        assert!(is_grease(types[0]) && is_grease(*types.last().unwrap()));
        // No TCP-only extensions leak into the QUIC hello.
        for t in [
            EXT_EXTENDED_MASTER_SECRET,
            EXT_RENEGOTIATION_INFO,
            EXT_SESSION_TICKET,
            EXT_STATUS_REQUEST,
            EXT_SCT,
            EXT_EC_POINT_FORMATS,
            EXT_TRUST_ANCHORS,
        ] {
            assert!(!types.contains(&t), "QUIC hello must not carry {t:#06x}");
        }
        // GREASE ECH is carried over QUIC, as Chrome 133+ does.
        assert!(
            types.contains(&EXT_ECH),
            "QUIC hello should carry GREASE ECH"
        );
        let non_grease: Vec<u16> = types.iter().copied().filter(|t| !is_grease(*t)).collect();
        assert_eq!(non_grease.len(), 11, "QUICChrome_146 set: {non_grease:?}");
        // rsa_pkcs1_sha1 is appended to the signature algorithms.
        let sigalgs: Vec<u16> =
            be_u16s(&h.extension(EXT_SIGNATURE_ALGORITHMS).unwrap()[2..]).collect();
        assert_eq!(sigalgs.last(), Some(&RSA_PKCS1_SHA1));
    }

    #[test]
    fn quic_ja4_is_stable_across_connections() {
        // JA4 sorts ciphers and extensions, so two connections — different
        // GREASE and extension order — must hash to the same QUIC JA4. This
        // is the value a probe sees; it must not vary per connection.
        let original = rustls_like_quic_hello();
        let a = ChromeHello::from_seed(Profile::Chrome155, [5u8; 32]);
        let b = ChromeHello::from_seed(Profile::Chrome155, [99u8; 32]);
        let ja4_a = ja4_quic(&a.rewrite(&original.encode(), false).unwrap()).unwrap();
        let ja4_b = ja4_quic(&b.rewrite(&original.encode(), false).unwrap()).unwrap();
        assert_eq!(ja4_a, ja4_b, "QUIC JA4 varies per connection");

        // The `q` transport prefix, TLS 1.3, SNI present, 3 cipher suites, and
        // an h3 ALPN. The extension count is the Chrome-QUIC set we emit.
        assert!(
            ja4_a.starts_with("q13d0311h3"),
            "unexpected QUIC JA4 header: {ja4_a}"
        );
        assert!(ja4_a.contains("h3_"), "ALPN not h3 in QUIC JA4: {ja4_a}");
        // Pin the whole string so a change to the shaped set is caught here and
        // can be compared against a real Chrome-QUIC capture.
        assert_eq!(ja4_a, QUIC_JA4, "QUIC JA4 changed: {ja4_a}");
    }

    /// The QUIC JA4 of our Chrome-QUIC shape: `q` (QUIC) + TLS 1.3 + SNI +
    /// three TLS 1.3 suites + eleven extensions + h3 ALPN, matching the uQUIC
    /// `QUICChrome_146` set (eleven extensions incl. GREASE ECH, nine
    /// signature algorithms). The cipher component `55b375c5d22e` is the
    /// canonical hash of the three TLS 1.3 suites real Chrome-QUIC emits.
    /// (The latest Chrome in FoxIO's DB shows `q13d0312h3` — one extension
    /// more; identifying the twelfth needs a live h3 capture, which the VPN on
    /// the dev machine blocks.) The wire test
    /// `quic_clienthello_on_the_wire_is_chrome` asserts a real quinn handshake
    /// produces exactly this.
    const QUIC_JA4: &str = "q13d0311h3_55b375c5d22e_653d80c3fe9d";
}
