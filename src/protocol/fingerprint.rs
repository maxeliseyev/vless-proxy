//! TLS ClientHello shaped like Chrome's, so the handshake does not stand out
//! from browser traffic (JA3/JA4 and friends). This is the client side of
//! what Xray does with uTLS `fp=chrome`; the profile is uTLS
//! `HelloChrome_133`, the one Xray 26.x sends.
//!
//! rustls builds its own hello; our fork hands the encoded bytes to a
//! [`ClientHelloRewriter`] and sends what it returns. The rewriter keeps the
//! fields that carry cryptographic state (random, session id, key shares,
//! ALPN, SNI) and replaces the rest: Chrome's cipher suite list, its set of
//! extensions in a per-connection random order (Chrome shuffles them since
//! version 110), GREASE values in the five places BoringSSL puts them, a
//! GREASE ECH extension, ALPS, SCT and session ticket requests. Extensions
//! rustls does not implement are advertised only; servers do not select them.

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
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

const X25519MLKEM768: u16 = 0x11ec;
const X25519: u16 = 0x001d;
const SECP256R1: u16 = 0x0017;
const SECP384R1: u16 = 0x0018;

/// Chrome's cipher suites (GREASE first).
const CIPHER_SUITES: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

/// Chrome's signature algorithms.
const SIGNATURE_ALGORITHMS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Which browser to look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fingerprint {
    Chrome,
    /// Send what rustls builds.
    None,
}

impl Fingerprint {
    /// `fp=` / `server.fingerprint` value. Anything Xray would hand to uTLS
    /// (chrome, firefox, safari, ios, android, edge, 360, qq, random,
    /// randomized) becomes Chrome: that is the only profile implemented, and
    /// the one almost every link asks for. `none`, `rustls`, `raw` and `go`
    /// disable shaping.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("none") | Some("rustls") | Some("raw") | Some("go") | Some("golang") => {
                Fingerprint::None
            }
            _ => Fingerprint::Chrome,
        }
    }

    /// A fresh rewriter for one connection (its random choices are made
    /// once, so a HelloRetryRequest hello keeps the same shape).
    pub fn rewriter(self) -> Option<Arc<dyn ClientHelloRewriter>> {
        match self {
            Fingerprint::Chrome => Some(Arc::new(ChromeHello::new())),
            Fingerprint::None => None,
        }
    }
}

/// Per-connection random choices of a Chrome hello.
#[derive(Debug)]
pub struct ChromeHello {
    grease_cipher: u16,
    grease_group: u16,
    grease_ext1: u16,
    grease_ext2: u16,
    grease_version: u16,
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
        Self::new()
    }
}

impl ChromeHello {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Deterministic variant (tests).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut rng = StdRng::from_seed(seed);
        let grease_cipher = grease(rng.gen());
        let grease_group = grease(rng.gen());
        let grease_ext1 = grease(rng.gen());
        let mut grease_ext2 = grease(rng.gen());
        if grease_ext2 == grease_ext1 {
            grease_ext2 ^= 0x1010;
        }
        let grease_version = grease(rng.gen());
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
            EXT_ECH,
            EXT_RENEGOTIATION_INFO,
        ] {
            ranks.insert(ext, rng.gen());
        }
        let ech = grease_ech(&mut rng);
        Self {
            grease_cipher,
            grease_group,
            grease_ext1,
            grease_ext2,
            grease_version,
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
        exts.push((EXT_SIGNATURE_ALGORITHMS, u16_list(&SIGNATURE_ALGORITHMS)));
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
        let shaped = self.shape(&original, retry)?.encode();
        if let Some(ja4) = ja4(&shaped) {
            tracing::debug!("ClientHello shaped like Chrome (JA4 {ja4})");
        }
        Some(shaped)
    }
}

/// JA4 fingerprint of an encoded ClientHello (TCP, no QUIC), per the FoxIO
/// spec: `t13d1516h2_<ciphers>_<extensions+sigalgs>`.
pub fn ja4(raw: &[u8]) -> Option<String> {
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
        "t{version}{sni}{:02}{:02}{alpn}",
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
    fn shaped_hello_matches_chrome_133() {
        let chrome = ChromeHello::from_seed([3u8; 32]);
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
        assert_eq!(non_grease.len(), 16, "{non_grease:?}");
        for t in [
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

        // JA4 of Chrome (t13d1516h2 + Chrome's cipher hash)
        let ja4 = ja4(&raw).unwrap();
        assert!(ja4.starts_with("t13d1516h2_8daaf6152771_"), "{ja4}");

        // the same connection keeps its order on a retry, minus the GREASE share
        let again = ParsedHello::parse(&chrome.rewrite(&original.encode(), true).unwrap()).unwrap();
        let again_types: Vec<u16> = again.extensions.iter().map(|(t, _)| *t).collect();
        assert_eq!(again_types, types);
        assert_eq!(
            &again.extension(EXT_KEY_SHARE).unwrap()[2..4],
            &X25519MLKEM768.to_be_bytes()
        );

        // different connections differ in order and GREASE
        let other = ChromeHello::from_seed([4u8; 32]);
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
    fn resumption_hellos_are_left_alone() {
        let mut h = rustls_like_hello();
        h.extensions.push((EXT_PRE_SHARED_KEY, vec![0; 40]));
        assert!(ChromeHello::from_seed([1u8; 32])
            .rewrite(&h.encode(), false)
            .is_none());
    }

    #[test]
    fn fingerprint_names() {
        assert_eq!(Fingerprint::parse(None), Fingerprint::Chrome);
        assert_eq!(Fingerprint::parse(Some("chrome")), Fingerprint::Chrome);
        assert_eq!(Fingerprint::parse(Some("firefox")), Fingerprint::Chrome);
        assert_eq!(Fingerprint::parse(Some("none")), Fingerprint::None);
        assert_eq!(Fingerprint::parse(Some("rustls")), Fingerprint::None);
    }
}
