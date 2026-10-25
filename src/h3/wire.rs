//! What the h3 client and server say to each other inside QUIC: the auth
//! token, the target header of a stream and the status byte that answers
//! it, and the UDP datagram framing. None of it is visible on the wire;
//! QUIC encrypts it all.
//!
//! UDP rides QUIC DATAGRAM frames (RFC 9221), one per UDP packet. Client to
//! server: `[session varint][target header][payload]`; every datagram names
//! its target, so a lost first one costs nothing. Server to client:
//! `[session varint][payload]`. A session is one client flow to one target;
//! its id is the client's choice, unique per connection.

use crate::protocol::vless::Address;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

/// What the TLS handshake negotiates, as for any HTTP/3 site.
pub const ALPN: &[u8] = b"h3";

/// TLS exporter label the auth token is derived from (RFC 5705 / 8446 7.5).
pub const AUTH_LABEL: &[u8] = b"vproxy h3 auth";

/// Bytes the client writes on its first stream, and nothing else.
pub const TOKEN_LEN: usize = 32;

/// Target address types, the same numbers as VLESS uses.
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// QUIC application error code for closing a connection: `H3_NO_ERROR`,
/// what an HTTP/3 server sends when it is simply done.
pub const H3_NO_ERROR: u32 = 0x100;

/// The server's answer to a target header, one byte before any data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Connected = 0,
    /// The server's policy refuses the target (private addresses).
    Refused = 1,
    /// The name did not resolve, or the connection was refused or reset.
    Unreachable = 2,
    /// The target did not answer in time.
    Timeout = 3,
    /// The header could not be read.
    BadRequest = 4,
}

impl Status {
    pub fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Connected,
            1 => Self::Refused,
            2 => Self::Unreachable,
            3 => Self::Timeout,
            4 => Self::BadRequest,
            _ => return None,
        })
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Refused => "refused by the server's policy",
            Self::Unreachable => "unreachable from the server",
            Self::Timeout => "timed out from the server",
            Self::BadRequest => "bad request",
        }
    }
}

/// `HMAC-SHA256(key = SHA-256(uuid), msg = exporter)`, where `exporter` is
/// [`TOKEN_LEN`] bytes of TLS keying material under [`AUTH_LABEL`]. Bound to
/// the TLS session, so a recorded token is useless on another connection.
pub type AuthToken = [u8; TOKEN_LEN];

pub fn auth_token(uuid: &Uuid, exporter: &[u8; TOKEN_LEN]) -> AuthToken {
    mac(uuid, exporter).finalize().into_bytes().into()
}

/// Whether `token` is `uuid`'s token for this session; constant time.
pub fn token_matches(uuid: &Uuid, exporter: &[u8; TOKEN_LEN], token: &[u8]) -> bool {
    mac(uuid, exporter).verify_slice(token).is_ok()
}

fn mac(uuid: &Uuid, exporter: &[u8; TOKEN_LEN]) -> Hmac<Sha256> {
    let key = Sha256::digest(uuid.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
    mac.update(exporter);
    mac
}

/// `[type][address][port, big endian]` at the start of a TCP stream.
pub fn encode_target(address: &Address, port: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    match address {
        Address::Ipv4(ip) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            if name.is_empty() || name.len() > 255 {
                bail!("domain name must be 1 to 255 bytes: {name:?}");
            }
            out.push(ATYP_DOMAIN);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Address::Ipv6(ip) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// QUIC variable-length integer (RFC 9000 16): 1, 2, 4 or 8 bytes, the top
/// two bits of the first byte giving the length.
pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(
            &((value & 0x3fff_ffff_ffff_ffff) | 0xc000_0000_0000_0000).to_be_bytes(),
        ),
    }
}

/// Read a varint off the front of `buf`: the value and the rest.
pub fn take_varint(buf: &[u8]) -> Result<(u64, &[u8])> {
    let first = *buf.first().ok_or_else(|| anyhow::anyhow!("empty varint"))?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        bail!("short varint");
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok((value, &buf[len..]))
}

/// The front of a client datagram for `session` to `address:port`; the
/// payload follows it.
pub fn datagram_prefix(session: u64, address: &Address, port: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    put_varint(&mut out, session);
    out.extend_from_slice(&encode_target(address, port)?);
    Ok(out)
}

/// A client datagram: session, target, payload.
pub fn parse_client_datagram(buf: &[u8]) -> Result<(u64, Address, u16, &[u8])> {
    let (session, rest) = take_varint(buf)?;
    let need = |n: usize, rest: &[u8]| {
        if rest.len() < n {
            bail!("short datagram");
        }
        Ok(())
    };
    need(1, rest)?;
    let (address, rest) = match rest[0] {
        ATYP_IPV4 => {
            need(5, rest)?;
            let octets: [u8; 4] = rest[1..5].try_into().expect("4 bytes");
            (Address::Ipv4(Ipv4Addr::from(octets)), &rest[5..])
        }
        ATYP_DOMAIN => {
            need(2, rest)?;
            let len = rest[1] as usize;
            need(2 + len, rest)?;
            if len == 0 {
                bail!("empty domain name");
            }
            let name = std::str::from_utf8(&rest[2..2 + len])?.to_string();
            (Address::Domain(name), &rest[2 + len..])
        }
        ATYP_IPV6 => {
            need(17, rest)?;
            let octets: [u8; 16] = rest[1..17].try_into().expect("16 bytes");
            (Address::Ipv6(Ipv6Addr::from(octets)), &rest[17..])
        }
        other => bail!("unknown address type {other}"),
    };
    need(2, rest)?;
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Ok((session, address, port, &rest[2..]))
}

/// Read what [`encode_target`] wrote.
pub async fn read_target<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Address, u16)> {
    let address = match reader.read_u8().await? {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader.read_exact(&mut octets).await?;
            Address::Ipv4(Ipv4Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let len = reader.read_u8().await? as usize;
            if len == 0 {
                bail!("empty domain name");
            }
            let mut name = vec![0u8; len];
            reader.read_exact(&mut name).await?;
            Address::Domain(String::from_utf8(name)?)
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader.read_exact(&mut octets).await?;
            Address::Ipv6(Ipv6Addr::from(octets))
        }
        other => bail!("unknown address type {other}"),
    };
    Ok((address, reader.read_u16().await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn targets_round_trip() {
        for (address, port) in [
            (Address::Ipv4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            (Address::Domain("example.com".into()), 80),
            (Address::Ipv6("2001:db8::1".parse().unwrap()), 8443),
        ] {
            let bytes = encode_target(&address, port).unwrap();
            let (read, read_port) = read_target(&mut bytes.as_slice()).await.unwrap();
            assert_eq!((read.to_string(), read_port), (address.to_string(), port));
        }
        assert!(encode_target(&Address::Domain(String::new()), 1).is_err());
        assert!(read_target(&mut [9u8, 0, 0].as_slice()).await.is_err());
    }

    #[test]
    fn varints_and_datagrams_round_trip() {
        for value in [0, 63, 64, 16_383, 16_384, 1 << 30, (1 << 62) - 1] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            out.push(0xaa);
            let (read, rest) = take_varint(&out).unwrap();
            assert_eq!((read, rest), (value, &[0xaa][..]), "{value}");
        }
        assert!(take_varint(&[0x80, 0]).is_err());

        let mut datagram = datagram_prefix(70, &Address::Domain("dns.example".into()), 53).unwrap();
        datagram.extend_from_slice(b"query");
        let (session, address, port, payload) = parse_client_datagram(&datagram).unwrap();
        assert_eq!(
            (session, address.to_string(), port, payload),
            (70, "dns.example".into(), 53, &b"query"[..])
        );
        assert!(parse_client_datagram(&datagram[..4]).is_err());
    }

    #[test]
    fn token_is_per_account_and_per_session() {
        let alice = Uuid::from_u128(1);
        let bob = Uuid::from_u128(2);
        let session = [7u8; TOKEN_LEN];
        let token = auth_token(&alice, &session);
        assert!(token_matches(&alice, &session, &token));
        assert!(!token_matches(&bob, &session, &token));
        assert!(!token_matches(&alice, &[8u8; TOKEN_LEN], &token));
        assert!(!token_matches(&alice, &session, &token[..31]));
    }
}
