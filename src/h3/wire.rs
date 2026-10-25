//! What the h3 client and server say to each other inside QUIC: the auth
//! token, the target header of a stream and the status byte that answers
//! it. None of it is visible on the wire; QUIC encrypts it all.

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
