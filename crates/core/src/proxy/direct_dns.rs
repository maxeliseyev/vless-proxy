//! Real DNS resolution for `direct` dials in TUN mode.
//!
//! In TUN mode vproxy points the system resolver at the netstack's FakeDNS, so
//! the OS `lookup_host` only ever returns fake pool addresses (`198.18.x.x`).
//! That is what the tunnelled apps want — they connect to the fake IP, the
//! netstack maps it back to the name and routes it. But a `direct` connection
//! that vproxy opens itself needs the target's *real* IP: connecting to a fake
//! address egresses nowhere (`ENETUNREACH`).
//!
//! So for `direct` domains we resolve ourselves, querying an upstream DNS
//! server over a UDP socket pinned to the physical interface (the same
//! [`Egress`] the direct connection uses). That bypasses both the tunnel and
//! FakeDNS and yields routable addresses. Only the desktop TUN runner builds
//! one; elsewhere (local proxy mode, iOS) the OS resolver is untouched and the
//! normal `lookup_host` path is used instead.

use crate::proxy::dns_cache::DnsCache;
use crate::proxy::egress::Egress;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Resolves `direct` targets against an upstream DNS server, off the tunnel.
#[derive(Clone)]
pub struct DirectResolver {
    upstream: SocketAddr,
    egress: Option<Egress>,
    cache: DnsCache,
    timeout: Duration,
}

impl DirectResolver {
    /// Query `upstream` (e.g. `8.8.8.8:53`), pinning query sockets to `egress`
    /// when set so they leave the physical interface, not the tunnel.
    pub fn new(upstream: SocketAddr, egress: Option<Egress>, cache: DnsCache) -> Self {
        Self {
            upstream,
            egress,
            cache,
            timeout: Duration::from_secs(5),
        }
    }

    /// Real addresses for `host:port`, A and AAAA, IPv4 first. Cached by TTL.
    pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        if let Some(cached) = self.cache.get(host).await {
            if !cached.is_empty() {
                return Ok(cached
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect());
            }
        }

        // A and AAAA in parallel; a site may have only one of them.
        let (v4, v6) = tokio::join!(self.query(host, TYPE_A), self.query(host, TYPE_AAAA));
        let mut ips: Vec<IpAddr> = Vec::new();
        let mut ttl = self.cache.config().default_ttl_secs;
        for (answers, answer_ttl) in [v4, v6].into_iter().flatten() {
            if !answers.is_empty() {
                ttl = ttl.min(answer_ttl.max(1));
            }
            ips.extend(answers);
        }
        if ips.is_empty() {
            bail!("no DNS answer for {host} from {}", self.upstream);
        }
        self.cache
            .insert(host, ips.clone(), Duration::from_secs(ttl))
            .await;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// One query/response round trip; returns the addresses and the smallest
    /// answer TTL.
    async fn query(&self, host: &str, qtype: u16) -> Result<(Vec<IpAddr>, u64)> {
        let bind: SocketAddr = if self.upstream.is_ipv4() {
            ([0u8, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let socket = UdpSocket::bind(bind)
            .await
            .context("bind DNS query socket")?;
        if let Some(egress) = &self.egress {
            egress
                .bind_fd(socket.as_raw_fd(), self.upstream)
                .context("pin DNS query socket to egress")?;
        }
        socket.connect(self.upstream).await?;
        let id: u16 = rand::random();
        socket.send(&build_query(id, host, qtype)?).await?;
        let mut buf = [0u8; 1500];
        let n = timeout(self.timeout, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS query to {} timed out", self.upstream))??;
        parse_answers(&buf[..n], id, qtype)
    }
}

/// A standard recursion-desired query for one name.
fn build_query(id: u16, host: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut q = Vec::with_capacity(17 + host.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in {host}");
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(q)
}

/// Pull A/AAAA addresses and the minimum TTL out of a response.
fn parse_answers(msg: &[u8], id: u16, qtype: u16) -> Result<(Vec<IpAddr>, u64)> {
    if msg.len() < 12 {
        bail!("short DNS response");
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != id {
        bail!("DNS response id mismatch");
    }
    let rcode = msg[3] & 0x0f;
    if rcode != 0 {
        bail!("DNS rcode {rcode}");
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos).context("skip question name")?;
        pos = pos.checked_add(4).context("truncated question")?; // qtype + qclass
    }

    let mut ips = Vec::new();
    let mut min_ttl = u64::MAX;
    for _ in 0..ancount {
        pos = skip_name(msg, pos).context("skip answer name")?;
        let rtype = u16::from_be_bytes([
            *msg.get(pos).context("rr")?,
            *msg.get(pos + 1).context("rr")?,
        ]);
        let ttl = u32::from_be_bytes([
            *msg.get(pos + 4).context("rr")?,
            *msg.get(pos + 5).context("rr")?,
            *msg.get(pos + 6).context("rr")?,
            *msg.get(pos + 7).context("rr")?,
        ]);
        let rdlen = u16::from_be_bytes([
            *msg.get(pos + 8).context("rr")?,
            *msg.get(pos + 9).context("rr")?,
        ]) as usize;
        let rdata = pos + 10;
        let end = rdata.checked_add(rdlen).context("rdata overflow")?;
        if end > msg.len() {
            bail!("truncated rdata");
        }
        if rtype == qtype && rtype == TYPE_A && rdlen == 4 {
            ips.push(IpAddr::from([
                msg[rdata],
                msg[rdata + 1],
                msg[rdata + 2],
                msg[rdata + 3],
            ]));
            min_ttl = min_ttl.min(ttl as u64);
        } else if rtype == qtype && rtype == TYPE_AAAA && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&msg[rdata..end]);
            ips.push(IpAddr::from(octets));
            min_ttl = min_ttl.min(ttl as u64);
        }
        pos = end;
    }
    Ok((ips, if min_ttl == u64::MAX { 0 } else { min_ttl }))
}

/// Advance past a (possibly compressed) name, returning the offset after it.
/// A pointer ends the name in the wire stream, so we stop at the first one.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize> {
    loop {
        let len = *msg.get(pos).context("name byte")?;
        if len & 0xc0 == 0xc0 {
            return Ok(pos + 2); // compression pointer: two bytes, name ends here
        }
        if len == 0 {
            return Ok(pos + 1);
        }
        pos = pos.checked_add(1 + len as usize).context("name overflow")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn cache() -> DnsCache {
        DnsCache::new(crate::proxy::dns_cache::DnsCacheConfig::default())
    }

    #[test]
    fn query_round_trips_a_name() {
        let q = build_query(0xABCD, "example.com.", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0xAB, 0xCD]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // qdcount
                                                         // 7 "example" 3 "com" 0  + qtype + qclass
        assert_eq!(&q[12..20], b"\x07example");
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]);
    }

    /// Build a minimal response: one question echoed, then `ips` as A answers.
    fn response(id: u16, ips: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut m = build_query(id, "host.test", TYPE_A).unwrap();
        m[2] = 0x81; // QR + RD
        m[3] = 0x80; // RA, rcode 0
        m[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes()); // ancount
        for ip in ips {
            m.extend_from_slice(&[0xc0, 0x0c]); // name pointer to question
            m.extend_from_slice(&TYPE_A.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(&ip.octets());
        }
        m
    }

    #[test]
    fn parses_a_answers_and_ttl() {
        let ips = [Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(1, 2, 3, 4)];
        let msg = response(0x1111, &ips, 120);
        let (got, ttl) = parse_answers(&msg, 0x1111, TYPE_A).unwrap();
        assert_eq!(got, vec![IpAddr::from(ips[0]), IpAddr::from(ips[1])]);
        assert_eq!(ttl, 120);
    }

    #[test]
    fn rejects_id_mismatch_and_rcode() {
        let msg = response(0x1111, &[Ipv4Addr::LOCALHOST], 60);
        assert!(parse_answers(&msg, 0x2222, TYPE_A).is_err());
        let mut nx = response(0x3333, &[], 0);
        nx[3] = 0x83; // NXDOMAIN
        assert!(parse_answers(&nx, 0x3333, TYPE_A).is_err());
    }

    #[tokio::test]
    async fn resolve_returns_ip_literals_without_a_query() {
        let resolver = DirectResolver::new("8.8.8.8:53".parse().unwrap(), None, cache());
        let out = resolver.resolve("1.1.1.1", 443).await.unwrap();
        assert_eq!(out, vec!["1.1.1.1:443".parse().unwrap()]);
    }
}
