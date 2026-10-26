//! Fake DNS for the in-process TUN: every `A` query gets a fresh address
//! from a private pool, and the netstack maps it back to the name when a
//! connection to it arrives. The server then sees the domain, as with a
//! SOCKS client, and routing rules match on it.
//!
//! Other query types get an empty answer (NODATA), so clients fall back to
//! `A`: no fake IPv6, and `HTTPS`/`SVCB` records are not forwarded.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// `198.18.0.0/15`, reserved for benchmarking (RFC 2544): never a real target.
pub const DEFAULT_POOL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 0);
/// Pool offsets below this are kept for the tunnel itself (gateway, DNS).
const FIRST_OFFSET: u32 = 3;
/// TTL of fake answers. Short, so a reused address is not cached for long.
const ANSWER_TTL: u32 = 60;

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
const RCODE_FORMERR: u8 = 1;
const RCODE_NOTIMP: u8 = 4;

pub struct FakeDns {
    pool: u32,
    capacity: u32,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next: u32,
    by_ip: HashMap<u32, String>,
    by_domain: HashMap<String, u32>,
}

impl FakeDns {
    /// A pool of `capacity` addresses starting a few above `pool`. When it
    /// runs out the oldest name loses its address.
    pub fn new(pool: Ipv4Addr, capacity: u32) -> Self {
        Self {
            pool: u32::from(pool),
            capacity: capacity.clamp(16, (1 << 17) - FIRST_OFFSET),
            inner: Mutex::default(),
        }
    }

    /// The address the tunnel announces as its DNS server.
    pub fn server_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.pool + 2)
    }

    /// Fake address for `domain`, allocated on first use.
    pub fn address_for(&self, domain: &str) -> Ipv4Addr {
        let domain = normalize(domain);
        let mut inner = self.inner.lock().expect("fake dns lock poisoned");
        if let Some(ip) = inner.by_domain.get(&domain) {
            return Ipv4Addr::from(*ip);
        }
        let ip = self.pool + FIRST_OFFSET + inner.next;
        inner.next = (inner.next + 1) % self.capacity;
        if let Some(old) = inner.by_ip.insert(ip, domain.clone()) {
            inner.by_domain.remove(&old);
        }
        inner.by_domain.insert(domain, ip);
        Ipv4Addr::from(ip)
    }

    /// The name behind a fake address, if `ip` is one we handed out.
    pub fn domain_for(&self, ip: Ipv4Addr) -> Option<String> {
        let inner = self.inner.lock().expect("fake dns lock poisoned");
        inner.by_ip.get(&u32::from(ip)).cloned()
    }

    /// Whether `ip` lies in the pool, handed out or not.
    pub fn is_fake(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        ip >= self.pool && ip < self.pool + FIRST_OFFSET + self.capacity
    }

    /// Answer one DNS query message. `None` when it is too broken to answer.
    pub fn answer(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 12 || query[2] & 0x80 != 0 {
            return None; // too short, or a response
        }
        let opcode = (query[2] >> 3) & 0x0f;
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if opcode != 0 || qdcount != 1 {
            return Some(error_reply(query, RCODE_NOTIMP));
        }
        let Some((name, end)) = read_name(query, 12) else {
            return Some(error_reply(query, RCODE_FORMERR));
        };
        if query.len() < end + 4 {
            return Some(error_reply(query, RCODE_FORMERR));
        }
        let qtype = u16::from_be_bytes([query[end], query[end + 1]]);
        let qclass = u16::from_be_bytes([query[end + 2], query[end + 3]]);
        let question = &query[12..end + 4];

        let mut reply = Vec::with_capacity(12 + question.len() + 16);
        reply.extend_from_slice(&query[..2]); // id
        reply.push(0x80 | (query[2] & 0x01)); // QR, opcode 0, RD copied
        reply.push(0x80); // RA, rcode 0
        reply.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        let answer = qtype == TYPE_A && qclass == CLASS_IN && !name.is_empty();
        reply.extend_from_slice(&u16::from(answer).to_be_bytes()); // ancount
        reply.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
        reply.extend_from_slice(question);
        if answer {
            let ip = self.address_for(&name);
            reply.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to the question
            reply.extend_from_slice(&TYPE_A.to_be_bytes());
            reply.extend_from_slice(&CLASS_IN.to_be_bytes());
            reply.extend_from_slice(&ANSWER_TTL.to_be_bytes());
            reply.extend_from_slice(&4u16.to_be_bytes());
            reply.extend_from_slice(&ip.octets());
        }
        Some(reply)
    }
}

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Uncompressed name at `start` (queries carry no pointers). Returns the
/// dotted name and the offset just past it.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    let name = labels.join(".");
    (name.len() <= 253).then_some((name, pos))
}

fn error_reply(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut reply = query[..12].to_vec();
    reply[2] = 0x80 | (query[2] & 0x79); // QR, opcode and RD kept
    reply[3] = 0x80 | rcode;
    reply[4..12].fill(0);
    reply
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn a_query_gets_a_stable_fake_address() {
        let dns = FakeDns::new(DEFAULT_POOL, 1024);
        let reply = dns.answer(&query("Example.COM", TYPE_A)).unwrap();
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        assert_eq!(reply[2] & 0x80, 0x80);
        assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 1);
        let ip = Ipv4Addr::new(
            reply[reply.len() - 4],
            reply[reply.len() - 3],
            reply[reply.len() - 2],
            reply[reply.len() - 1],
        );
        assert_eq!(ip, Ipv4Addr::new(198, 18, 0, 3));
        assert!(dns.is_fake(ip));
        assert_eq!(dns.domain_for(ip).as_deref(), Some("example.com"));
        assert_eq!(dns.address_for("example.com."), ip);
    }

    #[test]
    fn aaaa_and_https_get_nodata() {
        let dns = FakeDns::new(DEFAULT_POOL, 1024);
        for qtype in [28, 65] {
            let reply = dns.answer(&query("example.com", qtype)).unwrap();
            assert_eq!(reply[3] & 0x0f, 0, "rcode");
            assert_eq!(u16::from_be_bytes([reply[6], reply[7]]), 0, "ancount");
        }
        assert!(dns.domain_for(Ipv4Addr::new(198, 18, 0, 3)).is_none());
    }

    #[test]
    fn full_pool_reuses_the_oldest_address() {
        let dns = FakeDns::new(DEFAULT_POOL, 16);
        let first = dns.address_for("a0.test");
        for i in 1..16 {
            dns.address_for(&format!("a{i}.test"));
        }
        assert_eq!(dns.address_for("late.test"), first);
        assert_eq!(dns.domain_for(first).as_deref(), Some("late.test"));
        assert!(dns.address_for("a1.test") != first);
    }

    #[test]
    fn broken_queries_are_refused_not_answered() {
        let dns = FakeDns::new(DEFAULT_POOL, 1024);
        assert!(dns.answer(&[0; 5]).is_none());
        let mut truncated = query("example.com", TYPE_A);
        truncated.truncate(truncated.len() - 3);
        assert_eq!(dns.answer(&truncated).unwrap()[3] & 0x0f, RCODE_FORMERR);
        let mut two = query("example.com", TYPE_A);
        two[5] = 2;
        assert_eq!(dns.answer(&two).unwrap()[3] & 0x0f, RCODE_NOTIMP);
    }
}
