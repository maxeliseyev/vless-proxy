//! Per-connection routing: decide whether a target goes through the VLESS
//! server (`proxy`), straight from this machine (`direct`) or is refused
//! (`block`).
//!
//! Rule semantics follow sing-box so the same `[routing]` section can be
//! translated 1:1 for TUN mode (see `tun.rs`): inside one rule every listed
//! field must match (AND), inside a list any entry may match (OR), the first
//! matching rule wins, `final` applies otherwise. `geoip` / `geosite` are
//! only evaluated by sing-box in TUN mode; here such rules never match.

use crate::config::{RoutingConfig, RoutingRule};
use crate::protocol::vless::Address;
use anyhow::{bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    Proxy,
    Direct,
    Block,
}

impl Outbound {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "proxy" => Ok(Self::Proxy),
            "direct" => Ok(Self::Direct),
            "block" | "reject" => Ok(Self::Block),
            other => {
                bail!("routing outbound must be \"proxy\", \"direct\" or \"block\", got {other:?}")
            }
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Direct => "direct",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, prefix)) => (
                ip.parse::<IpAddr>()
                    .with_context(|| format!("bad CIDR {s:?}"))?,
                prefix
                    .parse::<u8>()
                    .with_context(|| format!("bad CIDR prefix in {s:?}"))?,
            ),
            None => {
                let ip = s
                    .parse::<IpAddr>()
                    .with_context(|| format!("bad IP/CIDR {s:?}"))?;
                (ip, if ip.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            bail!("CIDR prefix /{prefix} too long for {ip}");
        }
        Ok(Self {
            network: ip,
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix as u32)
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix as u32)
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V4(ip)) => {
                // ::ffff:a.b.c.d
                let mapped = ip.to_ipv6_mapped();
                Self {
                    network: IpAddr::V6(net),
                    prefix: self.prefix,
                }
                .contains(IpAddr::V6(mapped))
            }
            (IpAddr::V4(_), IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
        }
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_private_v4(v4),
            None => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
            }
        },
    }
}

fn is_private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
}

#[derive(Debug, Clone)]
struct CompiledRule {
    outbound: Outbound,
    domain: Vec<String>,
    domain_suffix: Vec<String>,
    domain_keyword: Vec<String>,
    ip_cidr: Vec<Cidr>,
    ip_private: bool,
    port: Vec<u16>,
    /// geoip/geosite are TUN-only; a rule that has them can never match here.
    geo_only: bool,
}

#[derive(Debug, Clone)]
pub struct Router {
    rules: Vec<CompiledRule>,
    final_outbound: Outbound,
    has_geo_rules: bool,
}

impl Router {
    pub fn new(config: &RoutingConfig) -> Result<Self> {
        let final_outbound = if config.final_outbound.trim().is_empty() {
            Outbound::Proxy
        } else {
            Outbound::parse(&config.final_outbound)?
        };
        if final_outbound == Outbound::Block {
            bail!("routing.final cannot be \"block\"");
        }
        let mut rules = Vec::with_capacity(config.rules.len());
        let mut has_geo_rules = false;
        for (i, rule) in config.rules.iter().enumerate() {
            let compiled = compile_rule(rule).with_context(|| format!("routing.rules[{i}]"))?;
            has_geo_rules |= !rule.geoip.is_empty() || !rule.geosite.is_empty();
            rules.push(compiled);
        }
        Ok(Self {
            rules,
            final_outbound,
            has_geo_rules,
        })
    }

    pub fn has_geo_rules(&self) -> bool {
        self.has_geo_rules
    }

    pub fn final_outbound(&self) -> Outbound {
        self.final_outbound
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.final_outbound == Outbound::Proxy
    }

    pub fn decide(&self, address: &Address, port: u16) -> Outbound {
        let domain = match address {
            Address::Domain(d) => Some(d.trim_end_matches('.').to_ascii_lowercase()),
            _ => None,
        };
        let ip = match address {
            Address::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Address::Domain(_) => None,
        };
        for rule in &self.rules {
            if rule.geo_only {
                continue;
            }
            if rule_matches(rule, domain.as_deref(), ip, port) {
                return rule.outbound;
            }
        }
        self.final_outbound
    }
}

fn compile_rule(rule: &RoutingRule) -> Result<CompiledRule> {
    let outbound = Outbound::parse(&rule.outbound)?;
    let ip_cidr = rule
        .ip_cidr
        .iter()
        .map(|s| Cidr::parse(s))
        .collect::<Result<Vec<_>>>()?;
    let lower = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let compiled = CompiledRule {
        outbound,
        domain: lower(&rule.domain),
        domain_suffix: lower(&rule.domain_suffix),
        domain_keyword: lower(&rule.domain_keyword),
        ip_cidr,
        ip_private: rule.ip_private,
        port: rule.port.clone(),
        geo_only: (!rule.geoip.is_empty() || !rule.geosite.is_empty()),
    };
    let has_local_condition = !compiled.domain.is_empty()
        || !compiled.domain_suffix.is_empty()
        || !compiled.domain_keyword.is_empty()
        || !compiled.ip_cidr.is_empty()
        || compiled.ip_private
        || !compiled.port.is_empty();
    if !has_local_condition && !compiled.geo_only {
        bail!("a routing rule needs at least one condition");
    }
    Ok(compiled)
}

/// sing-box semantics: every field present must match; lists are OR.
fn rule_matches(rule: &CompiledRule, domain: Option<&str>, ip: Option<IpAddr>, port: u16) -> bool {
    if !rule.port.is_empty() && !rule.port.contains(&port) {
        return false;
    }
    let domain_fields = !rule.domain.is_empty()
        || !rule.domain_suffix.is_empty()
        || !rule.domain_keyword.is_empty();
    if domain_fields {
        let Some(d) = domain else { return false };
        let exact = rule.domain.iter().any(|x| x == d);
        let suffix = rule
            .domain_suffix
            .iter()
            .any(|x| d == x || d.ends_with(&format!(".{x}")));
        let keyword = rule.domain_keyword.iter().any(|x| d.contains(x.as_str()));
        if !(exact || suffix || keyword) {
            return false;
        }
    }
    if !rule.ip_cidr.is_empty() {
        let Some(ip) = ip else { return false };
        if !rule.ip_cidr.iter().any(|c| c.contains(ip)) {
            return false;
        }
    }
    if rule.ip_private {
        let Some(ip) = ip else { return false };
        if !is_private_ip(ip) {
            return false;
        }
    }
    true
}

#[allow(dead_code)]
fn _ipv6_unused(_: Ipv6Addr) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RoutingConfig, RoutingRule};

    fn rule(outbound: &str) -> RoutingRule {
        RoutingRule {
            outbound: outbound.to_string(),
            ..Default::default()
        }
    }

    fn router(rules: Vec<RoutingRule>, final_outbound: &str) -> Router {
        Router::new(&RoutingConfig {
            final_outbound: final_outbound.to_string(),
            rules,
        })
        .unwrap()
    }

    fn dom(s: &str) -> Address {
        Address::Domain(s.to_string())
    }

    #[test]
    fn domain_suffix_exact_and_keyword() {
        let mut r = rule("direct");
        r.domain_suffix = vec!["ru".into(), ".yandex.net".into()];
        let mut k = rule("block");
        k.domain_keyword = vec!["ads".into()];
        let mut e = rule("direct");
        e.domain = vec!["Exact.Example".into()];
        let router = router(vec![r, k, e], "proxy");
        assert_eq!(router.decide(&dom("mail.ru"), 443), Outbound::Direct);
        assert_eq!(router.decide(&dom("ru"), 443), Outbound::Direct);
        assert_eq!(router.decide(&dom("notru.com"), 443), Outbound::Proxy);
        assert_eq!(router.decide(&dom("a.yandex.net."), 80), Outbound::Direct);
        assert_eq!(router.decide(&dom("ads.example.com"), 80), Outbound::Block);
        assert_eq!(router.decide(&dom("exact.example"), 80), Outbound::Direct);
        assert_eq!(
            router.decide(&dom("sub.exact.example"), 80),
            Outbound::Proxy
        );
    }

    #[test]
    fn cidr_and_private_and_port() {
        let mut c = rule("direct");
        c.ip_cidr = vec![
            "10.0.0.0/8".into(),
            "2001:db8::/32".into(),
            "9.9.9.9".into(),
        ];
        let mut p = rule("direct");
        p.ip_private = true;
        let mut dns = rule("block");
        dns.port = vec![53];
        let router = router(vec![c, p, dns], "proxy");
        assert_eq!(
            router.decide(&Address::Ipv4("10.1.2.3".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv4("9.9.9.9".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv6("2001:db8::1".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv4("192.168.1.1".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv4("100.64.0.1".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv6("fd00::1".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(
            router.decide(&Address::Ipv4("8.8.8.8".parse().unwrap()), 443),
            Outbound::Proxy
        );
        assert_eq!(
            router.decide(&Address::Ipv4("8.8.8.8".parse().unwrap()), 53),
            Outbound::Block
        );
        assert_eq!(router.decide(&dom("example.com"), 53), Outbound::Block);
        // ip rules never match unresolved domains
        assert_eq!(router.decide(&dom("intranet.local"), 443), Outbound::Proxy);
    }

    #[test]
    fn fields_in_one_rule_are_anded() {
        let mut r = rule("direct");
        r.domain_suffix = vec!["example.com".into()];
        r.port = vec![8080];
        let router = router(vec![r], "proxy");
        assert_eq!(router.decide(&dom("a.example.com"), 8080), Outbound::Direct);
        assert_eq!(router.decide(&dom("a.example.com"), 443), Outbound::Proxy);
    }

    #[test]
    fn geo_rules_are_tun_only_and_final_applies() {
        let mut g = rule("direct");
        g.geoip = vec!["ru".into()];
        let router = router(vec![g], "direct");
        assert!(router.has_geo_rules());
        assert_eq!(
            router.decide(&Address::Ipv4("77.88.8.8".parse().unwrap()), 443),
            Outbound::Direct
        );
        assert_eq!(router.final_outbound(), Outbound::Direct);
    }

    #[test]
    fn validation_errors() {
        assert!(Router::new(&RoutingConfig {
            final_outbound: "block".into(),
            rules: vec![]
        })
        .is_err());
        assert!(Router::new(&RoutingConfig {
            final_outbound: "nowhere".into(),
            rules: vec![]
        })
        .is_err());
        assert!(Router::new(&RoutingConfig {
            final_outbound: "proxy".into(),
            rules: vec![rule("direct")]
        })
        .is_err());
        let mut bad = rule("direct");
        bad.ip_cidr = vec!["10.0.0.0/33".into()];
        assert!(Router::new(&RoutingConfig {
            final_outbound: "proxy".into(),
            rules: vec![bad]
        })
        .is_err());
        assert!(Cidr::parse("::ffff:10.0.0.0/104")
            .unwrap()
            .contains("10.1.1.1".parse().unwrap()));
    }
}
