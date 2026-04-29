use crate::config::{DnsConfig, DnsIpStrategy, DnsResolveMode};
use crate::vless::Address;
use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone)]
pub struct ResolverPolicy {
    mode: DnsResolveMode,
    strategy: DnsIpStrategy,
}

impl ResolverPolicy {
    pub fn new(config: DnsConfig) -> Result<Self> {
        Ok(Self {
            mode: config.resolve_mode()?,
            strategy: config.ip_strategy()?,
        })
    }

    pub fn mode(&self) -> DnsResolveMode {
        self.mode
    }

    pub fn strategy(&self) -> DnsIpStrategy {
        self.strategy
    }

    pub async fn resolve(&self, address: Address, port: u16) -> Result<Address> {
        match (self.mode, address) {
            (DnsResolveMode::Remote, address) => Ok(address),
            (DnsResolveMode::Local, Address::Domain(domain)) => {
                let resolved = tokio::net::lookup_host((domain.as_str(), port))
                    .await
                    .with_context(|| {
                        format!("Failed to resolve domain via system DNS: {domain}")
                    })?;
                let ip = select_ip(resolved, self.strategy).ok_or_else(|| {
                    anyhow::anyhow!("No DNS answer matched strategy for {domain}")
                })?;
                Ok(match ip {
                    IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
                    IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
                })
            }
            (_, address) => Ok(address),
        }
    }
}

fn select_ip<I>(addresses: I, strategy: DnsIpStrategy) -> Option<IpAddr>
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut ipv4 = None;
    let mut ipv6 = None;

    for addr in addresses {
        match addr.ip() {
            IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(ip),
            IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(ip),
            _ => {}
        }
    }

    match strategy {
        DnsIpStrategy::PreferIpv4 => ipv4.map(IpAddr::V4).or_else(|| ipv6.map(IpAddr::V6)),
        DnsIpStrategy::PreferIpv6 => ipv6.map(IpAddr::V6).or_else(|| ipv4.map(IpAddr::V4)),
        DnsIpStrategy::Ipv4Only => ipv4.map(IpAddr::V4),
        DnsIpStrategy::Ipv6Only => ipv6.map(IpAddr::V6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn localhost_v4() -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 53))
    }

    fn localhost_v6() -> SocketAddr {
        SocketAddr::from((Ipv6Addr::LOCALHOST, 53))
    }

    #[test]
    fn keeps_domain_when_mode_is_remote() {
        let policy = ResolverPolicy::new(DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
        })
        .unwrap();

        let resolved = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(policy.resolve(Address::Domain("example.com".to_string()), 443))
            .unwrap();

        assert_eq!(resolved, Address::Domain("example.com".to_string()));
    }

    #[test]
    fn prefers_ipv4_when_available() {
        let result = select_ip([localhost_v6(), localhost_v4()], DnsIpStrategy::PreferIpv4);

        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn prefers_ipv6_when_available() {
        let result = select_ip([localhost_v4(), localhost_v6()], DnsIpStrategy::PreferIpv6);

        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn enforces_ipv4_only_strategy() {
        let result = select_ip([localhost_v6()], DnsIpStrategy::Ipv4Only);

        assert_eq!(result, None);
    }

    #[test]
    fn enforces_ipv6_only_strategy() {
        let result = select_ip([localhost_v6()], DnsIpStrategy::Ipv6Only);

        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
