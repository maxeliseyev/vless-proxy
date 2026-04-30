use crate::config::{DnsConfig, DnsIpStrategy, DnsResolveMode, DnsRule};
use crate::dns_cache::DnsCache;
use crate::vless::Address;
use anyhow::{Context, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ResolverPolicy {
    mode: DnsResolveMode,
    strategy: DnsIpStrategy,
    rules: Vec<DnsRule>,
    cache: DnsCache,
}

impl ResolverPolicy {
    pub fn new(config: DnsConfig) -> Result<Self> {
        let cache_config = crate::dns_cache::DnsCacheConfig {
            enabled: config.cache.enabled,
            max_entries: config.cache.max_entries,
            default_ttl_secs: config.cache.ttl_secs,
            min_ttl_secs: config.cache.min_ttl_secs,
            max_ttl_secs: config.cache.max_ttl_secs,
        };

        Ok(Self {
            mode: config.resolve_mode()?,
            strategy: config.ip_strategy()?,
            rules: config.rules,
            cache: DnsCache::new(cache_config),
        })
    }

    pub fn mode(&self) -> DnsResolveMode {
        self.mode
    }

    pub fn strategy(&self) -> DnsIpStrategy {
        self.strategy
    }

    pub fn rules(&self) -> &[DnsRule] {
        &self.rules
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    pub async fn resolve(&self, address: Address, port: u16) -> Result<Address> {
        match (self.mode, address) {
            (DnsResolveMode::Remote, address) => {
                if let Address::Domain(ref domain) = address {
                    if let Some(rule) = self.find_matching_rule(domain) {
                        if rule.resolve == "local" {
                            return self.resolve_domain_locally(domain, port).await;
                        }
                    }
                }
                Ok(address)
            }
            (DnsResolveMode::Local, Address::Domain(domain)) => {
                if let Some(rule) = self.find_matching_rule(&domain) {
                    if rule.resolve == "remote" {
                        return Ok(Address::Domain(domain));
                    }
                }
                self.resolve_domain_locally(&domain, port).await
            }
            (_, address) => Ok(address),
        }
    }

    fn find_matching_rule(&self, domain: &str) -> Option<&DnsRule> {
        let domain_lower = domain.to_lowercase();
        
        for rule in &self.rules {
            if let Some(suffix) = &rule.domain_suffix {
                if domain_lower.ends_with(&suffix.to_lowercase()) {
                    return Some(rule);
                }
            }
            
            if let Some(exact) = &rule.domain {
                if domain_lower == exact.to_lowercase() {
                    return Some(rule);
                }
            }
            
            if let Some(keyword) = &rule.domain_keyword {
                if domain_lower.contains(&keyword.to_lowercase()) {
                    return Some(rule);
                }
            }
        }
        
        None
    }

    async fn resolve_domain_locally(&self, domain: &str, port: u16) -> Result<Address> {
        if let Some(cached) = self.cache.get(domain).await {
            if let Some(ip) = select_ip_from_vec(&cached, self.strategy) {
                return Ok(match ip {
                    IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
                    IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
                });
            }
        }

        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((domain, port))
            .await
            .with_context(|| format!("Failed to resolve domain via system DNS: {domain}"))?
            .collect();

        let ttl = Duration::from_secs(self.cache.config().default_ttl_secs);
        let ip_addresses: Vec<IpAddr> = addresses.iter().map(|addr| addr.ip()).collect();
        self.cache.insert(domain, ip_addresses.clone(), ttl).await;

        let ip = select_ip(addresses.into_iter(), self.strategy).ok_or_else(|| {
            anyhow::anyhow!("No DNS answer matched strategy for {domain}")
        })?;

        Ok(match ip {
            IpAddr::V4(ipv4) => Address::Ipv4(ipv4),
            IpAddr::V6(ipv6) => Address::Ipv6(ipv6),
        })
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

fn select_ip_from_vec(addresses: &[IpAddr], strategy: DnsIpStrategy) -> Option<IpAddr> {
    let mut ipv4 = None;
    let mut ipv6 = None;

    for &addr in addresses {
        match addr {
            IpAddr::V4(ip) if ipv4.is_none() => ipv4 = Some(addr),
            IpAddr::V6(ip) if ipv6.is_none() => ipv6 = Some(addr),
            _ => {}
        }
    }

    match strategy {
        DnsIpStrategy::PreferIpv4 => ipv4.or(ipv6),
        DnsIpStrategy::PreferIpv6 => ipv6.or(ipv4),
        DnsIpStrategy::Ipv4Only => ipv4,
        DnsIpStrategy::Ipv6Only => ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsCacheConfig;
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
            rules: vec![],
            cache: DnsCacheConfig::default(),
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

    #[test]
    fn matches_domain_suffix_rule() {
        let policy = ResolverPolicy::new(DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![DnsRule {
                domain: None,
                domain_suffix: Some(".ru".to_string()),
                domain_keyword: None,
                resolve: "local".to_string(),
            }],
            cache: DnsCacheConfig::default(),
        })
        .unwrap();

        assert!(policy.find_matching_rule("example.ru").is_some());
        assert!(policy.find_matching_rule("sub.example.ru").is_some());
        assert!(policy.find_matching_rule("example.com").is_none());
    }

    #[test]
    fn matches_exact_domain_rule() {
        let policy = ResolverPolicy::new(DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![DnsRule {
                domain: Some("example.com".to_string()),
                domain_suffix: None,
                domain_keyword: None,
                resolve: "local".to_string(),
            }],
            cache: DnsCacheConfig::default(),
        })
        .unwrap();

        assert!(policy.find_matching_rule("example.com").is_some());
        assert!(policy.find_matching_rule("sub.example.com").is_none());
    }

    #[test]
    fn matches_domain_keyword_rule() {
        let policy = ResolverPolicy::new(DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![DnsRule {
                domain: None,
                domain_suffix: None,
                domain_keyword: Some("google".to_string()),
                resolve: "local".to_string(),
            }],
            cache: DnsCacheConfig::default(),
        })
        .unwrap();

        assert!(policy.find_matching_rule("google.com").is_some());
        assert!(policy.find_matching_rule("www.google.com").is_some());
        assert!(policy.find_matching_rule("googled.com").is_some());
        assert!(policy.find_matching_rule("example.com").is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = ResolverPolicy::new(DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![
                DnsRule {
                    domain: Some("example.com".to_string()),
                    domain_suffix: None,
                    domain_keyword: None,
                    resolve: "local".to_string(),
                },
                DnsRule {
                    domain: None,
                    domain_suffix: Some(".com".to_string()),
                    domain_keyword: None,
                    resolve: "remote".to_string(),
                },
            ],
            cache: DnsCacheConfig::default(),
        })
        .unwrap();

        let rule = policy.find_matching_rule("example.com").unwrap();
        assert_eq!(rule.resolve, "local");

        let rule = policy.find_matching_rule("other.com").unwrap();
        assert_eq!(rule.resolve, "remote");
    }
}
