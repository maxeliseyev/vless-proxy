use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub addresses: Vec<IpAddr>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct DnsCacheConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub default_ttl_secs: u64,
    pub min_ttl_secs: u64,
    pub max_ttl_secs: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 1000,
            default_ttl_secs: 300,
            min_ttl_secs: 30,
            max_ttl_secs: 3600,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsCache {
    config: DnsCacheConfig,
    entries: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Self {
        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &DnsCacheConfig {
        &self.config
    }

    pub async fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        if !self.config.enabled {
            return None;
        }

        let entries = self.entries.read().await;
        let entry = entries.get(&domain.to_lowercase())?;

        if Instant::now() > entry.expires_at {
            return None;
        }

        Some(entry.addresses.clone())
    }

    pub async fn insert(&self, domain: &str, addresses: Vec<IpAddr>, ttl: Duration) {
        if !self.config.enabled {
            return;
        }

        let ttl = self.clamp_ttl(ttl);
        let expires_at = Instant::now() + ttl;

        let mut entries = self.entries.write().await;

        if entries.len() >= self.config.max_entries {
            self.evict_expired(&mut entries).await;

            if entries.len() >= self.config.max_entries {
                self.evict_oldest(&mut entries).await;
            }
        }

        entries.insert(
            domain.to_lowercase(),
            DnsCacheEntry {
                addresses,
                expires_at,
            },
        );
    }

    pub async fn remove(&self, domain: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(domain);
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    fn clamp_ttl(&self, ttl: Duration) -> Duration {
        let ttl_secs = ttl.as_secs();
        let clamped = ttl_secs
            .max(self.config.min_ttl_secs)
            .min(self.config.max_ttl_secs);
        Duration::from_secs(clamped)
    }

    async fn evict_expired(&self, entries: &mut HashMap<String, DnsCacheEntry>) {
        let now = Instant::now();
        entries.retain(|_, entry| now < entry.expires_at);
    }

    async fn evict_oldest(&self, entries: &mut HashMap<String, DnsCacheEntry>) {
        if entries.is_empty() {
            return;
        }

        let oldest_key = entries
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest_key {
            entries.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cache_returns_stored_value_before_expiry() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            default_ttl_secs: 60,
            min_ttl_secs: 10,
            max_ttl_secs: 300,
        });

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("example.com", vec![ip], Duration::from_secs(60))
            .await;

        let result = cache.get("example.com").await;
        assert_eq!(result, Some(vec![ip]));
    }

    #[tokio::test]
    async fn cache_returns_none_after_expiry() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            default_ttl_secs: 1,
            min_ttl_secs: 1,
            max_ttl_secs: 1,
        });

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("example.com", vec![ip], Duration::from_secs(1))
            .await;

        tokio::time::sleep(Duration::from_millis(1100)).await;

        let result = cache.get("example.com").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn cache_is_case_insensitive() {
        let cache = DnsCache::new(DnsCacheConfig::default());

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("Example.COM", vec![ip], Duration::from_secs(60))
            .await;

        let result = cache.get("example.com").await;
        assert_eq!(result, Some(vec![ip]));

        let result = cache.get("EXAMPLE.COM").await;
        assert_eq!(result, Some(vec![ip]));
    }

    #[tokio::test]
    async fn cache_clamps_ttl_to_min() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            default_ttl_secs: 300,
            min_ttl_secs: 30,
            max_ttl_secs: 300,
        });

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("example.com", vec![ip], Duration::from_secs(5))
            .await;

        let result = cache.get("example.com").await;
        assert!(result.is_some());

        tokio::time::sleep(Duration::from_millis(6000)).await;

        let result = cache.get("example.com").await;
        assert!(result.is_some());

        tokio::time::sleep(Duration::from_millis(25000)).await;

        let result = cache.get("example.com").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn cache_clamps_ttl_to_max() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 100,
            default_ttl_secs: 300,
            min_ttl_secs: 30,
            max_ttl_secs: 60,
        });

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("example.com", vec![ip], Duration::from_secs(3600))
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = cache.get("example.com").await;
        assert!(result.is_some());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = cache.get("example.com").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn cache_disabled_returns_none() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: false,
            max_entries: 100,
            default_ttl_secs: 300,
            min_ttl_secs: 30,
            max_ttl_secs: 3600,
        });

        let ip = IpAddr::from([127u8, 0, 0, 1]);
        cache
            .insert("example.com", vec![ip], Duration::from_secs(60))
            .await;

        let result = cache.get("example.com").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn cache_evicts_oldest_when_full() {
        let cache = DnsCache::new(DnsCacheConfig {
            enabled: true,
            max_entries: 3,
            default_ttl_secs: 300,
            min_ttl_secs: 30,
            max_ttl_secs: 3600,
        });

        cache
            .insert(
                "first.com",
                vec![IpAddr::from([127u8, 0, 0, 1])],
                Duration::from_secs(10),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        cache
            .insert(
                "second.com",
                vec![IpAddr::from([127u8, 0, 0, 2])],
                Duration::from_secs(300),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(10)).await;

        cache
            .insert(
                "third.com",
                vec![IpAddr::from([127u8, 0, 0, 3])],
                Duration::from_secs(300),
            )
            .await;

        assert_eq!(cache.len().await, 3);

        cache
            .insert(
                "fourth.com",
                vec![IpAddr::from([127u8, 0, 0, 4])],
                Duration::from_secs(300),
            )
            .await;

        assert_eq!(cache.len().await, 3);
        assert!(cache.get("first.com").await.is_none());
        assert!(cache.get("fourth.com").await.is_some());
    }

    #[tokio::test]
    async fn cache_clear_removes_all_entries() {
        let cache = DnsCache::new(DnsCacheConfig::default());

        cache
            .insert(
                "example.com",
                vec![IpAddr::from([127u8, 0, 0, 1])],
                Duration::from_secs(60),
            )
            .await;
        cache
            .insert(
                "test.com",
                vec![IpAddr::from([127u8, 0, 0, 2])],
                Duration::from_secs(60),
            )
            .await;

        assert_eq!(cache.len().await, 2);

        cache.clear().await;

        assert_eq!(cache.len().await, 0);
        assert!(cache.get("example.com").await.is_none());
    }

    #[tokio::test]
    async fn cache_remove_single_entry() {
        let cache = DnsCache::new(DnsCacheConfig::default());

        cache
            .insert(
                "example.com",
                vec![IpAddr::from([127u8, 0, 0, 1])],
                Duration::from_secs(60),
            )
            .await;
        cache
            .insert(
                "test.com",
                vec![IpAddr::from([127u8, 0, 0, 2])],
                Duration::from_secs(60),
            )
            .await;

        assert_eq!(cache.len().await, 2);

        cache.remove("example.com").await;

        assert_eq!(cache.len().await, 1);
        assert!(cache.get("example.com").await.is_none());
        assert!(cache.get("test.com").await.is_some());
    }
}
