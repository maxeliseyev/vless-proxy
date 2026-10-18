//! Subscription URLs: a page whose body is a base64 (or plain) list of
//! links, one per line, as served by 3x-ui, Marzban, Remnawave and friends.
//! vproxy keeps the links in a links file whose header comments remember
//! the URL and the last update, so the list can be refreshed from the TUI,
//! with `--refresh`, or automatically when it is older than the interval
//! the provider sets (`profile-update-interval`, default 24 h).
//!
//! Links file layout:
//!
//! ```text
//! # subscription: https://provider/sub/token
//! # title: My provider
//! # updated: 1760000000
//! # interval: 12
//! # traffic: upload=.. download=.. total=.. expire=..
//! # active: vless://...          (the server to start with)
//! vless://...                    (subscription links, replaced on refresh)
//! # manual
//! vless://...                    (links added by hand or appended; kept on refresh)
//! ```

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const HEADER_URL: &str = "# subscription:";
pub const HEADER_TITLE: &str = "# title:";
pub const HEADER_UPDATED: &str = "# updated:";
pub const HEADER_INTERVAL: &str = "# interval:";
pub const HEADER_TRAFFIC: &str = "# traffic:";
pub const HEADER_ACTIVE: &str = "# active:";
pub const MANUAL_MARKER: &str = "# manual";
const DEFAULT_INTERVAL_HOURS: u64 = 24;
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);

/// `subscription-userinfo` header values (bytes, unix seconds).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserInfo {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expire: Option<u64>,
}

impl UserInfo {
    pub fn parse(header: &str) -> Self {
        let mut info = Self::default();
        for part in header.split(';') {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let v = v.trim().parse::<u64>().ok();
            match k.trim().to_ascii_lowercase().as_str() {
                "upload" => info.upload = v,
                "download" => info.download = v,
                "total" => info.total = v,
                "expire" => info.expire = v,
                _ => {}
            }
        }
        info
    }

    fn render(&self) -> String {
        let mut parts = Vec::new();
        if let Some(v) = self.upload {
            parts.push(format!("upload={v}"));
        }
        if let Some(v) = self.download {
            parts.push(format!("download={v}"));
        }
        if let Some(v) = self.total {
            parts.push(format!("total={v}"));
        }
        if let Some(v) = self.expire {
            parts.push(format!("expire={v}"));
        }
        parts.join("; ")
    }

    /// `used 12.3 GB of 100 GB, expires 2026-12-01` (what is known).
    pub fn summary(&self) -> String {
        let mut out = Vec::new();
        let used = self.upload.unwrap_or(0) + self.download.unwrap_or(0);
        match self.total {
            Some(total) if total > 0 => out.push(format!(
                "used {} of {}",
                crate::proxy::stats::human_bytes(used),
                crate::proxy::stats::human_bytes(total)
            )),
            _ if self.upload.is_some() || self.download.is_some() => {
                out.push(format!("used {}", crate::proxy::stats::human_bytes(used)))
            }
            _ => {}
        }
        if let Some(expire) = self.expire.filter(|e| *e > 0) {
            out.push(format!("expires {}", format_date(expire)));
        }
        out.join(", ")
    }
}

/// What the links file remembers about its subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub url: String,
    pub title: Option<String>,
    /// Unix seconds of the last successful refresh.
    pub updated: Option<u64>,
    pub interval_hours: u64,
    pub userinfo: Option<UserInfo>,
}

impl Meta {
    /// Read the header comments of a links file.
    pub fn from_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Option<Self> {
        let mut meta: Option<Meta> = None;
        for line in lines {
            let line = line.trim();
            if let Some(url) = line.strip_prefix(HEADER_URL) {
                meta = Some(Meta {
                    url: url.trim().to_string(),
                    title: None,
                    updated: None,
                    interval_hours: DEFAULT_INTERVAL_HOURS,
                    userinfo: None,
                });
                continue;
            }
            let Some(m) = meta.as_mut() else { continue };
            if let Some(v) = line.strip_prefix(HEADER_TITLE) {
                m.title = Some(v.trim().to_string()).filter(|t| !t.is_empty());
            } else if let Some(v) = line.strip_prefix(HEADER_UPDATED) {
                m.updated = v.trim().parse().ok();
            } else if let Some(v) = line.strip_prefix(HEADER_INTERVAL) {
                m.interval_hours = v.trim().parse().unwrap_or(DEFAULT_INTERVAL_HOURS);
            } else if let Some(v) = line.strip_prefix(HEADER_TRAFFIC) {
                m.userinfo = Some(UserInfo::parse(v));
            }
        }
        meta
    }

    pub fn header_lines(&self, active: Option<&str>) -> Vec<String> {
        let mut out = vec![format!("{HEADER_URL} {}", self.url)];
        if let Some(t) = &self.title {
            out.push(format!("{HEADER_TITLE} {t}"));
        }
        if let Some(u) = self.updated {
            out.push(format!("{HEADER_UPDATED} {u}"));
        }
        out.push(format!("{HEADER_INTERVAL} {}", self.interval_hours));
        if let Some(info) = &self.userinfo {
            out.push(format!("{HEADER_TRAFFIC} {}", info.render()));
        }
        if let Some(a) = active {
            out.push(format!("{HEADER_ACTIVE} {a}"));
        }
        out
    }

    /// True when the list is older than the provider's interval (or never fetched).
    pub fn is_stale(&self) -> bool {
        let Some(updated) = self.updated else {
            return true;
        };
        let interval = self.interval_hours.max(1) * 3600;
        now_unix().saturating_sub(updated) >= interval
    }

    pub fn age_text(&self) -> String {
        match self.updated {
            None => "never updated".to_string(),
            Some(u) => {
                let age = now_unix().saturating_sub(u);
                if age < 3600 {
                    format!("updated {} min ago", age / 60)
                } else if age < 48 * 3600 {
                    format!("updated {} h ago", age / 3600)
                } else {
                    format!("updated {} days ago", age / 86400)
                }
            }
        }
    }
}

/// A fetched subscription.
#[derive(Debug, Clone)]
pub struct Subscription {
    pub meta: Meta,
    /// `vless://` and `vpn://` links, in the provider's order.
    pub links: Vec<String>,
    /// Links of other protocols (vmess, trojan, ss, …) that were skipped.
    pub skipped: usize,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD` of a unix timestamp (UTC).
pub fn format_date(unix: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = (unix / 86400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Download and parse a subscription.
pub async fn fetch(url: &str) -> Result<Subscription> {
    let client = reqwest::Client::builder()
        .user_agent(format!("vproxy/{}", env!("CARGO_PKG_VERSION")))
        .timeout(FETCH_TIMEOUT)
        .build()?;
    let resp = client
        .get(url)
        .header("Accept", "text/plain, */*")
        .send()
        .await
        .with_context(|| format!("cannot fetch subscription {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("subscription {url} answered {status}");
    }
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let userinfo = header("subscription-userinfo").map(|h| UserInfo::parse(&h));
    let title = header("profile-title").map(|t| decode_title(&t));
    let interval_hours = header("profile-update-interval")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|h| *h > 0)
        .unwrap_or(DEFAULT_INTERVAL_HOURS);
    let body = resp.text().await.context("reading subscription body")?;
    let (links, skipped) = parse_body(&body);
    if links.is_empty() {
        bail!(
            "subscription {url} has no vless:// or vpn:// links{}",
            if skipped > 0 {
                format!(" ({skipped} links of other protocols)")
            } else {
                String::new()
            }
        );
    }
    Ok(Subscription {
        meta: Meta {
            url: url.to_string(),
            title,
            updated: Some(now_unix()),
            interval_hours,
            userinfo,
        },
        links,
        skipped,
    })
}

/// `profile-title` may be `base64:<...>`.
fn decode_title(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(b64) = raw.strip_prefix("base64:") {
        if let Some(bytes) = decode_base64(b64) {
            if let Ok(s) = String::from_utf8(bytes) {
                return s.trim().to_string();
            }
        }
    }
    raw.to_string()
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(compact.as_bytes()) {
            return Some(bytes);
        }
    }
    let trimmed = compact.trim_end_matches('=');
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(trimmed.as_bytes()) {
            return Some(bytes);
        }
    }
    None
}

/// Links of a subscription body: base64 of a link list, or the list itself.
/// Returns the supported links and how many others were skipped.
pub fn parse_body(body: &str) -> (Vec<String>, usize) {
    let text = if body.contains("://") {
        body.to_string()
    } else {
        decode_base64(body)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| body.to_string())
    };
    let mut links = Vec::new();
    let mut skipped = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("vless://") || line.starts_with("vpn://") {
            if !links.contains(&line.to_string()) {
                links.push(line.to_string());
            }
        } else if line.contains("://") {
            skipped += 1;
        }
    }
    (links, skipped)
}

/// Render a links file for `sub`, keeping `manual` links and marking `active`.
pub fn render_file(sub: &Subscription, active: Option<&str>, manual: &[String]) -> String {
    let active =
        active.filter(|a| sub.links.iter().any(|l| l == a) || manual.iter().any(|l| l == a));
    let mut out = String::new();
    for line in sub.meta.header_lines(active) {
        out.push_str(&line);
        out.push('\n');
    }
    for link in &sub.links {
        out.push_str(link);
        out.push('\n');
    }
    // The marker is always written, so links appended by hand land in the
    // manual section and survive the next refresh.
    out.push_str(MANUAL_MARKER);
    out.push('\n');
    for link in manual {
        out.push_str(link);
        out.push('\n');
    }
    out
}

/// Split an existing links file into (subscription links, manual links).
pub fn split_sections(content: &str) -> (Vec<String>, Vec<String>) {
    let mut subscription = Vec::new();
    let mut manual = Vec::new();
    let mut in_manual = false;
    for line in content.lines() {
        let line = line.trim();
        if line == MANUAL_MARKER {
            in_manual = true;
            continue;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_manual {
            manual.push(line.to_string());
        } else {
            subscription.push(line.to_string());
        }
    }
    (subscription, manual)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "vless://00000000-0000-0000-0000-000000000001@a.example:443?security=tls#alpha";
    const B: &str = "vless://00000000-0000-0000-0000-000000000002@b.example:443?security=reality&pbk=k&sid=ab&sni=s#beta";

    #[test]
    fn parses_base64_and_plain_bodies() {
        let plain = format!("{A}\ntrojan://x@y:1\n{B}\n{A}\n");
        assert_eq!(parse_body(&plain), (vec![A.to_string(), B.to_string()], 1));
        let b64 = STANDARD.encode(&plain);
        assert_eq!(parse_body(&b64), (vec![A.to_string(), B.to_string()], 1));
        let b64 = URL_SAFE_NO_PAD.encode(&plain);
        let wrapped = format!("{}\n{}", &b64[..10], &b64[10..]);
        assert_eq!(parse_body(&wrapped).0.len(), 2);
    }

    #[test]
    fn userinfo_and_dates() {
        let info = UserInfo::parse(
            "upload=1000; download=2000000000; total=10737418240; expire=1767225600",
        );
        assert_eq!(info.total, Some(10737418240));
        assert_eq!(format_date(1767225600), "2026-01-01");
        assert_eq!(format_date(0), "1970-01-01");
        assert!(info.summary().contains("expires 2026-01-01"));
        assert!(
            info.summary().starts_with("used 1.86 GB of 10.00 GB")
                || info.summary().contains("of 10")
        );
        assert_eq!(decode_title("base64:TXkgdnBu"), "My vpn");
        assert_eq!(decode_title("Plain"), "Plain");
    }

    #[test]
    fn file_round_trip_keeps_manual_links_and_active() {
        let sub = Subscription {
            meta: Meta {
                url: "https://p.example/sub".into(),
                title: Some("P".into()),
                updated: Some(1_700_000_000),
                interval_hours: 12,
                userinfo: Some(UserInfo::parse("total=5; expire=0")),
            },
            links: vec![A.to_string(), B.to_string()],
            skipped: 0,
        };
        let manual = vec!["vpn://xyz".to_string()];
        let text = render_file(&sub, Some(B), &manual);
        assert!(text.starts_with("# subscription: https://p.example/sub\n# title: P\n# updated: 1700000000\n# interval: 12\n# traffic: total=5; expire=0\n# active: "));
        let meta = Meta::from_lines(text.lines()).unwrap();
        assert_eq!(meta.url, "https://p.example/sub");
        assert_eq!(meta.interval_hours, 12);
        assert!(meta.is_stale());
        let (s, m) = split_sections(&text);
        assert_eq!(s, vec![A.to_string(), B.to_string()]);
        assert_eq!(m, manual);
        // an active link that is no longer listed is dropped
        assert!(!render_file(&sub, Some("vless://gone"), &[]).contains("# active"));
        assert!(Meta::from_lines(format!("{A}\n").lines()).is_none());
    }
}
