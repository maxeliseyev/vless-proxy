//! Live server counters and a point-in-time [`Snapshot`] of them. The server
//! serves snapshots as newline-delimited JSON over a local Unix socket (see
//! `admin`), which `vproxy-server --stats` and `--tui` read.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Shared, cheap-to-update counters. Gauges (`*_open`) rise and fall; totals
/// only rise. Bytes are added as a stream or UDP session closes, so an open
/// transfer shows up in the byte totals only once it ends.
pub struct Stats {
    started: Instant,
    conns_open: AtomicU64,
    conns_total: AtomicU64,
    streams_open: AtomicU64,
    streams_total: AtomicU64,
    udp_open: AtomicU64,
    udp_total: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    site_requests: AtomicU64,
    accounts: Mutex<HashMap<String, Account>>,
}

struct Account {
    open: u64,
    total: u64,
    last_seen: Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            conns_open: AtomicU64::new(0),
            conns_total: AtomicU64::new(0),
            streams_open: AtomicU64::new(0),
            streams_total: AtomicU64::new(0),
            udp_open: AtomicU64::new(0),
            udp_total: AtomicU64::new(0),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            site_requests: AtomicU64::new(0),
            accounts: Mutex::new(HashMap::new()),
        }
    }

    pub fn conn_open(&self, tag: &str) {
        self.conns_open.fetch_add(1, Ordering::Relaxed);
        self.conns_total.fetch_add(1, Ordering::Relaxed);
        let mut accounts = self.accounts.lock().expect("stats lock");
        let a = accounts.entry(tag.to_string()).or_insert(Account {
            open: 0,
            total: 0,
            last_seen: self.started,
        });
        a.open += 1;
        a.total += 1;
        a.last_seen = Instant::now();
    }

    pub fn conn_close(&self, tag: &str) {
        self.conns_open.fetch_sub(1, Ordering::Relaxed);
        if let Some(a) = self.accounts.lock().expect("stats lock").get_mut(tag) {
            a.open = a.open.saturating_sub(1);
            a.last_seen = Instant::now();
        }
    }

    pub fn stream_open(&self) {
        self.streams_open.fetch_add(1, Ordering::Relaxed);
        self.streams_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stream_close(&self, up: u64, down: u64) {
        self.streams_open.fetch_sub(1, Ordering::Relaxed);
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    pub fn udp_open(&self) {
        self.udp_open.fetch_add(1, Ordering::Relaxed);
        self.udp_total.fetch_add(1, Ordering::Relaxed);
    }

    /// A UDP session ended, carrying its byte totals.
    pub fn udp_close(&self, up: u64, down: u64) {
        self.udp_open.fetch_sub(1, Ordering::Relaxed);
        self.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.bytes_down.fetch_add(down, Ordering::Relaxed);
    }

    pub fn site_request(&self) {
        self.site_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let mut accounts: Vec<AccountSnapshot> = self
            .accounts
            .lock()
            .expect("stats lock")
            .iter()
            .map(|(tag, a)| AccountSnapshot {
                tag: tag.clone(),
                open: a.open,
                total: a.total,
                idle_secs: a.last_seen.elapsed().as_secs(),
            })
            .collect();
        // Online accounts first, then by most recently seen.
        accounts.sort_by(|a, b| b.open.cmp(&a.open).then(a.idle_secs.cmp(&b.idle_secs)));
        Snapshot {
            uptime_secs: self.started.elapsed().as_secs(),
            conns_open: g(&self.conns_open),
            conns_total: g(&self.conns_total),
            streams_open: g(&self.streams_open),
            streams_total: g(&self.streams_total),
            udp_open: g(&self.udp_open),
            udp_total: g(&self.udp_total),
            bytes_up: g(&self.bytes_up),
            bytes_down: g(&self.bytes_down),
            site_requests: g(&self.site_requests),
            accounts,
        }
    }
}

/// A point-in-time view of [`Stats`], serialized as one JSON line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub uptime_secs: u64,
    pub conns_open: u64,
    pub conns_total: u64,
    pub streams_open: u64,
    pub streams_total: u64,
    pub udp_open: u64,
    pub udp_total: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub site_requests: u64,
    pub accounts: Vec<AccountSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountSnapshot {
    pub tag: String,
    pub open: u64,
    pub total: u64,
    pub idle_secs: u64,
}
