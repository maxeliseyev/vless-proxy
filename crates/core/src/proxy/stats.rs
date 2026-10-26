//! Process-wide traffic counters, read by the TUI.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub struct Stats {
    active: AtomicUsize,
    total: AtomicU64,
    up: AtomicU64,
    down: AtomicU64,
    errors: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub active: usize,
    pub total: u64,
    pub up: u64,
    pub down: u64,
    pub errors: u64,
}

pub static STATS: Stats = Stats::new();

impl Stats {
    pub const fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            total: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn connection_opened(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_closed(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Bytes sent towards the VLESS server.
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Bytes received from the VLESS server.
    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            active: self.active.load(Ordering::Relaxed),
            total: self.total.load(Ordering::Relaxed),
            up: self.up.load(Ordering::Relaxed),
            down: self.down.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// `1.5 MiB`, `812 B`, ...
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_formatting() {
        let s = Stats::new();
        s.connection_opened();
        s.connection_opened();
        s.connection_closed();
        s.add_up(1536);
        s.add_down(10);
        s.error();
        let snap = s.snapshot();
        assert_eq!(snap.active, 1);
        assert_eq!(snap.total, 2);
        assert_eq!(snap.up, 1536);
        assert_eq!(snap.down, 10);
        assert_eq!(snap.errors, 1);
        assert_eq!(human_bytes(812), "812 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
    }
}
