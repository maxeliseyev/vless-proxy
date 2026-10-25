//! Recent flows of the netstack, for the app's live log: which name each
//! connection went to, by which route, how many bytes moved, whether it is
//! still open. A bounded ring: the oldest records are dropped.

use crate::proxy::routing::Outbound;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Records kept; enough for a screenful and then some, small in memory.
pub const DEFAULT_CAPACITY: usize = 200;

pub struct FlowLog {
    capacity: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    records: VecDeque<Arc<Flow>>,
}

/// Not measured (yet) in the millisecond fields of [`Flow`].
const UNSET: u64 = u64::MAX;

/// One TCP connection or UDP flow. Counters are updated while it runs.
pub struct Flow {
    id: u64,
    started_ms: u64,
    started: Instant,
    /// From the start: the server connection was ready (TCP + TLS/REALITY,
    /// including the wait for a handshake slot), the first byte came back,
    /// the flow ended.
    dial_ms: AtomicU64,
    first_down_ms: AtomicU64,
    ended_ms: AtomicU64,
    /// Why it ended, when there is more to say than "ok".
    reason: Mutex<Option<String>>,
    proto: &'static str,
    host: String,
    port: u16,
    route: Outbound,
    up: AtomicU64,
    down: AtomicU64,
    closed: AtomicBool,
    failed: AtomicBool,
}

impl Flow {
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: usize) {
        if n > 0 && self.first_down_ms.load(Ordering::Relaxed) == UNSET {
            self.first_down_ms
                .store(self.elapsed_ms(), Ordering::Relaxed);
        }
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// The connection to the server (or the direct target) is ready.
    pub fn dialed(&self) {
        self.dial_ms.store(self.elapsed_ms(), Ordering::Relaxed);
    }

    pub fn close(&self, ok: bool) {
        self.ended_ms.store(self.elapsed_ms(), Ordering::Relaxed);
        self.failed.store(!ok, Ordering::Relaxed);
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Close as failed, keeping why.
    pub fn fail(&self, error: String) {
        *self.reason.lock().expect("flow lock poisoned") = Some(error);
        self.close(false);
    }

    /// Close as fine, saying how (`closed by app`).
    pub fn close_because(&self, reason: &str) {
        *self.reason.lock().expect("flow lock poisoned") = Some(reason.to_owned());
        self.close(true);
    }

    /// One line for the diagnostic log, written when the flow ends:
    /// `#12 tcp proxy example.com:443 dial 312ms first 640ms up 1.2 KB
    /// down 18.0 KB in 34.1s: Read timeout: …`. A stall shows as bytes up,
    /// a few KB down and a timeout.
    pub fn summary(&self) -> String {
        let mut line = format!(
            "#{} {} {} {}:{}",
            self.id,
            self.proto,
            self.route.as_str(),
            self.host,
            self.port
        );
        let ms = |field: &AtomicU64| Some(field.load(Ordering::Relaxed)).filter(|v| *v != UNSET);
        if let Some(dial) = ms(&self.dial_ms) {
            line += &format!(" dial {dial}ms");
        }
        if let Some(first) = ms(&self.first_down_ms) {
            line += &format!(" first {first}ms");
        }
        line += &format!(
            " up {} down {}",
            human(self.up.load(Ordering::Relaxed)),
            human(self.down.load(Ordering::Relaxed))
        );
        if !self.closed.load(Ordering::Relaxed) {
            let open = self.elapsed_ms() as f64 / 1000.0;
            return line + &format!(" for {open:.1}s: still open");
        }
        if let Some(ended) = ms(&self.ended_ms) {
            line += &format!(" in {:.1}s", ended as f64 / 1000.0);
        }
        match self.reason.lock().expect("flow lock poisoned").as_deref() {
            Some(reason) => line + ": " + reason,
            None if self.failed.load(Ordering::Relaxed) => line + ": failed",
            None => line + ": ok",
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

fn human(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
    }
}

impl FlowLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::default(),
        }
    }

    /// Start a record; the caller updates and closes it.
    pub fn open(&self, proto: &'static str, host: String, port: u16, route: Outbound) -> Arc<Flow> {
        let started_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut inner = self.inner.lock().expect("flow log lock poisoned");
        inner.next_id += 1;
        let flow = Arc::new(Flow {
            id: inner.next_id,
            started_ms,
            started: Instant::now(),
            dial_ms: AtomicU64::new(UNSET),
            first_down_ms: AtomicU64::new(UNSET),
            ended_ms: AtomicU64::new(UNSET),
            reason: Mutex::new(None),
            proto,
            host,
            port,
            route,
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        });
        if inner.records.len() == self.capacity {
            inner.records.pop_front();
        }
        inner.records.push_back(flow.clone());
        flow
    }

    /// Records not closed yet, oldest first (for a last word at shutdown).
    pub fn still_open(&self) -> Vec<Arc<Flow>> {
        let inner = self.inner.lock().expect("flow log lock poisoned");
        inner
            .records
            .iter()
            .filter(|f| !f.closed.load(Ordering::Relaxed))
            .cloned()
            .collect()
    }

    /// The newest `max` records, newest first, as a JSON array of
    /// `{id, t (unix ms), proto, host, port, route, up, down, open, failed,
    /// dial, first (ms from t, or null), error (or null)}`.
    pub fn to_json(&self, max: usize) -> String {
        let inner = self.inner.lock().expect("flow log lock poisoned");
        let rows: Vec<serde_json::Value> = inner
            .records
            .iter()
            .rev()
            .take(max)
            .map(|f| {
                let ms =
                    |field: &AtomicU64| Some(field.load(Ordering::Relaxed)).filter(|v| *v != UNSET);
                serde_json::json!({
                    "id": f.id,
                    "t": f.started_ms,
                    "proto": f.proto,
                    "host": f.host,
                    "port": f.port,
                    "route": f.route.as_str(),
                    "up": f.up.load(Ordering::Relaxed),
                    "down": f.down.load(Ordering::Relaxed),
                    "open": !f.closed.load(Ordering::Relaxed),
                    "failed": f.failed.load(Ordering::Relaxed),
                    "dial": ms(&f.dial_ms),
                    "first": ms(&f.first_down_ms),
                    "error": f
                        .failed
                        .load(Ordering::Relaxed)
                        .then(|| f.reason.lock().expect("flow lock poisoned").clone())
                        .flatten(),
                })
            })
            .collect();
        serde_json::Value::Array(rows).to_string()
    }
}

/// The app side of a TCP flow with its bytes counted: reads are what the app
/// sent (up), writes are what it receives (down).
pub struct Counted<S> {
    inner: S,
    flow: Arc<Flow>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, flow: Arc<Flow>) -> Self {
        Self { inner, flow }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            self.flow.add_up(buf.filled().len() - before);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            self.flow.add_down(n);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_the_newest_and_reports_newest_first() {
        let log = FlowLog::new(2);
        let a = log.open("tcp", "a.test".into(), 443, Outbound::Proxy);
        let b = log.open("udp", "b.test".into(), 53, Outbound::Direct);
        b.add_up(10);
        b.add_down(20);
        b.close(true);
        log.open("tcp", "c.test".into(), 80, Outbound::Block)
            .close(false);
        drop(a);
        let rows: Vec<serde_json::Value> = serde_json::from_str(&log.to_json(10)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["host"], "c.test");
        assert_eq!(rows[0]["route"], "block");
        assert_eq!(rows[0]["failed"], true);
        assert_eq!(rows[1]["host"], "b.test");
        assert_eq!(
            (rows[1]["up"].as_u64(), rows[1]["down"].as_u64()),
            (Some(10), Some(20))
        );
        assert_eq!(rows[1]["open"], false);
        assert_eq!(rows[1]["dial"], serde_json::Value::Null);
        assert_eq!(
            serde_json::from_str::<Vec<serde_json::Value>>(&log.to_json(1))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn summary_tells_a_stall_from_a_clean_close() {
        let log = FlowLog::new(4);
        let stalled = log.open("tcp", "example.com".into(), 443, Outbound::Proxy);
        stalled.dialed();
        stalled.add_up(600);
        stalled.add_down(18 * 1024);
        stalled.fail("Read timeout: no response from target in 30s".into());
        let line = stalled.summary();
        assert!(
            line.starts_with("#1 tcp proxy example.com:443 dial "),
            "{line}"
        );
        assert!(line.contains(" first "), "{line}");
        assert!(line.contains(" up 600 B down 18.0 KB in "), "{line}");
        assert!(
            line.ends_with(": Read timeout: no response from target in 30s"),
            "{line}"
        );

        let quiet = log.open("udp", "dns.test".into(), 53, Outbound::Direct);
        quiet.close_because("closed by app");
        let line = quiet.summary();
        assert!(!line.contains("dial") && !line.contains("first"), "{line}");
        assert!(line.ends_with(": closed by app"), "{line}");

        let open = log.open("tcp", "push.test".into(), 5223, Outbound::Proxy);
        let line = open.summary();
        assert!(
            line.contains(" for ") && line.ends_with(": still open"),
            "{line}"
        );
        let still: Vec<u64> = log.still_open().iter().map(|f| f.id).collect();
        assert_eq!(still, vec![3]);

        let rows: Vec<serde_json::Value> = serde_json::from_str(&log.to_json(3)).unwrap();
        assert_eq!(
            rows[2]["error"],
            "Read timeout: no response from target in 30s"
        );
        assert!(rows[2]["dial"].is_u64() && rows[2]["first"].is_u64());
        assert_eq!(rows[1]["error"], serde_json::Value::Null);
    }
}
