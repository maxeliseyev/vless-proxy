//! Recent flows of the netstack, for the app's live log: which name each
//! connection went to, by which route, how many bytes moved, whether it is
//! still open. A bounded ring: the oldest records are dropped.

use crate::proxy::routing::Outbound;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
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

/// One TCP connection or UDP flow. Counters are updated while it runs.
pub struct Flow {
    id: u64,
    started_ms: u64,
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
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }

    pub fn close(&self, ok: bool) {
        self.failed.store(!ok, Ordering::Relaxed);
        self.closed.store(true, Ordering::Relaxed);
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

    /// The newest `max` records, newest first, as a JSON array of
    /// `{id, t (unix ms), proto, host, port, route, up, down, open, failed}`.
    pub fn to_json(&self, max: usize) -> String {
        let inner = self.inner.lock().expect("flow log lock poisoned");
        let rows: Vec<serde_json::Value> = inner
            .records
            .iter()
            .rev()
            .take(max)
            .map(|f| {
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
        assert_eq!(
            serde_json::from_str::<Vec<serde_json::Value>>(&log.to_json(1))
                .unwrap()
                .len(),
            1
        );
    }
}
