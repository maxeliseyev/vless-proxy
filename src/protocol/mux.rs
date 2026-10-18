//! Mux.Cool client (Xray `common/mux`): several TCP sessions share one VLESS
//! connection to `v1.mux.cool:9527`, which saves a transport handshake per
//! connection. Frame layout:
//!
//! ```text
//! u16 metadata length | u16 session id | u8 status | u8 option
//! New only:            u8 network (1=TCP) | u16 port | address (1 IPv4, 2 domain, 3 IPv6)
//! option & DATA:       u16 data length | data
//! ```
//!
//! Like Xray, a connection takes at most `concurrency` live sessions and 128
//! sessions in total, and is closed once it has sat without sessions for a
//! 16 s check interval. There is no half-close in Mux.Cool: when the local
//! side finishes writing, the session is ended.

use crate::protocol::vless::Address;
use anyhow::Result;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

pub const MUX_COOL_ADDRESS: &str = "v1.mux.cool";
pub const MUX_COOL_PORT: u16 = 9527;

pub const STATUS_NEW: u8 = 0x01;
pub const STATUS_KEEP: u8 = 0x02;
pub const STATUS_END: u8 = 0x03;
pub const STATUS_KEEP_ALIVE: u8 = 0x04;
pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;
const NETWORK_TCP: u8 = 0x01;

/// Largest data chunk per frame (Xray splits streams at 8 KiB).
pub const MAX_CHUNK: usize = 8 * 1024;
const MAX_METADATA: usize = 512;
/// Sessions a connection serves before it is retired (Xray `MaxConnection`).
pub const MAX_SESSIONS_PER_CONNECTION: u16 = 128;
const IDLE_CHECK: Duration = Duration::from_secs(16);
const FRAME_QUEUE: usize = 64;
const SESSION_QUEUE: usize = 32;

/// Build one frame. `target` is set for `New` frames only; `data` adds the
/// DATA option and the payload.
pub fn encode_frame(
    id: u16,
    status: u8,
    mut option: u8,
    target: Option<(&Address, u16)>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + data.map_or(0, |d| d.len() + 2));
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(status);
    if data.is_some() {
        option |= OPTION_DATA;
    }
    out.push(option);
    if let Some((address, port)) = target {
        out.push(NETWORK_TCP);
        out.extend_from_slice(&port.to_be_bytes());
        match address {
            Address::Ipv4(ip) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                out.push(2);
                out.push(domain.len().min(255) as u8);
                out.extend_from_slice(&domain.as_bytes()[..domain.len().min(255)]);
            }
            Address::Ipv6(ip) => {
                out.push(3);
                out.extend_from_slice(&ip.octets());
            }
        }
    }
    let meta_len = (out.len() - 2) as u16;
    out[..2].copy_from_slice(&meta_len.to_be_bytes());
    if let Some(data) = data {
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// A frame as read from the peer. Metadata past the option byte (the `New`
/// target, UDP addresses) is kept raw in `meta`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub id: u16,
    pub status: u8,
    pub option: u8,
    pub meta: Vec<u8>,
    pub data: Option<Vec<u8>>,
}

impl Frame {
    /// Target of a `New` frame: `(address, port)`.
    pub fn target(&self) -> Option<(Address, u16)> {
        let m = &self.meta;
        if self.status != STATUS_NEW || m.len() < 4 || m[0] != NETWORK_TCP {
            return None;
        }
        let port = u16::from_be_bytes([m[1], m[2]]);
        let address = match m[3] {
            1 if m.len() >= 8 => Address::Ipv4([m[4], m[5], m[6], m[7]].into()),
            2 if m.len() >= 5 && m.len() >= 5 + m[4] as usize => {
                Address::Domain(String::from_utf8_lossy(&m[5..5 + m[4] as usize]).into_owned())
            }
            3 if m.len() >= 20 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&m[4..20]);
                Address::Ipv6(o.into())
            }
            _ => return None,
        };
        Some((address, port))
    }
}

/// Read one frame; `Ok(None)` on a clean EOF between frames.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Frame>> {
    let mut len = [0u8; 2];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let meta_len = u16::from_be_bytes(len) as usize;
    if !(4..=MAX_METADATA).contains(&meta_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mux: invalid metadata length {meta_len}"),
        ));
    }
    let mut meta = vec![0u8; meta_len];
    reader.read_exact(&mut meta).await?;
    let id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    let data = if option & OPTION_DATA != 0 {
        let mut len = [0u8; 2];
        reader.read_exact(&mut len).await?;
        let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut data).await?;
        Some(data)
    } else {
        None
    };
    Ok(Some(Frame {
        id,
        status,
        option,
        meta: meta[4..].to_vec(),
        data,
    }))
}

/// Parse one frame from the front of `buf`: `Ok(Some((frame, used)))`, or
/// `Ok(None)` when more bytes are needed.
pub fn parse_frame(buf: &[u8]) -> io::Result<Option<(Frame, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let meta_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if !(4..=MAX_METADATA).contains(&meta_len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("mux: invalid metadata length {meta_len}"),
        ));
    }
    if buf.len() < 2 + meta_len {
        return Ok(None);
    }
    let meta = &buf[2..2 + meta_len];
    let (id, status, option) = (u16::from_be_bytes([meta[0], meta[1]]), meta[2], meta[3]);
    let mut used = 2 + meta_len;
    let data = if option & OPTION_DATA != 0 {
        if buf.len() < used + 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([buf[used], buf[used + 1]]) as usize;
        if buf.len() < used + 2 + len {
            return Ok(None);
        }
        let data = buf[used + 2..used + 2 + len].to_vec();
        used += 2 + len;
        Some(data)
    } else {
        None
    };
    Ok(Some((
        Frame {
            id,
            status,
            option,
            meta: meta[4..].to_vec(),
            data,
        },
        used,
    )))
}

/// One multiplexed VLESS connection and its sessions.
struct Connection {
    key: String,
    seq: usize,
    concurrency: usize,
    frames: mpsc::Sender<Vec<u8>>,
    sessions: Mutex<HashMap<u16, PollSender<Vec<u8>>>>,
    /// Sessions ever allocated; also the next session id.
    count: AtomicU16,
    closed: AtomicBool,
    /// No new sessions (server switched or session budget spent).
    retired: AtomicBool,
    driver: Mutex<Option<AbortHandle>>,
}

impl Connection {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn active(&self) -> usize {
        self.sessions.lock().expect("mux sessions poisoned").len()
    }

    /// Reserve a session id, or `None` when the connection cannot take more.
    fn allocate(&self) -> Option<(u16, mpsc::Receiver<Vec<u8>>)> {
        let mut sessions = self.sessions.lock().expect("mux sessions poisoned");
        if self.is_closed()
            || self.retired.load(Ordering::Acquire)
            || sessions.len() >= self.concurrency
            || self.count.load(Ordering::Acquire) >= MAX_SESSIONS_PER_CONNECTION
        {
            return None;
        }
        let id = self.count.fetch_add(1, Ordering::AcqRel) + 1;
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        sessions.insert(id, PollSender::new(tx));
        Some((id, rx))
    }

    fn remove(&self, id: u16) {
        self.sessions
            .lock()
            .expect("mux sessions poisoned")
            .remove(&id);
    }

    /// Close the connection: every session reads EOF, the driver stops.
    fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.sessions.lock().expect("mux sessions poisoned").clear();
        if let Some(driver) = self.driver.lock().expect("mux driver poisoned").take() {
            driver.abort();
        }
        debug!("mux: connection #{} to {} closed", self.seq, self.key);
    }

    /// Hand `data` to session `id`. `Err(data)` means its queue is full for
    /// now (the waker is registered); a gone session gets an `End` frame
    /// queued in `out`, like Xray.
    fn poll_deliver(
        &self,
        cx: &mut Context<'_>,
        id: u16,
        data: Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<(), Vec<u8>> {
        let mut sessions = self.sessions.lock().expect("mux sessions poisoned");
        let Some(session) = sessions.get_mut(&id) else {
            out.extend_from_slice(&encode_frame(id, STATUS_END, 0, None, None));
            return Ok(());
        };
        match session.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                if session.send_item(data).is_err() {
                    sessions.remove(&id);
                }
                Ok(())
            }
            Poll::Ready(Err(_)) => {
                sessions.remove(&id);
                Ok(())
            }
            Poll::Pending => Err(data),
        }
    }
}

/// Drive one connection in a single task: dial, then move frames both ways
/// until the stream ends or the connection sits idle for a check interval.
/// One task (one waker) for both directions keeps us safe from transports
/// whose reads also write (TLS key updates, WebSocket pongs).
async fn drive<S, F>(conn: Arc<Connection>, dial: F, mut rx: mpsc::Receiver<Vec<u8>>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: Future<Output = Result<S>> + Send + 'static,
{
    let mut stream = match dial.await {
        Ok(stream) => stream,
        Err(e) => {
            warn!("mux: connection #{} to {} failed: {e}", conn.seq, conn.key);
            conn.close();
            return;
        }
    };
    let mut out: Vec<u8> = Vec::new();
    let mut out_pos = 0usize;
    let mut need_flush = false;
    let mut raw: Vec<u8> = Vec::new();
    let mut raw_pos = 0usize;
    let mut undelivered: Option<(u16, Vec<u8>)> = None;
    let mut idle = tokio::time::interval(IDLE_CHECK);
    idle.reset();
    let mut last_count = conn.count.load(Ordering::Acquire);
    let mut chunk = vec![0u8; 16 * 1024];

    let result: io::Result<()> = std::future::poll_fn(|cx| {
        loop {
            let mut progress = false;

            // Outgoing: batch queued frames, write, flush.
            if out_pos == out.len() {
                out.clear();
                out_pos = 0;
                while out.len() < 64 * 1024 {
                    match rx.poll_recv(cx) {
                        Poll::Ready(Some(frame)) => out.extend_from_slice(&frame),
                        Poll::Ready(None) | Poll::Pending => break,
                    }
                }
            }
            while out_pos < out.len() {
                match Pin::new(&mut stream).poll_write(cx, &out[out_pos..]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        out_pos += n;
                        need_flush = true;
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => break,
                }
            }
            if need_flush && out_pos == out.len() {
                match Pin::new(&mut stream).poll_flush(cx) {
                    Poll::Ready(Ok(())) => need_flush = false,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }

            // Incoming: deliver what is waiting, parse more, read more.
            if let Some((id, data)) = undelivered.take() {
                match conn.poll_deliver(cx, id, data, &mut out) {
                    Ok(()) => progress = true,
                    Err(data) => undelivered = Some((id, data)),
                }
            }
            // `out` also collects End replies for unknown sessions; a server
            // flooding those must not grow it without bound, so parsing waits
            // for the batch to drain.
            while undelivered.is_none() && out.len() < 64 * 1024 {
                let (frame, used) = match parse_frame(&raw[raw_pos..]) {
                    Ok(Some(parsed)) => parsed,
                    Ok(None) => break,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                raw_pos += used;
                progress = true;
                match frame.status {
                    STATUS_KEEP => {
                        if let Some(data) = frame.data {
                            if let Err(data) = conn.poll_deliver(cx, frame.id, data, &mut out) {
                                undelivered = Some((frame.id, data));
                            }
                        }
                    }
                    STATUS_END => {
                        if frame.option & OPTION_ERROR != 0 {
                            debug!(
                                "mux: session {} ended by the server with an error",
                                frame.id
                            );
                        }
                        conn.remove(frame.id);
                    }
                    // The server never opens sessions towards us; keep-alives carry nothing.
                    STATUS_NEW | STATUS_KEEP_ALIVE => {}
                    other => debug!("mux: unknown frame status {other}"),
                }
            }
            if raw_pos == raw.len() {
                raw.clear();
                raw_pos = 0;
            } else if raw_pos > 64 * 1024 {
                raw.drain(..raw_pos);
                raw_pos = 0;
            }
            if undelivered.is_none() {
                let mut buf = ReadBuf::new(&mut chunk);
                match Pin::new(&mut stream).poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        if buf.filled().is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        raw.extend_from_slice(buf.filled());
                        progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {}
                }
            }

            if idle.poll_tick(cx).is_ready() {
                let count = conn.count.load(Ordering::Acquire);
                if conn.active() == 0 && count == last_count {
                    debug!("mux: connection #{} idle, closing", conn.seq);
                    return Poll::Ready(Ok(()));
                }
                last_count = count;
            }
            if !progress {
                return Poll::Pending;
            }
        }
    })
    .await;
    if let Err(e) = result {
        debug!("mux: connection #{} ended: {e}", conn.seq);
    }
    conn.close();
    let _ = stream.shutdown().await;
}

/// Picks or opens a multiplexed connection for every new TCP session.
pub struct MuxManager {
    concurrency: usize,
    connections: Mutex<Vec<Arc<Connection>>>,
    next_seq: Mutex<usize>,
}

impl MuxManager {
    pub fn new(concurrency: usize) -> Self {
        Self {
            concurrency: concurrency.max(1),
            connections: Mutex::new(Vec::new()),
            next_seq: Mutex::new(0),
        }
    }

    /// Open a session to `target`. `key` identifies the server; connections
    /// to another key are retired so a server switch takes effect for new
    /// sessions. `dial` produces the VLESS connection to `v1.mux.cool` when a
    /// new multiplexed connection is needed; it runs in the background and
    /// sessions queue frames until it completes.
    pub fn open<S, F>(&self, key: &str, target: (Address, u16), dial: F) -> MuxStream
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        F: Future<Output = Result<S>> + Send + 'static,
    {
        let mut connections = self.connections.lock().expect("mux connections poisoned");
        connections.retain(|c| !c.is_closed());
        for c in connections.iter() {
            if c.key != key {
                c.retired.store(true, Ordering::Release);
            }
        }
        for c in connections.iter() {
            if let Some((id, rx)) = c.allocate() {
                return MuxStream::new(c.clone(), id, rx, target);
            }
        }

        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let seq = {
            let mut next = self.next_seq.lock().expect("mux seq poisoned");
            *next += 1;
            *next
        };
        let conn = Arc::new(Connection {
            key: key.to_string(),
            seq,
            concurrency: self.concurrency,
            frames: tx,
            sessions: Mutex::new(HashMap::new()),
            count: AtomicU16::new(0),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            driver: Mutex::new(None),
        });
        debug!("mux: opening connection #{seq} to {key}");
        let driver = tokio::spawn(drive(conn.clone(), dial, rx));
        *conn.driver.lock().expect("mux driver poisoned") = Some(driver.abort_handle());
        let (id, session_rx) = conn.allocate().expect("fresh mux connection has room");
        connections.push(conn.clone());
        MuxStream::new(conn, id, session_rx, target)
    }

    /// Open connections (for the UI).
    pub fn connections(&self) -> usize {
        self.connections
            .lock()
            .expect("mux connections poisoned")
            .iter()
            .filter(|c| !c.is_closed())
            .count()
    }
}

/// One session: `AsyncRead`/`AsyncWrite` over frames of a shared connection.
pub struct MuxStream {
    id: u16,
    conn: Arc<Connection>,
    target: (Address, u16),
    frames: PollSender<Vec<u8>>,
    incoming: mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    pending_pos: usize,
    opened: bool,
    ended: bool,
}

impl MuxStream {
    fn new(
        conn: Arc<Connection>,
        id: u16,
        incoming: mpsc::Receiver<Vec<u8>>,
        target: (Address, u16),
    ) -> Self {
        let frames = PollSender::new(conn.frames.clone());
        Self {
            id,
            conn,
            target,
            frames,
            incoming,
            pending: Vec::new(),
            pending_pos: 0,
            opened: false,
            ended: false,
        }
    }

    pub fn session_id(&self) -> u16 {
        self.id
    }

    fn closed_error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "mux connection closed")
    }

    /// Queue a frame; `Pending` while the connection's queue is full.
    fn poll_send(&mut self, cx: &mut Context<'_>, frame: Vec<u8>) -> Poll<io::Result<()>> {
        if self.conn.is_closed() {
            return Poll::Ready(Err(Self::closed_error()));
        }
        ready!(self.frames.poll_reserve(cx)).map_err(|_| Self::closed_error())?;
        self.frames
            .send_item(frame)
            .map_err(|_| Self::closed_error())?;
        Poll::Ready(Ok(()))
    }

    fn open_frame(&self, data: Option<&[u8]>) -> Vec<u8> {
        encode_frame(
            self.id,
            STATUS_NEW,
            0,
            Some((&self.target.0, self.target.1)),
            data,
        )
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(buf.remaining());
                buf.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                return Poll::Ready(Ok(()));
            }
            if !this.opened {
                // The local side waits for the server to speak first: open the
                // session without data.
                let frame = this.open_frame(None);
                ready!(this.poll_send(cx, frame))?;
                this.opened = true;
            }
            match ready!(this.incoming.poll_recv(cx)) {
                Some(data) => {
                    this.pending = data;
                    this.pending_pos = 0;
                }
                None => return Poll::Ready(Ok(())), // session ended
            }
        }
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Err(Self::closed_error()));
        }
        let chunk = &buf[..buf.len().min(MAX_CHUNK)];
        let frame = if this.opened {
            encode_frame(this.id, STATUS_KEEP, 0, None, Some(chunk))
        } else {
            this.open_frame(Some(chunk))
        };
        ready!(this.poll_send(cx, frame))?;
        this.opened = true;
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(Ok(()));
        }
        if this.opened && !this.conn.is_closed() {
            let frame = encode_frame(this.id, STATUS_END, 0, None, None);
            ready!(this.poll_send(cx, frame))?;
        }
        this.ended = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.conn.remove(self.id);
        if self.opened && !self.ended && !self.conn.is_closed() {
            let frame = encode_frame(self.id, STATUS_END, 0, None, None);
            let _ = self.conn.frames.try_send(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let target = Address::Domain("example.com".to_string());
        let new = encode_frame(7, STATUS_NEW, 0, Some((&target, 443)), Some(b"hello"));
        // len=4+1+2+1+1+11=20, id 7, New, DATA, tcp, port, domain
        assert_eq!(&new[..4], &[0, 20, 0, 7]);
        assert_eq!(&new[4..6], &[STATUS_NEW, OPTION_DATA]);
        assert_eq!(&new[6..9], &[NETWORK_TCP, 1, 187]);
        assert_eq!(new[9], 2);
        assert_eq!(new[10], 11);
        assert_eq!(&new[22..24], &[0, 5]);
        assert_eq!(&new[24..], b"hello");

        let keep = encode_frame(7, STATUS_KEEP, 0, None, Some(b"xy"));
        let end = encode_frame(7, STATUS_END, OPTION_ERROR, None, None);
        let mut wire = new.clone();
        wire.extend_from_slice(&keep);
        wire.extend_from_slice(&end);

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut cursor = std::io::Cursor::new(wire);
            let f = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(f.id, 7);
            assert_eq!(f.status, STATUS_NEW);
            assert_eq!(f.target(), Some((target.clone(), 443)));
            assert_eq!(f.data.as_deref(), Some(&b"hello"[..]));
            let f = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(
                (f.status, f.data.as_deref()),
                (STATUS_KEEP, Some(&b"xy"[..]))
            );
            let f = read_frame(&mut cursor).await.unwrap().unwrap();
            assert_eq!(
                (f.status, f.option, f.data),
                (STATUS_END, OPTION_ERROR, None)
            );
            assert!(read_frame(&mut cursor).await.unwrap().is_none());
        });
    }

    #[test]
    fn ip_targets_encode_both_families() {
        let v4 = Address::Ipv4([10, 0, 0, 1].into());
        let f = encode_frame(1, STATUS_NEW, 0, Some((&v4, 80)), None);
        assert_eq!(&f[6..], &[NETWORK_TCP, 0, 80, 1, 10, 0, 0, 1]);
        let v6 = Address::Ipv6(std::net::Ipv6Addr::LOCALHOST);
        let f = encode_frame(1, STATUS_NEW, 0, Some((&v6, 80)), None);
        assert_eq!(f[9], 3);
        assert_eq!(f.len(), 10 + 16);
    }
}
