//! XHTTP transport (Xray `splithttp`): the VLESS stream rides on HTTP
//! requests so it looks like ordinary web traffic and passes through CDNs.
//!
//! Modes, as in Xray:
//! - `stream-one`: one POST whose request body carries the uplink and whose
//!   response body carries the downlink (needs HTTP/2; default with REALITY).
//! - `stream-up`: a GET for the downlink plus a POST with a streaming body
//!   for the uplink, tied together by a session id in the path.
//! - `packet-up`: a GET for the downlink plus one POST per uplink chunk with
//!   a sequence number (default over TLS and the only mode over HTTP/1.1).
//!
//! Requests carry Xray's padding (`Referer: <url>?x_padding=XXX…`),
//! `Content-Type: application/grpc` on streaming uploads, and custom headers.
//! HTTP/2 is used over REALITY (prior knowledge) and when TLS negotiates `h2`;
//! HTTP/1.1 otherwise.

use crate::config::{ServerConfig, TransportSecurity};
use crate::protocol::reality::tls::RealityConnector;
use crate::transport::tls::TlsClient;
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde_json::Value;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const UP_QUEUE: usize = 16;
const DOWN_QUEUE: usize = 16;
const WRITE_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Mode::Auto,
            "stream-one" => Mode::StreamOne,
            "stream-up" => Mode::StreamUp,
            "packet-up" => Mode::PacketUp,
            other => bail!("unknown xhttp mode {other:?} (auto, stream-one, stream-up, packet-up)"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::StreamOne => "stream-one",
            Mode::StreamUp => "stream-up",
            Mode::PacketUp => "packet-up",
        }
    }
}

/// Effective transport settings: `path`/`host`/`mode` plus what the link's
/// `extra` JSON (or Xray `xhttpSettings`) adds.
#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub query: String,
    pub host: String,
    pub mode: Mode,
    pub headers: Vec<(String, String)>,
    pub no_grpc_header: bool,
    pub padding_bytes: (usize, usize),
    pub max_post_bytes: usize,
    pub min_post_interval: Duration,
    pub uplink_method: Method,
}

impl XhttpConfig {
    pub fn from_server(server: &ServerConfig) -> Result<Self> {
        let raw_path = server.ws_path.as_deref().unwrap_or("/");
        let (path, query) = match raw_path.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (raw_path.to_string(), String::new()),
        };
        let mut path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        // Session id and seq go into the path (Xray's default placement).
        if !path.ends_with('/') {
            path.push('/');
        }
        let host = server
            .ws_host
            .as_deref()
            .filter(|h| !h.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| match server.transport_security() {
                Ok(TransportSecurity::None) => server.address.clone(),
                _ => server.tls_server_name().to_string(),
            });
        let mut config = Self {
            path,
            query,
            host,
            mode: Mode::parse(server.xhttp_mode.as_deref().unwrap_or(""))?,
            headers: Vec::new(),
            no_grpc_header: false,
            padding_bytes: (100, 1000),
            max_post_bytes: 1_000_000,
            min_post_interval: Duration::from_millis(30),
            uplink_method: Method::POST,
        };
        if let Some(extra) = server
            .xhttp_extra
            .as_deref()
            .filter(|e| !e.trim().is_empty())
        {
            let extra: Value =
                serde_json::from_str(extra).context("server.xhttp_extra is not valid JSON")?;
            config.apply_extra(&extra)?;
        }
        Ok(config)
    }

    /// Xray `xhttpSettings` keys that affect the client.
    fn apply_extra(&mut self, extra: &Value) -> Result<()> {
        if let Some(mode) = extra["mode"].as_str() {
            self.mode = Mode::parse(mode)?;
        }
        if let Some(headers) = extra["headers"].as_object() {
            for (k, v) in headers {
                if let Some(v) = v.as_str() {
                    self.headers.push((k.clone(), v.to_string()));
                }
            }
        }
        if extra["noGRPCHeader"].as_bool() == Some(true) {
            self.no_grpc_header = true;
        }
        if let Some(range) = int_range(&extra["xPaddingBytes"]) {
            if range.1 > 0 {
                self.padding_bytes = range;
            }
        }
        if let Some(range) = int_range(&extra["scMaxEachPostBytes"]) {
            if range.1 > 0 {
                self.max_post_bytes = range.0.max(1);
            }
        }
        if let Some(range) = int_range(&extra["scMinPostsIntervalMs"]) {
            if range.1 > 0 {
                self.min_post_interval = Duration::from_millis(range.0 as u64);
            }
        }
        if let Some(m) = extra["uplinkHTTPMethod"].as_str().filter(|m| !m.is_empty()) {
            self.uplink_method = Method::from_bytes(m.as_bytes()).context("uplinkHTTPMethod")?;
        }
        for unsupported in [
            "downloadSettings",
            "sessionIDPlacement",
            "seqPlacement",
            "uplinkDataPlacement",
            "xPaddingObfsMode",
        ] {
            if !extra[unsupported].is_null() && extra[unsupported] != Value::Bool(false) {
                warn!("xhttp: {unsupported} is not supported yet and is ignored");
            }
        }
        Ok(())
    }

    fn effective_mode(&self, security: TransportSecurity) -> Mode {
        match self.mode {
            Mode::Auto if security == TransportSecurity::Reality => Mode::StreamOne,
            Mode::Auto => Mode::PacketUp,
            m => m,
        }
    }

    /// Request URL with the session id and sequence appended to the path.
    fn url(&self, secure: bool, session: &str, seq: Option<u64>) -> String {
        let mut path = self.path.clone();
        if !session.is_empty() {
            path.push_str(session);
            if let Some(seq) = seq {
                path.push('/');
                path.push_str(&seq.to_string());
            }
        }
        let mut url = format!(
            "{}://{}{}",
            if secure { "https" } else { "http" },
            self.host,
            path
        );
        if !self.query.is_empty() {
            url.push('?');
            url.push_str(&self.query);
        }
        url
    }

    /// Xray's padding: the request URL with `x_padding` in the `Referer`.
    fn referer(&self, secure: bool) -> String {
        let n = rand_between(self.padding_bytes.0, self.padding_bytes.1);
        let mut base = format!(
            "{}://{}{}",
            if secure { "https" } else { "http" },
            self.host,
            self.path
        );
        base.push_str("?x_padding=");
        base.extend(std::iter::repeat_n('X', n));
        base
    }
}

/// Xray `Int32Range`: a number, `"from-to"` or `{from, to}`.
fn int_range(v: &Value) -> Option<(usize, usize)> {
    match v {
        Value::Number(n) => n.as_u64().map(|n| (n as usize, n as usize)),
        Value::String(s) => {
            let s = s.trim();
            if let Some((a, b)) = s.split_once('-') {
                Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
            } else {
                let n: usize = s.parse().ok()?;
                Some((n, n))
            }
        }
        Value::Object(_) => Some((
            v["from"].as_u64()? as usize,
            v["to"].as_u64().unwrap_or(v["from"].as_u64()?) as usize,
        )),
        _ => None,
    }
}

fn rand_between(from: usize, to: usize) -> usize {
    if to <= from {
        return from;
    }
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    from + (u64::from_le_bytes(b) % (to - from + 1) as u64) as usize
}

/// Request body: nothing, a fixed chunk, or a stream fed by the session.
pub enum UpBody {
    Empty,
    Full(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl Body for UpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            UpBody::Empty => Poll::Ready(None),
            UpBody::Full(data) => Poll::Ready(data.take().map(|d| Ok(Frame::data(d)))),
            UpBody::Stream(rx) => match ready!(rx.poll_recv(cx)) {
                Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
                None => Poll::Ready(None),
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            UpBody::Empty => true,
            UpBody::Full(data) => data.is_none(),
            UpBody::Stream(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            UpBody::Empty => SizeHint::with_exact(0),
            UpBody::Full(Some(d)) => SizeHint::with_exact(d.len() as u64),
            UpBody::Full(None) => SizeHint::with_exact(0),
            UpBody::Stream(_) => SizeHint::default(),
        }
    }
}

type BoxIo = Box<dyn AsyncReadWrite + Send + Unpin>;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// One HTTP connection that requests can be sent on.
#[derive(Clone)]
enum HttpConn {
    H1(std::sync::Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<UpBody>>>),
    H2(hyper::client::conn::http2::SendRequest<UpBody>),
}

impl HttpConn {
    fn version(&self) -> &'static str {
        match self {
            HttpConn::H1(_) => "1.1",
            HttpConn::H2(_) => "2",
        }
    }

    async fn send(&self, req: Request<UpBody>) -> Result<hyper::Response<Incoming>> {
        match self {
            HttpConn::H2(send) => {
                let mut send = send.clone();
                send.ready().await?;
                Ok(send.send_request(req).await?)
            }
            HttpConn::H1(send) => {
                let mut send = send.lock().await;
                send.ready().await?;
                Ok(send.send_request(req).await?)
            }
        }
    }
}

/// TCP + TLS/REALITY to the server, then the HTTP handshake.
async fn dial(server: &ServerConfig, config: &XhttpConfig) -> Result<HttpConn> {
    let addr = (server.address.as_str(), server.port);
    let security = server.transport_security()?;
    let (io, h2): (BoxIo, bool) = match security {
        TransportSecurity::Reality => {
            let client = crate::proxy::runtime::reality_client(server)?;
            let tcp = TcpStream::connect(addr).await?;
            let stream = RealityConnector::new(client)
                .with_fingerprint(server.fingerprint_kind())
                .connect(tcp)
                .await?;
            (Box::new(stream), true)
        }
        TransportSecurity::Tls => {
            let alpn: Vec<&str> = match server.alpn.as_deref().map(str::trim) {
                Some(a) if !a.is_empty() => a.split(',').map(str::trim).collect(),
                _ => vec!["h2", "http/1.1"],
            };
            let tls = TlsClient::with_alpn(server.tls_server_name().to_string(), &alpn)?
                .with_fingerprint(server.fingerprint_kind());
            let stream = tls.connect_tls(addr).await?;
            let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
            (Box::new(stream), h2)
        }
        TransportSecurity::None => (Box::new(TcpStream::connect(addr).await?), false),
    };
    let _ = config;
    if h2 {
        let (send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(Duration::from_secs(45))
            .keep_alive_timeout(Duration::from_secs(15))
            .handshake(TokioIo::new(io))
            .await
            .context("HTTP/2 handshake")?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("xhttp: HTTP/2 connection ended: {e}");
            }
        });
        Ok(HttpConn::H2(send))
    } else {
        let (send, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(TokioIo::new(io))
            .await
            .context("HTTP/1.1 handshake")?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("xhttp: HTTP/1.1 connection ended: {e}");
            }
        });
        Ok(HttpConn::H1(std::sync::Arc::new(tokio::sync::Mutex::new(
            send,
        ))))
    }
}

fn build_request(
    config: &XhttpConfig,
    conn: &HttpConn,
    method: Method,
    url: &str,
    secure: bool,
    streaming: bool,
    body: UpBody,
) -> Result<Request<UpBody>> {
    let uri: Uri = url
        .parse()
        .with_context(|| format!("bad xhttp URL {url}"))?;
    let mut builder = Request::builder().method(method).uri(uri);
    if matches!(conn, HttpConn::H1(_)) {
        builder = builder.header(http::header::HOST, &config.host);
    }
    builder = builder
        .header(http::header::USER_AGENT, USER_AGENT)
        .header(http::header::REFERER, config.referer(secure));
    for (k, v) in &config.headers {
        let name = HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("header {k}"))?;
        let value = HeaderValue::from_str(v).with_context(|| format!("header {k}"))?;
        builder = builder.header(name, value);
    }
    if streaming && !config.no_grpc_header {
        builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
    }
    Ok(builder.body(body)?)
}

/// The VLESS carrier: bytes written go up through HTTP, bytes read come
/// from the downlink response body.
pub struct XhttpStream {
    up: PollSender<Bytes>,
    down: mpsc::Receiver<Bytes>,
    pending: Bytes,
    description: String,
    closed: bool,
}

impl XhttpStream {
    /// What the probe reports.
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Open an XHTTP session: dial, start the downlink request (and wait for its
/// `200`), and set the uplink going per mode.
pub async fn connect(server: &ServerConfig) -> Result<XhttpStream> {
    let config = XhttpConfig::from_server(server)?;
    let security = server.transport_security()?;
    let secure = security != TransportSecurity::None;
    let conn = dial(server, &config).await?;
    let mode = config.effective_mode(security);
    if matches!(conn, HttpConn::H1(_)) && mode != Mode::PacketUp {
        bail!(
            "xhttp mode {} needs HTTP/2, but the connection negotiated HTTP/1.1; \
             use mode packet-up or enable h2 (alpn) on the server",
            mode.name()
        );
    }
    let session = if mode == Mode::StreamOne {
        String::new()
    } else {
        uuid::Uuid::new_v4().to_string()
    };
    debug!(
        "xhttp: {} mode {} over HTTP/{} host {} path {}",
        server.endpoint(),
        mode.name(),
        conn.version(),
        config.host,
        config.path
    );

    let (up_tx, up_rx) = mpsc::channel::<Bytes>(UP_QUEUE);
    let mut up_rx = Some(up_rx);
    let (down_tx, down_rx) = mpsc::channel::<Bytes>(DOWN_QUEUE);

    // Downlink (and, for stream-one, the uplink body on the same request).
    let (method, body, streaming, url) = match mode {
        Mode::StreamOne => (
            config.uplink_method.clone(),
            UpBody::Stream(up_rx.take().expect("uplink receiver")),
            true,
            config.url(secure, "", None),
        ),
        _ => (
            Method::GET,
            UpBody::Empty,
            false,
            config.url(secure, &session, None),
        ),
    };
    let req = build_request(&config, &conn, method, &url, secure, streaming, body)?;
    let resp = conn.send(req).await.context("xhttp downlink request")?;
    if resp.status() != StatusCode::OK {
        bail!(
            "xhttp: server answered {} to the downlink request ({})",
            resp.status(),
            url
        );
    }
    tokio::spawn(pump_downlink(resp.into_body(), down_tx));

    match mode {
        Mode::StreamOne => {}
        Mode::StreamUp => {
            let url = config.url(secure, &session, None);
            let req = build_request(
                &config,
                &conn,
                config.uplink_method.clone(),
                &url,
                secure,
                true,
                UpBody::Stream(up_rx.take().expect("uplink receiver")),
            )?;
            let conn = conn.clone();
            tokio::spawn(async move {
                match conn.send(req).await {
                    Ok(resp) => {
                        if resp.status() != StatusCode::OK {
                            warn!("xhttp: uplink stream answered {}", resp.status());
                        }
                        let _ = resp.into_body().collect().await;
                    }
                    Err(e) => debug!("xhttp: uplink stream ended: {e}"),
                }
            });
        }
        Mode::PacketUp | Mode::Auto => {
            // Over HTTP/1.1 uploads need their own connection: the GET holds
            // the first one open for the whole session.
            let up_conn = match &conn {
                HttpConn::H1(_) => dial(server, &config).await?,
                HttpConn::H2(_) => conn.clone(),
            };
            tokio::spawn(pump_packets(
                config.clone(),
                up_conn,
                secure,
                session.clone(),
                up_rx.take().expect("uplink receiver"),
            ));
        }
    }

    Ok(XhttpStream {
        up: PollSender::new(up_tx),
        down: down_rx,
        pending: Bytes::new(),
        description: format!(
            "XHTTP {} over HTTP/{} with {} ({}, host {}, path {})",
            mode.name(),
            conn.version(),
            server.endpoint(),
            match security {
                TransportSecurity::Reality => "reality",
                TransportSecurity::Tls => "tls",
                TransportSecurity::None => "plain",
            },
            config.host,
            config.path
        ),
        closed: false,
    })
}

async fn pump_downlink(mut body: Incoming, down: mpsc::Sender<Bytes>) {
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() && down.send(data).await.is_err() {
                        return; // session dropped
                    }
                }
            }
            Err(e) => {
                debug!("xhttp: downlink ended: {e}");
                return;
            }
        }
    }
}

/// packet-up: batch queued writes into POSTs with increasing sequence numbers.
async fn pump_packets(
    config: XhttpConfig,
    conn: HttpConn,
    secure: bool,
    session: String,
    mut up: mpsc::Receiver<Bytes>,
) {
    let mut seq: u64 = 0;
    let mut last_post = Instant::now() - config.min_post_interval;
    let mut queue: VecDeque<Bytes> = VecDeque::new();
    loop {
        let first = match queue.pop_front() {
            Some(b) => b,
            None => match up.recv().await {
                Some(b) => b,
                None => return, // uplink closed
            },
        };
        let mut batch = Vec::with_capacity(first.len());
        batch.extend_from_slice(&first);
        while batch.len() < config.max_post_bytes {
            match up.try_recv() {
                Ok(b) => {
                    if batch.len() + b.len() > config.max_post_bytes {
                        let room = config.max_post_bytes - batch.len();
                        batch.extend_from_slice(&b[..room]);
                        queue.push_front(b.slice(room..));
                        break;
                    }
                    batch.extend_from_slice(&b);
                }
                Err(_) => break,
            }
        }
        let since = last_post.elapsed();
        if since < config.min_post_interval {
            tokio::time::sleep(config.min_post_interval - since).await;
        }
        last_post = Instant::now();
        let url = config.url(secure, &session, Some(seq));
        seq += 1;
        let req = match build_request(
            &config,
            &conn,
            config.uplink_method.clone(),
            &url,
            secure,
            false,
            UpBody::Full(Some(Bytes::from(batch))),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("xhttp: cannot build upload request: {e}");
                return;
            }
        };
        match conn.send(req).await {
            Ok(resp) => {
                let status = resp.status();
                let _ = resp.into_body().collect().await;
                if status != StatusCode::OK {
                    warn!("xhttp: upload #{} answered {status}", seq - 1);
                    return;
                }
            }
            Err(e) => {
                debug!("xhttp: upload #{} failed: {e}", seq - 1);
                return;
            }
        }
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "xhttp session closed")
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            match ready!(this.down.poll_recv(cx)) {
                Some(data) => this.pending = data,
                None => return Poll::Ready(Ok(())), // downlink finished
            }
        }
        let n = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending[..n]);
        this.pending = this.pending.slice(n..);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed {
            return Poll::Ready(Err(closed_error()));
        }
        ready!(this.up.poll_reserve(cx)).map_err(|_| closed_error())?;
        let n = buf.len().min(WRITE_CHUNK);
        this.up
            .send_item(Bytes::copy_from_slice(&buf[..n]))
            .map_err(|_| closed_error())?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Ending the uplink body tells the server the client side is done.
        this.up.close();
        this.closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        self.up.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(path: Option<&str>, host: Option<&str>, security: &str) -> ServerConfig {
        let mut s = crate::config::Config::from_vless_url(
            &crate::config::url::VlessUrl::parse(&format!(
                "vless://00000000-0000-0000-0000-000000000001@203.0.113.9:443?type=xhttp&security={security}&sni=cdn.example{}{}",
                path.map(|p| format!("&path={}", p.replace('/', "%2F"))).unwrap_or_default(),
                host.map(|h| format!("&host={h}")).unwrap_or_default(),
            ))
            .unwrap(),
            1080,
        )
        .server;
        if security == "reality" {
            s.reality_public_key = Some("Mkpry4Un0Ka6RkyokWUIKYWVCuugce3hdEU7dLn6yD4".into());
        }
        s
    }

    #[test]
    fn urls_follow_xray_path_rules() {
        let c = XhttpConfig::from_server(&server(Some("/api/v2?x=1"), Some("h.example"), "tls"))
            .unwrap();
        assert_eq!(c.path, "/api/v2/");
        assert_eq!(c.host, "h.example");
        assert_eq!(c.url(true, "", None), "https://h.example/api/v2/?x=1");
        assert_eq!(
            c.url(true, "sess", Some(3)),
            "https://h.example/api/v2/sess/3?x=1"
        );
        assert!(c
            .referer(true)
            .starts_with("https://h.example/api/v2/?x_padding=XXX"));

        let c = XhttpConfig::from_server(&server(None, None, "tls")).unwrap();
        assert_eq!(c.path, "/");
        assert_eq!(c.host, "cdn.example");
        let c = XhttpConfig::from_server(&server(None, None, "none")).unwrap();
        assert_eq!(c.host, "203.0.113.9");
    }

    #[test]
    fn auto_mode_depends_on_security_and_extra_overrides() {
        let mut s = server(None, None, "reality");
        let c = XhttpConfig::from_server(&s).unwrap();
        assert_eq!(
            c.effective_mode(TransportSecurity::Reality),
            Mode::StreamOne
        );
        assert_eq!(c.effective_mode(TransportSecurity::Tls), Mode::PacketUp);

        s.xhttp_extra = Some(
            r#"{"mode":"stream-up","noGRPCHeader":true,"xPaddingBytes":"200-300",
                "scMaxEachPostBytes":500000,"scMinPostsIntervalMs":{"from":50,"to":60},
                "headers":{"X-Test":"1"}}"#
                .into(),
        );
        let c = XhttpConfig::from_server(&s).unwrap();
        assert_eq!(c.effective_mode(TransportSecurity::Reality), Mode::StreamUp);
        assert!(c.no_grpc_header);
        assert_eq!(c.padding_bytes, (200, 300));
        assert_eq!(c.max_post_bytes, 500000);
        assert_eq!(c.min_post_interval, Duration::from_millis(50));
        assert_eq!(c.headers, vec![("X-Test".to_string(), "1".to_string())]);

        s.xhttp_mode = Some("packet-up".into());
        s.xhttp_extra = None;
        let c = XhttpConfig::from_server(&s).unwrap();
        assert_eq!(c.effective_mode(TransportSecurity::Reality), Mode::PacketUp);
        assert!(Mode::parse("bogus").is_err());
    }
}
