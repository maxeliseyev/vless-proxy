//! WebSocket transport (`network = "ws"` in Xray terms): the VLESS byte
//! stream is carried in binary WebSocket frames over TLS or plain TCP.
//! Each write becomes one frame, reads concatenate frame payloads, which is
//! exactly how Xray-core's `ws` transport behaves.

use anyhow::{Context, Result};
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::client::ClientRequestBuilder;
use tokio_tungstenite::tungstenite::http::Uri;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::WebSocketStream;
use tracing::debug;

/// Browser-like User-Agent, like Xray's default for the `ws` dialer.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

/// `AsyncRead + AsyncWrite` over a WebSocket connection.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    read_buf: Bytes,
    read_pos: usize,
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Bytes::new(),
            read_pos: 0,
            eof: false,
        }
    }

    /// Perform the HTTP upgrade on an already connected (and, if needed,
    /// TLS-wrapped) stream. `host` goes into the `Host` header, `path` is the
    /// request path (`/` if empty).
    pub async fn connect(stream: S, host: &str, path: &str) -> Result<Self> {
        let path = if path.is_empty() {
            "/".to_string()
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let uri: Uri = format!("ws://{host}{path}")
            .parse()
            .with_context(|| format!("invalid WebSocket host/path: {host}{path}"))?;
        let request = ClientRequestBuilder::new(uri).with_header("User-Agent", USER_AGENT);
        debug!("WebSocket upgrade: host {host} path {path}");
        let config = WebSocketConfig::default();
        let (inner, response) =
            tokio_tungstenite::client_async_with_config(request, stream, Some(config))
                .await
                .context("WebSocket upgrade failed")?;
        debug!("WebSocket upgraded: HTTP {}", response.status());
        Ok(Self::new(inner))
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::other(e)
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => {
                    this.read_buf = b;
                    this.read_pos = 0;
                }
                Some(Ok(Message::Text(t))) => {
                    this.read_buf = Bytes::from(t.as_str().as_bytes().to_vec());
                    this.read_pos = 0;
                }
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                    // tungstenite queued the pong; push it out opportunistically.
                    let _ = Pin::new(&mut this.inner).poll_flush(cx);
                }
                Some(Ok(Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(e)) => return Poll::Ready(Err(ws_err(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(ws_err)?;
        Pin::new(&mut this.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(ws_err)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(ws_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn frames_round_trip_as_a_byte_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut s = WsStream::new(ws);
            let mut got = [0u8; 11];
            s.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"hello world");
            s.write_all(b"ok").await.unwrap();
            s.write_all(&[7u8; 70_000]).await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut client = WsStream::connect(tcp, "example.test", "/vless")
            .await
            .unwrap();
        client.write_all(b"hello ").await.unwrap();
        client.write_all(b"world").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 2];
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ok");
        let mut big = Vec::new();
        client.read_to_end(&mut big).await.unwrap();
        assert_eq!(big.len(), 70_000);
        assert!(big.iter().all(|&b| b == 7));
        server.await.unwrap();
    }
}
