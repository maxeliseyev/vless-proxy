//! Preserve the first uni streams while distinguishing the legacy auth
//! token from HTTP/3 control/QPACK streams. Nothing read here is lost.

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming};
use std::collections::VecDeque;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context as TaskContext, Poll};
use tokio::time::timeout;
use uuid::Uuid;
use vproxy_core::h3::wire::{self, AUTH_LABEL, TOKEN_LEN};

const MAX_PROBES: usize = 16;

type Incoming =
    Pin<Box<dyn Future<Output = Result<quinn::RecvStream, quinn::ConnectionError>> + Send + Sync>>;

pub(crate) struct Transport {
    conn: quinn::Connection,
    inner: h3_quinn::Connection,
    incoming: Incoming,
    pending: VecDeque<Receive>,
}

impl Transport {
    /// A matching token selects the proxy. Any incompatible prefix selects
    /// HTTP/3 immediately. Probe streams concurrently: an empty QPACK stream
    /// whose type byte happens to match a token must not delay the browser.
    pub(crate) async fn classify(
        conn: quinn::Connection,
        users: &[Uuid],
    ) -> Result<(Option<Uuid>, Self)> {
        let mut exporter = [0; TOKEN_LEN];
        conn.export_keying_material(&mut exporter, AUTH_LABEL, b"")
            .map_err(|_| anyhow!("TLS exporter unavailable"))?;
        let tokens: Vec<_> = users
            .iter()
            .map(|user| wire::auth_token(user, &exporter))
            .collect();
        let mut transport = Self {
            incoming: incoming(conn.clone()),
            inner: h3_quinn::Connection::new(conn.clone()),
            conn,
            pending: VecDeque::new(),
        };
        let probe = poll_fn(|cx| -> Poll<Result<Option<Uuid>>> {
            while transport.pending.len() < MAX_PROBES {
                match transport.incoming.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        transport.pending.push_back(Receive::new(stream));
                        transport.incoming = incoming(transport.conn.clone());
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => break,
                }
            }
            for stream in &mut transport.pending {
                let mut buf = [0; TOKEN_LEN];
                loop {
                    let remaining = TOKEN_LEN - stream.prefix.len();
                    match stream.stream.poll_read(cx, &mut buf[..remaining]) {
                        Poll::Pending => break,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                        Poll::Ready(Ok(0)) => return Poll::Ready(Ok(None)),
                        Poll::Ready(Ok(n)) => stream.prefix.extend_from_slice(&buf[..n]),
                    }
                    if stream.prefix.len() == TOKEN_LEN {
                        let token: &[u8; TOKEN_LEN] = stream
                            .prefix
                            .as_ref()
                            .try_into()
                            .expect("the probe reads at most TOKEN_LEN bytes");
                        let user = users
                            .iter()
                            .find(|user| wire::token_matches(user, &exporter, token));
                        return Poll::Ready(Ok(user.copied()));
                    }
                    // This only selects the HTTP parser; authentication still
                    // requires the full constant-time HMAC check above.
                    if !tokens.iter().any(|token| token.starts_with(&stream.prefix)) {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
            if transport.pending.len() == MAX_PROBES {
                return Poll::Ready(Ok(None));
            }
            Poll::Pending
        });
        let user = timeout(super::super::AUTH_TIMEOUT, probe)
            .await
            .unwrap_or(Ok(None))?;
        Ok((user, transport))
    }
}

fn incoming(conn: quinn::Connection) -> Incoming {
    Box::pin(async move { conn.accept_uni().await })
}

impl quic::OpenStreams<Bytes> for Transport {
    type BidiStream = h3_quinn::BidiStream<Bytes>;
    type SendStream = h3_quinn::SendStream<Bytes>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}

impl quic::Connection<Bytes> for Transport {
    type RecvStream = Receive;
    type OpenStreams = h3_quinn::OpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Receive, ConnectionErrorIncoming>> {
        if let Some(stream) = self.pending.pop_front() {
            return Poll::Ready(Ok(stream));
        }
        let result = ready!(self.incoming.as_mut().poll(cx));
        self.incoming = incoming(self.conn.clone());
        Poll::Ready(result.map(Receive::new).map_err(connection_error))
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        quic::Connection::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner)
    }
}

pub(crate) struct Receive {
    stream: quinn::RecvStream,
    prefix: BytesMut,
}

impl Receive {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream,
            prefix: BytesMut::new(),
        }
    }
}

impl quic::RecvStream for Receive {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            return Poll::Ready(Ok(Some(self.prefix.split().freeze())));
        }
        let mut buf = [0; 16 * 1024];
        let n = ready!(self.stream.poll_read(cx, &mut buf)).map_err(|error| match error {
            quinn::ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
                error_code: code.into_inner(),
            },
            quinn::ReadError::ConnectionLost(error) => {
                StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: connection_error(error),
                }
            }
            error => StreamErrorIncoming::Unknown(Box::new(error)),
        })?;
        Poll::Ready(Ok((n != 0).then(|| Bytes::copy_from_slice(&buf[..n]))))
    }

    fn stop_sending(&mut self, error_code: u64) {
        if let Ok(code) = quinn::VarInt::from_u64(error_code) {
            let _ = self.stream.stop(code);
        }
    }

    fn recv_id(&self) -> quic::StreamId {
        u64::from(self.stream.id())
            .try_into()
            .expect("QUIC stream id fits an HTTP/3 stream id")
    }
}

fn connection_error(error: quinn::ConnectionError) -> ConnectionErrorIncoming {
    match error {
        quinn::ConnectionError::ApplicationClosed(close) => {
            ConnectionErrorIncoming::ApplicationClose {
                error_code: close.error_code.into_inner(),
            }
        }
        quinn::ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        error => ConnectionErrorIncoming::Undefined(Arc::new(error)),
    }
}
