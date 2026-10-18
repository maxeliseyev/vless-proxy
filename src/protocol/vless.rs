use crate::protocol::vision::Vision;
use anyhow::Result;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use uuid::Uuid;

pub const VERSION: u8 = 0;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

pub struct Response {
    pub version: u8,
    pub addons: Vec<u8>,
}

pub struct Request {
    pub uuid: Uuid,
    pub command: Command,
    pub port: u16,
    pub address: Address,
    /// VLESS addons `Flow` (e.g. `xtls-rprx-vision`); `None` sends empty addons.
    pub flow: Option<String>,
}

impl Request {
    /// Serialize the request header (version, uuid, addons, command, target).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(64);
        out.push(VERSION);
        out.extend_from_slice(self.uuid.as_bytes());
        match self.flow.as_deref() {
            Some(flow) if !flow.is_empty() => {
                // protobuf `Addons { string Flow = 1; }`
                if flow.len() > 127 {
                    anyhow::bail!("VLESS flow name too long");
                }
                let addons_len = 2 + flow.len();
                out.push(addons_len as u8);
                out.push(0x0a);
                out.push(flow.len() as u8);
                out.extend_from_slice(flow.as_bytes());
            }
            _ => out.push(0),
        }
        out.push(self.command as u8);
        if self.command == Command::Mux {
            // Mux.Cool requests carry no target (Xray `EncodeRequestHeader`).
            return Ok(out);
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        match &self.address {
            Address::Ipv4(addr) => {
                out.push(1);
                out.extend_from_slice(&addr.octets());
            }
            Address::Domain(domain) => {
                if domain.len() > u8::MAX as usize {
                    anyhow::bail!("VLESS domain address length must be <= 255 bytes");
                }
                out.push(2);
                out.push(domain.len() as u8);
                out.extend_from_slice(domain.as_bytes());
            }
            Address::Ipv6(addr) => {
                out.push(3);
                out.extend_from_slice(&addr.octets());
            }
        }
        Ok(out)
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.encode()?).await?;
        Ok(())
    }
}

impl Response {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let version = reader.read_u8().await?;
        if version != VERSION {
            anyhow::bail!("Unsupported VLESS response version: {version}");
        }

        let addons_len = reader.read_u8().await? as usize;
        let mut addons = vec![0u8; addons_len];
        reader.read_exact(&mut addons).await?;

        Ok(Self { version, addons })
    }
}

/// Hooks a transport must offer for XTLS Vision direct copy.
pub trait XtlsDirect {
    fn supports_direct(&self) -> bool;
    fn switch_read_direct(&mut self);
    fn switch_write_direct(&mut self);
}

/// A VLESS session over `S`.
///
/// * The request header is not written until the first payload (or an
///   explicit flush), so both go out in one record like Xray does.
/// * The response header is consumed lazily: servers such as Xray-core only
///   send it together with the first downstream bytes, so waiting for it
///   before relaying deadlocks client-speaks-first protocols.
/// * With [`Vision`] enabled, writes are padded and reads unpadded, and each
///   direction switches the transport to direct copy when the peer says so.
pub struct VlessStream<S> {
    inner: S,
    state: ResponseState,
    vision: Option<Vision>,
    /// Bytes waiting to be written to `inner` (deferred header, padded data).
    pending_out: Vec<u8>,
    pending_pos: usize,
    header_sent: bool,
    write_direct: bool,
    switch_write_after_flush: bool,
    /// Decoded downstream bytes not yet handed to the caller.
    read_buf: Vec<u8>,
    read_pos: usize,
    read_direct: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    Header { filled: usize, bytes: [u8; 2] },
    Addons { remaining: usize },
    Ready,
}

impl<S> VlessStream<S> {
    /// `request_header` is sent ahead of the first write (see type docs).
    pub fn new(inner: S, request_header: Vec<u8>) -> Self {
        let header_sent = request_header.is_empty();
        Self {
            inner,
            state: ResponseState::Header {
                filled: 0,
                bytes: [0; 2],
            },
            vision: None,
            pending_out: request_header,
            pending_pos: 0,
            header_sent,
            write_direct: false,
            switch_write_after_flush: false,
            read_buf: Vec::new(),
            read_pos: 0,
            read_direct: false,
        }
    }

    pub fn with_vision(mut self, vision: Vision) -> Self {
        self.vision = Some(vision);
        self
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// `true` once the response header has been read and validated.
    pub fn response_received(&self) -> bool {
        self.state == ResponseState::Ready
    }

    pub fn vision_enabled(&self) -> bool {
        self.vision.is_some()
    }

    /// `true` until the request header has left this stream.
    pub fn header_pending(&self) -> bool {
        !self.header_sent
    }

    /// Queue an empty Vision padding block (Xray sends one when no client
    /// payload arrives within 500 ms, so the bare header is never visible).
    /// Call `flush` afterwards.
    pub fn queue_vision_camouflage(&mut self) {
        if let Some(vision) = self.vision.as_mut() {
            if vision.padder.is_padding {
                vision.encode_camouflage(&mut self.pending_out);
            }
        }
    }

    fn pending_len(&self) -> usize {
        self.pending_out.len() - self.pending_pos
    }
}

impl<S: AsyncRead + Unpin> VlessStream<S> {
    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.state {
                ResponseState::Ready => return Poll::Ready(Ok(())),
                ResponseState::Header { filled, mut bytes } => {
                    let mut scratch = [0u8; 2];
                    let mut tmp = ReadBuf::new(&mut scratch[..2 - filled]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut tmp))?;
                    let got = tmp.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS connection closed before response header",
                        )));
                    }
                    bytes[filled..filled + got].copy_from_slice(tmp.filled());
                    let filled = filled + got;
                    if filled < 2 {
                        self.state = ResponseState::Header { filled, bytes };
                        continue;
                    }
                    if bytes[0] != VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Unsupported VLESS response version: {}", bytes[0]),
                        )));
                    }
                    self.state = match bytes[1] as usize {
                        0 => ResponseState::Ready,
                        remaining => ResponseState::Addons { remaining },
                    };
                }
                ResponseState::Addons { remaining } => {
                    let mut scratch = [0u8; 255];
                    let mut tmp = ReadBuf::new(&mut scratch[..remaining]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut tmp))?;
                    let got = tmp.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS connection closed inside response addons",
                        )));
                    }
                    self.state = match remaining - got {
                        0 => ResponseState::Ready,
                        remaining => ResponseState::Addons { remaining },
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + XtlsDirect + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_pos < this.read_buf.len() {
                let n = (this.read_buf.len() - this.read_pos).min(buf.remaining());
                buf.put_slice(&this.read_buf[this.read_pos..this.read_pos + n]);
                this.read_pos += n;
                if this.read_pos == this.read_buf.len() {
                    this.read_buf.clear();
                    this.read_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            ready!(this.poll_response_header(cx))?;
            let vision = match this.vision.as_mut() {
                Some(v) if !this.read_direct => v,
                _ => return Pin::new(&mut this.inner).poll_read(cx, buf),
            };
            let mut scratch = [0u8; crate::protocol::vision::BUF_SIZE];
            let mut tmp = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut tmp))?;
            if tmp.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            if vision.decode_read(tmp.filled(), &mut this.read_buf) {
                this.inner.switch_read_direct();
                this.read_direct = true;
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + XtlsDirect + Unpin> VlessStream<S> {
    /// Write out `pending_out`; once empty, apply a deferred direct switch.
    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending_out.len() {
            let n = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.pending_out[self.pending_pos..])
            )?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_pos += n;
        }
        self.pending_out.clear();
        self.pending_pos = 0;
        self.header_sent = true;
        if self.switch_write_after_flush {
            self.switch_write_after_flush = false;
            self.inner.switch_write_direct();
            self.write_direct = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + XtlsDirect + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        let pass_through = this.header_sent && this.pending_len() == 0;
        match this.vision.as_mut() {
            Some(vision) if !this.write_direct => {
                if vision.encode_write(buf, &mut this.pending_out) {
                    this.switch_write_after_flush = true;
                }
            }
            _ if pass_through => {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            _ => this.pending_out.extend_from_slice(buf),
        }
        if let Poll::Ready(Err(e)) = this.poll_flush_pending(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_pending(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub async fn write_udp_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    if payload.len() > u16::MAX as usize {
        anyhow::bail!("VLESS UDP payload length must be <= 65535 bytes");
    }

    writer.write_u16(payload.len() as u16).await?;
    writer.write_all(payload).await?;
    Ok(())
}

pub async fn read_udp_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let length = reader.read_u16().await? as usize;
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ipv4(addr) => write!(f, "{addr}"),
            Address::Domain(domain) => write!(f, "{domain}"),
            Address::Ipv6(addr) => write!(f, "{addr}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    impl XtlsDirect for tokio::io::DuplexStream {
        fn supports_direct(&self) -> bool {
            false
        }
        fn switch_read_direct(&mut self) {}
        fn switch_write_direct(&mut self) {}
    }

    #[tokio::test]
    async fn serializes_domain_request() {
        let request = Request {
            uuid: Uuid::nil(),
            command: Command::Tcp,
            port: 443,
            address: Address::Domain("example.com".to_string()),
            flow: None,
        };
        let (mut client, mut server) = tokio::io::duplex(256);

        let writer = tokio::spawn(async move {
            request.write_to(&mut server).await.unwrap();
        });

        let mut header = vec![0u8; 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11];
        client.read_exact(&mut header).await.unwrap();
        writer.await.unwrap();

        assert_eq!(header[0], VERSION);
        assert_eq!(&header[1..17], Uuid::nil().as_bytes());
        assert_eq!(header[17], 0);
        assert_eq!(header[18], Command::Tcp as u8);
        assert_eq!(&header[19..21], &[0x01, 0xbb]);
        assert_eq!(header[21], 2);
        assert_eq!(header[22], 11);
        assert_eq!(&header[23..], b"example.com");
    }

    #[tokio::test]
    async fn reads_response_header_without_consuming_payload() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let writer = tokio::spawn(async move {
            server
                .write_all(&[VERSION, 2, 0xaa, 0xbb, 0xcc])
                .await
                .unwrap();
        });

        let response = Response::read_from(&mut client).await.unwrap();
        let mut payload = [0u8; 1];
        client.read_exact(&mut payload).await.unwrap();
        writer.await.unwrap();

        assert_eq!(response.version, VERSION);
        assert_eq!(response.addons, vec![0xaa, 0xbb]);
        assert_eq!(payload, [0xcc]);
    }

    #[tokio::test]
    async fn rejects_overlong_domain_names() {
        let request = Request {
            uuid: Uuid::nil(),
            command: Command::Tcp,
            port: 80,
            address: Address::Domain("a".repeat(256)),
            flow: None,
        };
        let mut sink = tokio::io::sink();

        let error = request.write_to(&mut sink).await.unwrap_err().to_string();
        assert!(error.contains("<= 255 bytes"));
    }

    #[tokio::test]
    async fn writes_and_reads_udp_frames() {
        let payload = b"hello over udp".to_vec();
        let (mut client, mut server) = tokio::io::duplex(256);

        let writer = tokio::spawn(async move {
            write_udp_frame(&mut server, &payload).await.unwrap();
        });

        let frame = read_udp_frame(&mut client).await.unwrap();
        writer.await.unwrap();

        assert_eq!(frame, b"hello over udp");
    }

    #[tokio::test]
    async fn rejects_oversized_udp_frame() {
        let mut sink = tokio::io::sink();

        let error = write_udp_frame(&mut sink, &vec![0u8; 65_536])
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("<= 65535 bytes"));
    }

    #[tokio::test]
    async fn vless_stream_strips_response_header_split_across_reads() {
        let (mut server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client, Vec::new());

        server.write_all(&[VERSION]).await.unwrap();
        server.write_all(&[2]).await.unwrap();
        server.write_all(&[0xAA]).await.unwrap();
        server.write_all(&[0xBB, b'o', b'k']).await.unwrap();

        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
        assert!(stream.response_received());

        server.write_all(b"more").await.unwrap();
        let mut out = [0u8; 4];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"more");
    }

    #[tokio::test]
    async fn vless_stream_rejects_bad_version_and_early_eof() {
        let (mut server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client, Vec::new());
        server.write_all(&[7, 0, b'x']).await.unwrap();
        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let (server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client, Vec::new());
        drop(server);
        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn vless_stream_writes_pass_through_before_response() {
        let (mut server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client, Vec::new());
        stream.write_all(b"client-first").await.unwrap();
        let mut got = [0u8; 12];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"client-first");
        assert!(!stream.response_received());
    }

    #[test]
    fn mux_request_has_no_target() {
        let request = Request {
            uuid: Uuid::nil(),
            command: Command::Mux,
            port: 9527,
            address: Address::Domain("v1.mux.cool".to_string()),
            flow: None,
        };
        let bytes = request.encode().unwrap();
        assert_eq!(bytes.len(), 1 + 16 + 1 + 1);
        assert_eq!(bytes[17], 0);
        assert_eq!(bytes[18], Command::Mux as u8);
    }

    #[test]
    fn encodes_vision_flow_as_protobuf_addons() {
        let request = Request {
            uuid: Uuid::nil(),
            command: Command::Tcp,
            port: 443,
            address: Address::Ipv4([1, 2, 3, 4].into()),
            flow: Some("xtls-rprx-vision".to_string()),
        };
        let bytes = request.encode().unwrap();
        assert_eq!(bytes[0], VERSION);
        assert_eq!(&bytes[1..17], Uuid::nil().as_bytes());
        assert_eq!(bytes[17], 18, "addons length");
        assert_eq!(&bytes[18..20], &[0x0a, 16]);
        assert_eq!(&bytes[20..36], b"xtls-rprx-vision");
        assert_eq!(bytes[36], Command::Tcp as u8);
        assert_eq!(&bytes[37..39], &443u16.to_be_bytes());
        assert_eq!(&bytes[39..], &[1, 1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn request_header_goes_out_with_first_payload() {
        let (mut server, client) = tokio::io::duplex(1024);
        let mut stream = VlessStream::new(client, b"HDR".to_vec());
        assert!(stream.header_pending());
        stream.write_all(b"payload").await.unwrap();
        stream.flush().await.unwrap();
        assert!(!stream.header_pending());
        let mut got = [0u8; 10];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HDRpayload");

        // explicit flush sends a lone header
        let (mut server, client) = tokio::io::duplex(1024);
        let mut stream = VlessStream::new(client, b"HDR".to_vec());
        stream.flush().await.unwrap();
        let mut got = [0u8; 3];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HDR");
    }

    #[tokio::test]
    async fn vision_stream_pads_and_unpads_against_mirror_peer() {
        use crate::protocol::vision::{Unpadder, Vision, CMD_END, PADDING_OVERHEAD};
        let uuid = [0x42u8; 16];
        let (mut server, client) = tokio::io::duplex(65536);
        let mut stream = VlessStream::new(client, vec![VERSION, 0]).with_vision(Vision::new(uuid));

        // client -> server: header + padded block in one go
        stream.write_all(b"hello over vision").await.unwrap();
        stream.flush().await.unwrap();
        let mut wire = vec![0u8; 4096];
        let n = server.read(&mut wire).await.unwrap();
        let wire = &wire[..n];
        assert_eq!(&wire[..2], &[VERSION, 0], "request header first");
        assert_eq!(&wire[2..18], &uuid, "then the uuid marker");
        let mut unpadder = Unpadder::new(uuid);
        let mut content = Vec::new();
        unpadder.unpad(&wire[2..], &mut content);
        assert_eq!(content, b"hello over vision");
        let block = n - 2 - PADDING_OVERHEAD - "hello over vision".len();
        assert!(
            block < 256,
            "non-TLS payload gets short padding, got {block}"
        );

        // server -> client: response header + padded reply, split over two writes
        let mut reply = vec![VERSION, 0];
        let mut padder = crate::protocol::vision::Padder::new(uuid, Default::default());
        padder.pad(
            b"reply ",
            crate::protocol::vision::CMD_CONTINUE,
            true,
            &mut reply,
        );
        padder.pad(b"done", CMD_END, false, &mut reply);
        let (first, second) = reply.split_at(40);
        server.write_all(first).await.unwrap();
        server.flush().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        got.extend_from_slice(&buf[..n]);
        server.write_all(second).await.unwrap();
        server.flush().await.unwrap();
        while got.len() < 10 {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"reply done");
        assert!(stream.response_received());
    }
}
