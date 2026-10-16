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
}

impl Request {
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(VERSION).await?;
        writer.write_all(self.uuid.as_bytes()).await?;
        writer.write_u8(0).await?;
        writer.write_u8(self.command as u8).await?;
        writer.write_u16(self.port).await?;
        match &self.address {
            Address::Ipv4(addr) => {
                writer.write_u8(1).await?;
                writer.write_all(&addr.octets()).await?;
            }
            Address::Domain(domain) => {
                if domain.len() > u8::MAX as usize {
                    anyhow::bail!("VLESS domain address length must be <= 255 bytes");
                }
                writer.write_u8(2).await?;
                writer.write_u8(domain.len() as u8).await?;
                writer.write_all(domain.as_bytes()).await?;
            }
            Address::Ipv6(addr) => {
                writer.write_u8(3).await?;
                writer.write_all(&addr.octets()).await?;
            }
        }

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

/// A VLESS session whose response header is consumed lazily.
///
/// Servers such as Xray-core do not send the VLESS response header until they
/// have the first bytes of downstream data, so a client that waits for the
/// header before relaying anything deadlocks on client-speaks-first protocols
/// (HTTP, TLS). This wrapper strips the header from the first bytes read and
/// is transparent afterwards.
pub struct VlessStream<S> {
    inner: S,
    state: ResponseState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseState {
    Header { filled: usize, bytes: [u8; 2] },
    Addons { remaining: usize },
    Ready,
}

impl<S> VlessStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: ResponseState::Header {
                filled: 0,
                bytes: [0; 2],
            },
        }
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
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.state {
                ResponseState::Ready => return Pin::new(&mut this.inner).poll_read(cx, buf),
                ResponseState::Header { filled, mut bytes } => {
                    let mut scratch = [0u8; 2];
                    let mut tmp = ReadBuf::new(&mut scratch[..2 - filled]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut tmp))?;
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
                        this.state = ResponseState::Header { filled, bytes };
                        continue;
                    }
                    if bytes[0] != VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Unsupported VLESS response version: {}", bytes[0]),
                        )));
                    }
                    this.state = match bytes[1] as usize {
                        0 => ResponseState::Ready,
                        remaining => ResponseState::Addons { remaining },
                    };
                }
                ResponseState::Addons { remaining } => {
                    let mut scratch = [0u8; 255];
                    let mut tmp = ReadBuf::new(&mut scratch[..remaining]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut tmp))?;
                    let got = tmp.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "VLESS connection closed inside response addons",
                        )));
                    }
                    this.state = match remaining - got {
                        0 => ResponseState::Ready,
                        remaining => ResponseState::Addons { remaining },
                    };
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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

    #[tokio::test]
    async fn serializes_domain_request() {
        let request = Request {
            uuid: Uuid::nil(),
            command: Command::Tcp,
            port: 443,
            address: Address::Domain("example.com".to_string()),
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
        let mut stream = VlessStream::new(client);

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
        let mut stream = VlessStream::new(client);
        server.write_all(&[7, 0, b'x']).await.unwrap();
        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        let (server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client);
        drop(server);
        let err = stream.read_u8().await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn vless_stream_writes_pass_through_before_response() {
        let (mut server, client) = tokio::io::duplex(64);
        let mut stream = VlessStream::new(client);
        stream.write_all(b"client-first").await.unwrap();
        let mut got = [0u8; 12];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"client-first");
        assert!(!stream.response_received());
    }
}
