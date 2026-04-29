use rustls::ClientConfig;
use rustls::RootStore;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct TlsClient {
    connector: TlsConnector,
    server_name: String,
}

impl TlsClient {
    pub fn new(server_name: impl Into<String>) -> anyhow::Result<Self> {
        let server_name = server_name.into();

        let mut root_store = RootStore::empty();
        root_store.add_parsable_certificates(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(config));

        Ok(Self {
            connector,
            server_name,
        })
    }

    pub async fn connect(
        &self,
        addr: &str,
    ) -> anyhow::Result<MaybeTlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;
        let domain = self.server_name.clone().try_into().map_err(|_| anyhow::anyhow!("Invalid domain"))?;
        let stream = self.connector.connect(domain, tcp).await?;

        Ok(MaybeTlsStream::Tls(stream))
    }
}

pub enum MaybeTlsStream<T> {
    Plain(T),
    Tls(tokio_rustls::client::TlsStream<T>),
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
