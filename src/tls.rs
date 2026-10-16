use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::debug;

pub struct TlsClient {
    connector: tokio_rustls::TlsConnector,
    server_name: String,
}

impl TlsClient {
    pub fn new(server_name: impl Into<String>) -> Result<Self> {
        let server_name = server_name.into();
        let mut root_store = rustls::RootCertStore::empty();

        let native_certs = rustls_native_certs::load_native_certs();
        if !native_certs.errors.is_empty() {
            debug!(
                "Skipped {} invalid native certificates while building trust store",
                native_certs.errors.len()
            );
        }
        root_store.add_parsable_certificates(native_certs.certs);
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        Ok(Self {
            connector,
            server_name,
        })
    }

    pub async fn connect(
        &self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> Result<MaybeTlsStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;
        let domain = ServerName::try_from(self.server_name.as_str())
            .with_context(|| format!("Invalid TLS server name: {}", self.server_name))?
            .to_owned();

        let stream = self.connector.connect(domain, tcp).await?;

        Ok(MaybeTlsStream::Tls(stream))
    }
}

pub enum MaybeTlsStream<T> {
    Plain(T),
    Tls(tokio_rustls::client::TlsStream<T>),
    Reality(crate::reality_tls::RealityStream<T>),
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for MaybeTlsStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Reality(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MaybeTlsStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Reality(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Reality(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Reality(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl<T> crate::vless::XtlsDirect for MaybeTlsStream<T> {
    fn supports_direct(&self) -> bool {
        matches!(self, MaybeTlsStream::Reality(_))
    }

    fn switch_read_direct(&mut self) {
        if let MaybeTlsStream::Reality(s) = self {
            s.switch_read_direct();
        }
    }

    fn switch_write_direct(&mut self) {
        if let MaybeTlsStream::Reality(s) = self {
            s.switch_write_direct();
        }
    }
}
