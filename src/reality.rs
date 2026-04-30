use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct RealityClient {
    server_name: String,
    sni: String,
    public_key: [u8; 32],
    short_id: [u8; 8],
}

impl RealityClient {
    pub fn new(
        server_name: impl Into<String>,
        sni: impl Into<String>,
        public_key: &str,
        short_id: &str,
    ) -> Result<Self> {
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(public_key)
            .with_context(|| format!("Invalid REALITY public key: {}", public_key))?;
        
        if pk_bytes.len() != 32 {
            anyhow::bail!("REALITY public key must be 32 bytes");
        }
        
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&pk_bytes);
        
        let short_id_bytes = hex::decode(short_id)
            .with_context(|| format!("Invalid REALITY short ID: {}", short_id))?;
        
        if short_id_bytes.len() != 8 {
            anyhow::bail!("REALITY short ID must be 8 bytes (16 hex chars)");
        }
        
        let mut short_id = [0u8; 8];
        short_id.copy_from_slice(&short_id_bytes);
        
        Ok(Self {
            server_name: server_name.into(),
            sni: sni.into(),
            public_key,
            short_id,
        })
    }

    pub async fn connect(
        &self,
        addr: impl tokio::net::ToSocketAddrs,
    ) -> Result<RealityStream<TcpStream>> {
        let tcp = TcpStream::connect(addr).await?;
        
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(self.public_key);
        let shared_secret = ephemeral.diffie_hellman(&server_public);
        
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        
        debug!("REALITY handshake with SNI: {}", self.sni);
        
        let stream = RealityStream {
            inner: tcp,
            shared_secret: shared_secret.as_bytes().to_vec(),
            authenticated: false,
        };
        
        Ok(stream)
    }
}

pub struct RealityStream<T> {
    inner: T,
    shared_secret: Vec<u8>,
    authenticated: bool,
}

impl<T: AsyncRead + AsyncWrite + Unpin> RealityStream<T> {
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for RealityStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RealityStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}
