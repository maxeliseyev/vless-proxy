use crate::vless;
use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub struct HandshakeResult {
    pub port: u16,
    pub address: vless::Address,
}

pub async fn handle_handshake<S>(mut stream: S) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Negotiation
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    
    if header[0] != 5 {
        return Err(anyhow!("Only SOCKS5 is supported"));
    }
    
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    
    // Check if "No Auth" (0x00) is supported
    if !methods.contains(&0x00) {
        return Err(anyhow!("No supported auth methods"));
    }
    
    // Select "No Auth"
    stream.write_all(&[5, 0]).await?;
    
    // 2. Request
    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;
    
    if request_header[0] != 5 {
        return Err(anyhow!("Invalid SOCKS5 version in request"));
    }
    
    if request_header[1] != 1 {
        return Err(anyhow!("Only CONNECT command is supported"));
    }
    
    let address = match request_header[3] {
        1 => { // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            vless::Address::Ipv4(Ipv4Addr::from(addr))
        }
        3 => { // Domain
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            vless::Address::Domain(String::from_utf8(domain)?)
        }
        4 => { // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            vless::Address::Ipv6(Ipv6Addr::from(addr))
        }
        _ => return Err(anyhow!("Unsupported address type")),
    };
    
    let port = stream.read_u16().await?;
    
    // 3. Success response
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    
    Ok(HandshakeResult { port, address })
}
