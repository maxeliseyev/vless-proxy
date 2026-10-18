use crate::protocol::vless;
use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect = 1,
    UdpAssociate = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeResult {
    pub command: Command,
    pub port: u16,
    pub address: vless::Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpPacket {
    pub address: vless::Address,
    pub port: u16,
    pub payload: Vec<u8>,
}

pub async fn accept_request<S>(stream: &mut S) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream).await?;
    read_request(stream).await
}

pub async fn send_success<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_success_with_addr(stream, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

pub async fn send_success_with_addr<S>(stream: &mut S, addr: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_reply_with_addr(stream, Reply::Succeeded, addr).await
}

pub async fn send_reply<S>(stream: &mut S, reply: Reply) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    send_reply_with_addr(stream, reply, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

pub async fn send_reply_with_addr<S>(stream: &mut S, reply: Reply, addr: SocketAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut response = vec![5, reply as u8, 0];
    push_socket_addr(&mut response, addr);
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

pub fn parse_udp_packet(packet: &[u8]) -> Result<UdpPacket> {
    if packet.len() < 4 {
        return Err(anyhow!("SOCKS5 UDP packet is too short"));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(anyhow!("SOCKS5 UDP packet has invalid reserved bytes"));
    }
    if packet[2] != 0 {
        return Err(anyhow!("SOCKS5 UDP fragmentation is not supported"));
    }

    let (address, port, header_len) = parse_address_port_bytes(&packet[3..])?;
    let payload = packet[3 + header_len..].to_vec();

    Ok(UdpPacket {
        address,
        port,
        payload,
    })
}

pub fn build_udp_packet(address: &vless::Address, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut packet = vec![0, 0, 0];
    push_address_port(&mut packet, address, port)?;
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn negotiate<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

    stream.write_all(&[5, 0]).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_request<S>(stream: &mut S) -> Result<HandshakeResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request_header = [0u8; 4];
    stream.read_exact(&mut request_header).await?;

    if request_header[0] != 5 {
        return Err(anyhow!("Invalid SOCKS5 version in request"));
    }

    let command = match request_header[1] {
        1 => Command::Connect,
        3 => Command::UdpAssociate,
        _ => {
            send_reply(stream, Reply::CommandNotSupported).await?;
            return Err(anyhow!(
                "Only CONNECT and UDP ASSOCIATE commands are supported"
            ));
        }
    };

    let address = match request_header[3] {
        1 => {
            // IPv4
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            vless::Address::Ipv4(Ipv4Addr::from(addr))
        }
        3 => {
            // Domain
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain)?;
            // Clients may send an IP literal as a domain; routing rules on IPs
            // (block, private) must still see it as an address.
            match domain.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(ip)) => vless::Address::Ipv4(ip),
                Ok(std::net::IpAddr::V6(ip)) => vless::Address::Ipv6(ip),
                Err(_) => vless::Address::Domain(domain),
            }
        }
        4 => {
            // IPv6
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            vless::Address::Ipv6(Ipv6Addr::from(addr))
        }
        _ => {
            send_reply(stream, Reply::AddressTypeNotSupported).await?;
            return Err(anyhow!("Unsupported address type"));
        }
    };

    let port = stream.read_u16().await?;

    Ok(HandshakeResult {
        command,
        port,
        address,
    })
}

fn push_socket_addr(buffer: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            buffer.push(1);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buffer.push(4);
            buffer.extend_from_slice(&addr.ip().octets());
            buffer.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

fn push_address_port(buffer: &mut Vec<u8>, address: &vless::Address, port: u16) -> Result<()> {
    match address {
        vless::Address::Ipv4(addr) => {
            buffer.push(1);
            buffer.extend_from_slice(&addr.octets());
        }
        vless::Address::Domain(domain) => {
            if domain.len() > u8::MAX as usize {
                return Err(anyhow!("SOCKS5 domain length must be <= 255 bytes"));
            }
            buffer.push(3);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
        vless::Address::Ipv6(addr) => {
            buffer.push(4);
            buffer.extend_from_slice(&addr.octets());
        }
    }
    buffer.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn parse_address_port_bytes(bytes: &[u8]) -> Result<(vless::Address, u16, usize)> {
    if bytes.is_empty() {
        return Err(anyhow!("Missing SOCKS5 address type"));
    }

    match bytes[0] {
        1 => {
            if bytes.len() < 1 + 4 + 2 {
                return Err(anyhow!("SOCKS5 UDP IPv4 packet is truncated"));
            }
            let address =
                vless::Address::Ipv4(Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]));
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok((address, port, 7))
        }
        3 => {
            if bytes.len() < 2 {
                return Err(anyhow!("SOCKS5 UDP domain packet is truncated"));
            }
            let domain_len = bytes[1] as usize;
            if bytes.len() < 2 + domain_len + 2 {
                return Err(anyhow!("SOCKS5 UDP domain packet is truncated"));
            }
            let domain = String::from_utf8(bytes[2..2 + domain_len].to_vec())?;
            let port_index = 2 + domain_len;
            let port = u16::from_be_bytes([bytes[port_index], bytes[port_index + 1]]);
            Ok((vless::Address::Domain(domain), port, port_index + 2))
        }
        4 => {
            if bytes.len() < 1 + 16 + 2 {
                return Err(anyhow!("SOCKS5 UDP IPv6 packet is truncated"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok((vless::Address::Ipv6(Ipv6Addr::from(octets)), port, 19))
        }
        _ => Err(anyhow!("Unsupported SOCKS5 address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn ip_literal_sent_as_domain_becomes_an_ip_address() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let server_task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        client.write_all(&[5, 1, 0, 3, 9]).await.unwrap();
        client.write_all(b"127.0.0.1").await.unwrap();
        client.write_u16(22).await.unwrap();
        let result = server_task.await.unwrap();
        assert_eq!(result.address, vless::Address::Ipv4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn accepts_domain_connect_request() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let server_task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [5, 0]);

        client.write_all(&[5, 1, 0, 3, 11]).await.unwrap();
        client.write_all(b"example.com").await.unwrap();
        client.write_u16(443).await.unwrap();

        let result = server_task.await.unwrap();
        assert_eq!(result.command, Command::Connect);
        assert_eq!(result.port, 443);
        match result.address {
            vless::Address::Domain(domain) => assert_eq!(domain, "example.com"),
            other => panic!("unexpected address: {other}"),
        }
    }

    #[tokio::test]
    async fn rejects_unsupported_command_with_reply() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let server_task = tokio::spawn(async move { accept_request(&mut server).await });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [5, 0]);

        client.write_all(&[5, 2, 0, 1, 127, 0, 0, 1]).await.unwrap();
        client.write_u16(80).await.unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], Reply::CommandNotSupported as u8);

        let error = server_task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("Only CONNECT and UDP ASSOCIATE commands are supported"));
    }

    #[tokio::test]
    async fn accepts_udp_associate_request() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let server_task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });

        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [5, 0]);

        client.write_all(&[5, 3, 0, 1, 0, 0, 0, 0]).await.unwrap();
        client.write_u16(0).await.unwrap();

        let result = server_task.await.unwrap();
        assert_eq!(result.command, Command::UdpAssociate);
        assert_eq!(result.address, vless::Address::Ipv4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(result.port, 0);
    }

    #[test]
    fn roundtrips_udp_packet() {
        let packet = build_udp_packet(
            &vless::Address::Domain("example.com".to_string()),
            5353,
            b"dns",
        )
        .unwrap();

        let decoded = parse_udp_packet(&packet).unwrap();
        assert_eq!(
            decoded.address,
            vless::Address::Domain("example.com".to_string())
        );
        assert_eq!(decoded.port, 5353);
        assert_eq!(decoded.payload, b"dns");
    }

    #[test]
    fn rejects_fragmented_udp_packet() {
        let error = parse_udp_packet(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 80])
            .unwrap_err()
            .to_string();
        assert!(error.contains("fragmentation"));
    }
}
