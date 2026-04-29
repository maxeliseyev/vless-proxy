use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const VERSION: u8 = 0;

pub enum Command {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
}

pub enum Address {
    Ipv4(Ipv4Addr),
    Domain(String),
    Ipv6(Ipv6Addr),
}

pub struct Request {
    pub uuid: Uuid,
    pub command: Command,
    pub port: u16,
    pub address: Address,
}

impl Request {
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        // Version
        writer.write_u8(VERSION).await?;
        
        // UUID (16 bytes)
        writer.write_all(self.uuid.as_bytes()).await?;
        
        // Addons length (0 for now)
        writer.write_u8(0).await?;
        
        // Command
        writer.write_u8(self.command as u8).await?;
        
        // Port (Big Endian)
        writer.write_u16(self.port).await?;
        
        // Address Type and Address
        match &self.address {
            Address::Ipv4(addr) => {
                writer.write_u8(1).await?;
                writer.write_all(&addr.octets()).await?;
            }
            Address::Domain(domain) => {
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
