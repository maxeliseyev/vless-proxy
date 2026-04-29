mod config;
mod socks5;
mod tls;
mod vless;

use anyhow::Result;
use config::Config;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let config_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));

    let config = Arc::new(Config::load(&config_path)?);
    info!("Loaded config from {}", config_path.display());

    let listener = TcpListener::bind(config.inbound_addr()).await?;
    info!(
        "Listening on {} (inbound: {})",
        config.inbound_addr(),
        config.inbound.protocol
    );

    loop {
        let (client, addr) = listener.accept().await?;
        info!("New connection from {}", addr);

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, config).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    mut client: TcpStream,
    config: Arc<Config>,
) -> Result<()> {
    // 1. SOCKS5 Handshake
    let socks_result = socks5::handle_handshake(&mut client).await?;
    info!(
        "SOCKS5 handshake successful: target {}:{}",
        match &socks_result.address {
            vless::Address::Ipv4(a) => a.to_string(),
            vless::Address::Domain(d) => d.clone(),
            vless::Address::Ipv6(a) => a.to_string(),
        },
        socks_result.port
    );

    // 2. Connect to VLESS Server
    let server_addr = config.server_addr();
    let use_tls = config.server.use_tls;

    let mut remote = if use_tls {
        let tls = tls::TlsClient::new(server_addr.split(':').next().unwrap_or("localhost"))?;
        tls.connect(&server_addr).await?
    } else {
        let stream = TcpStream::connect(&server_addr).await?;
        tls::TlsStream::new(stream)
    }?;

    info!("Connected to VLESS server {}", server_addr);

    // 3. Send VLESS Request Header
    let vless_request = vless::Request {
        uuid: config.server.uuid,
        command: vless::Command::Tcp,
        port: socks_result.port,
        address: socks_result.address,
    };
    vless_request.write_to(&mut remote).await?;

    // 4. Proxy traffic
    let (from_client, from_remote) = io::copy_bidirectional(&mut client, &mut remote).await?;

    info!(
        "Connection closed. client→remote: {}b, remote→client: {}b",
        from_client, from_remote
    );
    Ok(())
}
