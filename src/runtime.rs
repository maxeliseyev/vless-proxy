use crate::config::{Config, DnsConfig, InboundProtocol, ServerConfig, TransportSecurity};
use crate::dns::ResolverPolicy;
use crate::http;
use crate::socks5;
use crate::tls::{self, MaybeTlsStream};
use crate::vless::{self, Address, Request, Response};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// Reusable outbound VLESS connector that can be embedded by other Rust entrypoints.
///
/// The terminal CLI uses this type today, and future mobile/FFI bridges can wrap the same
/// `connect_target` API instead of depending on SOCKS5 listener logic.
#[derive(Clone)]
pub struct ProxyClient {
    server: ServerConfig,
    resolver: ResolverPolicy,
}

impl ProxyClient {
    pub fn new(server: ServerConfig, dns: DnsConfig) -> Result<Self> {
        Ok(Self {
            server,
            resolver: ResolverPolicy::new(dns)?,
        })
    }

    pub fn server(&self) -> &ServerConfig {
        &self.server
    }

    pub fn dns_policy(&self) -> &ResolverPolicy {
        &self.resolver
    }

    pub async fn connect_target(
        &self,
        address: Address,
        port: u16,
    ) -> Result<MaybeTlsStream<TcpStream>> {
        self.connect_with_command(vless::Command::Tcp, address, port)
            .await
    }

    pub async fn connect_udp_target(
        &self,
        address: Address,
        port: u16,
    ) -> Result<MaybeTlsStream<TcpStream>> {
        self.connect_with_command(vless::Command::Udp, address, port)
            .await
    }

    async fn connect_with_command(
        &self,
        command: vless::Command,
        address: Address,
        port: u16,
    ) -> Result<MaybeTlsStream<TcpStream>> {
        let mut remote = connect_remote(&self.server).await?;
        let request_address = self.resolver.resolve(address.clone(), port).await?;
        let request = Request {
            uuid: self.server.uuid,
            command,
            port,
            address: request_address.clone(),
        };

        let response = setup_vless_session(&mut remote, &request).await?;
        debug!(
            "VLESS server acknowledged request with version {} and {} addon bytes",
            response.version,
            response.addons.len()
        );
        if request_address != address {
            debug!(
                "Resolved target locally before VLESS connect: {}:{} -> {}:{}",
                address, port, request_address, port
            );
        }

        Ok(remote)
    }
}

pub async fn serve(config: Arc<Config>) -> Result<()> {
    match config.inbound_protocol()? {
        InboundProtocol::Socks5 => serve_socks5(config).await,
        InboundProtocol::Http => serve_http(config).await,
    }
}

async fn serve_socks5(config: Arc<Config>) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;
    let connector = ProxyClient::new(config.server.clone(), config.dns.clone())?;

    info!(
        "Listening on {} (inbound: {})",
        config.inbound_addr(),
        config.inbound.protocol
    );

    loop {
        let (client, addr) = listener.accept().await?;
        info!("New connection from {}", addr);

        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_socks5_connection(client, connector).await {
                error!("Connection error: {}", error);
            }
        });
    }
}

async fn handle_socks5_connection(mut client: TcpStream, connector: ProxyClient) -> Result<()> {
    let request = socks5::accept_request(&mut client).await?;
    info!(
        "SOCKS5 {:?} request: target {}:{}",
        request.command, request.address, request.port
    );

    match request.command {
        socks5::Command::Connect => handle_socks5_tcp_request(client, connector, request).await,
        socks5::Command::UdpAssociate => {
            handle_socks5_udp_associate(client, connector, request).await
        }
    }
}

async fn handle_socks5_tcp_request(
    mut client: TcpStream,
    connector: ProxyClient,
    request: socks5::HandshakeResult,
) -> Result<()> {
    let mut remote = match connector
        .connect_target(request.address, request.port)
        .await
    {
        Ok(remote) => remote,
        Err(error) => {
            let _ = socks5::send_reply(&mut client, socks5::Reply::GeneralFailure).await;
            return Err(error);
        }
    };

    info!(
        "Connected to VLESS server {}",
        connector.server().endpoint()
    );
    socks5::send_success(&mut client).await?;

    let (from_client, from_remote) = io::copy_bidirectional(&mut client, &mut remote).await?;
    info!(
        "Connection closed. client→remote: {}b, remote→client: {}b",
        from_client, from_remote
    );
    Ok(())
}

async fn handle_socks5_udp_associate(
    mut control: TcpStream,
    connector: ProxyClient,
    request: socks5::HandshakeResult,
) -> Result<()> {
    let client_ip = control.peer_addr()?.ip();
    let bind_ip = control.local_addr()?.ip();
    let udp_socket = Arc::new(UdpSocket::bind((bind_ip, 0)).await?);
    let bind_addr = udp_socket.local_addr()?;

    socks5::send_success_with_addr(&mut control, bind_addr).await?;
    info!(
        "SOCKS5 UDP association ready on {} for client hint {}:{}",
        bind_addr, request.address, request.port
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let association_task = tokio::spawn(run_udp_association(
        Arc::clone(&udp_socket),
        client_ip,
        connector,
        shutdown_rx,
    ));

    let control_result = wait_for_tcp_close(&mut control).await;
    let _ = shutdown_tx.send(true);
    let association_result = association_task
        .await
        .map_err(|error| anyhow::anyhow!("UDP association task failed: {error}"))?;

    control_result?;
    association_result
}

async fn serve_http(config: Arc<Config>) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;
    let connector = ProxyClient::new(config.server.clone(), config.dns.clone())?;

    info!(
        "Listening on {} (inbound: {})",
        config.inbound_addr(),
        config.inbound.protocol
    );

    loop {
        let (client, addr) = listener.accept().await?;
        info!("New connection from {}", addr);

        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_http_connection(client, connector).await {
                error!("Connection error: {}", error);
            }
        });
    }
}

async fn handle_http_connection(mut client: TcpStream, connector: ProxyClient) -> Result<()> {
    let request = match http::accept_request(&mut client).await {
        Ok(request) => request,
        Err(error) => {
            let _ = http::send_error(&mut client, 400, "Bad Request").await;
            return Err(error);
        }
    };
    info!(
        "HTTP {} request: target {}:{}",
        request.method, request.address, request.port
    );

    let mut remote = match connector
        .connect_target(request.address.clone(), request.port)
        .await
    {
        Ok(remote) => remote,
        Err(error) => {
            let _ = http::send_error(&mut client, 502, "Bad Gateway").await;
            return Err(error);
        }
    };

    info!(
        "Connected to VLESS server {}",
        connector.server().endpoint()
    );

    if request.is_connect {
        http::send_connect_success(&mut client).await?;
    } else if !request.initial_payload.is_empty() {
        remote.write_all(&request.initial_payload).await?;
        remote.flush().await?;
    }

    let (from_client, from_remote) = io::copy_bidirectional(&mut client, &mut remote).await?;
    info!(
        "Connection closed. client→remote: {}b, remote→client: {}b",
        from_client, from_remote
    );
    Ok(())
}

async fn run_udp_association(
    socket: Arc<UdpSocket>,
    allowed_ip: IpAddr,
    connector: ProxyClient,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let mut buffer = vec![0u8; 65_535];
    let mut client_udp_addr = None;
    let mut tunnels: HashMap<(Address, u16), UdpTunnel> = HashMap::new();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            received = socket.recv_from(&mut buffer) => {
                let (len, sender_addr) = received?;
                if sender_addr.ip() != allowed_ip {
                    debug!("Ignoring UDP packet from unexpected IP {}", sender_addr);
                    continue;
                }

                match client_udp_addr {
                    Some(addr) if addr != sender_addr => {
                        debug!("Ignoring UDP packet from unexpected endpoint {}", sender_addr);
                        continue;
                    }
                    None => client_udp_addr = Some(sender_addr),
                    _ => {}
                }

                let packet = match socks5::parse_udp_packet(&buffer[..len]) {
                    Ok(packet) => packet,
                    Err(error) => {
                        debug!("Ignoring invalid SOCKS5 UDP packet: {}", error);
                        continue;
                    }
                };

                let client_addr = client_udp_addr.expect("client UDP address must be known");
                let key = (packet.address.clone(), packet.port);
                let mut payload = packet.payload;

                loop {
                    if !tunnels.contains_key(&key) {
                        let tunnel = create_udp_tunnel(
                            connector.clone(),
                            key.0.clone(),
                            key.1,
                            Arc::clone(&socket),
                            client_addr,
                            shutdown.clone(),
                        )
                        .await?;
                        tunnels.insert(key.clone(), tunnel);
                    }

                    let send_result = match tunnels.get(&key) {
                        Some(tunnel) => tunnel.sender.send(payload).await,
                        None => continue,
                    };

                    match send_result {
                        Ok(()) => break,
                        Err(error) => {
                            payload = error.0;
                        }
                    }

                    if let Some(tunnel) = tunnels.remove(&key) {
                        tunnel.abort();
                    }
                }
            }
        }
    }

    for (_, tunnel) in tunnels {
        tunnel.abort();
    }

    Ok(())
}

async fn create_udp_tunnel(
    connector: ProxyClient,
    address: Address,
    port: u16,
    socket: Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> Result<UdpTunnel> {
    let remote = connector.connect_udp_target(address.clone(), port).await?;
    let (mut reader, mut writer) = tokio::io::split(remote);
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);

    let mut writer_shutdown = shutdown.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = writer_shutdown.changed() => {
                    if changed.is_err() || *writer_shutdown.borrow() {
                        break;
                    }
                }
                payload = receiver.recv() => {
                    let Some(payload) = payload else {
                        break;
                    };
                    if let Err(error) = vless::write_udp_frame(&mut writer, &payload).await {
                        debug!("Failed to write VLESS UDP frame: {}", error);
                        break;
                    }
                    if let Err(error) = writer.flush().await {
                        debug!("Failed to flush VLESS UDP frame: {}", error);
                        break;
                    }
                }
            }
        }
    });

    let mut reader_shutdown = shutdown;
    let response_address = address.clone();
    let reader_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = reader_shutdown.changed() => {
                    if changed.is_err() || *reader_shutdown.borrow() {
                        break;
                    }
                }
                payload = vless::read_udp_frame(&mut reader) => {
                    let payload = match payload {
                        Ok(payload) => payload,
                        Err(error) => {
                            debug!("Failed to read VLESS UDP frame: {}", error);
                            break;
                        }
                    };
                    let packet = match socks5::build_udp_packet(&response_address, port, &payload) {
                        Ok(packet) => packet,
                        Err(error) => {
                            debug!("Failed to encode SOCKS5 UDP packet: {}", error);
                            break;
                        }
                    };
                    if let Err(error) = socket.send_to(&packet, client_addr).await {
                        debug!("Failed to send SOCKS5 UDP response: {}", error);
                        break;
                    }
                }
            }
        }
    });

    Ok(UdpTunnel {
        sender,
        writer_task,
        reader_task,
    })
}

async fn connect_remote(server: &ServerConfig) -> Result<MaybeTlsStream<TcpStream>> {
    match server.transport_security()? {
        TransportSecurity::Tls => {
            let tls = tls::TlsClient::new(server.address.clone())?;
            tls.connect((server.address.as_str(), server.port)).await
        }
        TransportSecurity::None => {
            let stream = TcpStream::connect((server.address.as_str(), server.port)).await?;
            Ok(MaybeTlsStream::Plain(stream))
        }
    }
}

async fn setup_vless_session(
    remote: &mut MaybeTlsStream<TcpStream>,
    request: &Request,
) -> Result<Response> {
    request.write_to(remote).await?;
    remote.flush().await?;
    Response::read_from(remote).await
}

async fn wait_for_tcp_close(stream: &mut TcpStream) -> Result<()> {
    let mut buffer = [0u8; 1];
    loop {
        if stream.read(&mut buffer).await? == 0 {
            return Ok(());
        }
    }
}

struct UdpTunnel {
    sender: mpsc::Sender<Vec<u8>>,
    writer_task: JoinHandle<()>,
    reader_task: JoinHandle<()>,
}

impl UdpTunnel {
    fn abort(self) {
        self.writer_task.abort();
        self.reader_task.abort();
    }
}
