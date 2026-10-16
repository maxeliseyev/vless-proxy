use crate::config::{
    Config, DnsConfig, InboundProtocol, RuntimeConfig, ServerConfig, TransportSecurity,
};
use crate::dns::ResolverPolicy;
use crate::http;
use crate::reality::RealityClient;
use crate::reality_tls::RealityConnector;
use crate::socks5;
use crate::tls::{self, MaybeTlsStream};
use crate::vision::{Vision, FLOW_VISION};
use crate::vless::{self, Address, Request, VlessStream, XtlsDirect};
use crate::xray_sidecar;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use tracing::{debug, error, info, warn};

/// A VLESS session to the configured server, ready for relaying.
pub type RemoteStream = VlessStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone)]
pub struct ProxyClient {
    server: ServerConfig,
    resolver: ResolverPolicy,
    runtime: RuntimeConfig,
}

impl ProxyClient {
    pub fn new(server: ServerConfig, dns: DnsConfig, runtime: RuntimeConfig) -> Result<Self> {
        Ok(Self {
            server,
            resolver: ResolverPolicy::new(dns)?,
            runtime,
        })
    }

    pub fn server(&self) -> &ServerConfig {
        &self.server
    }

    pub fn dns_policy(&self) -> &ResolverPolicy {
        &self.resolver
    }

    pub fn runtime(&self) -> &RuntimeConfig {
        &self.runtime
    }

    pub async fn connect_target(&self, address: Address, port: u16) -> Result<RemoteStream> {
        self.connect_with_command(vless::Command::Tcp, address, port)
            .await
    }

    pub async fn connect_udp_target(&self, address: Address, port: u16) -> Result<RemoteStream> {
        self.connect_with_command(vless::Command::Udp, address, port)
            .await
    }

    async fn connect_with_command(
        &self,
        command: vless::Command,
        address: Address,
        port: u16,
    ) -> Result<RemoteStream> {
        let connect_timeout = Duration::from_secs(self.runtime.connect_timeout_secs);

        let vision_flow = self.server.vision_flow()?;
        if command == vless::Command::Udp && port == 443 {
            if let Some(flow) = vision_flow {
                if !flow.allows_udp443() {
                    // Like Xray: make QUIC fall back to TCP so Vision can splice it.
                    anyhow::bail!(
                        "XTLS rejected UDP/443 traffic (use flow xtls-rprx-vision-udp443 to allow)"
                    );
                }
            }
        }

        let remote = timeout(connect_timeout, connect_remote(&self.server))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        // Vision applies to TCP sessions only (UDP keeps an empty flow), and
        // needs a transport that can hand us the raw socket.
        let use_vision =
            command == vless::Command::Tcp && vision_flow.is_some() && remote.supports_direct();

        let request_address = self.resolver.resolve(address.clone(), port).await?;
        let request = Request {
            uuid: self.server.uuid,
            command,
            port,
            address: request_address.clone(),
            flow: use_vision.then(|| FLOW_VISION.to_string()),
        };

        // The header is sent together with the first payload, and the response
        // header is consumed lazily, because that is how Xray-core behaves.
        let mut remote = VlessStream::new(remote, request.encode()?);
        if use_vision {
            remote = remote.with_vision(Vision::new(*self.server.uuid.as_bytes()));
        }
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
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let use_sidecar = xray_sidecar::should_use(config.as_ref())?;

    let mut ctrl_c_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let shutdown_signal = async {
        tokio::select! {
            _ = ctrl_c_stream.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            }
            _ = sigterm_stream.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }
    };

    let core = async {
        if use_sidecar {
            xray_sidecar::run(config.clone()).await
        } else {
            serve_with_shutdown(config.clone(), shutdown_rx.clone()).await
        }
    };
    let mut tun_task = config
        .tun
        .enabled
        .then(|| tokio::spawn(crate::tun::run(config.clone(), shutdown_rx.clone())));
    let tun_failed = async {
        match tun_task.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(e) => Err(anyhow::anyhow!("TUN sidecar task failed: {e}")),
            },
            None => std::future::pending().await,
        }
    };
    tokio::pin!(tun_failed);

    let result = tokio::select! {
        result = core => result,
        result = &mut tun_failed => result,
        _ = shutdown_signal => {
            info!("Shutdown signal received, stopping server");
            let _ = shutdown_tx.send(true);
            Ok(())
        }
    };

    // Give the TUN sidecar time to restore routes/DNS before we exit.
    let _ = shutdown_tx.send(true);
    match tokio::time::timeout(Duration::from_secs(6), &mut tun_failed).await {
        Ok(Err(e)) if result.is_ok() => warn!("TUN sidecar stopped with error: {e}"),
        Err(_) => warn!("TUN sidecar did not stop in time"),
        _ => {}
    }

    result
}

async fn serve_with_shutdown(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
    let connection_count = Arc::new(AtomicUsize::new(0));
    let max_connections = config.runtime.max_connections;
    let semaphore = Arc::new(Semaphore::new(max_connections));

    match config.inbound_protocol()? {
        InboundProtocol::Socks5 => {
            serve_socks5_with_limits(config, shutdown, connection_count, semaphore).await
        }
        InboundProtocol::Http => {
            serve_http_with_limits(config, shutdown, connection_count, semaphore).await
        }
    }
}

async fn serve_socks5_with_limits(
    config: Arc<Config>,
    mut shutdown: watch::Receiver<bool>,
    connection_count: Arc<AtomicUsize>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;
    let connector = ProxyClient::new(
        config.server.clone(),
        config.dns.clone(),
        config.runtime.clone(),
    )?;

    info!(
        "Listening on {} (inbound: {}, max_connections: {})",
        config.inbound_addr(),
        config.inbound.protocol,
        config.runtime.max_connections
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("Shutting down SOCKS5 listener");
                    break;
                }
            }
            accept_result = listener.accept() => {
                let (client, addr) = accept_result?;

                let current_connections = connection_count.fetch_add(1, Ordering::Relaxed) + 1;
                if current_connections > config.runtime.max_connections {
                    connection_count.fetch_sub(1, Ordering::Relaxed);
                    warn!("Rejecting connection from {}: max connections ({}) reached",
                          addr, config.runtime.max_connections);
                    continue;
                }

                debug!("New connection from {} (active: {})", addr, current_connections);

                let connector = connector.clone();
                let connection_count = connection_count.clone();
                let permit = semaphore.clone().acquire_owned().await?;

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_socks5_connection(client, connector).await {
                        error!("Connection error: {}", error);
                    }
                    let prev = connection_count.fetch_sub(1, Ordering::Relaxed);
                    debug!("Connection closed (active: {})", prev - 1);
                });
            }
        }
    }

    Ok(())
}

async fn handle_socks5_connection(mut client: TcpStream, connector: ProxyClient) -> Result<()> {
    let read_timeout = Duration::from_secs(connector.runtime().read_timeout_secs);

    let request = timeout(read_timeout, socks5::accept_request(&mut client))
        .await
        .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timeout"))??;

    debug!(
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
    let read_timeout = Duration::from_secs(connector.runtime().read_timeout_secs);
    let write_timeout = Duration::from_secs(connector.runtime().write_timeout_secs);
    let idle_timeout = Duration::from_secs(connector.runtime().idle_timeout_secs);

    let remote = match timeout(
        Duration::from_secs(connector.runtime().connect_timeout_secs),
        connector.connect_target(request.address, request.port),
    )
    .await
    {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            let _ = socks5::send_reply(&mut client, socks5::Reply::GeneralFailure).await;
            return Err(anyhow::anyhow!("Failed to connect to target: {}", error));
        }
        Err(_) => {
            let _ = socks5::send_reply(&mut client, socks5::Reply::GeneralFailure).await;
            return Err(anyhow::anyhow!("Connection timeout"));
        }
    };

    let mut remote = remote;
    debug!(
        "Connected to VLESS server {}",
        connector.server().endpoint()
    );
    socks5::send_success(&mut client).await?;
    prime_remote(&mut client, &mut remote, write_timeout).await?;

    let result = copy_bidirectional_with_timeouts(
        &mut client,
        &mut remote,
        read_timeout,
        write_timeout,
        idle_timeout,
    )
    .await;

    debug!("Connection closed");
    result.map(|_| ())
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
    debug!(
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

async fn serve_http_with_limits(
    config: Arc<Config>,
    mut shutdown: watch::Receiver<bool>,
    connection_count: Arc<AtomicUsize>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;
    let connector = ProxyClient::new(
        config.server.clone(),
        config.dns.clone(),
        config.runtime.clone(),
    )?;

    info!(
        "Listening on {} (inbound: {}, max_connections: {})",
        config.inbound_addr(),
        config.inbound.protocol,
        config.runtime.max_connections
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("Shutting down HTTP listener");
                    break;
                }
            }
            accept_result = listener.accept() => {
                let (client, addr) = accept_result?;

                let current_connections = connection_count.fetch_add(1, Ordering::Relaxed) + 1;
                if current_connections > config.runtime.max_connections {
                    connection_count.fetch_sub(1, Ordering::Relaxed);
                    warn!("Rejecting connection from {}: max connections ({}) reached",
                          addr, config.runtime.max_connections);
                    continue;
                }

                debug!("New connection from {} (active: {})", addr, current_connections);

                let connector = connector.clone();
                let connection_count = connection_count.clone();
                let permit = semaphore.clone().acquire_owned().await?;

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_http_connection(client, connector).await {
                        error!("Connection error: {}", error);
                    }
                    let prev = connection_count.fetch_sub(1, Ordering::Relaxed);
                    debug!("Connection closed (active: {})", prev - 1);
                });
            }
        }
    }

    Ok(())
}

async fn handle_http_connection(mut client: TcpStream, connector: ProxyClient) -> Result<()> {
    let read_timeout = Duration::from_secs(connector.runtime().read_timeout_secs);

    let request = match timeout(read_timeout, http::accept_request(&mut client)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let _ = http::send_error(&mut client, 400, "Bad Request").await;
            return Err(anyhow::anyhow!("HTTP request error: {}", error));
        }
        Err(_) => {
            let _ = http::send_error(&mut client, 408, "Request Timeout").await;
            return Err(anyhow::anyhow!("HTTP request timeout"));
        }
    };

    debug!(
        "HTTP {} request: target {}:{}",
        request.method, request.address, request.port
    );

    let write_timeout = Duration::from_secs(connector.runtime().write_timeout_secs);
    let idle_timeout = Duration::from_secs(connector.runtime().idle_timeout_secs);

    let remote = match timeout(
        Duration::from_secs(connector.runtime().connect_timeout_secs),
        connector.connect_target(request.address.clone(), request.port),
    )
    .await
    {
        Ok(Ok(remote)) => remote,
        Ok(Err(error)) => {
            let _ = http::send_error(&mut client, 502, "Bad Gateway").await;
            return Err(anyhow::anyhow!("Failed to connect to target: {}", error));
        }
        Err(_) => {
            let _ = http::send_error(&mut client, 504, "Gateway Timeout").await;
            return Err(anyhow::anyhow!("Connection timeout"));
        }
    };

    let mut remote = remote;
    debug!(
        "Connected to VLESS server {}",
        connector.server().endpoint()
    );

    if request.is_connect {
        http::send_connect_success(&mut client).await?;
    } else if !request.initial_payload.is_empty() {
        timeout(write_timeout, remote.write_all(&request.initial_payload))
            .await
            .map_err(|_| anyhow::anyhow!("Write timeout"))??;
        timeout(write_timeout, remote.flush())
            .await
            .map_err(|_| anyhow::anyhow!("Flush timeout"))??;
    }
    prime_remote(&mut client, &mut remote, write_timeout).await?;

    let result = copy_bidirectional_with_timeouts(
        &mut client,
        &mut remote,
        read_timeout,
        write_timeout,
        idle_timeout,
    )
    .await;

    debug!("Connection closed");
    result.map(|_| ())
}

async fn copy_bidirectional_with_timeouts<A, B>(
    a: &mut A,
    b: &mut B,
    read_timeout: Duration,
    write_timeout: Duration,
    idle_timeout: Duration,
) -> Result<(u64, u64)>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    B: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    let mut a_to_b = 0u64;
    let mut b_to_a = 0u64;
    let mut last_activity = Instant::now();
    let idle_deadline = idle_timeout;
    let mut buf_a = vec![0u8; 8192];
    let mut buf_b = vec![0u8; 8192];

    loop {
        tokio::select! {
            result = timeout(read_timeout, a.read(&mut buf_a)) => {
                let n = match result {
                    Ok(Ok(n)) => {
                        if n == 0 {
                            break;
                        }
                        n
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => return Err(anyhow::anyhow!("Read timeout from client")),
                };

                timeout(write_timeout, b.write_all(&buf_a[..n]))
                    .await
                    .map_err(|_| anyhow::anyhow!("Write timeout to remote"))??;
                b.flush().await?;

                a_to_b += n as u64;
                last_activity = Instant::now();
            }
            result = timeout(read_timeout, b.read(&mut buf_b)) => {
                let n = match result {
                    Ok(Ok(n)) => {
                        if n == 0 {
                            break;
                        }
                        n
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => return Err(anyhow::anyhow!("Read timeout from remote")),
                };

                timeout(write_timeout, a.write_all(&buf_b[..n]))
                    .await
                    .map_err(|_| anyhow::anyhow!("Write timeout to client"))??;
                a.flush().await?;

                b_to_a += n as u64;
                last_activity = Instant::now();
            }
            _ = tokio::time::sleep_until(last_activity + idle_deadline) => {
                return Err(anyhow::anyhow!("Idle timeout"));
            }
        }
    }

    Ok((a_to_b, b_to_a))
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
                        let tunnel = match create_udp_tunnel(
                            connector.clone(),
                            key.0.clone(),
                            key.1,
                            Arc::clone(&socket),
                            client_addr,
                            shutdown.clone(),
                        )
                        .await
                        {
                            Ok(tunnel) => tunnel,
                            Err(error) => {
                                // One destination failing (or being refused, e.g.
                                // UDP/443 under Vision) must not end the whole
                                // association; just drop this datagram.
                                let text = error.to_string();
                                if text.contains("XTLS rejected") {
                                    debug!("Dropping UDP to {}:{}: {}", key.0, key.1, text);
                                } else {
                                    warn!("Failed to open UDP session to {}:{}: {}", key.0, key.1, text);
                                }
                                break;
                            }
                        };
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

fn reality_client(server: &ServerConfig) -> Result<RealityClient> {
    RealityClient::new(
        server.tls_server_name(),
        server.reality_public_key.as_deref().unwrap_or(""),
        server.reality_short_id.as_deref().unwrap_or(""),
    )
}

/// Connect to the configured server once, complete the transport handshake
/// and describe the result. Used by `vproxy --probe`.
pub async fn probe_transport(config: &Config) -> Result<String> {
    let server = &config.server;
    let remote = tokio::time::timeout(
        Duration::from_secs(config.runtime.connect_timeout_secs),
        connect_remote(server),
    )
    .await
    .context("transport handshake timed out")??;

    Ok(match remote {
        MaybeTlsStream::Plain(_) => format!("plain TCP to {}", server.endpoint()),
        MaybeTlsStream::Tls(_) => format!(
            "TLS handshake OK with {} (sni {})",
            server.endpoint(),
            server.tls_server_name()
        ),
        MaybeTlsStream::Reality(stream) => {
            let info = crate::reality_tls::connection_info(&stream, server.tls_server_name());
            format!(
                "REALITY handshake OK with {} (sni {}, alpn {}, suite {}): server certificate authenticated",
                server.endpoint(),
                info.server_name,
                info.alpn.as_deref().unwrap_or("none"),
                info.cipher_suite
            )
        }
    })
}

async fn connect_remote(server: &ServerConfig) -> Result<MaybeTlsStream<TcpStream>> {
    match server.transport_security()? {
        TransportSecurity::Tls => {
            let tls = tls::TlsClient::new(server.tls_server_name().to_string())?;
            tls.connect((server.address.as_str(), server.port)).await
        }
        TransportSecurity::Reality => {
            let client = reality_client(server)?;
            let tcp = TcpStream::connect((server.address.as_str(), server.port)).await?;
            let stream = RealityConnector::new(client).connect(tcp).await?;
            Ok(MaybeTlsStream::Reality(stream))
        }
        TransportSecurity::None => {
            let stream = TcpStream::connect((server.address.as_str(), server.port)).await?;
            Ok(MaybeTlsStream::Plain(stream))
        }
    }
}

/// Send the VLESS request header the way Xray-core does: bundled with the
/// first client payload, or, if none arrives within 500 ms, with an empty
/// Vision padding block (or alone when Vision is off).
async fn prime_remote(
    client: &mut TcpStream,
    remote: &mut RemoteStream,
    write_timeout: Duration,
) -> Result<()> {
    if !remote.header_pending() {
        return Ok(());
    }
    let mut buf = vec![0u8; 8192];
    match timeout(Duration::from_millis(500), client.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            timeout(write_timeout, remote.write_all(&buf[..n]))
                .await
                .map_err(|_| anyhow::anyhow!("Write timeout to remote"))??;
        }
        Ok(Ok(_)) => {} // client closed already; still send the header so the relay ends cleanly
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => remote.queue_vision_camouflage(),
    }
    timeout(write_timeout, remote.flush())
        .await
        .map_err(|_| anyhow::anyhow!("Flush timeout to remote"))??;
    Ok(())
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
