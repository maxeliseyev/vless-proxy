use crate::config::{
    Config, DnsConfig, InboundProtocol, MuxConfig, RoutingConfig, RuntimeConfig, ServerConfig,
    Transport, TransportSecurity,
};
use crate::dns::ResolverPolicy;
use crate::http;
use crate::mux::{MuxManager, MuxStream, MUX_COOL_ADDRESS, MUX_COOL_PORT};
use crate::reality::RealityClient;
use crate::reality_tls::RealityConnector;
use crate::routing::{Outbound, Router};
use crate::socks5;
use crate::stats::STATS;
use crate::tls::{self, MaybeTlsStream, WsInner};
use crate::vision::{Vision, FLOW_VISION};
use crate::vless::{self, Address, Request, VlessStream, XtlsDirect};
use crate::ws::WsStream;
use crate::xray_sidecar;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// A VLESS session to the configured server, ready for relaying.
pub type RemoteStream = VlessStream<MaybeTlsStream<TcpStream>>;

/// Where a TCP connection ended up after routing.
pub enum OutboundStream {
    Proxy(Box<RemoteStream>),
    /// A session multiplexed over a shared VLESS connection.
    Mux(MuxStream),
    Direct(TcpStream),
}

impl OutboundStream {
    pub fn is_direct(&self) -> bool {
        matches!(self, OutboundStream::Direct(_))
    }
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Proxy(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutboundStream::Mux(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            OutboundStream::Direct(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            OutboundStream::Proxy(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutboundStream::Mux(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            OutboundStream::Direct(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Proxy(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutboundStream::Mux(s) => std::pin::Pin::new(s).poll_flush(cx),
            OutboundStream::Direct(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            OutboundStream::Proxy(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutboundStream::Mux(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutboundStream::Direct(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Where a UDP session ended up after routing.
pub enum UdpOutbound {
    Proxy(Box<RemoteStream>),
    Direct(UdpSocket),
}

/// The server new sessions are opened to. Swappable at runtime: existing
/// sessions keep their server, new ones use the replacement.
#[derive(Clone)]
pub struct ActiveServer(Arc<std::sync::RwLock<ServerConfig>>);

impl ActiveServer {
    pub fn new(server: ServerConfig) -> Self {
        Self(Arc::new(std::sync::RwLock::new(server)))
    }

    pub fn get(&self) -> ServerConfig {
        self.0.read().expect("active server lock poisoned").clone()
    }

    /// Validate `server` in the context of `config` (same inbound, dns,
    /// runtime, routing) and make it the active one. Servers that need the
    /// xray-core sidecar cannot be switched to live.
    pub fn swap(&self, server: ServerConfig, config: &Config) -> Result<()> {
        let mut probe = config.clone();
        probe.server = server;
        probe.validate()?;
        if probe.needs_xray_sidecar()? {
            anyhow::bail!(
                "{} needs the xray-core sidecar; restart vproxy with it as the first server",
                probe.server.endpoint()
            );
        }
        let name = probe
            .server
            .remark
            .clone()
            .unwrap_or_else(|| probe.server.endpoint());
        *self.0.write().expect("active server lock poisoned") = probe.server;
        info!("Switched to server {name}");
        Ok(())
    }
}

#[derive(Clone)]
pub struct ProxyClient {
    server: ActiveServer,
    resolver: ResolverPolicy,
    runtime: RuntimeConfig,
    router: Arc<Router>,
    mux: Option<Arc<MuxManager>>,
}

impl ProxyClient {
    pub fn new(
        server: ActiveServer,
        dns: DnsConfig,
        runtime: RuntimeConfig,
        routing: &RoutingConfig,
        mux: &MuxConfig,
    ) -> Result<Self> {
        let router = Router::new(routing)?;
        if router.has_geo_rules() {
            warn!("routing: geoip/geosite rules are only applied in TUN mode (sing-box); the local proxy ignores them");
        }
        let mux = mux.sessions_per_connection().map(|concurrency| {
            if server.get().vision_flow().ok().flatten().is_some() {
                warn!("mux: ignored for XTLS Vision servers (Mux.Cool cannot be combined with Vision)");
            }
            Arc::new(MuxManager::new(concurrency))
        });
        Ok(Self {
            server,
            resolver: ResolverPolicy::new(dns)?,
            runtime,
            router: Arc::new(router),
            mux,
        })
    }

    /// Multiplexer, when `[mux]` is on.
    pub fn mux(&self) -> Option<&MuxManager> {
        self.mux.as_deref()
    }

    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Route a TCP target: VLESS session, direct connection, or `block`.
    pub async fn open_tcp(&self, address: Address, port: u16) -> Result<OutboundStream> {
        match self.router.decide(&address, port) {
            Outbound::Block => anyhow::bail!("blocked by routing rules: {address}:{port}"),
            Outbound::Direct => {
                debug!("route direct: {address}:{port}");
                let stream = timeout(
                    Duration::from_secs(self.runtime.connect_timeout_secs),
                    TcpStream::connect(direct_target(&address, port)),
                )
                .await
                .map_err(|_| anyhow::anyhow!("Direct connection timeout"))??;
                Ok(OutboundStream::Direct(stream))
            }
            Outbound::Proxy => {
                if let Some(mux) = &self.mux {
                    let server = self.server.get();
                    // Vision cannot be multiplexed; such servers get plain sessions.
                    if server.vision_flow()?.is_none() {
                        return Ok(OutboundStream::Mux(
                            self.open_mux_session(mux, server, address, port).await?,
                        ));
                    }
                }
                Ok(OutboundStream::Proxy(Box::new(
                    self.connect_target(address, port).await?,
                )))
            }
        }
    }

    /// A Mux.Cool session to `address:port`, dialing a new multiplexed VLESS
    /// connection in the background when none has room.
    async fn open_mux_session(
        &self,
        mux: &MuxManager,
        server: ServerConfig,
        address: Address,
        port: u16,
    ) -> Result<MuxStream> {
        let request_address = self.resolver.resolve(address, port).await?;
        let key = format!("{}|{}", server.endpoint(), server.uuid);
        let connect_timeout = Duration::from_secs(self.runtime.connect_timeout_secs);
        let dial = async move {
            let remote = timeout(connect_timeout, connect_remote(&server))
                .await
                .map_err(|_| anyhow::anyhow!("Connection timeout"))??;
            let request = Request {
                uuid: server.uuid,
                command: vless::Command::Mux,
                port: MUX_COOL_PORT,
                address: Address::Domain(MUX_COOL_ADDRESS.to_string()),
                flow: None,
            };
            debug!("Connected to VLESS server {} (mux)", server.endpoint());
            Ok(VlessStream::new(remote, request.encode()?))
        };
        Ok(mux.open(&key, (request_address, port), dial))
    }

    /// Route a UDP target: VLESS UDP session, a direct connected socket, or `block`.
    pub async fn open_udp(&self, address: Address, port: u16) -> Result<UdpOutbound> {
        match self.router.decide(&address, port) {
            Outbound::Block => anyhow::bail!("blocked by routing rules: {address}:{port}"),
            Outbound::Direct => {
                debug!("route direct (udp): {address}:{port}");
                let target = tokio::net::lookup_host(direct_target(&address, port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("cannot resolve {address}"))?;
                let bind: std::net::SocketAddr = if target.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let socket = UdpSocket::bind(bind).await?;
                socket.connect(target).await?;
                Ok(UdpOutbound::Direct(socket))
            }
            Outbound::Proxy => Ok(UdpOutbound::Proxy(Box::new(
                self.connect_udp_target(address, port).await?,
            ))),
        }
    }

    /// Snapshot of the currently active server.
    pub fn server(&self) -> ServerConfig {
        self.server.get()
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
        let server = self.server.get();

        let vision_flow = server.vision_flow()?;
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

        let remote = timeout(connect_timeout, connect_remote(&server))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        // Vision applies to TCP sessions only (UDP keeps an empty flow), and
        // needs a transport that can hand us the raw socket.
        let use_vision =
            command == vless::Command::Tcp && vision_flow.is_some() && remote.supports_direct();

        let request_address = self.resolver.resolve(address.clone(), port).await?;
        let request = Request {
            uuid: server.uuid,
            command,
            port,
            address: request_address.clone(),
            flow: use_vision.then(|| FLOW_VISION.to_string()),
        };

        // The header is sent together with the first payload, and the response
        // header is consumed lazily, because that is how Xray-core behaves.
        let mut remote = VlessStream::new(remote, request.encode()?);
        if use_vision {
            remote = remote.with_vision(Vision::new(*server.uuid.as_bytes()));
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
    let active = ActiveServer::new(config.server.clone());
    serve_with_server(config, active).await
}

/// Like [`serve`], with an [`ActiveServer`] handle the caller can use to
/// switch servers while running (the TUI does this).
pub async fn serve_with_server(config: Arc<Config>, active: ActiveServer) -> Result<()> {
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
            serve_with_shutdown(config.clone(), active.clone(), shutdown_rx.clone()).await
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
    if config.tun.enabled {
        match tokio::time::timeout(Duration::from_secs(6), &mut tun_failed).await {
            Ok(Err(e)) if result.is_ok() => warn!("TUN sidecar stopped with error: {e}"),
            Err(_) => warn!("TUN sidecar did not stop in time"),
            _ => {}
        }
    }

    result
}

async fn serve_with_shutdown(
    config: Arc<Config>,
    active: ActiveServer,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let connection_count = Arc::new(AtomicUsize::new(0));
    let max_connections = config.runtime.max_connections;
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let connector = ProxyClient::new(
        active,
        config.dns.clone(),
        config.runtime.clone(),
        &config.routing,
        &config.mux,
    )?;

    match config.inbound_protocol()? {
        InboundProtocol::Socks5 => {
            serve_socks5_with_limits(config, connector, shutdown, connection_count, semaphore).await
        }
        InboundProtocol::Http => {
            serve_http_with_limits(config, connector, shutdown, connection_count, semaphore).await
        }
    }
}

async fn serve_socks5_with_limits(
    config: Arc<Config>,
    connector: ProxyClient,
    mut shutdown: watch::Receiver<bool>,
    connection_count: Arc<AtomicUsize>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;

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

                STATS.connection_opened();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_socks5_connection(client, connector).await {
                        STATS.error();
                        error!("Connection error: {}", error);
                    }
                    STATS.connection_closed();
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
        connector.open_tcp(request.address, request.port),
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
    if remote.is_direct() {
        debug!("Connected directly");
    } else {
        debug!(
            "Connected to VLESS server {}",
            connector.server().endpoint()
        );
    }
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
    connector: ProxyClient,
    mut shutdown: watch::Receiver<bool>,
    connection_count: Arc<AtomicUsize>,
    semaphore: Arc<Semaphore>,
) -> Result<()> {
    let listener =
        TcpListener::bind((config.inbound.address.as_str(), config.inbound.port)).await?;

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

                STATS.connection_opened();
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_http_connection(client, connector).await {
                        STATS.error();
                        error!("Connection error: {}", error);
                    }
                    STATS.connection_closed();
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
        connector.open_tcp(request.address.clone(), request.port),
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
    if remote.is_direct() {
        debug!("Connected directly");
    } else {
        debug!(
            "Connected to VLESS server {}",
            connector.server().endpoint()
        );
    }

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

/// Relay both directions until either side reads EOF or an error. The two
/// directions make progress independently (a stalled write towards one peer
/// never stops reads from the other), which matters for multiplexed sessions
/// where several relays share one connection. Timeouts: a single write
/// pending longer than `write_timeout`, or no bytes moving in either
/// direction for `min(read_timeout, idle_timeout)`, end the relay with an
/// error.
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
    let activity_timeout = read_timeout.min(idle_timeout);
    let mut a_to_b = RelayDirection::new("remote", write_timeout, true);
    let mut b_to_a = RelayDirection::new("client", write_timeout, false);
    let mut activity = Box::pin(tokio::time::sleep(activity_timeout));

    std::future::poll_fn(|cx| {
        let mut progress = false;
        let up = a_to_b.poll(cx, &mut *a, &mut *b, &mut progress);
        let down = b_to_a.poll(cx, &mut *b, &mut *a, &mut progress);
        match (up, down) {
            (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => return Poll::Ready(Err(e)),
            (Poll::Ready(Ok(())), _) | (_, Poll::Ready(Ok(()))) => {
                return Poll::Ready(Ok((a_to_b.copied, b_to_a.copied)));
            }
            _ => {}
        }
        if progress {
            activity
                .as_mut()
                .reset(tokio::time::Instant::now() + activity_timeout);
        }
        if activity.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(anyhow::anyhow!("Idle timeout")));
        }
        Poll::Pending
    })
    .await
}

/// One direction of a relay: a buffer being filled from the reader and
/// drained into the writer.
struct RelayDirection {
    buf: Box<[u8]>,
    pos: usize,
    cap: usize,
    eof: bool,
    copied: u64,
    peer: &'static str,
    write_timeout: Duration,
    write_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    upstream: bool,
}

impl RelayDirection {
    fn new(peer: &'static str, write_timeout: Duration, upstream: bool) -> Self {
        Self {
            buf: vec![0u8; 16 * 1024].into_boxed_slice(),
            pos: 0,
            cap: 0,
            eof: false,
            copied: 0,
            peer,
            write_timeout,
            write_deadline: None,
            upstream,
        }
    }

    /// `Ready(Ok(()))` once the reader hit EOF and everything buffered was
    /// written and flushed; `Pending` while waiting on either side.
    fn poll<R, W>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        reader: &mut R,
        writer: &mut W,
        progress: &mut bool,
    ) -> Poll<Result<()>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if self.pos == self.cap && !self.eof {
                let mut read_buf = tokio::io::ReadBuf::new(&mut self.buf);
                match std::pin::Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let n = read_buf.filled().len();
                        if n == 0 {
                            self.eof = true;
                        } else {
                            self.pos = 0;
                            self.cap = n;
                            *progress = true;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => return Poll::Pending,
                }
            }
            while self.pos < self.cap {
                match std::pin::Pin::new(&mut *writer).poll_write(cx, &self.buf[self.pos..self.cap])
                {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(anyhow::anyhow!(
                            "{} stopped accepting data",
                            self.peer
                        )))
                    }
                    Poll::Ready(Ok(n)) => {
                        self.pos += n;
                        self.copied += n as u64;
                        if self.upstream {
                            STATS.add_up(n);
                        } else {
                            STATS.add_down(n);
                        }
                        self.write_deadline = None;
                        *progress = true;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {
                        let deadline = self.write_deadline.get_or_insert_with(|| {
                            Box::pin(tokio::time::sleep(self.write_timeout))
                        });
                        if deadline.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Err(anyhow::anyhow!(
                                "Write timeout to {}",
                                self.peer
                            )));
                        }
                        return Poll::Pending;
                    }
                }
            }
            match std::pin::Pin::new(&mut *writer).poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => return Poll::Pending,
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
        }
    }
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
                                if text.contains("XTLS rejected") || text.contains("blocked by routing") {
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
    let remote = match connector.open_udp(address.clone(), port).await? {
        UdpOutbound::Proxy(remote) => *remote,
        UdpOutbound::Direct(udp) => {
            return create_direct_udp_tunnel(udp, address, port, socket, client_addr, shutdown);
        }
    };
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
                    STATS.add_up(payload.len());
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
                        Ok(payload) => {
                            STATS.add_down(payload.len());
                            payload
                        }
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

pub(crate) fn reality_client(server: &ServerConfig) -> Result<RealityClient> {
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
        MaybeTlsStream::Ws(_) => format!(
            "WebSocket upgrade OK with {} ({}, host {}, path {})",
            server.endpoint(),
            if server.use_tls { "tls" } else { "plain" },
            server.ws_host(),
            server.ws_path()
        ),
        MaybeTlsStream::Xhttp(stream) => format!("{} OK", stream.description()),
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

/// Time a full transport handshake (TCP + TLS/REALITY/WebSocket/XHTTP) to
/// the server; the connection is dropped right after. What the TUI and
/// `--ping` show as latency.
pub async fn measure_handshake(server: &ServerConfig, limit: Duration) -> Result<Duration> {
    let started = std::time::Instant::now();
    let remote = timeout(limit, connect_remote(server))
        .await
        .map_err(|_| anyhow::anyhow!("timeout after {}s", limit.as_secs()))??;
    let elapsed = started.elapsed();
    drop(remote);
    Ok(elapsed)
}

/// Handshake latency of every server, measured concurrently.
pub async fn ping_servers(
    servers: &[ServerConfig],
    limit: Duration,
) -> Vec<std::result::Result<Duration, String>> {
    let tasks: Vec<_> = servers
        .iter()
        .map(|server| {
            let server = server.clone();
            tokio::spawn(async move {
                measure_handshake(&server, limit)
                    .await
                    .map_err(|e| e.to_string())
            })
        })
        .collect();
    let mut out = Vec::with_capacity(tasks.len());
    for task in tasks {
        out.push(match task.await {
            Ok(r) => r,
            Err(e) => Err(format!("task failed: {e}")),
        });
    }
    out
}

async fn connect_remote(server: &ServerConfig) -> Result<MaybeTlsStream<TcpStream>> {
    let addr = (server.address.as_str(), server.port);
    match (server.transport_kind()?, server.transport_security()?) {
        (Transport::Tcp, TransportSecurity::Tls) => {
            let tls = tls::TlsClient::new(server.tls_server_name().to_string())?
                .with_fingerprint(server.fingerprint_kind());
            tls.connect(addr).await
        }
        (Transport::Tcp, TransportSecurity::Reality) => {
            let client = reality_client(server)?;
            let tcp = TcpStream::connect(addr).await?;
            let stream = RealityConnector::new(client)
                .with_fingerprint(server.fingerprint_kind())
                .connect(tcp)
                .await?;
            Ok(MaybeTlsStream::Reality(stream))
        }
        (Transport::Tcp, TransportSecurity::None) => {
            Ok(MaybeTlsStream::Plain(TcpStream::connect(addr).await?))
        }
        (Transport::Ws, TransportSecurity::Tls) => {
            let tls =
                tls::TlsClient::with_alpn(server.tls_server_name().to_string(), &["http/1.1"])?
                    .with_fingerprint(server.fingerprint_kind());
            let inner = WsInner::Tls(tls.connect_tls(addr).await?);
            let ws = WsStream::connect(inner, server.ws_host(), server.ws_path()).await?;
            Ok(MaybeTlsStream::Ws(ws))
        }
        (Transport::Ws, TransportSecurity::None) => {
            let inner = WsInner::Plain(TcpStream::connect(addr).await?);
            let ws = WsStream::connect(inner, server.ws_host(), server.ws_path()).await?;
            Ok(MaybeTlsStream::Ws(ws))
        }
        (Transport::Ws, TransportSecurity::Reality) => {
            anyhow::bail!("REALITY is not available over WebSocket")
        }
        (Transport::Xhttp, _) => Ok(MaybeTlsStream::Xhttp(crate::xhttp::connect(server).await?)),
    }
}

/// Send the VLESS request header the way Xray-core does: bundled with the
/// first client payload, or, if none arrives within 500 ms, with an empty
/// Vision padding block (or alone when Vision is off).
async fn prime_remote(
    client: &mut TcpStream,
    remote: &mut OutboundStream,
    write_timeout: Duration,
) -> Result<()> {
    let pending = match remote {
        OutboundStream::Proxy(r) => r.header_pending(),
        // A mux session opens with its first payload, or alone when the
        // local side reads first; nothing to wait for here.
        OutboundStream::Mux(_) | OutboundStream::Direct(_) => false,
    };
    if !pending {
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
        Err(_) => {
            if let OutboundStream::Proxy(r) = remote {
                r.queue_vision_camouflage();
            }
        }
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

/// Direct UDP session: datagrams go straight to the target from this machine.
fn create_direct_udp_tunnel(
    udp: UdpSocket,
    address: Address,
    port: u16,
    socket: Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> Result<UdpTunnel> {
    let udp = Arc::new(udp);
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);

    let writer_udp = udp.clone();
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
                    let Some(payload) = payload else { break };
                    if let Err(error) = writer_udp.send(&payload).await {
                        debug!("Failed to send direct UDP datagram: {}", error);
                        break;
                    }
                    STATS.add_up(payload.len());
                }
            }
        }
    });

    let mut reader_shutdown = shutdown;
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            tokio::select! {
                changed = reader_shutdown.changed() => {
                    if changed.is_err() || *reader_shutdown.borrow() {
                        break;
                    }
                }
                received = udp.recv(&mut buf) => {
                    let n = match received {
                        Ok(n) => n,
                        Err(error) => {
                            debug!("Failed to receive direct UDP datagram: {}", error);
                            break;
                        }
                    };
                    STATS.add_down(n);
                    let packet = match socks5::build_udp_packet(&address, port, &buf[..n]) {
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

fn direct_target(address: &Address, port: u16) -> String {
    match address {
        Address::Ipv6(ip) => format!("[{ip}]:{port}"),
        other => format!("{other}:{port}"),
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
