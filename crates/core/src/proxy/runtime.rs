use crate::config::{
    Config, DnsConfig, InboundProtocol, MuxConfig, RoutingConfig, RuntimeConfig, ServerConfig,
    Transport, TransportSecurity,
};
use crate::inbound::http;
use crate::inbound::socks5;
use crate::protocol::mux::{MuxManager, MuxStream, MUX_COOL_ADDRESS, MUX_COOL_PORT};
use crate::protocol::reality::tls::RealityConnector;
use crate::protocol::reality::RealityClient;
use crate::protocol::vision::{Vision, FLOW_VISION};
use crate::protocol::vless::{self, Address, Request, VlessStream, XtlsDirect};
use crate::proxy::dns::ResolverPolicy;
use crate::proxy::routing::{Outbound, Router};
use crate::proxy::stats::STATS;
use crate::transport::tls::{self, MaybeTlsStream, WsInner};
use crate::transport::ws::WsStream;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
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
    /// A stream on the shared QUIC connection to an h3 server.
    H3(crate::h3::H3Stream),
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
            OutboundStream::H3(s) => std::pin::Pin::new(s).poll_read(cx, buf),
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
            OutboundStream::H3(s) => std::pin::Pin::new(s).poll_write(cx, buf),
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
            OutboundStream::H3(s) => std::pin::Pin::new(s).poll_flush(cx),
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
            OutboundStream::H3(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            OutboundStream::Direct(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Where a UDP session ended up after routing.
pub enum UdpOutbound {
    Proxy(Box<RemoteStream>),
    /// A datagram session on the shared QUIC connection to an h3 server.
    H3(crate::h3::H3UdpSession),
    Direct(UdpSocket),
}

/// An h3 client and the key (address, SNI, account) it was made for.
type KeyedH3Client = (String, Arc<crate::h3::H3Client>);

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
    /// Admits server handshakes a few at a time (`runtime.max_parallel_handshakes`).
    handshakes: Option<Arc<Semaphore>>,
    /// Whether `direct` may reach loopback, private and link-local addresses.
    /// On when the inbound listens on loopback only (the default); off for a
    /// network-reachable inbound, where it would turn the proxy into a pivot
    /// into the host's own network.
    private_direct: bool,
    /// The h3 client of the active server, kept with the key it was made
    /// for (address, SNI, account) and replaced when the server changes.
    h3: Arc<std::sync::Mutex<Option<KeyedH3Client>>>,
    /// Roots h3 servers are checked against instead of the system's.
    h3_roots: Option<Arc<rustls::RootCertStore>>,
    /// Interface to pin `direct` outbound sockets to, so they do not loop back
    /// into the tunnel in TUN mode (set by the desktop TUN runner; `None`
    /// otherwise). See [`crate::proxy::egress`].
    egress: Option<crate::proxy::egress::Egress>,
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
            warn!("routing: geoip/geosite rules are not supported (they needed sing-box); these rules are ignored");
        }
        let mux = mux.sessions_per_connection().map(|concurrency| {
            if server.get().vision_flow().ok().flatten().is_some() {
                warn!("mux: ignored for XTLS Vision servers (Mux.Cool cannot be combined with Vision)");
            }
            Arc::new(MuxManager::new(concurrency))
        });
        let handshakes = (runtime.max_parallel_handshakes > 0)
            .then(|| Arc::new(Semaphore::new(runtime.max_parallel_handshakes)));
        Ok(Self {
            server,
            resolver: ResolverPolicy::new(dns)?,
            runtime,
            router: Arc::new(router),
            mux,
            handshakes,
            private_direct: true,
            h3: Arc::default(),
            h3_roots: None,
            egress: None,
        })
    }

    /// Allow or refuse `direct` connections to private destinations
    /// (see [`ProxyClient::private_direct`]).
    pub fn allow_private_direct(mut self, allow: bool) -> Self {
        self.private_direct = allow;
        self
    }

    /// Pin `direct` outbound sockets to this interface so they egress the
    /// physical NIC instead of looping back into the tunnel (desktop TUN mode).
    pub fn with_egress(mut self, egress: crate::proxy::egress::Egress) -> Self {
        self.egress = Some(egress);
        self
    }

    /// Check h3 servers' certificates against `roots` only, instead of the
    /// system's trust store (a private CA, tests).
    pub fn with_h3_roots(mut self, roots: rustls::RootCertStore) -> Self {
        self.h3_roots = Some(Arc::new(roots));
        self
    }

    /// Addresses of a `direct` target after DNS, minus what the rules block
    /// and, for a network-reachable inbound, minus private ranges.
    async fn direct_addrs(
        &self,
        address: &Address,
        port: u16,
    ) -> Result<Vec<std::net::SocketAddr>> {
        let resolved: Vec<std::net::SocketAddr> = match address {
            Address::Ipv4(ip) => vec![(IpAddr::V4(*ip), port).into()],
            Address::Ipv6(ip) => vec![(IpAddr::V6(*ip), port).into()],
            Address::Domain(_) => tokio::net::lookup_host(direct_target(address, port))
                .await?
                .collect(),
        };
        if resolved.is_empty() {
            anyhow::bail!("cannot resolve {address}");
        }
        let mut out = Vec::with_capacity(resolved.len());
        for addr in resolved {
            let ip = addr.ip();
            let as_address = match ip {
                IpAddr::V4(v4) => Address::Ipv4(v4),
                IpAddr::V6(v6) => Address::Ipv6(v6),
            };
            if self.router.decide(&as_address, port) == Outbound::Block {
                debug!("direct {address}:{port}: {ip} blocked by routing rules");
                continue;
            }
            if !self.private_direct && crate::proxy::routing::is_private_ip(ip) {
                debug!("direct {address}:{port}: {ip} is private, refused (inbound is not on loopback)");
                continue;
            }
            out.push(addr);
        }
        if out.is_empty() {
            anyhow::bail!("blocked by routing rules: {address}:{port} (resolved addresses)");
        }
        Ok(out)
    }

    /// Connect directly to the first working address, pinned to the egress
    /// interface when one is set so it does not loop back into the tunnel.
    async fn direct_tcp(&self, addrs: &[std::net::SocketAddr]) -> Result<TcpStream> {
        let connect_timeout = Duration::from_secs(self.runtime.connect_timeout_secs);
        let mut last: Option<anyhow::Error> = None;
        for &addr in addrs {
            let socket = if addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()
            } else {
                tokio::net::TcpSocket::new_v4()
            };
            let socket = match socket {
                Ok(s) => s,
                Err(e) => {
                    last = Some(e.into());
                    continue;
                }
            };
            if let Some(egress) = &self.egress {
                if let Err(e) = egress.bind_fd(socket.as_raw_fd(), addr) {
                    last = Some(anyhow::anyhow!(
                        "pin direct socket to egress interface: {e}"
                    ));
                    continue;
                }
            }
            match timeout(connect_timeout, socket.connect(addr)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => last = Some(e.into()),
                Err(_) => last = Some(anyhow::anyhow!("Direct connection timeout")),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no address to connect directly")))
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
                let addrs = self.direct_addrs(&address, port).await?;
                let stream = self.direct_tcp(&addrs).await?;
                Ok(OutboundStream::Direct(stream))
            }
            Outbound::Proxy => {
                let server = self.server.get();
                if server.transport_kind()? == Transport::H3 {
                    // Resolved here when DNS policy says so, as for VLESS.
                    let request_address = self.resolver.resolve(address, port).await?;
                    let client = self.h3_client(&server)?;
                    let stream = timeout(
                        Duration::from_secs(self.runtime.connect_timeout_secs),
                        client.open_tcp(&request_address, port),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;
                    return Ok(OutboundStream::H3(stream));
                }
                if let Some(mux) = &self.mux {
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

    /// The network under us changed: an h3 connection moves to the new path
    /// (other transports reconnect per session anyway).
    pub async fn network_changed(&self) {
        let client = self
            .h3
            .lock()
            .expect("h3 client lock poisoned")
            .as_ref()
            .map(|(_, client)| client.clone());
        if let Some(client) = client {
            client.network_changed().await;
        }
    }

    /// The h3 client for `server`, made on first use and reused while the
    /// server stays the same; one QUIC connection carries all its streams.
    fn h3_client(&self, server: &ServerConfig) -> Result<Arc<crate::h3::H3Client>> {
        let key = format!(
            "{}|{}|{}",
            server.endpoint(),
            server.tls_server_name(),
            server.uuid
        );
        let mut slot = self.h3.lock().expect("h3 client lock poisoned");
        if let Some((current, client)) = slot.as_ref() {
            if *current == key {
                return Ok(client.clone());
            }
        }
        let roots = match &self.h3_roots {
            Some(roots) => (**roots).clone(),
            None => crate::transport::tls::system_root_store(),
        };
        let client = Arc::new(crate::h3::H3Client::with_roots(
            &server.address,
            server.port,
            server.tls_server_name(),
            server.uuid,
            roots,
            server.fingerprint_kind(),
        )?);
        *slot = Some((key, client.clone()));
        Ok(client)
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
        // Logged on failures: identify the account without printing the UUID.
        let key = format!("{}#{}", server.endpoint(), account_tag(&server.uuid));
        let connect_timeout = Duration::from_secs(self.runtime.connect_timeout_secs);
        let handshakes = self.handshakes.clone();
        let dial = async move {
            let remote = admitted(
                handshakes.as_deref(),
                connect_timeout,
                connect_remote(&server),
            )
            .await?;
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
                let target = self.direct_addrs(&address, port).await?[0];
                let bind: std::net::SocketAddr = if target.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                };
                let socket = UdpSocket::bind(bind).await?;
                if let Some(egress) = &self.egress {
                    egress
                        .bind_fd(socket.as_raw_fd(), target)
                        .map_err(|e| anyhow::anyhow!("pin direct udp socket to egress: {e}"))?;
                }
                socket.connect(target).await?;
                Ok(UdpOutbound::Direct(socket))
            }
            Outbound::Proxy => {
                let server = self.server.get();
                if server.transport_kind()? == Transport::H3 {
                    let request_address = self.resolver.resolve(address, port).await?;
                    let client = self.h3_client(&server)?;
                    let session = timeout(
                        Duration::from_secs(self.runtime.connect_timeout_secs),
                        client.open_udp(&request_address, port),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("Connection timeout"))??;
                    return Ok(UdpOutbound::H3(session));
                }
                Ok(UdpOutbound::Proxy(Box::new(
                    self.connect_udp_target(address, port).await?,
                )))
            }
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

        let remote = admitted(
            self.handshakes.as_deref(),
            connect_timeout,
            connect_remote(&server),
        )
        .await?;

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

/// Run native proxy listeners until SIGINT or SIGTERM. Desktop sidecars
/// are managed by the CLI; embedding hosts can use [`serve_with_shutdown`].
pub async fn serve_with_server(config: Arc<Config>, active: ActiveServer) -> Result<()> {
    if config.needs_xray_sidecar()? {
        anyhow::bail!("this server needs the xray-core sidecar; run it through the desktop client");
    }
    if config.tun.enabled {
        anyhow::bail!("TUN mode is handled by the desktop client (native netstack), not here");
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = serve_with_shutdown(config, active, shutdown_rx) => result,
        _ = interrupt.recv() => {
            let _ = shutdown_tx.send(true);
            Ok(())
        }
        _ = terminate.recv() => {
            let _ = shutdown_tx.send(true);
            Ok(())
        }
    }
}

/// Serve native SOCKS5/HTTP listeners using a shutdown signal supplied
/// by the host. The host owns signals and any external TUN/sidecar process.
pub async fn serve_with_shutdown(
    config: Arc<Config>,
    active: ActiveServer,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let connection_count = Arc::new(AtomicUsize::new(0));
    let max_connections = config.runtime.max_connections;
    raise_nofile_limit((max_connections as u64) * 4 + 256);
    let semaphore = Arc::new(Semaphore::new(max_connections));
    let connector = ProxyClient::new(
        active,
        config.dns.clone(),
        config.runtime.clone(),
        &config.routing,
        &config.mux,
    )?
    .allow_private_direct(inbound_is_loopback(&config.inbound.address));
    if !inbound_is_loopback(&config.inbound.address) {
        info!(
            "Inbound {} is reachable from the network: direct connections to private addresses are refused",
            config.inbound.address
        );
    }

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
                let (client, addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // EMFILE/ENFILE/ECONNABORTED: keep serving, give the
                        // kernel a moment to free resources.
                        warn!("accept failed: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

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

    let request = timeout(
        handshake_timeout(read_timeout),
        socks5::accept_request(&mut client),
    )
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
    let request_sent = prime_remote(&mut client, &mut remote, write_timeout).await?;

    let result = copy_bidirectional_with_timeouts(
        &mut client,
        &mut remote,
        RelayTimeouts {
            read: read_timeout,
            write: write_timeout,
            idle: idle_timeout,
        },
        request_sent,
    )
    .await;

    debug!("Connection closed");
    result.map(|_| ())
}

/// Connect to `address:port` through routing and relay `client` there: the
/// TCP path of the netstack, where there is no handshake to answer.
/// `on_dialed` runs once the remote side is connected, before any data.
pub(crate) async fn relay_tcp<C>(
    mut client: C,
    connector: &ProxyClient,
    address: Address,
    port: u16,
    on_dialed: impl FnOnce(),
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let runtime = connector.runtime();
    let timeouts = RelayTimeouts {
        read: Duration::from_secs(runtime.read_timeout_secs),
        write: Duration::from_secs(runtime.write_timeout_secs),
        idle: Duration::from_secs(runtime.idle_timeout_secs),
    };
    let mut remote = timeout(
        Duration::from_secs(runtime.connect_timeout_secs),
        connector.open_tcp(address, port),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Connection timeout"))?
    .map_err(|error| anyhow::anyhow!("Failed to connect to target: {error}"))?;
    on_dialed();
    let request_sent = prime_remote(&mut client, &mut remote, timeouts.write).await?;
    copy_bidirectional_with_timeouts(&mut client, &mut remote, timeouts, request_sent).await?;
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
                let (client, addr) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // EMFILE/ENFILE/ECONNABORTED: keep serving, give the
                        // kernel a moment to free resources.
                        warn!("accept failed: {error}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

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

    let request = match timeout(
        handshake_timeout(read_timeout),
        http::accept_request(&mut client),
    )
    .await
    {
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
    let primed = prime_remote(&mut client, &mut remote, write_timeout).await?;
    let request_sent = primed || !request.initial_payload.is_empty();

    let result = copy_bidirectional_with_timeouts(
        &mut client,
        &mut remote,
        RelayTimeouts {
            read: read_timeout,
            write: write_timeout,
            idle: idle_timeout,
        },
        request_sent,
    )
    .await;

    debug!("Connection closed");
    result.map(|_| ())
}

/// Timeouts of an established relay, see [`RuntimeConfig`](crate::RuntimeConfig).
#[derive(Clone, Copy)]
struct RelayTimeouts {
    /// Target has been sent a request and nothing has come back yet.
    read: Duration,
    /// A single write pending towards one peer.
    write: Duration,
    /// No bytes in either direction on an otherwise healthy connection.
    idle: Duration,
}

/// Relay both directions until either side reads EOF or an error. The two
/// directions make progress independently (a stalled write towards one peer
/// never stops reads from the other), which matters for multiplexed sessions
/// where several relays share one connection.
///
/// Timeouts: a single write pending longer than `write` is an error. While
/// the client has sent something and the target has not answered at all,
/// `read` of silence is an error (the target is not responding). Otherwise a
/// connection nobody uses for `idle` is closed quietly and successfully: a
/// browser's spare keep-alive socket is not a failure. `request_sent` says
/// whether the caller already forwarded client bytes before the relay began.
async fn copy_bidirectional_with_timeouts<A, B>(
    a: &mut A,
    b: &mut B,
    timeouts: RelayTimeouts,
    request_sent: bool,
) -> Result<(u64, u64)>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin + Send,
    B: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    let mut a_to_b = RelayDirection::new("remote", timeouts.write, true);
    let mut b_to_a = RelayDirection::new("client", timeouts.write, false);
    let awaiting_reply = |a_to_b: &RelayDirection, b_to_a: &RelayDirection| {
        b_to_a.copied == 0 && (request_sent || a_to_b.copied > 0)
    };
    let silence_limit = |waiting: bool| {
        if waiting {
            timeouts.read
        } else {
            timeouts.idle
        }
    };
    let mut waiting = awaiting_reply(&a_to_b, &b_to_a);
    let mut activity = Box::pin(tokio::time::sleep(silence_limit(waiting)));

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
            waiting = awaiting_reply(&a_to_b, &b_to_a);
            activity
                .as_mut()
                .reset(tokio::time::Instant::now() + silence_limit(waiting));
        }
        if activity.as_mut().poll(cx).is_ready() {
            if waiting {
                return Poll::Ready(Err(anyhow::anyhow!(
                    "Read timeout: no response from target in {}s",
                    timeouts.read.as_secs()
                )));
            }
            debug!("Connection idle for {}s, closing", timeouts.idle.as_secs());
            return Poll::Ready(Ok((a_to_b.copied, b_to_a.copied)));
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
    let mut sweep = tokio::time::interval(Duration::from_secs(30));
    sweep.reset();

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = sweep.tick() => {
                let now = Instant::now();
                let idle: Vec<_> = tunnels
                    .iter()
                    .filter(|(_, t)| now.duration_since(t.last_used) >= UDP_TUNNEL_IDLE)
                    .map(|(k, _)| k.clone())
                    .collect();
                for key in idle {
                    if let Some(tunnel) = tunnels.remove(&key) {
                        debug!("UDP session to {}:{} idle, closed", key.0, key.1);
                        tunnel.abort();
                    }
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
                        if tunnels.len() >= MAX_UDP_TUNNELS {
                            if let Some(oldest) = tunnels
                                .iter()
                                .min_by_key(|(_, t)| t.last_used)
                                .map(|(k, _)| k.clone())
                            {
                                if let Some(tunnel) = tunnels.remove(&oldest) {
                                    debug!("UDP session limit reached, dropping {}:{}", oldest.0, oldest.1);
                                    tunnel.abort();
                                }
                            }
                        }
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

                    let send_result = match tunnels.get_mut(&key) {
                        Some(tunnel) => {
                            tunnel.last_used = Instant::now();
                            tunnel.sender.send(payload).await
                        }
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
        UdpOutbound::H3(session) => {
            return Ok(create_h3_udp_tunnel(
                session,
                address,
                port,
                socket,
                client_addr,
                shutdown,
            ));
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
        last_used: Instant::now(),
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
    if server.transport_kind()? == Transport::H3 {
        let elapsed = measure_handshake(
            server,
            Duration::from_secs(config.runtime.connect_timeout_secs),
        )
        .await?;
        return Ok(format!(
            "QUIC handshake OK with {} (sni {}, alpn h3) in {} ms",
            server.endpoint(),
            server.tls_server_name(),
            elapsed.as_millis()
        ));
    }
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
            let info =
                crate::protocol::reality::tls::connection_info(&stream, server.tls_server_name());
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
    if server.transport_kind()? == Transport::H3 {
        let client = crate::h3::H3Client::new(
            &server.address,
            server.port,
            server.tls_server_name(),
            server.uuid,
            server.fingerprint_kind(),
        )?;
        let conn = timeout(limit, client.connection())
            .await
            .map_err(|_| anyhow::anyhow!("timeout after {}s", limit.as_secs()))??;
        let elapsed = started.elapsed();
        conn.close(crate::h3::wire::H3_NO_ERROR.into(), b"");
        return Ok(elapsed);
    }
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

/// Run `dial` (a connection to the server) once `handshakes` admits it, so a
/// burst of new sessions becomes a steady trickle of handshakes. Waiting for
/// a slot and the dial itself each get `limit`.
async fn admitted<T>(
    handshakes: Option<&Semaphore>,
    limit: Duration,
    dial: impl Future<Output = Result<T>>,
) -> Result<T> {
    let _slot = match handshakes {
        Some(handshakes) => Some(
            timeout(limit, handshakes.acquire())
                .await
                .map_err(|_| anyhow::anyhow!("Timed out waiting for a handshake slot"))?
                .map_err(|_| anyhow::anyhow!("handshake limiter closed"))?,
        ),
        None => None,
    };
    timeout(limit, dial)
        .await
        .map_err(|_| anyhow::anyhow!("Connection timeout"))?
}

async fn connect_remote(server: &ServerConfig) -> Result<MaybeTlsStream<TcpStream>> {
    let addr = (server.address.as_str(), server.port);
    match (server.transport_kind()?, server.transport_security()?) {
        (Transport::Tcp, TransportSecurity::Tls) => {
            // Xray offers h2,http/1.1 by default; Chrome always sends ALPN,
            // so a hello with ALPS but no ALPN would stand out.
            let alpn: Vec<&str> = match server.alpn.as_deref().map(str::trim) {
                Some(a) if !a.is_empty() => a.split(',').map(str::trim).collect(),
                _ => vec!["h2", "http/1.1"],
            };
            let tls = tls::TlsClient::with_alpn(server.tls_server_name().to_string(), &alpn)?
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
        (Transport::Xhttp, _) => Ok(MaybeTlsStream::Xhttp(
            crate::transport::xhttp::connect(server).await?,
        )),
        // One shared QUIC connection, not a stream per session: ProxyClient
        // routes h3 servers to its H3Client before getting here.
        (Transport::H3, _) => anyhow::bail!("h3 servers carry no per-session transport"),
    }
}

/// Send the VLESS request header the way Xray-core does: bundled with the
/// first client payload, or, if none arrives within 500 ms, with an empty
/// Vision padding block (or alone when Vision is off).
/// Returns whether any client bytes were forwarded.
async fn prime_remote<C: AsyncRead + Unpin>(
    client: &mut C,
    remote: &mut OutboundStream,
    write_timeout: Duration,
) -> Result<bool> {
    let pending = match remote {
        OutboundStream::Proxy(r) => r.header_pending(),
        // A mux session opens with its first payload, or alone when the
        // local side reads first; nothing to wait for here.
        OutboundStream::Mux(_) | OutboundStream::H3(_) | OutboundStream::Direct(_) => false,
    };
    if !pending {
        return Ok(false);
    }
    let mut sent = false;
    let mut buf = vec![0u8; 8192];
    match timeout(Duration::from_millis(500), client.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            timeout(write_timeout, remote.write_all(&buf[..n]))
                .await
                .map_err(|_| anyhow::anyhow!("Write timeout to remote"))??;
            sent = true;
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
    Ok(sent)
}

/// Short, non-secret tag for a UUID (first 4 bytes of its SHA-256), for logs
/// and map keys.
fn account_tag(uuid: &uuid::Uuid) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(uuid.as_bytes());
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// A client gets this long to finish the SOCKS5/HTTP handshake; `read_timeout`
/// is meant for established relays and would let idle sockets hold slots.
fn handshake_timeout(read_timeout: Duration) -> Duration {
    read_timeout.min(Duration::from_secs(30))
}

/// Whether the inbound address is only reachable from this machine.
pub fn inbound_is_loopback(address: &str) -> bool {
    match address.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => address.eq_ignore_ascii_case("localhost"),
    }
}

/// Raise the open-files soft limit towards the hard limit: every proxied
/// connection costs at least two descriptors, and launchd starts agents with
/// a soft limit of 256.
pub fn raise_nofile_limit(wanted: u64) {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc call with a valid out-pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return;
    }
    let wanted = wanted as libc::rlim_t;
    if lim.rlim_cur >= wanted {
        return;
    }
    let target = if lim.rlim_max == libc::RLIM_INFINITY {
        wanted
    } else {
        wanted.min(lim.rlim_max)
    };
    // macOS refuses soft limits above OPEN_MAX unless the hard limit is infinite.
    let target = if cfg!(target_os = "macos") {
        target.min(10_240)
    } else {
        target
    };
    if target <= lim.rlim_cur {
        return;
    }
    let new = libc::rlimit {
        rlim_cur: target,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: plain libc call with a valid pointer.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) } == 0 {
        debug!(
            "open files limit raised from {} to {}",
            lim.rlim_cur, target
        );
    } else {
        debug!(
            "cannot raise open files limit from {} to {}",
            lim.rlim_cur, target
        );
    }
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
        last_used: Instant::now(),
    })
}

fn direct_target(address: &Address, port: u16) -> String {
    match address {
        Address::Ipv6(ip) => format!("[{ip}]:{port}"),
        other => format!("{other}:{port}"),
    }
}

/// SOCKS5 UDP to one target over an h3 datagram session.
fn create_h3_udp_tunnel(
    session: crate::h3::H3UdpSession,
    address: Address,
    port: u16,
    socket: Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> UdpTunnel {
    let (out, mut incoming) = session.into_split();
    let (sender, mut receiver) = mpsc::channel::<Vec<u8>>(64);

    let mut writer_shutdown = shutdown.clone();
    let target = address.clone();
    let writer_task = tokio::spawn(async move {
        let address = target;
        loop {
            tokio::select! {
                changed = writer_shutdown.changed() => {
                    if changed.is_err() || *writer_shutdown.borrow() {
                        break;
                    }
                }
                payload = receiver.recv() => {
                    let Some(payload) = payload else { break };
                    // Too large for a datagram now: dropped, as UDP may be.
                    match out.send(&payload) {
                        Ok(()) => STATS.add_up(payload.len()),
                        Err(error) => debug!("h3 UDP to {address}:{port}: {error}"),
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
                payload = incoming.recv() => {
                    let Some(payload) = payload else { break };
                    STATS.add_down(payload.len());
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

    UdpTunnel {
        sender,
        writer_task,
        reader_task,
        last_used: Instant::now(),
    }
}

struct UdpTunnel {
    sender: mpsc::Sender<Vec<u8>>,
    writer_task: JoinHandle<()>,
    reader_task: JoinHandle<()>,
    /// Last datagram from the client towards this target.
    last_used: Instant,
}

/// Distinct targets one UDP association may talk to at once; the least
/// recently used one is dropped beyond that. Each target costs a VLESS
/// connection or a socket plus two tasks, which `max_connections` does not see.
const MAX_UDP_TUNNELS: usize = 128;
/// A target the client has not sent to for this long is closed.
const UDP_TUNNEL_IDLE: Duration = Duration::from_secs(120);

impl UdpTunnel {
    fn abort(self) {
        self.writer_task.abort();
        self.reader_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn handshakes_are_admitted_a_few_at_a_time() {
        let limiter = Arc::new(Semaphore::new(3));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let dials: Vec<_> = (0..10)
            .map(|_| {
                let (limiter, in_flight, peak) = (limiter.clone(), in_flight.clone(), peak.clone());
                tokio::spawn(async move {
                    admitted(Some(&limiter), Duration::from_secs(5), async {
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
                })
            })
            .collect();
        for dial in dials {
            dial.await.unwrap().unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn waiting_for_a_handshake_slot_times_out() {
        let limiter = Semaphore::new(1);
        let _busy = limiter.acquire().await.unwrap();
        let result = admitted(Some(&limiter), Duration::from_millis(30), async { Ok(()) }).await;
        assert!(result.unwrap_err().to_string().contains("handshake slot"));
    }

    fn relay_timeouts(read_ms: u64, idle_ms: u64) -> RelayTimeouts {
        RelayTimeouts {
            read: Duration::from_millis(read_ms),
            write: Duration::from_secs(5),
            idle: Duration::from_millis(idle_ms),
        }
    }

    #[tokio::test]
    async fn idle_relay_closes_successfully() {
        let (mut client, _client_peer) = tokio::io::duplex(1024);
        let (mut remote, _remote_peer) = tokio::io::duplex(1024);
        let result = copy_bidirectional_with_timeouts(
            &mut client,
            &mut remote,
            relay_timeouts(5_000, 50),
            false,
        )
        .await;
        assert_eq!(result.unwrap(), (0, 0));
    }

    #[tokio::test]
    async fn unanswered_request_is_an_error() {
        let (mut client, mut client_peer) = tokio::io::duplex(1024);
        let (mut remote, _remote_peer) = tokio::io::duplex(1024);
        client_peer
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let err = copy_bidirectional_with_timeouts(
            &mut client,
            &mut remote,
            relay_timeouts(50, 5_000),
            false,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no response from target"), "{err}");
    }

    #[tokio::test]
    async fn request_sent_before_relay_counts_as_waiting() {
        let (mut client, _client_peer) = tokio::io::duplex(1024);
        let (mut remote, _remote_peer) = tokio::io::duplex(1024);
        let err = copy_bidirectional_with_timeouts(
            &mut client,
            &mut remote,
            relay_timeouts(50, 5_000),
            true,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("no response from target"), "{err}");
    }

    #[tokio::test]
    async fn answered_request_then_silence_is_idle() {
        let (mut client, mut client_peer) = tokio::io::duplex(1024);
        let (mut remote, mut remote_peer) = tokio::io::duplex(1024);
        client_peer.write_all(b"hello").await.unwrap();
        remote_peer.write_all(b"world").await.unwrap();
        let result = copy_bidirectional_with_timeouts(
            &mut client,
            &mut remote,
            relay_timeouts(5_000, 50),
            true,
        )
        .await;
        assert_eq!(result.unwrap(), (5, 5));
        let mut buf = [0u8; 5];
        client_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn loopback_detection() {
        assert!(inbound_is_loopback("127.0.0.1"));
        assert!(inbound_is_loopback("::1"));
        assert!(inbound_is_loopback("[::1]"));
        assert!(inbound_is_loopback("localhost"));
        assert!(!inbound_is_loopback("0.0.0.0"));
        assert!(!inbound_is_loopback("192.168.1.2"));
        assert!(!inbound_is_loopback("::"));
    }

    #[test]
    fn handshake_timeout_is_capped() {
        assert_eq!(
            handshake_timeout(Duration::from_secs(300)),
            Duration::from_secs(30)
        );
        assert_eq!(
            handshake_timeout(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn account_tag_hides_the_uuid() {
        let id = uuid::Uuid::parse_str("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d").unwrap();
        let tag = account_tag(&id);
        assert_eq!(tag.len(), 8);
        assert!(!id.to_string().contains(&tag));
    }

    #[tokio::test]
    async fn direct_to_private_is_refused_for_a_network_inbound() {
        let config = crate::config::Config::from_vless_url(
            &crate::config::url::VlessUrl::parse(
                "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@203.0.113.9:443?security=none",
            )
            .unwrap(),
            1080,
        );
        let routing = RoutingConfig {
            final_outbound: "proxy".to_string(),
            rules: vec![crate::config::RoutingRule {
                outbound: "direct".to_string(),
                ip_private: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let client = ProxyClient::new(
            ActiveServer::new(config.server.clone()),
            config.dns.clone(),
            config.runtime.clone(),
            &routing,
            &config.mux,
        )
        .unwrap();
        let loopback = Address::Ipv4(std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(client.router().decide(&loopback, 22), Outbound::Direct);
        assert!(client.direct_addrs(&loopback, 22).await.is_ok());
        let client = client.allow_private_direct(false);
        let err = client
            .direct_addrs(&loopback, 22)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("blocked"), "{err}");
        assert!(client
            .direct_addrs(&Address::Domain("localhost".to_string()), 22)
            .await
            .is_err());
    }
}
