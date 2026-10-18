use anyhow::{anyhow, Result};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use vproxy::inbound::socks5;
use vproxy::protocol::mux;
use vproxy::protocol::vless;
use vproxy::transport::ws::WsStream;
use vproxy::{
    serve, serve_with_server, ActiveServer, Config, DnsCacheConfig, DnsConfig, InboundConfig,
    MuxConfig, RoutingConfig, RoutingRule, RuntimeConfig, ServerConfig,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_tcp_round_trip_works_end_to_end() -> Result<()> {
    let server = spawn_mock_vless_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Tcp);
        assert_eq!(
            request.address,
            vless::Address::Domain("echo.example".to_string())
        );
        assert_eq!(request.port, 7000);

        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        send_vless_response(&mut stream).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        Ok(())
    })
    .await?;
    let proxy = spawn_proxy("socks5", server.addr).await?;

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    socks5_connect(&mut client, "echo.example", 7000).await?;
    client.write_all(b"ping").await?;

    let mut echoed = [0u8; 4];
    timeout(TEST_TIMEOUT, client.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"ping");

    server.finish().await?;
    proxy.stop();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_connect_round_trip_works_end_to_end() -> Result<()> {
    let server = spawn_mock_vless_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Tcp);
        assert_eq!(
            request.address,
            vless::Address::Domain("connect.example".to_string())
        );
        assert_eq!(request.port, 443);

        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"pong");
        send_vless_response(&mut stream).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        Ok(())
    })
    .await?;
    let proxy = spawn_proxy("http", server.addr).await?;

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    client
        .write_all(b"CONNECT connect.example:443 HTTP/1.1\r\nHost: connect.example:443\r\n\r\n")
        .await?;
    let response = read_http_headers(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200 Connection Established\r\n"));

    client.write_all(b"pong").await?;
    let mut echoed = [0u8; 4];
    timeout(TEST_TIMEOUT, client.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"pong");

    server.finish().await?;
    proxy.stop();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_proxy_request_rewrites_to_origin_form() -> Result<()> {
    let server = spawn_mock_vless_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Tcp);
        assert_eq!(
            request.address,
            vless::Address::Domain("example.com".to_string())
        );
        assert_eq!(request.port, 80);

        let request_headers = read_http_headers(&mut stream).await?;
        assert!(request_headers.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(request_headers.contains("Host: example.com\r\n"));
        assert!(!request_headers.contains("Proxy-Connection"));

        send_vless_response(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await?;
        stream.flush().await?;
        Ok(())
    })
    .await?;
    let proxy = spawn_proxy("http", server.addr).await?;

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    client
        .write_all(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .await?;

    let response = read_http_response(&mut client).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with("OK"));

    server.finish().await?;
    proxy.stop();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_udp_associate_relays_datagrams_end_to_end() -> Result<()> {
    let server = spawn_mock_vless_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Udp);
        assert_eq!(
            request.address,
            vless::Address::Domain("dns.example".to_string())
        );
        assert_eq!(request.port, 5353);

        let payload = vless::read_udp_frame(&mut stream).await?;
        assert_eq!(payload, b"hello-udp");
        send_vless_response(&mut stream).await?;
        vless::write_udp_frame(&mut stream, &payload).await?;
        stream.flush().await?;
        Ok(())
    })
    .await?;
    let proxy = spawn_proxy("socks5", server.addr).await?;

    let mut control = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    let udp_bind_addr = socks5_udp_associate(&mut control).await?;
    let udp_client = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let packet = socks5::build_udp_packet(
        &vless::Address::Domain("dns.example".to_string()),
        5353,
        b"hello-udp",
    )?;
    udp_client.send_to(&packet, udp_bind_addr).await?;

    let mut recv_buffer = vec![0u8; 65_535];
    let (len, _) = timeout(TEST_TIMEOUT, udp_client.recv_from(&mut recv_buffer)).await??;
    let response = socks5::parse_udp_packet(&recv_buffer[..len])?;
    assert_eq!(
        response.address,
        vless::Address::Domain("dns.example".to_string())
    );
    assert_eq!(response.port, 5353);
    assert_eq!(response.payload, b"hello-udp");

    drop(control);
    server.finish().await?;
    proxy.stop();
    Ok(())
}

struct ProxyHarness {
    addr: SocketAddr,
    task: JoinHandle<Result<()>>,
}

impl ProxyHarness {
    fn stop(self) {
        self.task.abort();
    }
}

struct MockServerHarness {
    addr: SocketAddr,
    task: JoinHandle<Result<()>>,
}

impl MockServerHarness {
    async fn finish(self) -> Result<()> {
        let result = timeout(TEST_TIMEOUT, self.task)
            .await
            .map_err(|_| anyhow!("mock VLESS server timed out"))??;
        result?;
        Ok(())
    }
}

#[derive(Debug)]
struct ObservedVlessRequest {
    command: vless::Command,
    address: vless::Address,
    port: u16,
}

#[tokio::test]
async fn switching_the_active_server_affects_new_sessions_only() -> Result<()> {
    let echo = |tag: &'static [u8]| {
        move |mut stream: TcpStream| async move {
            let _ = read_vless_request(&mut stream).await?;
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await?;
            send_vless_response(&mut stream).await?;
            stream.write_all(tag).await?;
            stream.flush().await?;
            Ok(())
        }
    };
    let server_a = spawn_mock_vless_server(echo(b"AAAA")).await?;
    let server_b = spawn_mock_vless_server(echo(b"BBBB")).await?;
    let (proxy, active, config) = spawn_switchable_proxy(server_a.addr).await?;

    let ask = |proxy_addr: SocketAddr| async move {
        let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy_addr)).await??;
        socks5_connect(&mut client, "echo.example", 7000).await?;
        client.write_all(b"ping").await?;
        let mut reply = [0u8; 4];
        timeout(TEST_TIMEOUT, client.read_exact(&mut reply)).await??;
        Ok::<_, anyhow::Error>(reply)
    };

    assert_eq!(&ask(proxy.addr).await?, b"AAAA");

    let mut server_b_config = config.server.clone();
    server_b_config.address = server_b.addr.ip().to_string();
    server_b_config.port = server_b.addr.port();
    active.swap(server_b_config, &config)?;
    assert_eq!(&ask(proxy.addr).await?, b"BBBB");

    // A server that needs the xray sidecar is refused and the active one stays.
    let mut needs_sidecar = config.server.clone();
    needs_sidecar.use_tls = true;
    needs_sidecar.security = "tls".to_string();
    needs_sidecar.flow = Some("xtls-rprx-vision".to_string());
    assert!(active.swap(needs_sidecar, &config).is_err());
    assert_eq!(active.get().port, server_b.addr.port());

    server_a.finish().await?;
    server_b.finish().await?;
    proxy.stop();
    Ok(())
}

#[tokio::test]
async fn websocket_transport_carries_the_vless_session() -> Result<()> {
    let server = spawn_mock_vless_ws_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Tcp);
        assert_eq!(
            request.address,
            vless::Address::Domain("echo.example".to_string())
        );
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
        send_vless_response(&mut stream).await?;
        stream.write_all(b"pong").await?;
        stream.flush().await?;
        Ok(())
    })
    .await?;
    let proxy = spawn_proxy_full("socks5", server.addr, RoutingConfig::default(), "ws").await?;

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    socks5_connect(&mut client, "echo.example", 7000).await?;
    client.write_all(b"ping").await?;
    let mut echoed = [0u8; 4];
    timeout(TEST_TIMEOUT, client.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"pong");

    server.finish().await?;
    proxy.stop();
    Ok(())
}

/// The mock accepts exactly one TCP connection, so two sessions reaching it
/// proves they were multiplexed. It upper-cases what it receives per session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mux_shares_one_vless_connection_between_sessions() -> Result<()> {
    let server = spawn_mock_vless_server(|mut stream| async move {
        let request = read_vless_request(&mut stream).await?;
        assert_eq!(request.command, vless::Command::Mux);
        assert_eq!(
            request.address,
            vless::Address::Domain(mux::MUX_COOL_ADDRESS.to_string())
        );
        send_vless_response(&mut stream).await?;

        let mut opened = Vec::new();
        let mut ended = 0;
        while ended < 2 {
            let frame = timeout(TEST_TIMEOUT, mux::read_frame(&mut stream))
                .await
                .map_err(|_| anyhow!("mock mux server timed out"))??
                .ok_or_else(|| anyhow!("mux connection closed early"))?;
            match frame.status {
                mux::STATUS_NEW => opened.push((frame.id, frame.target())),
                mux::STATUS_END => {
                    ended += 1;
                    stream
                        .write_all(&mux::encode_frame(frame.id, mux::STATUS_END, 0, None, None))
                        .await?;
                }
                _ => {}
            }
            if let Some(data) = frame.data {
                let reply = data.to_ascii_uppercase();
                stream
                    .write_all(&mux::encode_frame(
                        frame.id,
                        mux::STATUS_KEEP,
                        0,
                        None,
                        Some(&reply),
                    ))
                    .await?;
            }
            stream.flush().await?;
        }
        assert_eq!(
            opened,
            vec![
                (
                    1,
                    Some((vless::Address::Domain("echo-a.example".to_string()), 7001))
                ),
                (
                    2,
                    Some((vless::Address::Domain("echo-b.example".to_string()), 7002))
                ),
            ]
        );
        Ok(())
    })
    .await?;
    let proxy = spawn_mux_proxy(server.addr, 8).await?;

    let mut a = TcpStream::connect(proxy.addr).await?;
    socks5_connect(&mut a, "echo-a.example", 7001).await?;
    let mut b = TcpStream::connect(proxy.addr).await?;
    socks5_connect(&mut b, "echo-b.example", 7002).await?;

    b.write_all(b"hello from b").await?;
    a.write_all(b"hello from a").await?;
    let mut reply = [0u8; 12];
    timeout(TEST_TIMEOUT, a.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"HELLO FROM A");
    timeout(TEST_TIMEOUT, b.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"HELLO FROM B");

    // Client EOF ends the session (End frame); the server's End closes our side.
    a.shutdown().await?;
    b.shutdown().await?;
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, a.read_to_end(&mut rest)).await??;
    timeout(TEST_TIMEOUT, b.read_to_end(&mut rest)).await??;
    assert!(rest.is_empty());

    timeout(TEST_TIMEOUT, server.task)
        .await
        .map_err(|_| anyhow!("mock mux server did not finish"))???;
    proxy.task.abort();
    Ok(())
}

#[tokio::test]
async fn routing_direct_rule_bypasses_the_vless_server() -> Result<()> {
    // A plain TCP echo target that must be reached without any VLESS framing.
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let target_addr = target.local_addr()?;
    let echo = tokio::spawn(async move {
        let (mut s, _) = target.accept().await?;
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello");
        s.write_all(b"world").await?;
        s.flush().await?;
        Ok::<(), anyhow::Error>(())
    });

    // The mock VLESS server must never be contacted.
    let server = spawn_mock_vless_server(|_stream| async move {
        panic!("direct-routed connection reached the VLESS server")
    })
    .await?;
    let routing = RoutingConfig {
        final_outbound: "proxy".to_string(),
        rules: vec![RoutingRule {
            outbound: "direct".to_string(),
            ip_private: true,
            ..Default::default()
        }],
    };
    let proxy = spawn_proxy_with_routing("socks5", server.addr, routing).await?;

    let mut client = timeout(TEST_TIMEOUT, TcpStream::connect(proxy.addr)).await??;
    socks5_connect_ip(&mut client, target_addr).await?;
    client.write_all(b"hello").await?;
    let mut reply = [0u8; 5];
    timeout(TEST_TIMEOUT, client.read_exact(&mut reply)).await??;
    assert_eq!(&reply, b"world");

    timeout(TEST_TIMEOUT, echo).await???;
    proxy.stop();
    drop(server);
    Ok(())
}

/// Proxy with `[mux]` on: TCP sessions share VLESS connections.
async fn spawn_mux_proxy(server_addr: SocketAddr, concurrency: i64) -> Result<ProxyHarness> {
    let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_port()?));
    let mut config = proxy_config(
        "socks5",
        proxy_addr,
        server_addr,
        RoutingConfig::default(),
        "tcp",
    );
    config.mux = MuxConfig {
        enabled: true,
        concurrency,
    };
    let task = tokio::spawn(async move { serve(Arc::new(config)).await });
    wait_for_listener(proxy_addr).await?;
    Ok(ProxyHarness {
        addr: proxy_addr,
        task,
    })
}

async fn spawn_proxy(protocol: &str, server_addr: SocketAddr) -> Result<ProxyHarness> {
    spawn_proxy_with_routing(protocol, server_addr, RoutingConfig::default()).await
}

async fn spawn_proxy_with_routing(
    protocol: &str,
    server_addr: SocketAddr,
    routing: RoutingConfig,
) -> Result<ProxyHarness> {
    spawn_proxy_full(protocol, server_addr, routing, "tcp").await
}

async fn spawn_proxy_full(
    protocol: &str,
    server_addr: SocketAddr,
    routing: RoutingConfig,
    transport: &str,
) -> Result<ProxyHarness> {
    let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_port()?));
    let config = proxy_config(protocol, proxy_addr, server_addr, routing, transport);
    let task = tokio::spawn(async move { serve(Arc::new(config)).await });
    wait_for_listener(proxy_addr).await?;
    Ok(ProxyHarness {
        addr: proxy_addr,
        task,
    })
}

/// Proxy whose active server can be swapped at runtime.
async fn spawn_switchable_proxy(
    server_addr: SocketAddr,
) -> Result<(ProxyHarness, ActiveServer, Config)> {
    let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_port()?));
    let config = proxy_config(
        "socks5",
        proxy_addr,
        server_addr,
        RoutingConfig::default(),
        "tcp",
    );
    let active = ActiveServer::new(config.server.clone());
    let config = Arc::new(config);
    let task = {
        let (config, active) = (config.clone(), active.clone());
        tokio::spawn(async move { serve_with_server(config, active).await })
    };
    wait_for_listener(proxy_addr).await?;
    Ok((
        ProxyHarness {
            addr: proxy_addr,
            task,
        },
        active,
        (*config).clone(),
    ))
}

fn proxy_config(
    protocol: &str,
    proxy_addr: SocketAddr,
    server_addr: SocketAddr,
    routing: RoutingConfig,
    transport: &str,
) -> Config {
    Config {
        server: ServerConfig {
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            uuid: Uuid::nil(),
            use_tls: false,
            security: "none".to_string(),
            encryption: "none".to_string(),
            sni: None,
            fingerprint: None,
            reality_public_key: None,
            reality_short_id: None,
            flow: None,
            spider_x: None,
            transport: transport.to_string(),
            ws_path: Some("/vless-test".to_string()),
            ws_host: Some("mock.example".to_string()),
            alpn: None,
            xhttp_mode: None,
            xhttp_extra: None,
            remark: None,
        },
        inbound: InboundConfig {
            address: Ipv4Addr::LOCALHOST.to_string(),
            port: proxy_addr.port(),
            protocol: protocol.to_string(),
        },
        dns: DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
            rules: vec![],
            cache: DnsCacheConfig::default(),
        },
        runtime: RuntimeConfig {
            connect_timeout_secs: 5,
            read_timeout_secs: 30,
            write_timeout_secs: 10,
            idle_timeout_secs: 60,
            max_connections: 100,
            xray_path: "xray".to_string(),
            reality_engine: "auto".to_string(),
        },
        tun: Default::default(),
        routing,
        mux: Default::default(),
    }
}

/// The mock must see the path and Host header vproxy was configured with.
#[allow(clippy::result_large_err)]
fn check_ws_upgrade(
    req: &tokio_tungstenite::tungstenite::handshake::server::Request,
    resp: tokio_tungstenite::tungstenite::handshake::server::Response,
) -> Result<
    tokio_tungstenite::tungstenite::handshake::server::Response,
    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
> {
    assert_eq!(req.uri().path(), "/vless-test");
    assert_eq!(
        req.headers().get("host").and_then(|h| h.to_str().ok()),
        Some("mock.example")
    );
    Ok(resp)
}

/// Like `spawn_mock_vless_server`, but speaks WebSocket (plain, no TLS).
async fn spawn_mock_vless_ws_server<F, Fut>(handler: F) -> Result<MockServerHarness>
where
    F: FnOnce(WsStream<TcpStream>) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _) = timeout(TEST_TIMEOUT, listener.accept())
            .await
            .map_err(|_| anyhow!("mock VLESS ws server accept timed out"))??;
        let ws = tokio_tungstenite::accept_hdr_async(stream, check_ws_upgrade).await?;
        handler(WsStream::new(ws)).await
    });

    Ok(MockServerHarness { addr, task })
}

async fn spawn_mock_vless_server<F, Fut>(handler: F) -> Result<MockServerHarness>
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (stream, _) = timeout(TEST_TIMEOUT, listener.accept())
            .await
            .map_err(|_| anyhow!("mock VLESS server accept timed out"))??;
        handler(stream).await
    });

    Ok(MockServerHarness { addr, task })
}

async fn wait_for_listener(addr: SocketAddr) -> Result<()> {
    for _ in 0..50 {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    Err(anyhow!("listener did not start on {addr}"))
}

async fn socks5_connect_ip(stream: &mut TcpStream, target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(target) = target else {
        return Err(anyhow!("test expects an IPv4 target"));
    };
    stream.write_all(&[5, 1, 0]).await?;
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [5, 0] {
        return Err(anyhow!("unexpected SOCKS5 auth reply: {auth_reply:?}"));
    }
    stream.write_all(&[5, 1, 0, 1]).await?;
    stream.write_all(&target.ip().octets()).await?;
    stream.write_all(&target.port().to_be_bytes()).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != socks5::Reply::Succeeded as u8 {
        return Err(anyhow!("unexpected SOCKS5 connect reply: {reply:?}"));
    }
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<()> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [5, 0] {
        return Err(anyhow!("unexpected SOCKS5 auth reply: {auth_reply:?}"));
    }

    if host.len() > u8::MAX as usize {
        return Err(anyhow!("test host name is too long"));
    }
    stream.write_all(&[5, 1, 0, 3, host.len() as u8]).await?;
    stream.write_all(host.as_bytes()).await?;
    stream.write_all(&port.to_be_bytes()).await?;

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != socks5::Reply::Succeeded as u8 {
        return Err(anyhow!("unexpected SOCKS5 connect reply: {reply:?}"));
    }

    Ok(())
}

async fn socks5_udp_associate(stream: &mut TcpStream) -> Result<SocketAddr> {
    stream.write_all(&[5, 1, 0]).await?;
    let mut auth_reply = [0u8; 2];
    stream.read_exact(&mut auth_reply).await?;
    if auth_reply != [5, 0] {
        return Err(anyhow!("unexpected SOCKS5 auth reply: {auth_reply:?}"));
    }

    stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != socks5::Reply::Succeeded as u8 {
        return Err(anyhow!("unexpected SOCKS5 UDP associate reply: {reply:?}"));
    }
    if reply[3] != 1 {
        return Err(anyhow!(
            "expected IPv4 UDP bind reply, got atyp={}",
            reply[3]
        ));
    }

    Ok(SocketAddr::from((
        Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]),
        u16::from_be_bytes([reply[8], reply[9]]),
    )))
}

async fn read_vless_request<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<ObservedVlessRequest> {
    let version = stream.read_u8().await?;
    if version != vless::VERSION {
        return Err(anyhow!("unexpected VLESS version: {version}"));
    }

    let mut uuid_bytes = [0u8; 16];
    stream.read_exact(&mut uuid_bytes).await?;
    if uuid_bytes != *Uuid::nil().as_bytes() {
        return Err(anyhow!("unexpected VLESS UUID"));
    }

    let addons_len = stream.read_u8().await? as usize;
    let mut addons = vec![0u8; addons_len];
    stream.read_exact(&mut addons).await?;

    let command = match stream.read_u8().await? {
        1 => vless::Command::Tcp,
        2 => vless::Command::Udp,
        3 => vless::Command::Mux,
        other => return Err(anyhow!("unexpected VLESS command: {other}")),
    };
    // Like Xray, a Mux request carries no target: frames follow the header.
    let (port, address) = if command == vless::Command::Mux {
        (0, vless::Address::Domain(mux::MUX_COOL_ADDRESS.to_string()))
    } else {
        (stream.read_u16().await?, read_vless_address(stream).await?)
    };

    Ok(ObservedVlessRequest {
        command,
        address,
        port,
    })
}

async fn read_vless_address<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<vless::Address> {
    Ok(match stream.read_u8().await? {
        1 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            vless::Address::Ipv4(octets.into())
        }
        2 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            vless::Address::Domain(String::from_utf8(domain)?)
        }
        3 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            vless::Address::Ipv6(octets.into())
        }
        atyp => return Err(anyhow!("unexpected VLESS address type: {atyp}")),
    })
}

/// Like Xray-core, the mock only sends the VLESS response header together with
/// the first downstream bytes.
async fn send_vless_response<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<()> {
    stream.write_all(&[vless::VERSION, 0]).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_http_headers<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<String> {
    let mut buffer = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        timeout(TEST_TIMEOUT, stream.read_exact(&mut byte)).await??;
        buffer.push(byte[0]);
        if buffer.ends_with(b"\r\n\r\n") {
            return Ok(String::from_utf8(buffer)?);
        }
        if buffer.len() > 32 * 1024 {
            return Err(anyhow!("HTTP headers exceeded test limit"));
        }
    }
}

async fn read_http_response(stream: &mut TcpStream) -> Result<String> {
    let headers = read_http_headers(stream).await?;
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);

    let mut body = vec![0u8; content_length];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut body)).await??;
    Ok(format!("{headers}{}", String::from_utf8(body)?))
}

fn reserve_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    Ok(listener.local_addr()?.port())
}
