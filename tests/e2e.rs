use anyhow::{anyhow, Result};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use vproxy::{serve, socks5, vless, Config, DnsConfig, InboundConfig, ServerConfig};

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

        send_vless_response(&mut stream).await?;
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"ping");
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

        send_vless_response(&mut stream).await?;
        let mut payload = [0u8; 4];
        stream.read_exact(&mut payload).await?;
        assert_eq!(&payload, b"pong");
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

        send_vless_response(&mut stream).await?;
        let request_headers = read_http_headers(&mut stream).await?;
        assert!(request_headers.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(request_headers.contains("Host: example.com\r\n"));
        assert!(!request_headers.contains("Proxy-Connection"));

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

        send_vless_response(&mut stream).await?;
        let payload = vless::read_udp_frame(&mut stream).await?;
        assert_eq!(payload, b"hello-udp");
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

async fn spawn_proxy(protocol: &str, server_addr: SocketAddr) -> Result<ProxyHarness> {
    let proxy_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, reserve_port()?));
    let config = Config {
        server: ServerConfig {
            address: server_addr.ip().to_string(),
            port: server_addr.port(),
            uuid: Uuid::nil(),
            use_tls: false,
            security: "none".to_string(),
        },
        inbound: InboundConfig {
            address: Ipv4Addr::LOCALHOST.to_string(),
            port: proxy_addr.port(),
            protocol: protocol.to_string(),
        },
        dns: DnsConfig {
            mode: "remote".to_string(),
            strategy: "prefer_ipv4".to_string(),
        },
    };

    let task = tokio::spawn(async move { serve(Arc::new(config)).await });
    wait_for_listener(proxy_addr).await?;
    Ok(ProxyHarness {
        addr: proxy_addr,
        task,
    })
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

async fn read_vless_request(stream: &mut TcpStream) -> Result<ObservedVlessRequest> {
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
        other => return Err(anyhow!("unexpected VLESS command: {other}")),
    };
    let port = stream.read_u16().await?;
    let address = read_vless_address(stream).await?;

    Ok(ObservedVlessRequest {
        command,
        address,
        port,
    })
}

async fn read_vless_address(stream: &mut TcpStream) -> Result<vless::Address> {
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

async fn send_vless_response(stream: &mut TcpStream) -> Result<()> {
    stream.write_all(&[vless::VERSION, 0]).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_http_headers(stream: &mut TcpStream) -> Result<String> {
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
