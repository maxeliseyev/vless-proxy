//! The h3 transport end to end on loopback: `vproxy_core::h3::H3Client` against
//! `vproxy_server::Server` with a self-signed certificate, relaying to
//! local TCP and UDP echo servers.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use uuid::Uuid;
use vproxy_core::h3::H3Client;
use vproxy_core::protocol::vless::Address;
use vproxy_core::{ActiveServer, Config, ProxyClient, VlessUrl};
use vproxy_server::{Accounts, Server};

const NAME: &str = "h3.test";
const ALICE: Uuid = Uuid::from_u128(0xa11ce);

struct Stand {
    server: SocketAddr,
    echo: SocketAddr,
    udp_echo: SocketAddr,
    cert: CertificateDer<'static>,
    admin: std::path::PathBuf,
    accounts: Accounts,
}

async fn stand(allow_private: bool) -> Stand {
    let generated = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
    let admin = std::env::temp_dir().join(format!("vproxy-e2e-{}.sock", Uuid::new_v4()));
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        vec![ALICE],
        allow_private,
    )
    .unwrap()
    .with_admin(admin.clone());
    let server_addr = server.local_addr().unwrap();
    let accounts = server.accounts();
    tokio::spawn(server.run());

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    let udp_echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_echo_addr = udp_echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = udp_echo.recv_from(&mut buf).await {
            let _ = udp_echo.send_to(&buf[..n], from).await;
        }
    });
    Stand {
        server: server_addr,
        echo: echo_addr,
        udp_echo: udp_echo_addr,
        cert,
        admin,
        accounts,
    }
}

fn client(stand: &Stand, uuid: Uuid) -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(stand.cert.clone()).unwrap();
    // Chrome fingerprint: the existing tests then also cover the reshaped
    // QUIC ClientHello handshaking against the server.
    H3Client::with_roots(
        "127.0.0.1",
        stand.server.port(),
        NAME,
        uuid,
        roots,
        vproxy_core::protocol::fingerprint::Fingerprint::Chrome,
    )
    .unwrap()
}

fn echo_target(stand: &Stand) -> (Address, u16) {
    as_target(stand.echo)
}

fn udp_echo_target(stand: &Stand) -> (Address, u16) {
    as_target(stand.udp_echo)
}

fn as_target(addr: SocketAddr) -> (Address, u16) {
    let SocketAddr::V4(addr) = addr else {
        unreachable!()
    };
    (Address::Ipv4(*addr.ip()), addr.port())
}

#[tokio::test]
async fn streams_share_one_connection() {
    let stand = stand(true).await;
    let client = Arc::new(client(&stand, ALICE));
    let (address, port) = echo_target(&stand);

    let tasks: Vec<_> = (0..8u8)
        .map(|i| {
            let client = client.clone();
            let address = address.clone();
            tokio::spawn(async move {
                let mut stream = client.open_tcp(&address, port).await.unwrap();
                let payload = vec![i; 64 * 1024 + i as usize];
                stream.write_all(&payload).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut back = Vec::new();
                stream.read_to_end(&mut back).await.unwrap();
                assert_eq!(back, payload, "stream {i}");
            })
        })
        .collect();
    for task in tasks {
        timeout(Duration::from_secs(10), task)
            .await
            .expect("stream timed out")
            .unwrap();
    }
    assert_eq!(client.handshakes(), 1, "all streams on one QUIC connection");
}

#[tokio::test]
async fn wrong_account_gets_nothing_relayed() {
    let stand = stand(true).await;
    let client = client(&stand, Uuid::from_u128(0xbad));
    let (address, port) = echo_target(&stand);

    let attempt = async {
        let mut stream = client.open_tcp(&address, port).await?;
        stream.write_all(b"hello").await?;
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await?;
        anyhow::Ok(buf)
    };
    let result = timeout(Duration::from_secs(10), attempt)
        .await
        .expect("the server should close, not hang");
    assert!(result.is_err(), "relayed without a valid token: {result:?}");
}

#[tokio::test]
async fn private_targets_are_refused_by_default() {
    let stand = stand(false).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);

    let mut stream = client.open_tcp(&address, port).await.unwrap();
    let mut buf = [0u8; 1];
    let error = timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        error.to_string().contains("refused by the server's policy"),
        "{error}"
    );
}

/// The way the app uses it: an `h3://` link, `ProxyClient::open_tcp`.
#[tokio::test]
async fn proxy_client_routes_h3_links_over_quic() {
    let stand = stand(true).await;
    let link = format!(
        "h3://{ALICE}@127.0.0.1:{}?sni={NAME}#local",
        stand.server.port()
    );
    let config = Config::from_vless_url(&VlessUrl::parse(&link).unwrap(), 0);
    config.server.validate_transport_settings().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(stand.cert.clone()).unwrap();
    let proxy = ProxyClient::new(
        ActiveServer::new(config.server.clone()),
        config.dns.clone(),
        config.runtime.clone(),
        &config.routing,
        &config.mux,
    )
    .unwrap()
    .with_h3_roots(roots);

    let (address, port) = echo_target(&stand);
    for round in 0..3u8 {
        let mut stream = proxy.open_tcp(address.clone(), port).await.unwrap();
        stream.write_all(&[round; 1000]).await.unwrap();
        let mut back = [0u8; 1000];
        timeout(Duration::from_secs(10), stream.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back, [round; 1000]);
    }

    let (address, port) = udp_echo_target(&stand);
    let vproxy_core::proxy::runtime::UdpOutbound::H3(session) =
        proxy.open_udp(address, port).await.unwrap()
    else {
        panic!("h3 server, not an h3 UDP session");
    };
    let (out, mut incoming) = session.into_split();
    out.send(b"over quic").unwrap();
    let back = timeout(Duration::from_secs(10), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back[..], b"over quic");
}

#[tokio::test]
async fn udp_sessions_echo_over_datagrams() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = udp_echo_target(&stand);

    let mut sessions = Vec::new();
    for _ in 0..4 {
        sessions.push(client.open_udp(&address, port).await.unwrap().into_split());
    }
    // Interleaved: each reply must come back to its own session.
    for round in 0..10u8 {
        for (i, (out, _)) in sessions.iter().enumerate() {
            out.send(&vec![i as u8; 100 + round as usize * 90]).unwrap();
        }
    }
    for (i, (_, incoming)) in sessions.iter_mut().enumerate() {
        for round in 0..10u8 {
            let payload = timeout(Duration::from_secs(10), incoming.recv())
                .await
                .expect("reply timed out")
                .expect("session ended");
            assert_eq!(payload.len(), 100 + round as usize * 90, "session {i}");
            assert!(payload.iter().all(|b| *b == i as u8), "session {i}");
        }
    }
    assert_eq!(client.handshakes(), 1, "TCP and UDP share the connection");

    let (out, incoming) = &mut sessions[0];
    // An app's QUIC Initial is at least 1200 bytes: it must fit from the start.
    out.send(&[7u8; 1200]).unwrap();
    let back = timeout(Duration::from_secs(10), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.len(), 1200);

    // Over the datagram limit: fragments both ways, joined whole.
    let big: Vec<u8> = (0..4000u32).map(|i| i as u8).collect();
    out.send(&big).unwrap();
    let back = timeout(Duration::from_secs(10), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back[..], &big[..]);
    assert!(out.send(&[0u8; 20_000]).is_err(), "over the fragment limit");
}

#[tokio::test]
async fn private_udp_targets_get_no_replies() {
    let stand = stand(false).await;
    let client = client(&stand, ALICE);
    let (address, port) = udp_echo_target(&stand);
    let (out, mut incoming) = client.open_udp(&address, port).await.unwrap().into_split();
    out.send(b"hello?").unwrap();
    assert!(
        timeout(Duration::from_millis(800), incoming.recv())
            .await
            .is_err(),
        "a private target was reached"
    );
}

#[tokio::test]
async fn bulk_transfer_on_one_stream() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let stream = client.open_tcp(&address, port).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    const SIZE: usize = 16 * 1024 * 1024;

    let send = tokio::spawn(async move {
        let chunk = vec![0x5au8; 64 * 1024];
        for _ in 0..SIZE / chunk.len() {
            writer.write_all(&chunk).await.unwrap();
        }
        writer.shutdown().await.unwrap();
    });
    let mut received = 0usize;
    let mut buf = vec![0u8; 64 * 1024];
    timeout(Duration::from_secs(60), async {
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(buf[..n].iter().all(|b| *b == 0x5a));
            received += n;
        }
    })
    .await
    .expect("16 MB echo took over a minute");
    send.await.unwrap();
    assert_eq!(received, SIZE);
}

/// Wi-Fi to cellular, as far as loopback can show it: the client moves to a
/// new socket (new source port) mid-stream and the connection carries on.
#[tokio::test]
async fn connection_survives_a_network_change() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let mut stream = client.open_tcp(&address, port).await.unwrap();
    let mut buf = [0u8; 5];

    stream.write_all(b"wi-fi").await.unwrap();
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"wi-fi");

    client.network_changed().await;
    stream.write_all(b"cell!").await.unwrap();
    timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("stream stalled after the move")
        .unwrap();
    assert_eq!(&buf, b"cell!");

    let (udp_address, udp_port) = udp_echo_target(&stand);
    let (out, mut incoming) = client
        .open_udp(&udp_address, udp_port)
        .await
        .unwrap()
        .into_split();
    out.send(b"udp after").unwrap();
    let back = timeout(Duration::from_secs(10), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back[..], b"udp after");
    assert_eq!(client.handshakes(), 1, "moved, not reconnected");
}

/// A network change that arrives after the connection has already died (the
/// idle timeout fired during a gap with no connectivity): the dead connection
/// is dropped, so the next flow dials fresh on the new path instead of being
/// handed the corpse first.
#[tokio::test]
async fn network_change_on_a_dead_connection_redials() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let mut buf = [0u8; 4];
    {
        let mut stream = client.open_tcp(&address, port).await.unwrap();
        stream.write_all(b"once").await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
    }
    // Kill the connection as a lost-connectivity idle timeout would.
    let conn = client.connection().await.unwrap();
    conn.close(0u32.into(), b"");
    conn.closed().await;
    assert_eq!(client.handshakes(), 1);

    client.network_changed().await;

    let mut stream = client.open_tcp(&address, port).await.unwrap();
    stream.write_all(b"back").await.unwrap();
    timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .expect("did not redial after a network change on a dead connection")
        .unwrap();
    assert_eq!(&buf, b"back");
    assert_eq!(
        client.handshakes(),
        2,
        "should have dialed a fresh connection"
    );
}

/// A user added to the allow-list at runtime (what a SIGHUP reload does in the
/// binary) can connect, with no restart and without disturbing other accounts.
#[tokio::test]
async fn reloaded_account_can_connect() {
    let stand = stand(true).await;
    let carol = Uuid::from_u128(0xca401);
    let (address, port) = echo_target(&stand);
    let mut buf = [0u8; 4];

    // Not yet a user: the server treats it as an unauthenticated HTTP/3
    // client, so a proxy stream does not echo (it errors or never answers).
    let before = client(&stand, carol);
    let unauth = timeout(Duration::from_secs(5), async {
        let mut s = before.open_tcp(&address, port).await.map_err(|_| ())?;
        s.write_all(b"ping").await.map_err(|_| ())?;
        s.read_exact(&mut buf).await.map_err(|_| ())?;
        Ok::<(), ()>(())
    })
    .await;
    assert!(
        unauth.is_err() || unauth.unwrap().is_err(),
        "an account not on the list should not be able to tunnel"
    );

    // Reload the allow-list to include carol (what SIGHUP does in the binary).
    *stand.accounts.write().unwrap() = Arc::from(vec![ALICE, carol]);

    // A fresh client (new connection) now authenticates and echoes.
    let after = client(&stand, carol);
    let mut s = after.open_tcp(&address, port).await.unwrap();
    s.write_all(b"good").await.unwrap();
    timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("reloaded account did not get through")
        .unwrap();
    assert_eq!(&buf, b"good");

    // The original account is unaffected by the reload.
    let alice = client(&stand, ALICE);
    let mut s = alice.open_tcp(&address, port).await.unwrap();
    s.write_all(b"also").await.unwrap();
    timeout(Duration::from_secs(10), s.read_exact(&mut buf))
        .await
        .expect("existing account broke after reload")
        .unwrap();
    assert_eq!(&buf, b"also");
}

/// Past the 30 s idle timeout: kept up by pings while a stream is open.
#[tokio::test]
async fn open_stream_keeps_the_connection_alive() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let mut stream = client.open_tcp(&address, port).await.unwrap();
    let mut buf = [0u8; 4];
    stream.write_all(b"ping").await.unwrap();
    stream.read_exact(&mut buf).await.unwrap();

    tokio::time::sleep(Duration::from_secs(35)).await;
    stream.write_all(b"pong").await.unwrap();
    timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("stream died while idle")
        .unwrap();
    assert_eq!(&buf, b"pong");
    assert_eq!(client.handshakes(), 1);
}

/// With nothing open there are no pings: the connection times out, and the
/// next stream dials a new one.
#[tokio::test]
async fn idle_connection_is_let_go() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let mut buf = [0u8; 4];
    {
        let mut stream = client.open_tcp(&address, port).await.unwrap();
        stream.write_all(b"once").await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
    }
    let conn = client.connection().await.unwrap();
    timeout(Duration::from_secs(40), conn.closed())
        .await
        .expect("idle connection was kept alive");

    let mut stream = client.open_tcp(&address, port).await.unwrap();
    stream.write_all(b"back").await.unwrap();
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"back");
    assert_eq!(client.handshakes(), 2);
}

/// Layer A on the wire: drive a real quinn QUIC handshake against the server
/// and capture the exact ClientHello bytes our rustls fork hands to quinn.
/// That the capture fills at all proves quinn's QUIC path invokes the fork's
/// `client_hello_rewriter` (a successful handshake alone would not — rustls's
/// native hello would also connect). The captured bytes' QUIC JA4 must be the
/// Chrome-QUIC value, so a probe on the wire sees Chrome, not quinn/rustls.
#[tokio::test]
async fn quic_clienthello_on_the_wire_is_chrome() {
    use rustls::client::ClientHelloRewriter;

    /// Wraps the real Chrome rewriter and keeps a copy of what it emits (i.e.
    /// exactly what goes into the QUIC Initial on the wire).
    #[derive(Debug)]
    struct Capturing {
        inner: Arc<dyn ClientHelloRewriter>,
        seen: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    impl ClientHelloRewriter for Capturing {
        fn rewrite(&self, raw: &[u8], retry: bool) -> Option<Vec<u8>> {
            let out = self.inner.rewrite(raw, retry);
            // What leaves the socket: the reshaped hello, or the original if
            // the rewriter declined (it does not, for a first QUIC hello).
            self.seen
                .lock()
                .unwrap()
                .push(out.clone().unwrap_or_else(|| raw.to_vec()));
            out
        }
    }

    let stand = stand(true).await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let chrome = vproxy_core::protocol::fingerprint::Fingerprint::Chrome
        .rewriter()
        .expect("Chrome yields a rewriter");

    // The client TLS config as H3Client::with_roots builds it, but with the
    // Chrome rewriter wrapped so we can read the hello it produces.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(stand.cert.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.client_hello_rewriter = Some(Arc::new(Capturing {
        inner: chrome,
        seen: seen.clone(),
    }));
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let config = quinn::ClientConfig::new(Arc::new(crypto));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let conn = timeout(
        Duration::from_secs(10),
        endpoint.connect(stand.server, NAME).unwrap(),
    )
    .await
    .expect("QUIC handshake timed out")
    .expect("the Chrome-shaped QUIC hello did not complete a handshake");
    assert_eq!(conn.remote_address(), stand.server);

    let captured = seen.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "quinn never called the fork's client_hello_rewriter on the QUIC path"
    );
    let ja4 = vproxy_core::protocol::fingerprint::ja4_quic(&captured[0])
        .expect("the wire ClientHello parses");
    assert_eq!(
        ja4, "q13d0311h3_55b375c5d22e_653d80c3fe9d",
        "the on-the-wire QUIC JA4 is not the Chrome-QUIC value"
    );
}

/// The admin socket reports a connected client and its open stream.
#[tokio::test]
async fn stats_report_a_connection_and_its_stream() {
    let stand = stand(true).await;
    let client = client(&stand, ALICE);
    let (address, port) = echo_target(&stand);
    let mut stream = client.open_tcp(&address, port).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // The admin socket comes up alongside the server; retry briefly.
    let mut snap = None;
    for _ in 0..30 {
        if let Ok(s) = vproxy_server::fetch_stats(&stand.admin).await {
            snap = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let snap = snap.expect("admin socket never answered");
    assert!(snap.conns_open >= 1, "a client is connected: {snap:?}");
    assert_eq!(snap.conns_total, 1);
    assert!(snap.streams_open >= 1, "the echo stream is open: {snap:?}");
    assert!(snap.streams_total >= 1);
    assert_eq!(snap.accounts.len(), 1);
    assert_eq!(snap.accounts[0].open, 1);
}
