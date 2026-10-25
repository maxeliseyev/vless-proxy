//! The h3 transport end to end on loopback: `vproxy::h3::H3Client` against
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
use vproxy::h3::H3Client;
use vproxy::protocol::vless::Address;
use vproxy::{ActiveServer, Config, ProxyClient, VlessUrl};
use vproxy_server::Server;

const NAME: &str = "h3.test";
const ALICE: Uuid = Uuid::from_u128(0xa11ce);

struct Stand {
    server: SocketAddr,
    echo: SocketAddr,
    udp_echo: SocketAddr,
    cert: CertificateDer<'static>,
}

async fn stand(allow_private: bool) -> Stand {
    let generated = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        vec![cert.clone()],
        key,
        vec![ALICE],
        allow_private,
    )
    .unwrap();
    let server_addr = server.local_addr().unwrap();
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
    }
}

fn client(stand: &Stand, uuid: Uuid) -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(stand.cert.clone()).unwrap();
    H3Client::with_roots("127.0.0.1", stand.server.port(), NAME, uuid, roots).unwrap()
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
    let vproxy::proxy::runtime::UdpOutbound::H3(session) =
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
