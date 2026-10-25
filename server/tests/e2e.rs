//! The h3 transport end to end on loopback: `vproxy::h3::H3Client` against
//! `vproxy_server::Server` with a self-signed certificate, relaying to a
//! local TCP echo server.

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
    Stand {
        server: server_addr,
        echo: echo_addr,
        cert,
    }
}

fn client(stand: &Stand, uuid: Uuid) -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(stand.cert.clone()).unwrap();
    H3Client::with_roots("127.0.0.1", stand.server.port(), NAME, uuid, roots).unwrap()
}

fn echo_target(stand: &Stand) -> (Address, u16) {
    let SocketAddr::V4(echo) = stand.echo else {
        unreachable!()
    };
    (Address::Ipv4(*echo.ip()), echo.port())
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
    assert!(
        proxy.open_udp(address, port).await.is_err(),
        "no UDP over h3 yet"
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
