//! Ordinary HTTP/3 clients and the legacy proxy share the same endpoint.

use bytes::{Buf, Bytes};
use http::{header, Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use uuid::Uuid;
use vproxy_server::Server;

const NAME: &str = "site.test";
const LIMIT: Duration = Duration::from_secs(3);

struct Browser {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    requests: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.conn.close(0x100u32.into(), b"");
        self.driver.abort();
    }
}

impl Browser {
    async fn new(backend: Option<&str>) -> Self {
        let generated = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
        let cert = CertificateDer::from(generated.cert.der().to_vec());
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
        let mut server = Server::bind(
            "127.0.0.1:0".parse().unwrap(),
            vec![cert.clone()],
            key,
            vec![Uuid::from_u128(1)],
            false,
        )
        .unwrap();
        if let Some(backend) = backend {
            server = server.with_site_backend(backend).unwrap();
        }
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.run());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(config);
        let conn = timeout(LIMIT, endpoint.connect(addr, NAME).unwrap())
            .await
            .unwrap()
            .unwrap();
        let (mut driver, requests) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            driver.wait_idle().await;
        });
        Self {
            _endpoint: endpoint,
            conn,
            requests,
            driver,
        }
    }

    async fn get(&mut self, request: Request<()>) -> (Response<()>, Vec<u8>) {
        timeout(LIMIT, async {
            let mut stream = self.requests.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
            }
            (response, body)
        })
        .await
        .expect("ordinary HTTP/3 must not wait for the 10 s auth timeout")
    }
}

fn request(method: Method, path: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(format!("https://{NAME}{path}"))
        .body(())
        .unwrap()
}

async fn backend() -> (String, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                while !request.windows(4).any(|b| b == b"\r\n\r\n") {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                    assert!(request.len() <= 16 * 1024);
                }
                let request = String::from_utf8(request).unwrap();
                tx.send(request.clone()).unwrap();
                let path = request.split_whitespace().nth(1).unwrap();
                let (status, extra, body) = match path {
                    "/range" => (
                        "206 Partial Content",
                        "Content-Range: bytes 2-4/10\r\n",
                        b"234".to_vec(),
                    ),
                    "/redirect" => (
                        "302 Found",
                        "Location: https://elsewhere.invalid/\r\n",
                        Vec::new(),
                    ),
                    "/missing" => ("404 Not Found", "", b"missing".to_vec()),
                    "/big" => ("200 OK", "", vec![42; 256 * 1024]),
                    _ => ("200 OK", "", b"external site".to_vec()),
                };
                let headers = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: video/mp4\r\nConnection: close, x-internal\r\nX-Internal: private\r\n{extra}\r\n", body.len());
                socket.write_all(headers.as_bytes()).await.unwrap();
                if !request.starts_with("HEAD ") {
                    socket.write_all(&body).await.unwrap();
                }
            });
        }
    });
    (origin, rx)
}

#[tokio::test]
async fn browser_gets_content_and_head_on_one_connection_without_auth() {
    let (origin, mut seen) = backend().await;
    let mut browser = Browser::new(Some(&origin)).await;
    let (response, body) = browser.get(request(Method::GET, "/?view=city")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body, b"external site");
    assert!(!response.headers().contains_key("x-internal"));
    assert!(!response.headers().contains_key(header::CONNECTION));
    let received = seen.recv().await.unwrap().to_lowercase();
    assert!(received.starts_with("get /?view=city http/1.1\r\n"));
    assert!(received.contains("host: site.test\r\n"));
    let (response, body) = browser.get(request(Method::HEAD, "/")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "13");
    assert!(body.is_empty());
    let (response, _) = browser.get(request(Method::GET, "/missing")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn media_range_large_body_and_redirect_are_forwarded() {
    let (origin, mut seen) = backend().await;
    let mut browser = Browser::new(Some(&origin)).await;
    let mut range = request(Method::GET, "/range");
    range
        .headers_mut()
        .insert(header::RANGE, "bytes=2-4".parse().unwrap());
    let (response, body) = browser.get(range).await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 2-4/10");
    assert_eq!(body, b"234");
    assert!(seen
        .recv()
        .await
        .unwrap()
        .to_lowercase()
        .contains("range: bytes=2-4\r\n"));
    let (response, body) = browser.get(request(Method::GET, "/big")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body, vec![42; 256 * 1024]);
    let (response, _) = browser.get(request(Method::GET, "/redirect")).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://elsewhere.invalid/"
    );
}

#[tokio::test]
async fn absent_backend_and_unsupported_method_do_not_open_a_proxy() {
    let mut browser = Browser::new(None).await;
    let (response, _) = browser.get(request(Method::GET, "/")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let (response, body) = browser.get(request(Method::POST, "/")).await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()[header::ALLOW], "GET, HEAD");
    assert!(body.is_empty());
}

#[tokio::test]
async fn unavailable_backend_returns_bad_gateway_and_connection_survives() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let mut browser = Browser::new(Some(&origin)).await;
    for _ in 0..2 {
        let (response, body) = browser.get(request(Method::GET, "/")).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(body, b"Bad Gateway\n");
    }
}
