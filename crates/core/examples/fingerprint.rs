//! Show the TLS fingerprint a server sees from vproxy's TLS client.
//!
//!     cargo run --example fingerprint                 # Chrome-shaped (default)
//!     cargo run --example fingerprint -- chrome133     # previous Chrome shape
//!     cargo run --example fingerprint -- none          # plain rustls
//!     cargo run --example fingerprint -- chrome www.google.com   # any host
//!
//! Connects to tls.peet.ws, which reports the JA3/JA4 of the connecting
//! client. With another host it only performs the handshake and a GET /,
//! which checks that the shaped hello is accepted by that server.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vproxy_core::protocol::fingerprint::Fingerprint;
use vproxy_core::transport::tls::TlsClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fp = Fingerprint::parse(std::env::args().nth(1).as_deref());
    let host = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "tls.peet.ws".to_string());
    let host = host.as_str();
    let tls = TlsClient::with_alpn(host, &["http/1.1"])?.with_fingerprint(fp);
    let mut stream = tls.connect_tls((host, 443)).await?;
    let path = if host == "tls.peet.ws" {
        "/api/all"
    } else {
        "/"
    };
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut body = Vec::new();
    // Some servers (Google) close without close_notify or after a KeyUpdate
    // rustls cannot follow on a half-closed stream; the response is already
    // in `body` then, so only an empty body makes that an error.
    if let Err(e) = stream.read_to_end(&mut body).await {
        if body.is_empty() {
            return Err(e.into());
        }
        eprintln!("(read ended with: {e})");
    }
    let text = String::from_utf8_lossy(&body);
    if host != "tls.peet.ws" {
        println!("fingerprint: {fp:?}");
        println!("{host}: {}", text.lines().next().unwrap_or("(no response)"));
        return Ok(());
    }
    let json = text.split("\r\n\r\n").nth(1).unwrap_or("");
    let v: serde_json::Value = serde_json::from_str(json.trim())?;
    let tls = &v["tls"];
    println!("fingerprint: {fp:?}");
    println!("ja3:  {}", tls["ja3"].as_str().unwrap_or("?"));
    println!("ja3_hash: {}", tls["ja3_hash"].as_str().unwrap_or("?"));
    println!("ja4:  {}", tls["ja4"].as_str().unwrap_or("?"));
    println!(
        "peetprint_hash: {}",
        tls["peetprint_hash"].as_str().unwrap_or("?")
    );
    println!(
        "ciphers: {}",
        tls["ciphers"].as_array().map(|a| a.len()).unwrap_or(0)
    );
    println!(
        "extensions: {}",
        tls["extensions"].as_array().map(|a| a.len()).unwrap_or(0)
    );
    Ok(())
}
