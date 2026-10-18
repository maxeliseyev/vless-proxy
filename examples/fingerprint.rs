//! Show the TLS fingerprint a server sees from vproxy's TLS client.
//!
//!     cargo run --example fingerprint            # Chrome-shaped (default)
//!     cargo run --example fingerprint -- none    # plain rustls
//!
//! Connects to tls.peet.ws, which reports the JA3/JA4 of the connecting client.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vproxy::fingerprint::Fingerprint;
use vproxy::tls::TlsClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fp = Fingerprint::parse(std::env::args().nth(1).as_deref());
    let host = "tls.peet.ws";
    let tls = TlsClient::with_alpn(host, &["http/1.1"])?.with_fingerprint(fp);
    let mut stream = tls.connect_tls((host, 443)).await?;
    stream
        .write_all(
            format!("GET /api/all HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut body = Vec::new();
    stream.read_to_end(&mut body).await?;
    let text = String::from_utf8_lossy(&body);
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
