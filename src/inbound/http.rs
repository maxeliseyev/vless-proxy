use crate::protocol::vless::Address;
use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_SIZE: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub address: Address,
    pub port: u16,
    pub initial_payload: Vec<u8>,
    pub is_connect: bool,
}

pub async fn accept_request<S>(stream: &mut S) -> Result<Request>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);

    loop {
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            bail!("HTTP client closed connection before sending complete request headers");
        }

        buffer.push(byte[0]);
        if buffer.len() > MAX_HEADER_SIZE {
            bail!("HTTP request headers exceed {MAX_HEADER_SIZE} bytes");
        }

        if buffer.ends_with(b"\r\n\r\n") {
            return parse_request(&buffer);
        }
    }
}

pub async fn send_connect_success<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    stream.flush().await?;
    Ok(())
}

pub async fn send_error<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

fn parse_request(buffer: &[u8]) -> Result<Request> {
    let header_text =
        std::str::from_utf8(buffer).context("HTTP request headers are not valid UTF-8")?;
    let mut lines = header_text.split("\r\n");

    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("HTTP request is missing request line"))?;
    let (method, target, version) = parse_request_line(request_line)?;
    validate_http_version(version)?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("Malformed HTTP header line: {line}"))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(target, 443)?;
        return Ok(Request {
            method: method.to_string(),
            address: parse_address(&host),
            port,
            initial_payload: Vec::new(),
            is_connect: true,
        });
    }

    let (host, port, path_and_query) = resolve_forward_target(target, &headers)?;
    let payload = rewrite_forward_request(method, &path_and_query, version, &headers);

    Ok(Request {
        method: method.to_string(),
        address: parse_address(&host),
        port,
        initial_payload: payload,
        is_connect: false,
    })
}

fn parse_request_line(line: &str) -> Result<(&str, &str, &str)> {
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP request line is missing method"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP request line is missing target"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP request line is missing version"))?;

    if parts.next().is_some() {
        bail!("HTTP request line has unexpected extra tokens");
    }

    Ok((method, target, version))
}

fn validate_http_version(version: &str) -> Result<()> {
    if version == "HTTP/1.0" || version == "HTTP/1.1" {
        Ok(())
    } else {
        bail!("Only HTTP/1.0 and HTTP/1.1 requests are supported");
    }
}

fn resolve_forward_target(
    target: &str,
    headers: &[(String, String)],
) -> Result<(String, u16, String)> {
    if let Some(rest) = target.strip_prefix("http://") {
        let (authority, path) = split_absolute_http_target(rest);
        let (host, port) = parse_authority(authority, 80)?;
        return Ok((host, port, normalize_path(path)));
    }

    if target.starts_with('/') {
        let host_header = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("Host"))
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| anyhow!("Origin-form HTTP requests require a Host header"))?;
        let (host, port) = parse_authority(host_header, 80)?;
        return Ok((host, port, target.to_string()));
    }

    bail!("Unsupported HTTP proxy target: {target}");
}

fn rewrite_forward_request(
    method: &str,
    path_and_query: &str,
    version: &str,
    headers: &[(String, String)],
) -> Vec<u8> {
    let mut request = format!("{method} {path_and_query} {version}\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("Proxy-Connection") {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    request.into_bytes()
}

fn split_absolute_http_target(target: &str) -> (&str, &str) {
    match target.find('/') {
        Some(index) => (&target[..index], &target[index..]),
        None => (target, "/"),
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        bail!("HTTP authority must not be empty");
    }

    if let Some(host) = authority.strip_prefix('[') {
        let end = host
            .find(']')
            .ok_or_else(|| anyhow!("Invalid bracketed IPv6 authority: {authority}"))?;
        let address = &host[..end];
        let rest = &host[end + 1..];
        let port = if rest.is_empty() {
            default_port
        } else {
            let port = rest
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("Invalid bracketed IPv6 authority: {authority}"))?;
            parse_port(port)?
        };
        return Ok((address.to_string(), port));
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.contains(':') {
            return Ok((host.to_string(), parse_port(port)?));
        }
    }

    Ok((authority.to_string(), default_port))
}

fn parse_port(port: &str) -> Result<u16> {
    let port: u16 = port
        .parse()
        .with_context(|| format!("Invalid port: {port}"))?;
    if port == 0 {
        bail!("Port must be 1-65535");
    }
    Ok(port)
}

fn parse_address(host: &str) -> Address {
    if let Ok(ipv4) = host.parse() {
        Address::Ipv4(ipv4)
    } else if let Ok(ipv6) = host.parse() {
        Address::Ipv6(ipv6)
    } else {
        Address::Domain(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn parses_connect_request() {
        let (mut client, mut server) = tokio::io::duplex(512);

        let task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();

        let request = task.await.unwrap();
        assert_eq!(request.method, "CONNECT");
        assert!(request.is_connect);
        assert_eq!(request.port, 443);
        assert_eq!(request.initial_payload, Vec::<u8>::new());
        assert_eq!(request.address, Address::Domain("example.com".to_string()));
    }

    #[tokio::test]
    async fn rewrites_absolute_form_http_request() {
        let (mut client, mut server) = tokio::io::duplex(512);

        let task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });
        client
            .write_all(
                b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nUser-Agent: test\r\n\r\n",
            )
            .await
            .unwrap();

        let request = task.await.unwrap();
        assert_eq!(request.method, "GET");
        assert!(!request.is_connect);
        assert_eq!(request.port, 8080);
        assert_eq!(request.address, Address::Domain("example.com".to_string()));
        let rewritten = String::from_utf8(request.initial_payload).unwrap();
        assert!(rewritten.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(rewritten.contains("Host: example.com:8080\r\n"));
        assert!(rewritten.contains("User-Agent: test\r\n"));
        assert!(!rewritten.contains("Proxy-Connection"));
    }

    #[tokio::test]
    async fn accepts_origin_form_with_host_header() {
        let (mut client, mut server) = tokio::io::duplex(512);

        let task = tokio::spawn(async move { accept_request(&mut server).await.unwrap() });
        client
            .write_all(b"GET /plain HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n\r\n")
            .await
            .unwrap();

        let request = task.await.unwrap();
        assert_eq!(request.port, 9000);
        assert_eq!(request.address, Address::Ipv4("127.0.0.1".parse().unwrap()));
        assert!(String::from_utf8(request.initial_payload)
            .unwrap()
            .starts_with("GET /plain HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn writes_connect_success_response() {
        let (mut client, mut server) = tokio::io::duplex(256);

        let task = tokio::spawn(async move { send_connect_success(&mut server).await.unwrap() });
        let mut response = vec![0u8; 39];
        client.read_exact(&mut response).await.unwrap();
        task.await.unwrap();

        assert_eq!(
            std::str::from_utf8(&response).unwrap(),
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        );
    }
}
