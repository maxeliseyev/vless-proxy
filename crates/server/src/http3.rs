//! HTTP/3 frontend for an operator-configured HTTP origin. Production site
//! content is deployed independently and is never embedded in this binary.

mod transport;
pub(crate) use transport::Transport;

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use h3::error::Code;
use http::{header, HeaderMap, Method, Request, Response, StatusCode};
use std::time::Duration;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::debug;

const MAX_REQUESTS: usize = 32;
const HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(30);

type RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Clone)]
pub(crate) struct Site {
    backend: reqwest::Url,
    client: reqwest::Client,
}

impl Site {
    pub(crate) fn new(backend: &str) -> Result<Self> {
        let backend = reqwest::Url::parse(backend).context("parse site_backend")?;
        if backend.scheme() != "http"
            || backend.host_str().is_none()
            || !backend.username().is_empty()
            || backend.password().is_some()
            || backend.path() != "/"
            || backend.query().is_some()
            || backend.fragment().is_some()
        {
            bail!("site_backend must be an HTTP origin, e.g. http://caddy:8080");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .read_timeout(IO_TIMEOUT)
            .build()
            .context("build site backend client")?;
        Ok(Self { backend, client })
    }

    async fn response(&self, request: Request<()>) -> Result<reqwest::Response> {
        // Keep the configured origin even for an absolute URI or a path
        // beginning with '//'. The visitor cannot choose a backend host.
        let mut url = self.backend.clone();
        url.set_path(request.uri().path());
        url.set_query(request.uri().query());
        let mut headers = request.headers().clone();
        strip_hop_headers(&mut headers);
        if let Some(authority) = request.uri().authority() {
            headers.insert(header::HOST, authority.as_str().parse()?);
        }
        Ok(self
            .client
            .request(request.method().clone(), url)
            .headers(headers)
            .send()
            .await?)
    }
}

pub(crate) async fn serve(transport: Transport, site: Option<Site>) -> Result<()> {
    let mut connection = h3::server::builder()
        .max_field_section_size(16 * 1024)
        .build(transport)
        .await
        .context("HTTP/3 settings")?;
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            result = requests.join_next(), if !requests.is_empty() => {
                match result {
                    Some(Ok(Err(error))) => debug!("HTTP/3 request: {error:#}"),
                    Some(Err(error)) => debug!("HTTP/3 request task: {error}"),
                    _ => {}
                }
            }
            request = connection.accept() => {
                let Some(resolver) = request.context("HTTP/3 request stream")? else { return Ok(()) };
                if requests.len() >= MAX_REQUESTS {
                    // Dropping an unresolved request resets that stream.
                    drop(resolver);
                    continue;
                }
                let site = site.clone();
                requests.spawn(async move {
                    let (request, stream) = timeout(HEADER_TIMEOUT, resolver.resolve_request())
                        .await.context("HTTP/3 headers timed out")??;
                    serve_request(request, stream, site).await
                });
            }
        }
    }
}

async fn serve_request(
    request: Request<()>,
    mut stream: RequestStream,
    site: Option<Site>,
) -> Result<()> {
    // The static/media frontend has no request-body API. Refuse other
    // methods locally rather than sending a bodyless request to the origin.
    let head = request.method() == Method::HEAD;
    if request.method() != Method::GET && !head {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_LENGTH, "0")
            .body(())?;
        timeout(IO_TIMEOUT, stream.send_response(response)).await??;
        timeout(IO_TIMEOUT, stream.finish()).await??;
        stream.stop_sending(Code::H3_NO_ERROR);
        return Ok(());
    }
    if request.headers().contains_key(header::TRANSFER_ENCODING)
        || request
            .headers()
            .get(header::CONTENT_LENGTH)
            .is_some_and(|length| length != "0")
    {
        return reply(&mut stream, StatusCode::BAD_REQUEST, b"Bad Request\n", head).await;
    }
    let Some(site) = site else {
        return reply(&mut stream, StatusCode::NOT_FOUND, b"Not Found\n", head).await;
    };
    let mut backend = match site.response(request).await {
        Ok(response) => response,
        Err(error) => {
            debug!("site backend: {error}");
            return reply(&mut stream, StatusCode::BAD_GATEWAY, b"Bad Gateway\n", head).await;
        }
    };
    let mut response = Response::new(());
    *response.status_mut() = backend.status();
    *response.headers_mut() = backend.headers().clone();
    strip_hop_headers(response.headers_mut());
    timeout(IO_TIMEOUT, stream.send_response(response)).await??;
    if !head {
        while let Some(chunk) = backend.chunk().await.context("read site backend")? {
            timeout(IO_TIMEOUT, stream.send_data(chunk)).await??;
        }
    }
    timeout(IO_TIMEOUT, stream.finish()).await??;
    stream.stop_sending(Code::H3_NO_ERROR);
    Ok(())
}

async fn reply(
    stream: &mut RequestStream,
    status: StatusCode,
    body: &'static [u8],
    head: bool,
) -> Result<()> {
    let response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .body(())?;
    timeout(IO_TIMEOUT, stream.send_response(response)).await??;
    if !head {
        timeout(IO_TIMEOUT, stream.send_data(Bytes::from_static(body))).await??;
    }
    timeout(IO_TIMEOUT, stream.finish()).await??;
    stream.stop_sending(Code::H3_NO_ERROR);
    Ok(())
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let nominated: Vec<header::HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| name.trim().parse().ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_is_an_operator_configured_http_origin() {
        for url in [
            "https://example.com",
            "http://user:pass@localhost/",
            "http://localhost/prefix",
            "http://localhost/?url=other",
            "http://localhost/#fragment",
        ] {
            assert!(Site::new(url).is_err(), "accepted {url}");
        }
        assert!(Site::new("http://localhost:8080").is_ok());
    }

    #[test]
    fn connection_nominated_headers_do_not_cross_the_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            "keep-alive, x-internal".parse().unwrap(),
        );
        headers.insert("x-internal", "secret".parse().unwrap());
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(header::CONTENT_TYPE, "video/mp4".parse().unwrap());
        strip_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[header::CONTENT_TYPE], "video/mp4");
    }
}
