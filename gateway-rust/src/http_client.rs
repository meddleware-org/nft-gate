//! Thin async HTTP client for Sui RPC calls and upstream proxy forwarding.
//!
//! Uses hyper 1.x + hyper-rustls directly instead of reqwest to avoid the
//! `url → idna → icu_normalizer` compile-time dep chain (~10 min on GHA).
//! All URLs here are operator-configured ASCII-domain strings; `hyper::Uri`
//! handles them without any IDNA processing.
//!
//! Every call is bounded: a connect timeout, a whole-request timeout (headers **and** body), and a
//! response-size cap, so a slow or hostile peer can neither hold a task forever nor exhaust memory.

use crate::config::AuthHeader;
use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

type Connector = HttpsConnector<HttpConnector>;

/// TCP connect timeout for every outbound call.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole-request timeout for Sui RPC calls.
pub const RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a gRPC-web response body (the gateway reads small messages only).
pub const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Response from a proxied upstream request.
pub struct ProxyResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// Shared async HTTP client (cheap to clone — inner client is `Arc`-backed).
#[derive(Clone)]
pub struct HttpClient {
    inner: Client<Connector, Full<Bytes>>,
}

/// Add `h` to `headers` (validated at config load; a failure here is a programming error surfaced
/// as a request error, never a panic).
fn insert_auth(headers: &mut HeaderMap, h: &AuthHeader) -> anyhow::Result<()> {
    let name = HeaderName::from_bytes(h.name.as_bytes()).context("invalid auth header name")?;
    let value = HeaderValue::from_str(&h.value).context("invalid auth header value")?;
    headers.insert(name, value);
    Ok(())
}

impl HttpClient {
    /// Build a new client backed by rustls with bundled WebPKI/Mozilla root certificates. The
    /// URL schemes are policed at config load (`https://` unless `ALLOW_INSECURE_HTTP=1`).
    pub fn new() -> anyhow::Result<Self> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let inner = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self { inner })
    }

    /// Send `req` and collect at most `max_body` bytes of the response, all within `timeout`.
    async fn send(
        &self,
        req: Request<Full<Bytes>>,
        timeout: Duration,
        max_body: usize,
        what: &str,
    ) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
        let fut = async {
            let resp = self
                .inner
                .request(req)
                .await
                .with_context(|| format!("{what} request failed"))?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = Limited::new(resp.into_body(), max_body)
                .collect()
                .await
                .map_err(|e| {
                    anyhow::anyhow!("reading {what} response (cap {max_body} bytes): {e}")
                })?
                .to_bytes();
            Ok::<_, anyhow::Error>((status, headers, body))
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| anyhow::anyhow!("{what} request timed out after {}s", timeout.as_secs()))?
    }

    /// POST an already gRPC-web-framed `body` to `url` with the `application/grpc-web+proto`
    /// content type and return the raw response body (a message frame plus a trailer frame — the
    /// caller unframes it; see `grpc::unframe`). Sui full nodes serve gRPC-web over HTTP/1.1.
    pub async fn post_grpc_web(
        &self,
        url: &str,
        body: Bytes,
        auth: Option<&AuthHeader>,
    ) -> anyhow::Result<(HeaderMap, Bytes)> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .header(header::ACCEPT, "application/grpc-web+proto")
            .body(Full::new(body))
            .context("failed to build gRPC-web request")?;
        if let Some(h) = auth {
            insert_auth(req.headers_mut(), h)?;
        }
        let (status, headers, bytes) = self
            .send(req, RPC_TIMEOUT, MAX_RPC_RESPONSE_BYTES, "gRPC-web")
            .await?;
        if !status.is_success() {
            anyhow::bail!("gRPC-web HTTP {status}");
        }
        Ok((headers, bytes))
    }

    /// Forward a request to `url`, preserving the method, headers, and body, adding `auth`
    /// headers (which replace any client-supplied header of the same name).
    #[allow(clippy::too_many_arguments)]
    pub async fn forward(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        auth: &[AuthHeader],
        timeout: Duration,
        max_response: usize,
    ) -> anyhow::Result<ProxyResponse> {
        let mut builder = Request::builder().method(method).uri(url);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let mut req = builder
            .body(Full::new(body))
            .context("failed to build proxy request")?;
        for h in auth {
            insert_auth(req.headers_mut(), h)?;
        }
        let (status, headers, body) = self.send(req, timeout, max_response, "upstream").await?;
        Ok(ProxyResponse {
            status,
            headers,
            body,
        })
    }
}
