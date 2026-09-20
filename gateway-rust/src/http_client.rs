//! Thin async HTTP client for Sui RPC calls and upstream proxy forwarding.
//!
//! Uses hyper 1.x + hyper-rustls directly instead of reqwest to avoid the
//! `url → idna → icu_normalizer` compile-time dep chain (~10 min on GHA).
//! All URLs here are operator-configured ASCII-domain strings; `hyper::Uri`
//! handles them without any IDNA processing.

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::http::{header, HeaderMap, Method, StatusCode};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

type Connector = HttpsConnector<HttpConnector>;

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

impl HttpClient {
    /// Build a new client backed by rustls with bundled WebPKI/Mozilla root certificates.
    pub fn new() -> anyhow::Result<Self> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let inner = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self { inner })
    }

    /// POST an already gRPC-web-framed `body` to `url` with the `application/grpc-web+proto`
    /// content type and return the raw response body (a message frame plus a trailer frame — the
    /// caller unframes it; see `grpc::unframe`). Sui full nodes serve gRPC-web over HTTP/1.1.
    pub async fn post_grpc_web(&self, url: &str, body: Bytes) -> anyhow::Result<Bytes> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .header(header::ACCEPT, "application/grpc-web+proto")
            .body(Full::new(body))
            .context("failed to build gRPC-web request")?;
        let resp = self
            .inner
            .request(req)
            .await
            .context("gRPC-web request failed")?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .context("reading gRPC-web response")?
            .to_bytes();
        if !status.is_success() {
            anyhow::bail!("gRPC-web HTTP {status}");
        }
        Ok(bytes)
    }

    /// Forward a request to `url`, preserving the method, headers, and body.
    pub async fn forward(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<ProxyResponse> {
        let mut builder = Request::builder().method(method).uri(url);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let req = builder
            .body(Full::new(body))
            .context("failed to build proxy request")?;
        let resp = self
            .inner
            .request(req)
            .await
            .context("upstream request failed")?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_body = resp
            .into_body()
            .collect()
            .await
            .context("reading upstream response")?
            .to_bytes();
        Ok(ProxyResponse {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }
}
