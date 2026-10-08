//! Reverse-proxy an authorised request to the configured upstream. Body is capped at
//! `max_body_bytes` (a griefing guard): a declared `Content-Length` over the cap is rejected
//! before any byte is read; otherwise the body is read up to the cap, within `BODY_READ_TIMEOUT_SECS`.
//!
//! Scope: this gateway is for **small-body upstreams** (a tip-config read, a small API). The request
//! body is buffered in full (`to_bytes`), and so is the upstream response (capped at
//! `MAX_RESPONSE_BYTES`). Worst case per in-flight request is about `2 × max_body_bytes` plus the
//! response; `MAX_CONCURRENT_REQUESTS` bounds the number in flight. A large-upload relay (the
//! Walrus upload relay takes up to ~100 MiB) belongs behind `gateway-workers`, which streams; see
//! README.
//!
//! Policy (identical to the Workers gateway; see `headers.rs`): only `GET`, `HEAD`, `POST` and `PUT`
//! are forwarded (405 otherwise); the path must be free of encoded separators and dot segments (400);
//! hop-by-hop fields (and those named in `Connection`), credentials, cookies and spoofable forwarding
//! fields are stripped from the request, and hop-by-hop fields, cookies and CORS fields from the
//! response. `UPSTREAM_AUTH_HEADERS` are then added (replacing any client-supplied header of the same
//! name). Redirects are never followed (the service-token headers must not follow a `Location`): an
//! upstream 3xx is a 502. The whole exchange is bounded by `UPSTREAM_TIMEOUT_SECS` (504).

use crate::headers::{client_response_headers, is_safe_path, upstream_request_headers};
use crate::http_client::TimedOut;
use crate::AppState;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Methods the gateway forwards; anything else is refused with 405 before any work is done.
pub const FORWARDED_METHODS: [Method; 4] = [Method::GET, Method::HEAD, Method::POST, Method::PUT];

/// Build a JSON `{"error": reason}` response with the given status code.
fn error(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({ "error": reason }))).into_response()
}

/// True when the request declares a `Content-Length` above `max` — rejected before reading.
fn declared_too_large(headers: &axum::http::HeaderMap, max: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > max as u64)
}

/// Forward `req` to the upstream configured in `app.cfg.upstream_url`.
///
/// # Errors
///
/// Answers 400 (unsafe path), 405 (method), 413 (body over the cap), 408 (slow body), 502 (upstream
/// failure or redirect) or 504 (upstream deadline).
pub async fn forward(app: &AppState, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    if !FORWARDED_METHODS.contains(&parts.method) {
        return error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    if !is_safe_path(parts.uri.path()) {
        return error(StatusCode::BAD_REQUEST, "invalid path");
    }
    if declared_too_large(&parts.headers, app.cfg.max_body_bytes) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }
    let read = axum::body::to_bytes(body, app.cfg.max_body_bytes);
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(app.cfg.body_read_timeout_secs),
        read,
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "request body timed out"),
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let url = format!("{}{}", app.cfg.upstream_url, path_and_query);
    let headers = upstream_request_headers(&parts.headers);

    match app
        .http
        .forward(
            parts.method,
            &url,
            headers,
            bytes,
            &app.cfg.upstream_auth_headers,
            std::time::Duration::from_secs(app.cfg.upstream_timeout_secs),
            app.cfg.max_response_bytes,
        )
        .await
    {
        // A relay has no business redirecting; treating a 3xx as an error also covers an Access
        // login redirect after the service token expires. Nothing from the response is passed on.
        Ok(resp) if resp.status.is_redirection() => {
            tracing::warn!(status = %resp.status, "upstream answered a redirect; refusing to follow");
            error(StatusCode::BAD_GATEWAY, "upstream error")
        }
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status);
            if let Some(h) = builder.headers_mut() {
                *h = client_response_headers(&resp.headers);
            }
            builder
                .body(Body::from(resp.body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) if e.downcast_ref::<TimedOut>().is_some() => {
            error(StatusCode::GATEWAY_TIMEOUT, "upstream timed out")
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            error(StatusCode::BAD_GATEWAY, "upstream error")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::declared_too_large;
    use axum::http::{header, HeaderMap, HeaderValue};

    fn with_len(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn declared_length_over_cap_is_rejected_up_front() {
        assert!(declared_too_large(&with_len("1001"), 1000));
        assert!(!declared_too_large(&with_len("1000"), 1000));
        // No or unparseable length: left to the capped read, never rejected here.
        assert!(!declared_too_large(&HeaderMap::new(), 1000));
        assert!(!declared_too_large(&with_len("abc"), 1000));
    }
}
