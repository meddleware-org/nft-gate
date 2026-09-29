//! Reverse-proxy an authorised request to the configured upstream. Body is capped at
//! `max_body_bytes` (a griefing guard): a declared `Content-Length` over the cap is rejected
//! before any byte is read; otherwise the body is read up to the cap.
//!
//! Memory: the request body is buffered in full (`to_bytes`), and so is the upstream response.
//! Worst case per in-flight gated request is about `max_body_bytes` (transiently up to ~2× while
//! multi-chunk bodies are collected into one buffer) plus the response size; there is no
//! concurrency cap, so peak RSS scales with concurrent uploads. Streaming both directions (as
//! `gateway-workers` does) is the follow-up — see README "Request body limit".
//!
//! Headers stripped from the **forwarded request**: `Host`, `Authorization`,
//! `X-Access-Proof`, and `Content-Length` (recomputed by the HTTP client).
//!
//! Headers stripped from the **upstream response**: `Content-Length`, `Transfer-Encoding`,
//! and `Connection` (hop-by-hop; recomputed / not safe to forward).

use crate::AppState;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

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
/// Caps the request body at `app.cfg.max_body_bytes` before reading. Strips gateway-specific
/// headers (`Host`, `Authorization`, `X-Access-Proof`, `Content-Length`) before sending.
/// Returns a 413 if the body exceeds the cap.
///
/// # Errors
///
/// Returns 502 if the upstream request fails (connection error, timeout, etc.).
pub async fn forward(app: &AppState, req: Request) -> Response {
    let (parts, body) = req.into_parts();

    if declared_too_large(&parts.headers, app.cfg.max_body_bytes) {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    }
    let bytes = match axum::body::to_bytes(body, app.cfg.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let url = format!("{}{}", app.cfg.upstream_url, path_and_query);

    let mut headers = parts.headers.clone();
    headers.remove(header::HOST);
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::CONTENT_LENGTH);
    headers.remove("x-access-proof");

    match app.http.forward(parts.method, &url, headers, bytes).await {
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status);
            for (name, value) in &resp.headers {
                if name == header::CONTENT_LENGTH
                    || name == header::TRANSFER_ENCODING
                    || name == header::CONNECTION
                {
                    continue; // recomputed by the server / not hop-safe
                }
                builder = builder.header(name, value);
            }
            builder
                .body(Body::from(resp.body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
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
