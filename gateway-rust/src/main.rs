//! Generic NFT-gated reverse proxy binary.
#![forbid(unsafe_code)]
//!
//! # Startup sequence
//!
//! 1. Load [`config::GatewayConfig`] from environment variables (see `config.rs`). Abort on
//!    missing required vars.
//! 2. Build an [`http_client::HttpClient`] for upstream and Sui RPC HTTP.
//! 3. Construct a [`sui_rpc::SuiRpc`] from the shared client.
//! 4. Open either an in-memory or Redis [`challenge::NonceStore`] based on `REDIS_URL`.
//! 5. Create the per-address [`ratelimit::RateLimiter`].
//! 6. Spawn a background task that prunes the in-memory nonce store every
//!    `NONCE_PRUNE_INTERVAL_SECS` (no-op for the Redis backend).
//! 7. Bind an axum TCP listener and serve (with the peer address available for client-IP
//!    derivation) under a `MAX_CONCURRENT_REQUESTS` cap, with graceful shutdown on SIGINT/SIGTERM.
//!
//! # AppState
//!
//! [`AppState`] is the single shared object threaded through every request via
//! `axum::extract::State`. It holds:
//!
//! - `cfg` — the loaded gateway configuration.
//! - `store` — the nonce store (in-memory or Redis).
//! - `limiter` — the per-address, per-minute rate limiter.
//! - `chain` — the Sui RPC client for ownership / event queries.
//! - `http` — the shared [`http_client::HttpClient`] used both by the proxy and the RPC client.

mod challenge;
mod config;
mod grpc;
mod http_client;
mod proof;
mod proxy;
mod ratelimit;
mod sui_rpc;
mod verify;

use axum::error_handling::HandleErrorLayer;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;

use challenge::NonceStore;
use config::GatewayConfig;
use http_client::HttpClient;
use ratelimit::RateLimiter;
use sui_rpc::SuiRpc;
use verify::verify_access_request;

/// Shared state threaded through every axum request handler.
pub struct AppState {
    /// Loaded gateway configuration (env vars).
    cfg: GatewayConfig,
    /// Single-use nonce store (in-memory or Redis).
    store: NonceStore,
    /// Per-authenticated-address, fixed-window rate limiter (post-auth).
    limiter: RateLimiter,
    /// Per-IP rate limiter for the challenge endpoint and public paths (pre-auth).
    ip_limiter: RateLimiter,
    /// Sui gRPC client (gRPC-web) for ownership and consume-transaction queries.
    chain: SuiRpc,
    /// Shared HTTP client used by both the reverse proxy and the Sui RPC calls.
    http: HttpClient,
}

/// Build a JSON `{"error": reason}` response with the given status code.
fn deny(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({ "error": reason }))).into_response()
}

/// The client IP used as the pre-auth rate-limit key (never for authentication).
///
/// With `trusted_hops == 0` it is the TCP peer address: forwarding headers are client-controlled
/// and would let anyone pick a fresh rate-limit bucket per request. With N trusted proxies in
/// front, each appends the address it saw, so the Nth `X-Forwarded-For` entry from the right is
/// the address the outermost trusted proxy received the request from. A header with fewer entries
/// did not pass through every proxy, so the peer address is used instead.
fn client_ip(headers: &HeaderMap, peer: Option<SocketAddr>, trusted_hops: usize) -> String {
    let peer_ip = || peer.map_or_else(|| "unknown".to_string(), |p| p.ip().to_string());
    if trusted_hops == 0 {
        return peer_ip();
    }
    let entries: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    match entries.len().checked_sub(trusted_hops) {
        Some(i) => entries[i].to_string(),
        None => peer_ip(),
    }
}

/// [`client_ip`] for an axum request (peer address from `ConnectInfo`).
fn extract_client_ip(req: &Request, trusted_hops: usize) -> String {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    client_ip(req.headers(), peer, trusted_hops)
}

/// Extract the base64 access-proof token from the request. Prefers `Authorization: Bearer
/// <token>`; falls back to the `X-Access-Proof` header.
fn extract_proof_token(req: &Request) -> Option<String> {
    // Prefer `Authorization: Bearer <token>` (the conventional client channel); fall back to
    // an explicit `X-Access-Proof` header.
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some(rest) = s.strip_prefix("Bearer ") {
                return Some(rest.trim().to_string());
            }
        }
    }
    req.headers()
        .get("x-access-proof")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// Main request dispatcher. Handles `/healthz`, `/v1/challenge`, configured public paths, and
/// gated paths (signature + ownership verification before forwarding to the upstream).
async fn handle(State(app): State<Arc<AppState>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if method == Method::GET && path == "/v1/challenge" {
        let ip = extract_client_ip(&req, app.cfg.trusted_proxy_hops);
        if !app.ip_limiter.check(&ip) {
            return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
        return match app.store.issue().await {
            Ok((nonce, expires_at)) => {
                Json(json!({ "nonce": nonce, "expiresAt": expires_at })).into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "nonce issue failed");
                deny(StatusCode::SERVICE_UNAVAILABLE, "gateway state unavailable")
            }
        };
    }

    // Public passthrough (e.g. /v1/tip-config): rate-limit per IP then forward without auth.
    if app.cfg.is_public_path(&path) {
        let ip = extract_client_ip(&req, app.cfg.trusted_proxy_hops);
        if !app.ip_limiter.check(&ip) {
            return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
        return proxy::forward(&app, req).await;
    }

    let token = match extract_proof_token(&req) {
        Some(t) => t,
        None => return deny(StatusCode::UNAUTHORIZED, "missing access proof"),
    };

    match verify_access_request(&app.cfg, &app.store, &token, &app.chain).await {
        Ok(verified) => {
            if !app.limiter.check(&verified.address) {
                return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            match verified.redemption_key {
                // Single-use: the permanent on-chain consume digest is the one-time token. Lease it,
                // proxy, then COMMIT on a successful upload or RELEASE on failure — so an interrupted
                // upload leaves the consume redeemable while a duplicate can't double-spend it.
                Some(key) => {
                    match app
                        .store
                        .try_lease_redemption(&key, app.cfg.redemption_lease_ttl_secs)
                        .await
                    {
                        challenge::Lease::Redeemed | challenge::Lease::Leased => deny(
                            StatusCode::CONFLICT,
                            verify::Denied::RedeemConflict.reason(),
                        ),
                        challenge::Lease::Ok => {
                            let resp = proxy::forward(&app, req).await;
                            if resp.status().is_success() {
                                if let Err(e) = app
                                    .store
                                    .commit_redemption(&key, app.cfg.redemption_retention_secs)
                                    .await
                                {
                                    tracing::error!(error = %e, "commit_redemption failed");
                                    app.store.release_redemption(&key).await;
                                    return deny(
                                        StatusCode::BAD_GATEWAY,
                                        "redemption commit failed",
                                    );
                                }
                            } else {
                                app.store.release_redemption(&key).await;
                            }
                            resp
                        }
                    }
                }
                None => proxy::forward(&app, req).await,
            }
        }
        Err(d) => {
            let status = match d {
                verify::Denied::ChainError => StatusCode::BAD_GATEWAY,
                verify::Denied::RedeemConflict => StatusCode::CONFLICT,
                _ => StatusCode::FORBIDDEN,
            };
            deny(status, d.reason())
        }
    }
}

/// Construct the axum [`Router`] with the shared [`AppState`]. `/healthz` is answered directly and
/// is never shed (so probes stay truthful under load); everything else goes through the single
/// [`handle`] fallback behind a `MAX_CONCURRENT_REQUESTS` cap that answers `503` at once when full.
fn build_router(state: Arc<AppState>) -> Router {
    let max_in_flight = state.cfg.max_concurrent_requests;
    let gated = Router::new().fallback(any(handle)).with_state(state).layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: tower::BoxError| async {
                deny(StatusCode::SERVICE_UNAVAILABLE, "gateway overloaded")
            }))
            .load_shed()
            .concurrency_limit(max_in_flight),
    );
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(gated)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = GatewayConfig::from_env()?;
    tracing::info!(?cfg.bind_addr, upstream = %cfg.upstream_url, nft_type = %cfg.nft_type, single_use = cfg.single_use, "starting nft-gate-gateway");

    let http = HttpClient::new()?;
    let chain = SuiRpc::new(
        http.clone(),
        cfg.sui_rpc_url.clone(),
        cfg.ownership_cache_ttl_ms,
        cfg.sui_rpc_auth_header.clone(),
    );
    let store = match &cfg.redis_url {
        Some(url) => {
            tracing::info!("using Redis/Dragonfly nonce store — fleet-wide replay protection");
            NonceStore::redis(url, cfg.challenge_ttl_secs).await?
        }
        None => {
            tracing::info!(
                "using in-memory nonce store (correct at replicas:1; set REDIS_URL to scale out)"
            );
            NonceStore::in_memory(cfg.challenge_ttl_secs, cfg.nonce_max_entries)
        }
    };
    let limiter = RateLimiter::new(cfg.rate_limit_per_min);
    let ip_limiter = RateLimiter::new(cfg.challenge_rate_limit_per_min);
    let bind_addr = cfg.bind_addr;
    let prune_interval = cfg.nonce_prune_interval_secs.max(1);

    let state = Arc::new(AppState {
        cfg,
        store,
        limiter,
        ip_limiter,
        chain,
        http,
    });

    // Background prune keeps the in-memory nonce map bounded independent of issue cadence
    // (no-op for the Redis backend, which expires via key TTL).
    {
        let prune_state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(prune_interval));
            loop {
                ticker.tick().await;
                prune_state.store.prune();
            }
        });
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (what Kubernetes and Docker send), triggering axum's
/// graceful shutdown so in-flight uploads finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}

/// Shared test fixtures.
#[cfg(test)]
pub(crate) mod tests_support {
    use crate::config::GatewayConfig;

    /// A complete config with test defaults (single-use off, `/v1/tip-config` public).
    pub fn test_cfg() -> GatewayConfig {
        GatewayConfig {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_url: "http://upstream".into(),
            sui_rpc_url: "http://rpc".into(),
            nft_type: "0x1::access_gate::AccessNFT".into(),
            gate_id: "0x2".into(),
            challenge_ttl_secs: 300,
            single_use: false,
            public_paths: vec!["/v1/tip-config".into()],
            rate_limit_per_min: 30,
            challenge_rate_limit_per_min: 30,
            max_body_bytes: 262144,
            redis_url: None,
            nonce_max_entries: 10_000,
            nonce_prune_interval_secs: 60,
            ownership_cache_ttl_ms: 0,
            redemption_lease_ttl_secs: 120,
            redemption_retention_secs: 2_592_000,
            max_concurrent_requests: 64,
            trusted_proxy_hops: 0,
            upstream_timeout_secs: 120,
            max_response_bytes: 16_777_216,
            upstream_auth_headers: Vec::new(),
            sui_rpc_auth_header: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    #[test]
    fn client_ip_ignores_forwarding_headers_without_trusted_proxies() {
        let peer: SocketAddr = "198.51.100.7:4000".parse().unwrap();
        assert_eq!(client_ip(&xff("1.2.3.4"), Some(peer), 0), "198.51.100.7");
        assert_eq!(client_ip(&HeaderMap::new(), None, 0), "unknown");
    }

    #[test]
    fn client_ip_takes_the_entry_the_outermost_trusted_proxy_saw() {
        let peer: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        // client spoofed "6.6.6.6"; the one trusted proxy appended the real client 203.0.113.9.
        assert_eq!(
            client_ip(&xff("6.6.6.6, 203.0.113.9"), Some(peer), 1),
            "203.0.113.9"
        );
        // two hops: CDN appended the client, ingress appended the CDN edge.
        assert_eq!(
            client_ip(&xff("6.6.6.6, 203.0.113.9, 172.16.0.1"), Some(peer), 2),
            "203.0.113.9"
        );
        // fewer entries than hops: fall back to the peer.
        assert_eq!(client_ip(&xff("203.0.113.9"), Some(peer), 2), "10.0.0.2");
    }

    #[tokio::test]
    async fn router_serves_healthz_and_routes_through_the_concurrency_layer() {
        use tower::ServiceExt;
        let mut cfg = tests_support::test_cfg();
        cfg.max_concurrent_requests = 1;
        let http = HttpClient::new().unwrap();
        let state = Arc::new(AppState {
            chain: SuiRpc::new(http.clone(), cfg.sui_rpc_url.clone(), 0, None),
            store: NonceStore::in_memory(300, 100),
            limiter: RateLimiter::new(30),
            ip_limiter: RateLimiter::new(30),
            http,
            cfg,
        });
        let app = build_router(state);
        let get = |p: &str| {
            axum::http::Request::builder()
                .uri(p)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let health = app.clone().oneshot(get("/healthz")).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let challenge = app.oneshot(get("/v1/challenge")).await.unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
    }

    #[test]
    fn public_path_matching() {
        let cfg = tests_support::test_cfg();
        assert!(cfg.is_public_path("/v1/tip-config"));
        assert!(!cfg.is_public_path("/v1/blob-upload"));
    }
}
