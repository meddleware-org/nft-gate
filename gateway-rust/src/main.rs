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
mod headers;
mod http_client;
mod proof;
mod proxy;
mod ratelimit;
mod sui_rpc;
mod verify;

use axum::error_handling::HandleErrorLayer;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
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
    /// Per-IP rate limiter for gated requests, applied BEFORE signature verification.
    preauth_limiter: RateLimiter,
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
    rate_key(&client_ip_raw(headers, peer, trusted_hops))
}

/// IPv6 clients are keyed by their /64 (one subscriber controls the whole prefix and could
/// otherwise rotate source addresses to dodge the limit and grow the limiter); IPv4 and anything
/// unparseable are used as is.
fn rate_key(ip: &str) -> String {
    match ip.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

fn client_ip_raw(headers: &HeaderMap, peer: Option<SocketAddr>, trusted_hops: usize) -> String {
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
/// <token>` (scheme case-insensitive, any whitespace after it: the Workers gateway's
/// `^Bearer\s+(.+)$`); falls back to the `X-Access-Proof` header.
fn extract_proof_token(req: &Request) -> Option<String> {
    if let Some(v) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(s) = v.to_str() {
            if let Some((scheme, rest)) = s.split_once(char::is_whitespace) {
                let token = rest.trim();
                if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
                    return Some(token.to_string());
                }
            }
        }
    }
    req.headers()
        .get("x-access-proof")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
}

/// JSON `{"error": reason, "code": code}` (the machine-readable code a client can act on).
fn deny_code(status: StatusCode, reason: &str, code: &str) -> Response {
    (status, Json(json!({ "error": reason, "code": code }))).into_response()
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

    // Public passthrough (e.g. /v1/tip-config): read-only. A body-carrying method would reach the
    // upstream with no proof, so only GET/HEAD are forwarded. Rate-limit per IP first.
    if app.cfg.is_public_path(&path) {
        if method != Method::GET && method != Method::HEAD {
            let mut res = deny(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            res.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
            return res;
        }
        let ip = extract_client_ip(&req, app.cfg.trusted_proxy_hops);
        if !app.ip_limiter.check(&ip) {
            return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
        }
        return proxy::forward(&app, req).await;
    }

    if !proxy::FORWARDED_METHODS.contains(&method) {
        return deny(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }

    let token = match extract_proof_token(&req) {
        Some(t) => t,
        None => return deny(StatusCode::UNAUTHORIZED, "missing access proof"),
    };

    // Verification costs CPU and a store call per request, so bound it per client first.
    let ip = extract_client_ip(&req, app.cfg.trusted_proxy_hops);
    if !app.preauth_limiter.check(&ip) {
        return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    match verify_access_request(&app.cfg, &app.store, &token, &app.chain).await {
        Ok(verified) => {
            if !app.limiter.check(&verified.address) {
                return deny(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
            }
            match verified.redemption_key {
                Some(key) => redeem_and_forward(&app, &key, req).await,
                None => proxy::forward(&app, req).await,
            }
        }
        Err(d) => {
            let status = match d {
                verify::Denied::ChainError => StatusCode::BAD_GATEWAY,
                verify::Denied::StateUnavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::FORBIDDEN,
            };
            deny(status, d.reason())
        }
    }
}

/// Single-use: the permanent on-chain consume digest is the one-time token. Lease it (the lease
/// returns an owner token), proxy, then COMMIT on a successful upload or RELEASE on failure, both
/// presenting the token — so an interrupted upload leaves the consume redeemable, a duplicate can't
/// double-spend it, and a request whose lease lapsed can never clear or overwrite a newer holder's.
/// The lease outlives the upstream deadline (checked at startup). A commit that fails, or finds its
/// lease lost, is a 502 (never success); a store error is a 503 (never a conflict).
async fn redeem_and_forward(app: &AppState, key: &str, req: Request) -> Response {
    let unavailable = |e: anyhow::Error| {
        tracing::error!(error = %e, "redemption store failed");
        deny(StatusCode::SERVICE_UNAVAILABLE, "gateway state unavailable")
    };
    let token = match app
        .store
        .try_lease_redemption(key, app.cfg.redemption_lease_ttl_secs)
        .await
    {
        Err(e) => return unavailable(e),
        Ok(challenge::Lease::Redeemed) => {
            return deny_code(
                StatusCode::CONFLICT,
                "this consume has already been redeemed for an upload",
                "redeemed",
            )
        }
        Ok(challenge::Lease::Leased) => {
            return deny_code(
                StatusCode::CONFLICT,
                "an upload for this consume is already in progress",
                "leased",
            )
        }
        Ok(challenge::Lease::Ok(token)) => token,
    };
    let resp = proxy::forward(app, req).await;
    if !resp.status().is_success() {
        app.store.release_redemption(key, &token).await;
        return resp;
    }
    match app
        .store
        .commit_redemption(key, &token, app.cfg.redemption_retention_secs)
        .await
    {
        Ok(challenge::Commit::Ok) => resp,
        Ok(challenge::Commit::Lost) => {
            tracing::error!("redemption lease lost before commit");
            deny(StatusCode::BAD_GATEWAY, "redemption lease lost")
        }
        Err(e) => {
            tracing::error!(error = %e, "commit_redemption failed");
            app.store.release_redemption(key, &token).await;
            deny(StatusCode::BAD_GATEWAY, "redemption commit failed")
        }
    }
}

/// Grants every response carries — the same set as the Workers gateway (`cors.ts`).
const CORS_GRANTS: [(&str, &str); 4] = [
    (
        "access-control-allow-methods",
        "GET, POST, PUT, HEAD, OPTIONS",
    ),
    (
        "access-control-allow-headers",
        "authorization, content-type, x-access-proof",
    ),
    ("access-control-expose-headers", "location, upload-offset"),
    ("access-control-max-age", "86400"),
];

/// CORS as the Workers gateway does it: a preflight is answered here, before rate limits and auth;
/// every response (errors included) carries the grants and `Vary: Origin`; the request `Origin` is
/// reflected only on an exact `ALLOWED_ORIGINS` match — otherwise no `Access-Control-Allow-Origin`.
async fn cors(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let allowed = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| state.cfg.allowed_origins.iter().any(|a| a == o))
        .and_then(|o| HeaderValue::from_str(o).ok());
    let mut resp = if req.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let headers = resp.headers_mut();
    // Only the gateway's own CORS policy applies: nothing an inner handler set survives.
    let stale: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for k in stale {
        headers.remove(k);
    }
    for (name, value) in CORS_GRANTS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = allowed {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    resp
}

/// Construct the axum [`Router`] with the shared [`AppState`]. `/healthz` is answered directly and
/// is never shed (so probes stay truthful under load); everything else goes through the single
/// [`handle`] fallback behind a `MAX_CONCURRENT_REQUESTS` cap that answers `503` at once when full.
fn build_router(state: Arc<AppState>) -> Router {
    let max_in_flight = state.cfg.max_concurrent_requests;
    let cors_layer = middleware::from_fn_with_state(state.clone(), cors);
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
        .layer(cors_layer)
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
        std::time::Duration::from_secs(cfg.rpc_timeout_secs),
    );
    if cfg.single_use && cfg.redis_url.is_none() && cfg.allow_volatile_redemptions {
        tracing::warn!(
            "SINGLE_USE with an in-memory store (ALLOW_VOLATILE_REDEMPTIONS): spent consumes are \
             forgotten on restart; use REDIS_URL outside development"
        );
    }
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
    let preauth_limiter = RateLimiter::new(cfg.gated_preauth_rate_limit_per_min);
    let bind_addr = cfg.bind_addr;
    let prune_interval = cfg.nonce_prune_interval_secs.max(1);

    let state = Arc::new(AppState {
        cfg,
        store,
        limiter,
        ip_limiter,
        preauth_limiter,
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

    let limits = ServerLimits {
        header_read_timeout: std::time::Duration::from_secs(state.cfg.header_read_timeout_secs),
        max_connections: state.cfg.max_connections,
        shutdown_grace: std::time::Duration::from_secs(state.cfg.shutdown_grace_secs),
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");
    serve(listener, app, limits, shutdown_signal()).await
}

/// Connection-level limits applied by [`serve`].
struct ServerLimits {
    /// A client must send its request head within this long (also bounds an idle keep-alive wait).
    header_read_timeout: std::time::Duration,
    /// Open connections; further clients wait in the TCP backlog until one closes.
    max_connections: usize,
    /// After the shutdown signal, in-flight requests get this long before the process exits.
    shutdown_grace: std::time::Duration,
}

/// Serve `app` over HTTP/1 with connection-level limits axum's own `serve` does not offer: a header
/// read timeout (slowloris), a cap on open connections, and a bounded graceful shutdown.
async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: ServerLimits,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt as _;

    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    let mut make = app.into_make_service_with_connect_info::<SocketAddr>();
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            p = permits.clone().acquire_owned() => p?,
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };
        // The service for this connection carries the peer address (`ConnectInfo`).
        let Ok(service) = (&mut make).oneshot(peer).await;
        let hyper_service = TowerToHyperService::new(service);
        let header_timeout = limits.header_read_timeout;
        tasks.spawn(async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .serve_connection(TokioIo::new(stream), hyper_service);
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
        // Reap finished connection tasks so the set stays small.
        while tasks.try_join_next().is_some() {}
    }
    tracing::info!(
        grace_secs = limits.shutdown_grace.as_secs(),
        "draining connections"
    );
    drop(listener);
    // In-flight requests finish within the grace period; whatever remains is dropped.
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(limits.shutdown_grace, drain)
        .await
        .is_err()
    {
        tracing::warn!("shutdown grace elapsed; dropping remaining connections");
        tasks.abort_all();
    }
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
            gateway_origin: "https://gateway.example".into(),
            network: "testnet".into(),
            upstream_url: "http://upstream".into(),
            sui_rpc_url: "http://rpc".into(),
            nft_type: "0x1::access_gate::AccessNFT".into(),
            gate_id: "0x2".into(),
            challenge_ttl_secs: 300,
            single_use: false,
            public_paths: vec!["/v1/tip-config".into()],
            allowed_origins: vec!["https://app.example".into()],
            rate_limit_per_min: 30,
            challenge_rate_limit_per_min: 30,
            gated_preauth_rate_limit_per_min: 120,
            max_body_bytes: 262144,
            redis_url: None,
            nonce_max_entries: 10_000,
            nonce_prune_interval_secs: 60,
            ownership_cache_ttl_ms: 0,
            redemption_lease_ttl_secs: 900,
            redemption_retention_secs: 2_592_000,
            consume_max_age_secs: 432_000,
            allow_volatile_redemptions: false,
            rpc_timeout_secs: 15,
            header_read_timeout_secs: 10,
            body_read_timeout_secs: 30,
            max_connections: 1024,
            shutdown_grace_secs: 30,
            max_concurrent_requests: 64,
            trusted_proxy_hops: 0,
            upstream_timeout_secs: 600,
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
            chain: SuiRpc::new(
                http.clone(),
                cfg.sui_rpc_url.clone(),
                0,
                None,
                std::time::Duration::from_secs(15),
            ),
            store: NonceStore::in_memory(300, 100),
            limiter: RateLimiter::new(30),
            ip_limiter: RateLimiter::new(30),
            preauth_limiter: RateLimiter::new(120),
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

    fn cors_app() -> Router {
        let cfg = tests_support::test_cfg();
        let http = HttpClient::new().unwrap();
        build_router(Arc::new(AppState {
            chain: SuiRpc::new(
                http.clone(),
                cfg.sui_rpc_url.clone(),
                0,
                None,
                std::time::Duration::from_secs(15),
            ),
            store: NonceStore::in_memory(300, 100),
            limiter: RateLimiter::new(30),
            ip_limiter: RateLimiter::new(30),
            preauth_limiter: RateLimiter::new(120),
            http,
            cfg,
        }))
    }

    fn with_origin(
        method: Method,
        path: &str,
        origin: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder().method(method).uri(path);
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn cors_preflight_is_answered_before_auth_for_an_allowed_origin() {
        use tower::ServiceExt;
        let resp = cors_app()
            .oneshot(with_origin(
                Method::OPTIONS,
                "/v1/blob-upload-relay",
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let h = resp.headers();
        assert_eq!(
            h[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
        assert_eq!(
            h["access-control-allow-headers"],
            "authorization, content-type, x-access-proof"
        );
        assert_eq!(h[header::VARY], "Origin");
    }

    #[tokio::test]
    async fn cors_never_reflects_an_unlisted_or_absent_origin() {
        use tower::ServiceExt;
        for origin in [
            Some("https://evil.example"),
            Some("https://app.example.evil"),
            None,
        ] {
            let resp = cors_app()
                .oneshot(with_origin(Method::OPTIONS, "/v1/challenge", origin))
                .await
                .unwrap();
            assert!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "{origin:?}"
            );
            assert_eq!(resp.headers()[header::VARY], "Origin");
        }
    }

    #[tokio::test]
    async fn cors_headers_are_on_error_responses_too() {
        use tower::ServiceExt;
        let resp = cors_app()
            .oneshot(with_origin(
                Method::POST,
                "/v1/blob-upload-relay",
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
    }

    #[test]
    fn public_path_matching() {
        let cfg = tests_support::test_cfg();
        assert!(cfg.is_public_path("/v1/tip-config"));
        assert!(!cfg.is_public_path("/v1/blob-upload"));
    }

    #[test]
    fn ipv6_clients_are_keyed_by_their_slash_64() {
        assert_eq!(
            rate_key("2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
            rate_key("2001:db8:1:2::1")
        );
        assert_ne!(rate_key("2001:db8:1:2::1"), rate_key("2001:db8:1:3::1"));
        assert_eq!(rate_key("203.0.113.9"), "203.0.113.9");
        assert_eq!(rate_key("unknown"), "unknown");
    }

    fn token_request(auth: Option<&str>, x_proof: Option<&str>) -> Request {
        let mut b = axum::http::Request::builder().uri("/v1/x");
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        if let Some(x) = x_proof {
            b = b.header("x-access-proof", x);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn bearer_token_extraction_matches_the_workers_gateway() {
        for (auth, want) in [
            ("Bearer abc", Some("abc")),
            ("bearer abc", Some("abc")),
            ("BEARER   abc", Some("abc")),
            ("Bearer\tabc", Some("abc")),
            ("Bearer ", None),
            ("Basic abc", None),
            ("abc", None),
        ] {
            assert_eq!(
                extract_proof_token(&token_request(Some(auth), None)).as_deref(),
                want,
                "{auth:?}"
            );
        }
        // Bearer wins over X-Access-Proof; the header is the fallback.
        assert_eq!(
            extract_proof_token(&token_request(Some("Bearer abc"), Some("zzz"))).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_proof_token(&token_request(None, Some(" zzz "))).as_deref(),
            Some("zzz")
        );
    }

    async fn status_of(app: Router, method: Method, path: &str, auth: Option<&str>) -> StatusCode {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        app.oneshot(b.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn public_paths_are_read_only_and_gated_methods_are_listed() {
        // A body-carrying method on a public path never reaches the upstream.
        assert_eq!(
            status_of(cors_app(), Method::POST, "/v1/tip-config", None).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // A method outside the list is refused before any verification work.
        assert_eq!(
            status_of(cors_app(), Method::DELETE, "/v1/x", Some("Bearer abc")).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // A listed method with a malformed proof reaches verification (403), not the method check.
        assert_eq!(
            status_of(cors_app(), Method::POST, "/v1/x", Some("Bearer !!!")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn gated_requests_are_rate_limited_per_ip_before_verification() {
        use tower::ServiceExt;
        let mut cfg = tests_support::test_cfg();
        cfg.gated_preauth_rate_limit_per_min = 3;
        let http = HttpClient::new().unwrap();
        let app = build_router(Arc::new(AppState {
            chain: SuiRpc::new(
                http.clone(),
                cfg.sui_rpc_url.clone(),
                0,
                None,
                std::time::Duration::from_secs(15),
            ),
            store: NonceStore::in_memory(300, 100),
            limiter: RateLimiter::new(30),
            ip_limiter: RateLimiter::new(30),
            preauth_limiter: RateLimiter::new(cfg.gated_preauth_rate_limit_per_min),
            http,
            cfg,
        }));
        let mut seen = Vec::new();
        for _ in 0..5 {
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/x")
                .header(header::AUTHORIZATION, "Bearer !!!")
                .body(axum::body::Body::empty())
                .unwrap();
            seen.push(app.clone().oneshot(req).await.unwrap().status());
        }
        assert_eq!(
            seen,
            [
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
    }

    #[tokio::test]
    async fn the_server_drops_a_client_that_never_finishes_its_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = ServerLimits {
            header_read_timeout: std::time::Duration::from_millis(200),
            max_connections: 4,
            shutdown_grace: std::time::Duration::from_secs(1),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, cors_app(), limits, async {
            let _ = stopped.await;
        }));
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap(); // never finishes
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), slow.read(&mut buf))
            .await
            .expect("the server must close the stalled connection")
            .unwrap_or(0);
        let reply = String::from_utf8_lossy(&buf[..n]);
        assert!(n == 0 || reply.starts_with("HTTP/1.1 408"), "{reply}");
        // A well-formed request is still served.
        let mut ok = tokio::net::TcpStream::connect(addr).await.unwrap();
        ok.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        ok.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        let _ = stop.send(());
        server.await.unwrap().unwrap();
    }
}
