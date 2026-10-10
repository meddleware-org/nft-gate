//! Gateway configuration, loaded from environment variables. Nothing here is
//! consumer-specific — the same binary fronts an upload relay, a website, a game API, etc.
//!
//! # Environment Variables
//!
//! Every value is validated at startup: a typo (an unknown boolean, a negative or fractional number, a
//! malformed origin) is an error, never a silent fall-back to a weaker mode.
//!
//! Required:
//! - `GATEWAY_ORIGIN` — the canonical public origin of THIS gateway (`https://host`, no path,
//!   lower-case). Signed into every access proof (`nft-gate:access:v2`), so a proof made for another
//!   gateway is useless here.
//! - `NETWORK` — `localnet` | `devnet` | `testnet` | `mainnet`; signed into every access proof.
//! - `UPSTREAM_URL` — base URL of the upstream this gateway protects (trailing `/` stripped).
//! - `SUI_RPC_URL` — Sui fullnode (queried over gRPC-web) for ownership / event / gate queries.
//! - `NFT_TYPE` — the access_gate pass type: `<pkg>::access_gate::AccessNFT` or
//!   `<pkg>::access_gate::SoulboundAccessNFT` (anything else, e.g. a fungible `Coin<T>`, is rejected).
//! - `GATE_ID` — the gate whose passes are accepted (object ID).
//!
//! Optional (with defaults):
//! - `CHALLENGE_TTL_SECS` — nonce lifetime in seconds (default: `300`).
//! - `SINGLE_USE` — `true` to require an on-chain single-use consume (default: `false`). Requires
//!   `REDIS_URL` (a restart or a second replica would otherwise forget spent consumes), unless
//!   `ALLOW_VOLATILE_REDEMPTIONS=1` accepts that for development.
//! - `GATED_PREAUTH_RATE_LIMIT_PER_MIN` — per-client-IP budget for gated requests, checked before
//!   signature verification, 0 to disable (default: `120`).
//! - `CONSUME_MAX_AGE_SECS` — single-use: oldest consume accepted, seconds since its event
//!   (default: `432000` = 5 days, inside public fullnodes' transaction retention); at most
//!   `REDEMPTION_RETENTION_SECS`.
//! - `RPC_TIMEOUT_SECS` — deadline for each Sui RPC call (default: `15`).
//! - `HEADER_READ_TIMEOUT_SECS` / `BODY_READ_TIMEOUT_SECS` — slow-client limits (defaults: `10`/`30`).
//! - `MAX_CONNECTIONS` — open client connections (default: `1024`).
//! - `SHUTDOWN_GRACE_SECS` — how long in-flight requests may finish after SIGTERM (default: `30`).
//! - `PUBLIC_PATHS` — comma-separated paths proxied without auth (default: `/v1/tip-config`).
//! - `RATE_LIMIT_PER_MIN` — per-address request budget per minute, 0 to disable (default: `30`).
//! - `CHALLENGE_RATE_LIMIT_PER_MIN` — per-IP budget for the challenge endpoint per minute, 0 to
//!   disable (default: `30`). Keyed by the client IP: the TCP peer, or the `X-Forwarded-For`
//!   entry the outermost trusted proxy added (see `TRUSTED_PROXY_HOPS`).
//! - `MAX_BODY_BYTES` — request body cap in bytes before proxying (default: `262144`).
//! - `BIND_ADDR` — TCP listen address (default: `0.0.0.0:8080`).
//! - `REDIS_URL` — Redis/Dragonfly URL for fleet-wide replay protection (default: unset →
//!   in-memory store, correct only at `replicas: 1`).
//! - `NONCE_MAX_ENTRIES` — hard cap on in-memory nonce entries (default: `1000000`).
//! - `NONCE_PRUNE_INTERVAL_SECS` — background prune cadence for in-memory store (default: `60`).
//! - `OWNERSHIP_CACHE_TTL_MS` — ownership-cache TTL in ms, 0 to disable (default: `0`).
//! - `REDEMPTION_LEASE_TTL_SECS` — single-use: lease window for an in-flight consume-digest
//!   redemption (default: `900`); must exceed `UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS`.
//! - `REDEMPTION_RETENTION_SECS` — single-use: how long a committed (spent) consume-digest is
//!   remembered to block re-redemption (default: `2592000` = 30 days).
//! - `MAX_CONCURRENT_REQUESTS` — in-flight request cap; excess requests get `503` at once
//!   (default: `64`). Peak body memory ≈ `2 × MAX_BODY_BYTES × MAX_CONCURRENT_REQUESTS`.
//! - `TRUSTED_PROXY_HOPS` — reverse proxies in front of the gateway (default: `0` → the TCP peer
//!   address is the client IP). With N > 0 the client IP is the Nth `X-Forwarded-For` entry from
//!   the right, i.e. the address the outermost trusted proxy saw.
//! - `UPSTREAM_TIMEOUT_SECS` — whole-request timeout for upstream calls (default: `600`).
//! - `ALLOWED_ORIGINS` — comma-separated canonical browser origins allowed to call the gateway (CORS;
//!   e.g. `https://app.example`). Unset → none: browsers get no `Access-Control-Allow-Origin` grant.
//! - `MAX_RESPONSE_BYTES` — cap on a buffered upstream response (default: `16777216` = 16 MiB).
//! - `ALLOW_INSECURE_HTTP` — `1` permits `http://` for `UPSTREAM_URL` / `SUI_RPC_URL` (localnet or
//!   an in-cluster upstream); otherwise both must be `https://` (default: unset).
//! - `UPSTREAM_AUTH_HEADERS` — JSON array `[{"name":…,"value":…}]` of headers added to every
//!   upstream request (secret; same format as the Workers gateway).
//! - `SUI_RPC_AUTH_HEADER` — one `Name: value` header added to every Sui RPC call (secret).

use std::net::SocketAddr;

/// An extra header the gateway sends (credentials for the upstream or the RPC).
#[derive(Clone)]
pub struct AuthHeader {
    pub name: String,
    pub value: String,
}

#[derive(Clone)]
pub struct GatewayConfig {
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// Canonical origin of this gateway, signed into every access proof.
    pub gateway_origin: String,
    /// The Sui network, signed into every access proof (one of [`crate::proof::NETWORKS`]).
    pub network: String,
    /// Base URL of the upstream this gateway protects (e.g. the stock upload relay).
    pub upstream_url: String,
    /// Sui fullnode (gRPC-web) used for ownership / event / gate queries.
    pub sui_rpc_url: String,
    /// Fully-qualified access-NFT type string to gate on.
    pub nft_type: String,
    /// The gate whose passes are accepted.
    pub gate_id: String,
    /// Challenge validity window.
    pub challenge_ttl_secs: u64,
    /// When true, require an on-chain single-use consume bound to the challenge nonce.
    pub single_use: bool,
    /// Paths served WITHOUT auth (proxied straight through), e.g. `/v1/tip-config`.
    pub public_paths: Vec<String>,
    /// Browser origins granted CORS (exact match); empty → none.
    pub allowed_origins: Vec<String>,
    /// Per-address request budget per minute (post-auth).
    pub rate_limit_per_min: u32,
    /// Per-IP request budget for the challenge endpoint per minute (pre-auth).
    pub challenge_rate_limit_per_min: u32,
    /// Per-IP request budget for gated requests per minute, checked before verification.
    pub gated_preauth_rate_limit_per_min: u32,
    /// Maximum request body accepted before proxying (bytes).
    pub max_body_bytes: usize,
    /// Optional Redis/Dragonfly URL for a shared TTL nonce store (fleet-wide replay
    /// protection). When unset, an in-memory store is used (correct only at 1 replica).
    pub redis_url: Option<String>,
    /// Hard cap on in-memory nonce entries (evict-oldest beyond it). Ignored for Redis.
    pub nonce_max_entries: usize,
    /// Background prune interval for the in-memory nonce store (seconds).
    pub nonce_prune_interval_secs: u64,
    /// Ownership-cache TTL in ms. **0 = disabled (live check every request)** — the default,
    /// so a gated action is always confirmed on-chain. A small positive value collapses
    /// duplicate lookups under load at the cost of a brief staleness window on NFT
    /// transfer/burn. Never applied to the single-use consume-event check (always live).
    pub ownership_cache_ttl_ms: u64,
    /// Single-use: lease window (secs) for an in-flight consume-digest redemption.
    pub redemption_lease_ttl_secs: u64,
    /// Single-use: retention (secs) of a committed (spent) consume-digest.
    pub redemption_retention_secs: u64,
    /// Single-use: oldest accepted consume (secs since its event); at most the retention.
    pub consume_max_age_secs: u64,
    /// Single-use without Redis: accept that redemptions are forgotten on restart (development).
    pub allow_volatile_redemptions: bool,
    /// Deadline for each Sui RPC call (secs).
    pub rpc_timeout_secs: u64,
    /// Slow-client limits and connection cap.
    pub header_read_timeout_secs: u64,
    pub body_read_timeout_secs: u64,
    pub max_connections: usize,
    pub shutdown_grace_secs: u64,
    /// In-flight request cap (load-shed beyond it).
    pub max_concurrent_requests: usize,
    /// Number of trusted reverse proxies in front of the gateway (client-IP derivation).
    pub trusted_proxy_hops: usize,
    /// Whole-request timeout for upstream calls (secs).
    pub upstream_timeout_secs: u64,
    /// Cap on a buffered upstream response (bytes).
    pub max_response_bytes: usize,
    /// Headers added to every upstream request (e.g. a Cloudflare Access service token).
    pub upstream_auth_headers: Vec<AuthHeader>,
    /// Header added to every Sui RPC call (authenticated RPC providers).
    pub sui_rpc_auth_header: Option<AuthHeader>,
}

/// Hand-written so logs never carry credentials or the private origin: header values, the Redis URL
/// (which may embed a password), the upstream URL and the RPC URL are redacted.
impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self
            .upstream_auth_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        f.debug_struct("GatewayConfig")
            .field("bind_addr", &self.bind_addr)
            .field("gateway_origin", &self.gateway_origin)
            .field("network", &self.network)
            // The private origin is not logged (audit F26), and an RPC URL may carry a key in its
            // path: neither is printed.
            .field("upstream_url", &"<redacted>")
            .field("sui_rpc_url", &"<redacted>")
            .field("nft_type", &self.nft_type)
            .field("gate_id", &self.gate_id)
            .field("single_use", &self.single_use)
            .field("public_paths", &self.public_paths)
            .field("allowed_origins", &self.allowed_origins)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "<redacted>"))
            .field("upstream_auth_headers", &names)
            .field(
                "sui_rpc_auth_header",
                &self.sui_rpc_auth_header.as_ref().map(|h| h.name.as_str()),
            )
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("trusted_proxy_hops", &self.trusted_proxy_hops)
            .finish_non_exhaustive()
    }
}

/// True if `name` is an HTTP field name (RFC 9110 token).
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parse `UPSTREAM_AUTH_HEADERS` (JSON array of `{name, value}`). Malformed input is an error so
/// a mistyped secret fails at startup instead of silently dropping the upstream credentials.
pub fn parse_upstream_auth_headers(raw: Option<&str>) -> anyhow::Result<Vec<AuthHeader>> {
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let err = || {
        anyhow::anyhow!(
            "UPSTREAM_AUTH_HEADERS must be a JSON array of {{\"name\",\"value\"}} objects"
        )
    };
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|_| err())?;
    let items = v.as_array().ok_or_else(err)?;
    items
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let name = h["name"].as_str().filter(|n| is_header_name(n));
            let value = h["value"]
                .as_str()
                .filter(|v| !v.contains('\r') && !v.contains('\n'));
            match (name, value) {
                (Some(name), Some(value)) => Ok(AuthHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                }),
                _ => Err(anyhow::anyhow!(
                    "UPSTREAM_AUTH_HEADERS[{i}] must be {{\"name\": <header name>, \"value\": <string>}}"
                )),
            }
        })
        .collect()
}

/// Parse `SUI_RPC_AUTH_HEADER`: `Name: value`. A bare value is refused (it used to be sent as
/// `Authorization`, a guess the operator could not see), as are a bad header name and line breaks.
pub fn parse_rpc_auth_header(raw: Option<&str>) -> anyhow::Result<Option<AuthHeader>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match raw.split_once(':') {
        Some((n, v))
            if is_header_name(n.trim())
                && !v.trim().is_empty()
                && !v.contains('\r')
                && !v.contains('\n') =>
        {
            Ok(Some(AuthHeader {
                name: n.trim().to_string(),
                value: v.trim().to_string(),
            }))
        }
        _ => anyhow::bail!("SUI_RPC_AUTH_HEADER must be \"Name: value\""),
    }
}

/// Require `https://` unless `allow_http` (localnet / in-cluster) permits `http://`, and refuse
/// credentials in the URL (userinfo): they have their own redacted channels (`UPSTREAM_AUTH_HEADERS`,
/// `SUI_RPC_AUTH_HEADER`), and the Workers gateway refuses them too.
fn check_scheme(var: &str, url: &str, allow_http: bool) -> anyhow::Result<()> {
    if url.starts_with("https://") || (allow_http && url.starts_with("http://")) {
        let after = url.find("://").map_or(0, |i| i + 3);
        let authority = url[after..].split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            anyhow::bail!("{var} must not carry credentials (use the auth header variables)");
        }
        Ok(())
    } else if url.starts_with("http://") {
        anyhow::bail!("{var} must use https:// (set ALLOW_INSECURE_HTTP=1 for localnet or an in-cluster upstream)")
    } else {
        anyhow::bail!("{var} must be an http(s) URL")
    }
}

/// The `scheme://host[:port]` prefix of an http(s) URL.
fn origin_of(url: &str) -> &str {
    let after = url.find("://").map_or(0, |i| i + 3);
    match url[after..].find(['/', '?', '#']) {
        Some(i) => &url[..after + i],
        None => url,
    }
}

/// True if `o` is a canonical origin: `https://host[:port]` (or `http://` for a loopback host), a
/// lower-case ASCII host, no userinfo, path, query or fragment, and the scheme's default port omitted.
pub fn is_canonical_origin(o: &str) -> bool {
    let (rest, default_port, http) = if let Some(r) = o.strip_prefix("https://") {
        (r, "443", false)
    } else if let Some(r) = o.strip_prefix("http://") {
        (r, "80", true)
    } else {
        return false;
    };
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, Some(p)),
        _ => (rest, None),
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-']);
    let loopback = matches!(host, "localhost" | "127.0.0.1");
    let port_ok = port.is_none_or(|p| {
        p != default_port
            && !p.starts_with('0')
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    });
    host_ok && port_ok && (!http || loopback)
}

/// Strict integer in `[min, max]`: an unset variable is `default`; anything else that is not a plain
/// decimal in range is an error.
fn parse_int<T>(
    get: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: T,
    min: T,
    max: T,
) -> anyhow::Result<T>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let Some(raw) = get(key) else {
        return Ok(default);
    };
    let raw = raw.trim();
    let bad = || anyhow::anyhow!("{key} must be an integer in [{min}, {max}]");
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: T = raw.parse().map_err(|_| bad())?;
    if n < min || n > max {
        return Err(bad());
    }
    Ok(n)
}

/// Strict boolean: exactly `true` or `false`.
fn parse_bool(
    get: &dyn Fn(&str) -> Option<String>,
    key: &str,
    default: bool,
) -> anyhow::Result<bool> {
    match get(key).as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => anyhow::bail!("{key} must be \"true\" or \"false\""),
    }
}

/// `PUBLIC_PATHS`: exact absolute paths, free of query, fragment and dot segments.
fn parse_public_paths(raw: &str) -> anyhow::Result<Vec<String>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|p| {
            let plain = p.starts_with('/')
                && p.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'/')
                })
                && !p.split('/').any(|seg| seg == ".." || seg == ".");
            if plain {
                Ok(p.to_string())
            } else {
                anyhow::bail!("PUBLIC_PATHS entry is not a plain absolute path: {p}")
            }
        })
        .collect()
}

/// `ALLOWED_ORIGINS`: canonical origins, comma-separated; unset or empty allows none.
fn parse_allowed_origins(raw: &str, allow_http: bool) -> anyhow::Result<Vec<String>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|o| {
            if is_canonical_origin(o) && (allow_http || o.starts_with("https://")) {
                Ok(o.to_string())
            } else {
                anyhow::bail!("ALLOWED_ORIGINS entry is not a canonical https origin: {o}")
            }
        })
        .collect()
}

impl GatewayConfig {
    /// Load configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable is absent or invalid, or any optional one is
    /// malformed or out of range (see the module docs).
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&|key| std::env::var(key).ok())
    }

    /// [`from_env`](Self::from_env) over an arbitrary variable lookup (so tests need no process env).
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let required = |key: &str| -> anyhow::Result<String> {
            get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| anyhow::anyhow!("{key} is required"))
        };
        let allow_http = match get("ALLOW_INSECURE_HTTP").as_deref() {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(_) => anyhow::bail!("ALLOW_INSECURE_HTTP must be 1 (or unset)"),
        };
        let bind_addr: SocketAddr = get("BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid BIND_ADDR: {e}"))?;

        let gateway_origin = required("GATEWAY_ORIGIN")?;
        if !is_canonical_origin(&gateway_origin)
            || (!allow_http && !gateway_origin.starts_with("https://"))
        {
            anyhow::bail!(
                "GATEWAY_ORIGIN must be a canonical https origin (https://host, no path)"
            );
        }
        let network = required("NETWORK")?;
        if !crate::proof::NETWORKS.contains(&network.as_str()) {
            anyhow::bail!(
                "NETWORK must be one of {}",
                crate::proof::NETWORKS.join(", ")
            );
        }
        let upstream_url = required("UPSTREAM_URL")?.trim_end_matches('/').to_string();
        let sui_rpc_url = required("SUI_RPC_URL")?;
        check_scheme("UPSTREAM_URL", &upstream_url, allow_http)?;
        check_scheme("SUI_RPC_URL", &sui_rpc_url, allow_http)?;
        if origin_of(&upstream_url) == gateway_origin {
            anyhow::bail!("UPSTREAM_URL must not be this gateway (request loop)");
        }
        let nft_type = required("NFT_TYPE")?;
        if !is_access_gate_pass_type(&nft_type) {
            anyhow::bail!(
                "NFT_TYPE must be <pkg>::access_gate::AccessNFT or <pkg>::access_gate::SoulboundAccessNFT"
            );
        }
        let gate_id = required("GATE_ID")?;
        if !is_object_id(&gate_id) {
            anyhow::bail!("GATE_ID must be a 0x-prefixed object ID");
        }

        let single_use = parse_bool(get, "SINGLE_USE", false)?;
        let redis_url = get("REDIS_URL").filter(|s| !s.is_empty());
        let allow_volatile_redemptions = parse_bool(get, "ALLOW_VOLATILE_REDEMPTIONS", false)?;
        if single_use && redis_url.is_none() && !allow_volatile_redemptions {
            anyhow::bail!(
                "SINGLE_USE=true requires REDIS_URL: an in-memory store forgets spent consumes on restart \
                 (set ALLOW_VOLATILE_REDEMPTIONS=true for development)"
            );
        }

        let upstream_timeout_secs: u64 = parse_int(get, "UPSTREAM_TIMEOUT_SECS", 600, 1, 3600)?;
        let body_read_timeout_secs: u64 = parse_int(get, "BODY_READ_TIMEOUT_SECS", 30, 1, 3600)?;
        let redemption_lease_ttl_secs: u64 =
            parse_int(get, "REDEMPTION_LEASE_TTL_SECS", 900, 30, 86_400)?;
        // The lease is taken before the body is read and held until the upstream answers, so it
        // must outlive both deadlines (audit F46), or a duplicate could lease the same consume
        // while the first upload is still running.
        if redemption_lease_ttl_secs <= upstream_timeout_secs.saturating_add(body_read_timeout_secs)
        {
            anyhow::bail!(
                "REDEMPTION_LEASE_TTL_SECS must exceed UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS (a lease must outlive its whole request)"
            );
        }
        let redemption_retention_secs: u64 = parse_int(
            get,
            "REDEMPTION_RETENTION_SECS",
            2_592_000,
            3600,
            31_536_000,
        )?;
        let consume_max_age_secs: u64 =
            parse_int(get, "CONSUME_MAX_AGE_SECS", 432_000, 60, 31_536_000)?;
        if consume_max_age_secs > redemption_retention_secs {
            anyhow::bail!(
                "CONSUME_MAX_AGE_SECS must not exceed REDEMPTION_RETENTION_SECS (a spent consume must be remembered while it can be presented)"
            );
        }

        let upstream_auth_headers =
            parse_upstream_auth_headers(get("UPSTREAM_AUTH_HEADERS").as_deref())?;
        let sui_rpc_auth_header = parse_rpc_auth_header(get("SUI_RPC_AUTH_HEADER").as_deref())?;

        Ok(Self {
            bind_addr,
            gateway_origin,
            network,
            upstream_url,
            sui_rpc_url,
            nft_type,
            gate_id,
            challenge_ttl_secs: parse_int(get, "CHALLENGE_TTL_SECS", 300, 10, 3600)?,
            single_use,
            public_paths: parse_public_paths(
                &get("PUBLIC_PATHS").unwrap_or_else(|| "/v1/tip-config".to_string()),
            )?,
            allowed_origins: parse_allowed_origins(
                &get("ALLOWED_ORIGINS").unwrap_or_default(),
                allow_http,
            )?,
            rate_limit_per_min: parse_int(get, "RATE_LIMIT_PER_MIN", 30, 0, 1_000_000)?,
            challenge_rate_limit_per_min: parse_int(
                get,
                "CHALLENGE_RATE_LIMIT_PER_MIN",
                30,
                0,
                1_000_000,
            )?,
            gated_preauth_rate_limit_per_min: parse_int(
                get,
                "GATED_PREAUTH_RATE_LIMIT_PER_MIN",
                120,
                0,
                1_000_000,
            )?,
            max_body_bytes: parse_int(get, "MAX_BODY_BYTES", 262_144, 1, 1_073_741_824)?,
            redis_url,
            nonce_max_entries: parse_int(get, "NONCE_MAX_ENTRIES", 1_000_000, 1, 100_000_000)?,
            nonce_prune_interval_secs: parse_int(get, "NONCE_PRUNE_INTERVAL_SECS", 60, 1, 86_400)?,
            ownership_cache_ttl_ms: parse_int(get, "OWNERSHIP_CACHE_TTL_MS", 0, 0, 3_600_000)?,
            redemption_lease_ttl_secs,
            redemption_retention_secs,
            consume_max_age_secs,
            allow_volatile_redemptions,
            rpc_timeout_secs: parse_int(get, "RPC_TIMEOUT_SECS", 15, 1, 120)?,
            header_read_timeout_secs: parse_int(get, "HEADER_READ_TIMEOUT_SECS", 10, 1, 300)?,
            body_read_timeout_secs,
            max_connections: parse_int(get, "MAX_CONNECTIONS", 1024, 1, 1_000_000)?,
            shutdown_grace_secs: parse_int(get, "SHUTDOWN_GRACE_SECS", 30, 1, 3600)?,
            max_concurrent_requests: parse_int(get, "MAX_CONCURRENT_REQUESTS", 64, 1, 100_000)?,
            trusted_proxy_hops: parse_int(get, "TRUSTED_PROXY_HOPS", 0, 0, 16)?,
            upstream_timeout_secs,
            max_response_bytes: parse_int(get, "MAX_RESPONSE_BYTES", 16_777_216, 1, 1_073_741_824)?,
            upstream_auth_headers,
            sui_rpc_auth_header,
        })
    }

    /// Returns `true` if `path` is in the configured public-paths list (proxied without auth,
    /// `GET`/`HEAD` only).
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| p == path)
    }
}

/// `0x` followed by 1–64 hex digits.
pub fn is_object_id(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(h) => !h.is_empty() && h.len() <= 64 && h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// `<pkg>::access_gate::AccessNFT` or `<pkg>::access_gate::SoulboundAccessNFT`. Gating on any other
/// type (a fungible `Coin<T>`, an unrelated NFT) would admit holders of objects access_gate never
/// sold, so it is rejected at startup.
pub fn is_access_gate_pass_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split("::").collect();
    parts.len() == 3
        && is_object_id(parts[0])
        && parts[1] == "access_gate"
        && (parts[2] == "AccessNFT" || parts[2] == "SoulboundAccessNFT")
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn accepts_only_access_gate_pass_types() {
        assert!(is_access_gate_pass_type("0x1::access_gate::AccessNFT"));
        assert!(is_access_gate_pass_type(
            "0xab::access_gate::SoulboundAccessNFT"
        ));
        for bad in [
            "0x2::coin::Coin<0x2::sui::SUI>",
            "0x1::other::AccessNFT",
            "0x1::access_gate::Gate",
            "AccessNFT",
            "0xzz::access_gate::AccessNFT",
        ] {
            assert!(!is_access_gate_pass_type(bad), "{bad}");
        }
    }

    #[test]
    fn upstream_auth_headers_are_json_only() {
        assert!(parse_upstream_auth_headers(None).unwrap().is_empty());
        let h = parse_upstream_auth_headers(Some(
            r#"[{"name":"CF-Access-Client-Id","value":"id"},{"name":"CF-Access-Client-Secret","value":"a,b:c"}]"#,
        ))
        .unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[1].value, "a,b:c");
        for bad in [
            "CF-Access-Client-Id: id",
            r#"{"name":"a","value":"b"}"#,
            r#"[{"name":"Bad Name","value":"b"}]"#,
            "[{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}]",
        ] {
            assert!(parse_upstream_auth_headers(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn rpc_auth_header_forms() {
        let h = parse_rpc_auth_header(Some("X-Api-Key: k:1"))
            .unwrap()
            .unwrap();
        assert_eq!((h.name.as_str(), h.value.as_str()), ("X-Api-Key", "k:1"));
        assert!(parse_rpc_auth_header(Some("")).unwrap().is_none());
        for bad in [
            "Bearer tok",
            "Bad Name: v",
            "X-Key: ",
            "X-Key: a\r\nInjected: 1",
        ] {
            assert!(parse_rpc_auth_header(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn urls_must_be_https_unless_allowed() {
        assert!(check_scheme("U", "https://x", false).is_ok());
        assert!(check_scheme("U", "http://x", false).is_err());
        assert!(check_scheme("U", "http://127.0.0.1:9000", true).is_ok());
        assert!(check_scheme("U", "ftp://x", true).is_err());
    }

    #[test]
    fn urls_must_not_carry_credentials() {
        for bad in [
            "https://user:pass@x.example",
            "https://token@x.example/v1",
            "http://u:p@127.0.0.1:9000",
        ] {
            let e = check_scheme("U", bad, true).unwrap_err().to_string();
            assert!(e.contains("credentials"), "{bad}: {e}");
            assert!(!e.contains("pass") && !e.contains("token@"), "{e}"); // the URL is not echoed
        }
        // An `@` in the path or query is not userinfo.
        assert!(check_scheme("U", "https://x.example/a@b?c=d@e", false).is_ok());
    }

    #[test]
    fn debug_redacts_credentials() {
        let mut cfg = crate::tests_support::test_cfg();
        cfg.redis_url = Some("redis://:hunter2@redis:6379".into());
        cfg.upstream_auth_headers = vec![AuthHeader {
            name: "CF-Access-Client-Secret".into(),
            value: "s3cret".into(),
        }];
        cfg.upstream_url = "https://private-origin.internal.example".into();
        cfg.sui_rpc_url = "https://rpc.example/KEY123".into();
        let out = format!("{cfg:?}");
        assert!(!out.contains("hunter2") && !out.contains("s3cret"), "{out}");
        assert!(out.contains("CF-Access-Client-Secret"));
        // The private origin and an RPC key in the path are never printed (audit F26).
        assert!(
            !out.contains("private-origin") && !out.contains("KEY123"),
            "{out}"
        );
    }

    #[test]
    fn object_ids_are_0x_hex() {
        assert!(is_object_id("0x2"));
        assert!(!is_object_id("0x"));
        assert!(!is_object_id("gate"));
        assert!(!is_object_id(&format!("0x{}", "a".repeat(65))));
    }

    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            ("GATEWAY_ORIGIN", "https://gateway.example.com".to_string()),
            ("NETWORK", "testnet".to_string()),
            (
                "UPSTREAM_URL",
                "https://relay-origin.example.com".to_string(),
            ),
            (
                "SUI_RPC_URL",
                "https://fullnode.testnet.sui.io:443".to_string(),
            ),
            ("NFT_TYPE", "0x1::access_gate::AccessNFT".to_string()),
            ("GATE_ID", "0x2".to_string()),
        ])
    }

    fn load(extra: &[(&'static str, &str)]) -> anyhow::Result<GatewayConfig> {
        let mut env = base();
        for (k, v) in extra {
            if v == &"<unset>" {
                env.remove(k);
            } else {
                env.insert(k, v.to_string());
            }
        }
        GatewayConfig::from_lookup(&|k| env.get(k).cloned())
    }

    fn err(extra: &[(&'static str, &str)]) -> String {
        load(extra).unwrap_err().to_string()
    }

    #[test]
    fn defaults_load_and_are_self_consistent() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.gateway_origin, "https://gateway.example.com");
        assert_eq!(cfg.network, "testnet");
        assert!(cfg.allowed_origins.is_empty());
        assert!(cfg.redemption_lease_ttl_secs > cfg.upstream_timeout_secs);
        assert!(cfg.consume_max_age_secs <= cfg.redemption_retention_secs);
    }

    #[test]
    fn audience_binding_inputs_are_required_and_canonical() {
        assert!(err(&[("GATEWAY_ORIGIN", "<unset>")]).contains("GATEWAY_ORIGIN"));
        for bad in [
            "gateway.example.com",
            "http://gateway.example.com",
            "https://gateway.example.com/",
            "https://Gateway.example.com",
            "https://gateway.example.com:443",
            "https://user@gateway.example.com",
        ] {
            assert!(
                err(&[("GATEWAY_ORIGIN", bad)]).contains("GATEWAY_ORIGIN"),
                "{bad}"
            );
        }
        assert!(err(&[("NETWORK", "testnet2")]).contains("NETWORK"));
        assert!(err(&[("NETWORK", "<unset>")]).contains("NETWORK"));
        assert!(err(&[("UPSTREAM_URL", "https://gateway.example.com/relay")]).contains("loop"));
    }

    #[test]
    fn a_typo_never_selects_a_weaker_mode() {
        for bad in ["TRUE", "1", "yes", "true ", ""] {
            assert!(
                err(&[("SINGLE_USE", bad)]).contains("SINGLE_USE"),
                "{bad:?}"
            );
        }
        for (key, bad) in [
            ("MAX_BODY_BYTES", "0"),
            ("MAX_BODY_BYTES", "-1"),
            ("MAX_BODY_BYTES", "1.5"),
            ("MAX_BODY_BYTES", "lots"),
            ("RATE_LIMIT_PER_MIN", "-5"),
            ("NONCE_MAX_ENTRIES", "0"),
            ("CHALLENGE_TTL_SECS", "1"),
            ("UPSTREAM_TIMEOUT_SECS", "0"),
            ("REDEMPTION_LEASE_TTL_SECS", "5"),
            ("TRUSTED_PROXY_HOPS", "-1"),
        ] {
            assert!(err(&[(key, bad)]).contains(key), "{key}={bad}");
        }
        assert_eq!(
            load(&[("RATE_LIMIT_PER_MIN", "0")])
                .unwrap()
                .rate_limit_per_min,
            0
        );
    }

    #[test]
    fn origins_and_public_paths_are_validated() {
        assert!(load(&[(
            "ALLOWED_ORIGINS",
            " https://a.example , https://b.example:8443 "
        )])
        .is_ok());
        for bad in [
            "*",
            "http://a.example",
            "https://a.example/",
            "https://A.example",
            "a.example",
        ] {
            assert!(
                err(&[("ALLOWED_ORIGINS", bad)]).contains("ALLOWED_ORIGINS"),
                "{bad}"
            );
        }
        assert_eq!(
            load(&[("PUBLIC_PATHS", "/v1/tip-config, /health")])
                .unwrap()
                .public_paths,
            vec!["/v1/tip-config", "/health"]
        );
        for bad in ["v1/tip-config", "/a/../b", "/a?x=1", "/a b"] {
            assert!(
                err(&[("PUBLIC_PATHS", bad)]).contains("PUBLIC_PATHS"),
                "{bad}"
            );
        }
    }

    #[test]
    fn single_use_needs_a_durable_store_and_consistent_windows() {
        assert!(err(&[("SINGLE_USE", "true")]).contains("REDIS_URL"));
        assert!(load(&[("SINGLE_USE", "true"), ("REDIS_URL", "redis://r:6379")]).is_ok());
        assert!(load(&[
            ("SINGLE_USE", "true"),
            ("ALLOW_VOLATILE_REDEMPTIONS", "true")
        ])
        .is_ok());
        assert!(err(&[
            ("UPSTREAM_TIMEOUT_SECS", "600"),
            ("REDEMPTION_LEASE_TTL_SECS", "600")
        ])
        .contains("exceed UPSTREAM_TIMEOUT_SECS"));
        // The body-read deadline counts too (audit F46): 600 + 400 = 1000 >= 900.
        assert!(err(&[("BODY_READ_TIMEOUT_SECS", "400")]).contains("BODY_READ_TIMEOUT_SECS"));
        assert!(err(&[
            ("UPSTREAM_TIMEOUT_SECS", "500"),
            ("BODY_READ_TIMEOUT_SECS", "400"),
            ("REDEMPTION_LEASE_TTL_SECS", "900")
        ])
        .contains("BODY_READ_TIMEOUT_SECS"));
        assert!(load(&[
            ("UPSTREAM_TIMEOUT_SECS", "500"),
            ("BODY_READ_TIMEOUT_SECS", "399"),
            ("REDEMPTION_LEASE_TTL_SECS", "900")
        ])
        .is_ok());
        assert!(err(&[
            ("CONSUME_MAX_AGE_SECS", "864000"),
            ("REDEMPTION_RETENTION_SECS", "432000")
        ])
        .contains("CONSUME_MAX_AGE_SECS"));
    }

    #[test]
    fn canonical_origin_rules() {
        for ok in [
            "https://a.example",
            "https://a.example:8443",
            "http://localhost:8787",
            "http://127.0.0.1:3000",
        ] {
            assert!(is_canonical_origin(ok), "{ok}");
        }
        for bad in [
            "https://a.example:443",
            "https://a.example/x",
            "https://a.example?x",
            "http://a.example",
            "https://",
            "https://a b",
        ] {
            assert!(!is_canonical_origin(bad), "{bad}");
        }
    }
}
