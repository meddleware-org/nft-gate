//! Gateway configuration, loaded from environment variables. Nothing here is
//! consumer-specific — the same binary fronts an upload relay, a website, a game API, etc.
//!
//! # Environment Variables
//!
//! Required:
//! - `UPSTREAM_URL` — base URL of the upstream this gateway protects (trailing `/` stripped).
//! - `SUI_RPC_URL` — Sui fullnode (queried over gRPC-web) for ownership / event / gate queries.
//! - `NFT_TYPE` — the access_gate pass type: `<pkg>::access_gate::AccessNFT` or
//!   `<pkg>::access_gate::SoulboundAccessNFT` (anything else, e.g. a fungible `Coin<T>`, is rejected).
//! - `GATE_ID` — the gate whose passes are accepted (object ID).
//!
//! Optional (with defaults):
//! - `CHALLENGE_TTL_SECS` — nonce lifetime in seconds (default: `300`).
//! - `SINGLE_USE` — `true` to require an on-chain single-use consume (default: `false`).
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
//!   redemption (default: `120`).
//! - `REDEMPTION_RETENTION_SECS` — single-use: how long a committed (spent) consume-digest is
//!   remembered to block re-redemption (default: `2592000` = 30 days).
//! - `MAX_CONCURRENT_REQUESTS` — in-flight request cap; excess requests get `503` at once
//!   (default: `64`). Peak body memory ≈ `2 × MAX_BODY_BYTES × MAX_CONCURRENT_REQUESTS`.
//! - `TRUSTED_PROXY_HOPS` — reverse proxies in front of the gateway (default: `0` → the TCP peer
//!   address is the client IP). With N > 0 the client IP is the Nth `X-Forwarded-For` entry from
//!   the right, i.e. the address the outermost trusted proxy saw.
//! - `UPSTREAM_TIMEOUT_SECS` — whole-request timeout for upstream calls (default: `120`).
//! - `MAX_RESPONSE_BYTES` — cap on a buffered upstream response (default: `16777216` = 16 MiB).
//! - `ALLOW_INSECURE_HTTP` — `1` permits `http://` for `UPSTREAM_URL` / `SUI_RPC_URL` (localnet or
//!   an in-cluster upstream); otherwise both must be `https://` (default: unset).
//! - `UPSTREAM_AUTH_HEADERS` — JSON array `[{"name":…,"value":…}]` of headers added to every
//!   upstream request (secret; same format as the Workers gateway).
//! - `SUI_RPC_AUTH_HEADER` — one `Name: value` header added to every Sui RPC call (secret; a bare
//!   value means `Authorization`).

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
    /// Per-address request budget per minute (post-auth).
    pub rate_limit_per_min: u32,
    /// Per-IP request budget for the challenge endpoint per minute (pre-auth).
    pub challenge_rate_limit_per_min: u32,
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

/// Hand-written so logs never carry credentials: header values and the Redis URL (which may embed
/// a password) are redacted.
impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self
            .upstream_auth_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        f.debug_struct("GatewayConfig")
            .field("bind_addr", &self.bind_addr)
            .field("upstream_url", &self.upstream_url)
            .field("sui_rpc_url", &self.sui_rpc_url)
            .field("nft_type", &self.nft_type)
            .field("gate_id", &self.gate_id)
            .field("single_use", &self.single_use)
            .field("public_paths", &self.public_paths)
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

/// Parse `SUI_RPC_AUTH_HEADER`: `Name: value`, or a bare value meaning `Authorization`.
pub fn parse_rpc_auth_header(raw: Option<&str>) -> anyhow::Result<Option<AuthHeader>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let (name, value) = match raw.split_once(':') {
        Some((n, v)) if is_header_name(n.trim()) => (n.trim(), v.trim()),
        _ => ("Authorization", raw),
    };
    if value.contains('\r') || value.contains('\n') {
        anyhow::bail!("SUI_RPC_AUTH_HEADER value must not contain line breaks");
    }
    Ok(Some(AuthHeader {
        name: name.to_string(),
        value: value.to_string(),
    }))
}

/// Require `https://` unless `allow_http` (localnet / in-cluster) permits `http://`.
fn check_scheme(var: &str, url: &str, allow_http: bool) -> anyhow::Result<()> {
    if url.starts_with("https://") || (allow_http && url.starts_with("http://")) {
        Ok(())
    } else if url.starts_with("http://") {
        anyhow::bail!("{var} must use https:// (set ALLOW_INSECURE_HTTP=1 for localnet or an in-cluster upstream)")
    } else {
        anyhow::bail!("{var} must be an http(s) URL")
    }
}

/// Return the value of `key` from the environment, or `default` if it is absent or empty.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

impl GatewayConfig {
    /// Load configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable (`UPSTREAM_URL`, `SUI_RPC_URL`, `NFT_TYPE`,
    /// `GATE_ID`) is absent or invalid, or if `BIND_ADDR` cannot be parsed as a socket address.
    pub fn from_env() -> anyhow::Result<Self> {
        let bind_addr: SocketAddr = env_or("BIND_ADDR", "0.0.0.0:8080")
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid BIND_ADDR: {e}"))?;
        let upstream_url = std::env::var("UPSTREAM_URL")
            .map_err(|_| anyhow::anyhow!("UPSTREAM_URL is required"))?
            .trim_end_matches('/')
            .to_string();
        let sui_rpc_url =
            std::env::var("SUI_RPC_URL").map_err(|_| anyhow::anyhow!("SUI_RPC_URL is required"))?;
        let nft_type =
            std::env::var("NFT_TYPE").map_err(|_| anyhow::anyhow!("NFT_TYPE is required"))?;
        let nft_type = nft_type.trim().to_string();
        if !is_access_gate_pass_type(&nft_type) {
            anyhow::bail!(
                "NFT_TYPE must be <pkg>::access_gate::AccessNFT or <pkg>::access_gate::SoulboundAccessNFT"
            );
        }
        let gate_id = std::env::var("GATE_ID")
            .map_err(|_| anyhow::anyhow!("GATE_ID is required"))?
            .trim()
            .to_string();
        if !is_object_id(&gate_id) {
            anyhow::bail!("GATE_ID must be a 0x-prefixed object ID");
        }
        let challenge_ttl_secs = env_or("CHALLENGE_TTL_SECS", "300").parse().unwrap_or(300);
        let single_use = env_or("SINGLE_USE", "false").eq_ignore_ascii_case("true");
        let public_paths = env_or("PUBLIC_PATHS", "/v1/tip-config")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let rate_limit_per_min = env_or("RATE_LIMIT_PER_MIN", "30").parse().unwrap_or(30);
        let challenge_rate_limit_per_min = env_or("CHALLENGE_RATE_LIMIT_PER_MIN", "30")
            .parse()
            .unwrap_or(30);
        let max_body_bytes = env_or("MAX_BODY_BYTES", "262144")
            .parse()
            .unwrap_or(262_144);
        let redis_url = std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty());
        let nonce_max_entries = env_or("NONCE_MAX_ENTRIES", "1000000")
            .parse()
            .unwrap_or(1_000_000);
        let nonce_prune_interval_secs = env_or("NONCE_PRUNE_INTERVAL_SECS", "60")
            .parse()
            .unwrap_or(60);
        let ownership_cache_ttl_ms = env_or("OWNERSHIP_CACHE_TTL_MS", "0").parse().unwrap_or(0);
        let redemption_lease_ttl_secs = env_or("REDEMPTION_LEASE_TTL_SECS", "120")
            .parse()
            .unwrap_or(120);
        let redemption_retention_secs = env_or("REDEMPTION_RETENTION_SECS", "2592000")
            .parse()
            .unwrap_or(2_592_000);
        let max_concurrent_requests = env_or("MAX_CONCURRENT_REQUESTS", "64")
            .parse::<usize>()
            .unwrap_or(64)
            .max(1);
        let trusted_proxy_hops = env_or("TRUSTED_PROXY_HOPS", "0").parse().unwrap_or(0);
        let upstream_timeout_secs = env_or("UPSTREAM_TIMEOUT_SECS", "120")
            .parse::<u64>()
            .unwrap_or(120)
            .max(1);
        let max_response_bytes = env_or("MAX_RESPONSE_BYTES", "16777216")
            .parse()
            .unwrap_or(16_777_216);
        let allow_http = env_or("ALLOW_INSECURE_HTTP", "") == "1";
        check_scheme("UPSTREAM_URL", &upstream_url, allow_http)?;
        check_scheme("SUI_RPC_URL", &sui_rpc_url, allow_http)?;
        let upstream_auth_headers =
            parse_upstream_auth_headers(std::env::var("UPSTREAM_AUTH_HEADERS").ok().as_deref())?;
        let sui_rpc_auth_header =
            parse_rpc_auth_header(std::env::var("SUI_RPC_AUTH_HEADER").ok().as_deref())?;

        Ok(Self {
            bind_addr,
            upstream_url,
            sui_rpc_url,
            nft_type,
            gate_id,
            challenge_ttl_secs,
            single_use,
            public_paths,
            rate_limit_per_min,
            challenge_rate_limit_per_min,
            max_body_bytes,
            redis_url,
            nonce_max_entries,
            nonce_prune_interval_secs,
            ownership_cache_ttl_ms,
            redemption_lease_ttl_secs,
            redemption_retention_secs,
            max_concurrent_requests,
            trusted_proxy_hops,
            upstream_timeout_secs,
            max_response_bytes,
            upstream_auth_headers,
            sui_rpc_auth_header,
        })
    }

    /// Returns `true` if `path` is in the configured public-paths list (proxied without auth).
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
        let h = parse_rpc_auth_header(Some("Bearer tok")).unwrap().unwrap();
        assert_eq!(h.name, "Authorization");
        assert!(parse_rpc_auth_header(Some("")).unwrap().is_none());
    }

    #[test]
    fn urls_must_be_https_unless_allowed() {
        assert!(check_scheme("U", "https://x", false).is_ok());
        assert!(check_scheme("U", "http://x", false).is_err());
        assert!(check_scheme("U", "http://127.0.0.1:9000", true).is_ok());
        assert!(check_scheme("U", "ftp://x", true).is_err());
    }

    #[test]
    fn debug_redacts_credentials() {
        let mut cfg = crate::tests_support::test_cfg();
        cfg.redis_url = Some("redis://:hunter2@redis:6379".into());
        cfg.upstream_auth_headers = vec![AuthHeader {
            name: "CF-Access-Client-Secret".into(),
            value: "s3cret".into(),
        }];
        let out = format!("{cfg:?}");
        assert!(!out.contains("hunter2") && !out.contains("s3cret"), "{out}");
        assert!(out.contains("CF-Access-Client-Secret"));
    }

    #[test]
    fn object_ids_are_0x_hex() {
        assert!(is_object_id("0x2"));
        assert!(!is_object_id("0x"));
        assert!(!is_object_id("gate"));
        assert!(!is_object_id(&format!("0x{}", "a".repeat(65))));
    }
}
