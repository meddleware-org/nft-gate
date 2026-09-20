//! Gateway configuration, loaded from environment variables. Nothing here is
//! consumer-specific — the same binary fronts an upload relay, a website, a game API, etc.
//!
//! # Environment Variables
//!
//! Required:
//! - `UPSTREAM_URL` — base URL of the upstream this gateway protects (trailing `/` stripped).
//! - `SUI_RPC_URL` — Sui JSON-RPC endpoint for ownership / event queries.
//! - `NFT_TYPE` — fully-qualified NFT type string, e.g. `<pkg>::access_gate::AccessNFT`.
//!
//! Optional (with defaults):
//! - `GATE_ID` — restrict ownership to a specific gate object (default: unset, any gate).
//! - `CHALLENGE_TTL_SECS` — nonce lifetime in seconds (default: `300`).
//! - `SINGLE_USE` — `true` to require an on-chain single-use consume (default: `false`).
//! - `PUBLIC_PATHS` — comma-separated paths proxied without auth (default: `/v1/tip-config`).
//! - `RATE_LIMIT_PER_MIN` — per-address request budget per minute, 0 to disable (default: `30`).
//! - `CHALLENGE_RATE_LIMIT_PER_MIN` — per-IP budget for the challenge endpoint per minute, 0 to
//!   disable (default: `30`). Keyed by `X-Forwarded-For` first entry / `X-Real-IP` / "unknown".
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

use std::net::SocketAddr;

#[derive(Clone, Debug)]
pub struct GatewayConfig {
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// Base URL of the upstream this gateway protects (e.g. the stock upload relay).
    pub upstream_url: String,
    /// Sui JSON-RPC endpoint used for ownership / event queries.
    pub sui_rpc_url: String,
    /// Fully-qualified access-NFT type string to gate on.
    pub nft_type: String,
    /// Optional gate object ID; when set, ownership must be for this specific gate.
    pub gate_id: Option<String>,
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
    /// Returns an error if any required variable (`UPSTREAM_URL`, `SUI_RPC_URL`, `NFT_TYPE`) is
    /// absent, or if `BIND_ADDR` cannot be parsed as a socket address.
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
        let gate_id = std::env::var("GATE_ID").ok().filter(|s| !s.is_empty());
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
        })
    }

    /// Returns `true` if `path` is in the configured public-paths list (proxied without auth).
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| p == path)
    }
}
