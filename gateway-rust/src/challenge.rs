//! Challenge / nonce store. Issues random, time-bound nonces and lets a valid nonce be
//! consumed exactly once (replay protection).
//!
//! Two backends behind one async [`NonceStore`] enum:
//! - [`InMemoryNonceStore`] — process-local `Mutex<HashMap>`, hardened with a **hard entry
//!   cap** (evict-oldest) and a **background prune** so growth is bounded independent of issue
//!   cadence (gateway audit F3). Correct only at `replicas: 1` (F2).
//! - [`RedisNonceStore`] — a shared TTL store (Redis protocol; works with **Dragonfly**) so
//!   nonce consumption is fleet-wide and replay protection survives horizontal scale-out
//!   (gateway audit F2). Single-use is atomic via `GETDEL`; expiry is the key TTL.
//!
//! Both fail **closed**: a backend error is an `Err` the router answers `503` (never a business
//! conflict, never an implicit success). Redemptions are owner-bound: the lease returns a random
//! token, and commit/release are compare-and-set on it, so a request whose lease lapsed can never
//! clear or overwrite a newer holder's.

use rand_core::{OsRng, RngCore};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Current Unix time in milliseconds. Used to compute nonce expiry timestamps.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Generate a cryptographically random 24-byte hex nonce (48 hex chars). Matches the Workers
/// gateway's `randomHex24()` entropy. The nonce is **ASCII by contract** (hex only) — the client's
/// `decodeAccessProof` enforces ASCII, so the proof-token base64 can never carry non-ASCII bytes.
fn random_nonce() -> String {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Outcome of a redemption-lease attempt (single-use mode). The permanent on-chain `consumeDigest`
/// is the one-time token: a use is spent only when an upload succeeds (`commit`); an interrupted
/// upload `release`s the lease so the consume stays redeemable.
#[derive(Debug, PartialEq, Eq)]
pub enum Lease {
    /// The caller holds the lease (identified by this owner token) and must `commit`/`release` it.
    Ok(String),
    /// Another in-flight request holds an unexpired lease (concurrent duplicate).
    Leased,
    /// The digest was already committed — the use is spent.
    Redeemed,
}

/// Outcome of a commit: `Ok` — recorded as spent by the lease holder; `Lost` — the lease had
/// lapsed or belongs to another request, so nothing changed (the caller must not report success).
#[derive(Debug, PartialEq, Eq)]
pub enum Commit {
    Ok,
    Lost,
}

// ── In-memory backend ────────────────────────────────────────────────────────────

/// A single tracked nonce in the in-memory store.
struct Entry {
    /// When this nonce expires (monotonic).
    expiry: Instant,
    /// True once the nonce has been consumed (single-use enforcement).
    used: bool,
}

/// A tracked redemption (single-use mode): a leased (in-flight) or committed (spent) consume digest.
struct Redemption {
    /// True once committed (the use is spent); false while only leased for an in-flight upload.
    committed: bool,
    /// Lease deadline (leased) or retention deadline (committed), monotonic.
    expiry: Instant,
    /// Owner token of a lease (empty once committed).
    token: String,
}

/// Process-local nonce store backed by a `Mutex<HashMap>`.
pub struct InMemoryNonceStore {
    /// Lifetime of each issued nonce.
    ttl: Duration,
    /// Hard cap on live entries; evicts the soonest-to-expire entry when full (audit F3).
    max_entries: usize,
    /// The live nonce map, protected by a mutex for multi-threaded access.
    inner: Mutex<HashMap<String, Entry>>,
    /// Single-use redemption state, keyed by `consumeDigest`.
    redemptions: Mutex<HashMap<String, Redemption>>,
}

impl InMemoryNonceStore {
    /// Create a new store with the given TTL and entry cap.
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            ttl: Duration::from_secs(ttl_secs),
            max_entries: max_entries.max(1),
            inner: Mutex::new(HashMap::new()),
            redemptions: Mutex::new(HashMap::new()),
        }
    }

    /// Atomically claim `key` for an in-flight upload. Single-threaded per lock, so a concurrent
    /// duplicate sees `Leased` and a committed key sees `Redeemed`; an expired lease is reclaimable.
    fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> Lease {
        let now = Instant::now();
        let mut m = self.redemptions.lock().unwrap();
        m.retain(|_, r| r.expiry > now); // bound growth: drop expired leases + lapsed commits
        if let Some(r) = m.get(key) {
            if r.committed {
                return Lease::Redeemed;
            }
            if r.expiry > now {
                return Lease::Leased;
            }
        }
        if m.len() >= self.max_entries {
            // Evict the soonest-to-expire LEASE (never a commit — that would allow re-redemption).
            if let Some(oldest) = m
                .iter()
                .filter(|(_, r)| !r.committed)
                .min_by_key(|(_, r)| r.expiry)
                .map(|(k, _)| k.clone())
            {
                m.remove(&oldest);
            }
        }
        let token = random_nonce();
        m.insert(
            key.to_string(),
            Redemption {
                committed: false,
                expiry: now + Duration::from_secs(lease_ttl_secs),
                token: token.clone(),
            },
        );
        Lease::Ok(token)
    }

    /// Mark `key` redeemed (retained `retention_secs`) iff `token` still owns an unexpired lease.
    fn commit_redemption(&self, key: &str, token: &str, retention_secs: u64) -> Commit {
        let now = Instant::now();
        let mut m = self.redemptions.lock().unwrap();
        match m.get_mut(key) {
            Some(r) if !r.committed && r.token == token && r.expiry > now => {
                r.committed = true;
                r.expiry = now + Duration::from_secs(retention_secs);
                r.token.clear();
                Commit::Ok
            }
            _ => Commit::Lost,
        }
    }

    /// Release the lease on `key` iff `token` owns it (upload failed). Never clears a commit or a
    /// newer holder's lease.
    fn release_redemption(&self, key: &str, token: &str) {
        let mut m = self.redemptions.lock().unwrap();
        if m.get(key).is_some_and(|r| !r.committed && r.token == token) {
            m.remove(key);
        }
    }

    /// Insert `nonce` and return `(nonce, expires_at_unix_ms)`. Evicts expired entries and, if
    /// still full, the soonest-to-expire live entry before inserting.
    fn insert(&self, nonce: String) -> (String, u64) {
        let now = Instant::now();
        let expiry = now + self.ttl;
        let mut m = self.inner.lock().unwrap();
        m.retain(|_, e| e.expiry > now);
        // Hard cap: if still full after pruning expired, evict the soonest-to-expire entry so
        // memory is bounded regardless of issue rate (F3).
        if m.len() >= self.max_entries {
            if let Some(oldest) = m
                .iter()
                .min_by_key(|(_, e)| e.expiry)
                .map(|(k, _)| k.clone())
            {
                m.remove(&oldest);
            }
        }
        m.insert(
            nonce.clone(),
            Entry {
                expiry,
                used: false,
            },
        );
        (nonce, now_ms() + self.ttl.as_millis() as u64)
    }

    /// Mark `nonce` as used. Returns `true` iff it was present, unexpired, and not yet used.
    fn take_if_valid(&self, nonce: &str) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get_mut(nonce) {
            Some(e) if !e.used && e.expiry > Instant::now() => {
                e.used = true;
                true
            }
            _ => false,
        }
    }

    /// Drop expired entries. Called periodically by the background prune task.
    pub fn prune(&self) {
        let now = Instant::now();
        self.inner.lock().unwrap().retain(|_, e| e.expiry > now);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

// ── Redis / Dragonfly backend ───────────────────────────────────────────────────

/// Shared nonce store backed by a Redis-protocol server (Redis or Dragonfly).
pub struct RedisNonceStore {
    /// Multiplexed async connection manager; cloned cheaply per command.
    conn: redis::aio::ConnectionManager,
    /// Nonce TTL in milliseconds (used for `SET … PX`).
    ttl_ms: u64,
    /// Key prefix applied to every stored nonce (`nftgate:nonce:`).
    prefix: String,
}

/// Time limit for a Redis connection attempt and for each command.
const REDIS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl RedisNonceStore {
    /// Connect to a Redis-protocol server (Redis or Dragonfly). Startup-time async. Retries with
    /// exponential backoff (0.5 s doubling, 6 attempts, ~16 s in total) so a gateway that starts
    /// alongside its Redis does not crash-loop; gives up with the last error after that.
    pub async fn connect(url: &str, ttl_secs: u64) -> anyhow::Result<Self> {
        let client = redis::Client::open(url)?;
        // Bound every command and reconnect: a store that accepts connections but stops answering
        // must fail requests closed quickly, not hold them (and their concurrency slots) forever.
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(REDIS_TIMEOUT)
            .set_response_timeout(REDIS_TIMEOUT);
        let mut delay = std::time::Duration::from_millis(500);
        let mut attempt = 1;
        let conn = loop {
            match client
                .get_connection_manager_with_config(config.clone())
                .await
            {
                Ok(conn) => break conn,
                Err(e) if attempt < 6 => {
                    tracing::warn!(error = %e, attempt, "redis connect failed; retrying");
                    tokio::time::sleep(delay).await;
                    delay *= 2;
                    attempt += 1;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "redis connect failed after {attempt} attempts: {e}"
                    ))
                }
            }
        };
        Ok(Self {
            conn,
            ttl_ms: ttl_secs.saturating_mul(1000),
            prefix: "nftgate:nonce:".to_string(),
        })
    }

    /// Build the full Redis key for `nonce`.
    fn key(&self, nonce: &str) -> String {
        format!("{}{}", self.prefix, nonce)
    }

    /// Redis key for a redemption (separate namespace from nonces).
    fn redeem_key(&self, key: &str) -> String {
        format!("nftgate:redeem:{key}")
    }

    /// Atomically claim `key` via `SET NX PX` with an owner token (`leased:<token>`). On a
    /// pre-existing key, distinguish a committed (redeemed) digest from an active lease. A Redis
    /// error is an `Err` (answered 503), not a conflict.
    async fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> anyhow::Result<Lease> {
        let mut c = self.conn.clone();
        let k = self.redeem_key(key);
        let token = random_nonce();
        let set: Option<String> = redis::cmd("SET")
            .arg(&k)
            .arg(format!("leased:{token}"))
            .arg("NX")
            .arg("PX")
            .arg(lease_ttl_secs.saturating_mul(1000))
            .query_async(&mut c)
            .await
            .map_err(|e| anyhow::anyhow!("redis redemption SET failed: {e}"))?;
        if set.is_some() {
            return Ok(Lease::Ok(token)); // claimed the lease
        }
        // Key already present: committed (spent) or an unexpired lease.
        let cur: Option<String> = redis::cmd("GET")
            .arg(&k)
            .query_async(&mut c)
            .await
            .map_err(|e| anyhow::anyhow!("redis redemption GET failed: {e}"))?;
        Ok(match cur.as_deref() {
            Some("committed") => Lease::Redeemed,
            _ => Lease::Leased,
        })
    }

    /// Compare-and-set: mark `key` redeemed (retained `retention_secs`) iff it still holds this
    /// token's lease, in one Lua script.
    async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit> {
        let mut c = self.conn.clone();
        let script = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then \
               redis.call('SET', KEYS[1], 'committed', 'PX', ARGV[2]); return 1 \
             else return 0 end",
        );
        let ok: i64 = script
            .key(self.redeem_key(key))
            .arg(format!("leased:{token}"))
            .arg(retention_secs.saturating_mul(1000))
            .invoke_async(&mut c)
            .await
            .map_err(|e| anyhow::anyhow!("redis redemption commit failed: {e}"))?;
        Ok(if ok == 1 { Commit::Ok } else { Commit::Lost })
    }

    /// Compare-and-delete: release the lease iff it is still this token's (never a commit, never a
    /// newer holder's), in one Lua script.
    async fn release_redemption(&self, key: &str, token: &str) {
        let mut c = self.conn.clone();
        let script = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end",
        );
        let res: redis::RedisResult<i64> = script
            .key(self.redeem_key(key))
            .arg(format!("leased:{token}"))
            .invoke_async(&mut c)
            .await;
        if let Err(e) = res {
            // The lease still self-expires after REDEMPTION_LEASE_TTL_SECS.
            tracing::warn!(error = %e, "redis redemption release failed; lease will expire");
        }
    }

    /// Store `nonce` with a key TTL of `ttl_ms`. A failure is returned (the challenge endpoint
    /// answers 503) rather than handing out a nonce that can never verify.
    async fn insert(&self, nonce: String) -> anyhow::Result<(String, u64)> {
        let mut c = self.conn.clone();
        // SET key 1 PX <ttl> — random nonces don't collide, so NX is unnecessary.
        redis::cmd("SET")
            .arg(self.key(&nonce))
            .arg(1)
            .arg("PX")
            .arg(self.ttl_ms)
            .query_async::<()>(&mut c)
            .await
            .map_err(|e| anyhow::anyhow!("redis nonce SET failed: {e}"))?;
        Ok((nonce, now_ms() + self.ttl_ms))
    }

    /// Atomically consume `nonce` via `GETDEL` (Redis ≥6.2 / Dragonfly). `Ok(false)` for a
    /// missing/expired key; a Redis error is an `Err` (answered 503, fails closed).
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        let mut c = self.conn.clone();
        // GETDEL is atomic: returns the value and deletes the key in one step, so a nonce is
        // consumed exactly once fleet-wide; a missing/expired key returns nil.
        let res: redis::RedisResult<Option<String>> = redis::cmd("GETDEL")
            .arg(self.key(nonce))
            .query_async(&mut c)
            .await;
        match res {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false),
            Err(e) => Err(anyhow::anyhow!("redis nonce GETDEL failed: {e}")),
        }
    }
}

// ── Unified async enum ───────────────────────────────────────────────────────────

/// Unified async nonce store — either the process-local [`InMemoryNonceStore`] or the
/// shared [`RedisNonceStore`]. Selected at startup by the presence of `REDIS_URL`.
pub enum NonceStore {
    /// Process-local store (correct only at `replicas: 1`).
    InMemory(InMemoryNonceStore),
    /// Shared Redis/Dragonfly store (fleet-wide replay protection).
    Redis(RedisNonceStore),
}

impl NonceStore {
    /// Create an in-memory store with the given TTL and hard entry cap.
    pub fn in_memory(ttl_secs: u64, max_entries: usize) -> Self {
        NonceStore::InMemory(InMemoryNonceStore::new(ttl_secs, max_entries))
    }

    /// Connect to a Redis-protocol nonce store. Async startup — returns an error if the
    /// connection cannot be established.
    pub async fn redis(url: &str, ttl_secs: u64) -> anyhow::Result<Self> {
        Ok(NonceStore::Redis(
            RedisNonceStore::connect(url, ttl_secs).await?,
        ))
    }

    /// Issue a fresh random nonce. Returns `(nonce, expires_at_unix_ms)`, or an error when the
    /// shared store cannot record it.
    pub async fn issue(&self) -> anyhow::Result<(String, u64)> {
        let nonce = random_nonce();
        match self {
            NonceStore::InMemory(s) => Ok(s.insert(nonce)),
            NonceStore::Redis(s) => s.insert(nonce).await,
        }
    }

    /// Consume a nonce exactly once; `Ok(true)` iff it was valid, unexpired, and unused. `Err` when
    /// the shared store cannot answer.
    pub async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        match self {
            NonceStore::InMemory(s) => Ok(s.take_if_valid(nonce)),
            NonceStore::Redis(s) => s.take_if_valid(nonce).await,
        }
    }

    /// Prune expired entries (in-memory only; Redis expires via TTL). No-op for Redis.
    pub fn prune(&self) {
        if let NonceStore::InMemory(s) = self {
            s.prune();
        }
    }

    /// Single-use redemption: atomically claim a consume digest for an in-flight upload.
    pub async fn try_lease_redemption(
        &self,
        key: &str,
        lease_ttl_secs: u64,
    ) -> anyhow::Result<Lease> {
        match self {
            NonceStore::InMemory(s) => Ok(s.try_lease_redemption(key, lease_ttl_secs)),
            NonceStore::Redis(s) => s.try_lease_redemption(key, lease_ttl_secs).await,
        }
    }

    /// Mark a consume digest redeemed (after a successful upload) iff `token` still owns the lease.
    pub async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit> {
        match self {
            NonceStore::InMemory(s) => Ok(s.commit_redemption(key, token, retention_secs)),
            NonceStore::Redis(s) => s.commit_redemption(key, token, retention_secs).await,
        }
    }

    /// Release a redemption lease (after a failed upload) iff `token` still owns it.
    pub async fn release_redemption(&self, key: &str, token: &str) {
        match self {
            NonceStore::InMemory(s) => s.release_redemption(key, token),
            NonceStore::Redis(s) => s.release_redemption(key, token).await,
        }
    }

    /// Insert a caller-chosen nonce (test helper). Not available in production builds.
    #[cfg(test)]
    pub async fn issue_specific(&self, nonce: &str) -> (String, u64) {
        match self {
            NonceStore::InMemory(s) => s.insert(nonce.to_string()),
            NonceStore::Redis(s) => s.insert(nonce.to_string()).await.expect("redis insert"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> NonceStore {
        NonceStore::in_memory(300, 10_000)
    }

    async fn lease(s: &NonceStore, key: &str, ttl: u64) -> String {
        match s.try_lease_redemption(key, ttl).await.unwrap() {
            Lease::Ok(t) => t,
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn nonce_valid_once_then_used() {
        let store = store();
        let (nonce, _) = store.issue().await.unwrap();
        assert!(store.take_if_valid(&nonce).await.unwrap());
        assert!(!store.take_if_valid(&nonce).await.unwrap()); // already used
    }

    #[tokio::test]
    async fn unknown_nonce_rejected() {
        assert!(!store().take_if_valid("never-issued").await.unwrap());
    }

    #[tokio::test]
    async fn expired_nonce_rejected() {
        let store = NonceStore::in_memory(0, 10_000); // immediate expiry
        let (nonce, _) = store.issue().await.unwrap();
        assert!(!store.take_if_valid(&nonce).await.unwrap());
    }

    #[tokio::test]
    async fn hard_cap_bounds_memory() {
        let store = NonceStore::in_memory(300, 4); // cap 4
        for _ in 0..20 {
            store.issue().await.unwrap();
        }
        if let NonceStore::InMemory(s) = &store {
            assert!(s.len() <= 4, "entry count must stay within the hard cap");
        }
    }

    #[tokio::test]
    async fn prune_drops_expired() {
        let store = NonceStore::in_memory(0, 10_000);
        store.issue().await.unwrap();
        store.prune();
        if let NonceStore::InMemory(s) = &store {
            assert_eq!(s.len(), 0);
        }
    }

    #[tokio::test]
    async fn redemption_lease_commit_blocks_reuse() {
        let store = store();
        let token = lease(&store, "0xd", 120).await;
        // A concurrent duplicate sees the active lease.
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Leased
        );
        assert_eq!(
            store.commit_redemption("0xd", &token, 3600).await.unwrap(),
            Commit::Ok
        );
        // Once committed, it can never be re-leased.
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Redeemed
        );
    }

    #[tokio::test]
    async fn redemption_release_allows_retry() {
        let store = store();
        let token = lease(&store, "0xd", 120).await;
        store.release_redemption("0xd", &token).await; // upload failed
        lease(&store, "0xd", 120).await; // retry with the same consume
    }

    #[tokio::test]
    async fn redemption_release_never_clears_commit() {
        let store = store();
        let token = lease(&store, "0xd", 120).await;
        store.commit_redemption("0xd", &token, 3600).await.unwrap();
        store.release_redemption("0xd", &token).await; // must be a no-op on a committed key
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Redeemed
        );
    }

    #[tokio::test]
    async fn redemption_expired_lease_is_reclaimable() {
        let store = store();
        lease(&store, "0xd", 0).await; // lease expires immediately
        lease(&store, "0xd", 120).await; // reclaimed, not stuck
    }

    #[tokio::test]
    async fn a_stale_holder_cannot_release_or_commit_over_a_newer_lease() {
        let store = store();
        let stale = lease(&store, "0xd", 0).await; // lapses at once
        let fresh = lease(&store, "0xd", 120).await; // a newer holder
        assert_ne!(stale, fresh);
        store.release_redemption("0xd", &stale).await; // must not clear the newer lease
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Leased
        );
        assert_eq!(
            store.commit_redemption("0xd", &stale, 3600).await.unwrap(),
            Commit::Lost
        );
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Leased
        );
        assert_eq!(
            store.commit_redemption("0xd", &fresh, 3600).await.unwrap(),
            Commit::Ok
        );
        assert_eq!(
            store.try_lease_redemption("0xd", 120).await.unwrap(),
            Lease::Redeemed
        );
    }

    #[tokio::test]
    async fn a_commit_after_the_lease_lapsed_is_lost() {
        let store = store();
        let token = lease(&store, "0xd", 0).await;
        assert_eq!(
            store.commit_redemption("0xd", &token, 3600).await.unwrap(),
            Commit::Lost
        );
    }

    // Real Redis/Dragonfly check of the Redis backend: GETDEL single-use, SET NX leases, and the
    // Lua compare-and-set commit / compare-and-delete release (owner-bound; never erase a commit).
    // Keys are random and carry 60 s TTLs, so a shared instance is left clean. Run with:
    //   REDIS_URL=redis://:<password>@127.0.0.1:6379 cargo test -- --ignored redis_backend
    #[tokio::test]
    #[ignore = "needs REDIS_URL pointing at a Redis/Dragonfly instance"]
    async fn redis_backend_round_trip() {
        let url = std::env::var("REDIS_URL").expect("REDIS_URL");
        let store = NonceStore::redis(&url, 60).await.expect("connect");
        let key = format!("test-{}", random_nonce());

        let t1 = lease(&store, &key, 60).await;
        assert_eq!(
            store.try_lease_redemption(&key, 60).await.unwrap(),
            Lease::Leased
        );
        store.release_redemption(&key, "not-the-owner").await; // wrong token: no-op
        assert_eq!(
            store.try_lease_redemption(&key, 60).await.unwrap(),
            Lease::Leased
        );
        store.release_redemption(&key, &t1).await; // Lua: deletes the owner's lease
        let t2 = lease(&store, &key, 60).await;
        assert_eq!(
            store.commit_redemption(&key, &t1, 60).await.unwrap(),
            Commit::Lost
        );
        assert_eq!(
            store.commit_redemption(&key, &t2, 60).await.unwrap(),
            Commit::Ok
        );
        store.release_redemption(&key, &t2).await; // Lua: must NOT delete a `committed` value
        assert_eq!(
            store.try_lease_redemption(&key, 60).await.unwrap(),
            Lease::Redeemed
        );

        let (nonce, _) = store.issue().await.expect("issue");
        assert!(store.take_if_valid(&nonce).await.unwrap());
        assert!(!store.take_if_valid(&nonce).await.unwrap());
    }
}
