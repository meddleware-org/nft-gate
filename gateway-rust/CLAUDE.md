# CLAUDE.md — gateway-rust

## What this crate is

The Rust/Axum implementation of the nft-gate gateway. Wire-identical to `gateway-workers/` on the
client-facing contract — same routes, status codes, proof format, and env-var config. Deployed as
a Docker container or a Cargo binary; state backed by an in-memory store (single replica) or
Redis/Dragonfly (horizontal scale-out).

## Chain access: hand-rolled gRPC-web (no JSON-RPC, no tonic/prost)

Public Sui full nodes deprecated JSON-RPC and the GraphQL endpoints are unavailable, so `sui_rpc.rs`
queries the chain over **gRPC-web** (`application/grpc-web+proto`, HTTP/1.1) via a minimal
hand-rolled client in `grpc.rs` — deliberately **without** `tonic`/`prost`/`sui-rpc`, to keep the
lightweight build (same rationale as avoiding `reqwest`; see the HTTP-client note). `grpc.rs` is a
tiny protobuf writer/reader + gRPC-web framing over the shared `HttpClient`; only the fields the
gateway reads are decoded. Field numbers are pinned from `MystenLabs/sui-apis` and pinned by hermetic
gRPC-web fixtures in `sui_rpc.rs` (literal field numbers, no network) and checked against a real node by
the optional `--ignored live_` tests, which take a fresh consume from `NFT_GATE_LIVE_*` env vars
(public fullnodes prune old transactions, so no digest is fixed in the source).

- `consume_tx_valid` (single-use) is **digest-first**, mirroring the Workers gateway:
  `LedgerService/GetTransaction` (retried 4× at 500 ms) → a transaction whose effects status is success, with an event of **exactly**
  `<NFT_TYPE package>::access_gate::AccessConsumedEvent` (never a suffix match — any package can
  declare an `access_gate` module) for this **sender + gate** (gate read via
  a recursive lookup of the event's `google.protobuf.Value` json, so no BCS field-order assumption).
  It is NOT bound to the challenge nonce — single-use is enforced by the redemption store below.
- `owns_nft` (non-single-use) uses `StateService/ListOwnedObjects`, matching `gate_id` via the same
  json lookup. It reads every page (50 per page, at most `MAX_OWNED_PAGES` = 100, as in the Workers
  gateway) and errors past the bound.

## Single-use redemption (a consumed use is never lost)

The permanent on-chain `consumeDigest` is the one-time token, exactly as in the Workers gateway.
`verify_access_request` returns `Verified { address, redemption_key }`; for single-use the dispatcher
(`main.rs`) leases the digest (`NonceStore::try_lease_redemption`, which returns an owner token), proxies, then `commit`s with
the token on a 2xx upstream response or `release`s with it on failure (Lua compare-and-set in Redis) — so an interrupted upload leaves the consume redeemable
while a duplicate can't double-spend it. Redis keys use the `nftgate:redeem:` prefix; the in-memory
store mirrors the semantics (and `SINGLE_USE=true` requires Redis unless `ALLOW_VOLATILE_REDEMPTIONS`).
`REDEMPTION_LEASE_TTL_SECS` (900, above `UPSTREAM_TIMEOUT_SECS`) / `REDEMPTION_RETENTION_SECS` (30d)
tune the lease/retention windows. `redeemed`/`leased` → `409` with a machine-readable `code`; a store error → `503`; a lost lease → `502`.

## Hardening invariants

- ed25519 is verified under ZIP-215 (`ed25519-consensus`); secp256k1/r1 reject high-S explicitly.
  The shared conformance vectors (`negativeSignatures`, `zip215`) pin both gateways to Sui's rules.
- gRPC-web responses must carry a `grpc-status` (header for trailers-only, else trailer frame);
  anything else is an error. Messages are capped at 4 MiB; JSON lookups stop at depth 32.
- Every outbound call has connect and whole-request timeouts and a response-size cap.
- `MAX_CONCURRENT_REQUESTS` sheds load with `503`; `/healthz` is routed outside the cap.
- CORS mirrors the Workers gateway (`cors.ts`): exact `ALLOWED_ORIGINS` match only, the same grants, `Vary: Origin`, preflight before auth, headers on error responses too.
- The rate-limit client IP is the TCP peer unless `TRUSTED_PROXY_HOPS` says how many proxies to
  trust; never the leftmost `X-Forwarded-For` entry (client-controlled).
- `GatewayConfig`'s `Debug` is hand-written to redact secrets — keep it that way when adding fields.

## Axum architecture

`AppState` is the single shared object (`Arc<AppState>`) threaded through every request handler:
- `cfg: GatewayConfig` — loaded from env vars at startup; immutable for the process lifetime.
- `store: NonceStore` — in-memory or Redis, depending on `REDIS_URL`.
- `limiter: RateLimiter` — `Mutex<HashMap>`, per-address fixed 60s window (post-auth); `ip_limiter` (challenge and public paths) and `preauth_limiter` (gated requests, before verification) are the same limiter keyed by client IP.
- `chain: SuiRpc` — Sui gRPC-web client (`grpc.rs`; public fullnodes deprecated JSON-RPC); optional in-memory ownership cache.
- `http: HttpClient` — shared `hyper` client used by both the proxy and the RPC client.

All routes are dispatched through a single `fallback` handler (`handle`). The router
does not enumerate paths — the handler checks them in order: `/healthz` → `/v1/challenge`
→ public paths → gated paths.

## Nonce store options

**In-memory** (default; `REDIS_URL` unset)
- `Mutex<HashMap<String, Entry>>` — correct at `replicas: 1`.
- Hard entry cap (`NONCE_MAX_ENTRIES`, default 1,000,000): when full, evict the soonest-to-expire
  entry before inserting (audit F3 — bounds memory independent of issue rate).
- Background prune task (`NONCE_PRUNE_INTERVAL_SECS`, default 60s) drops expired entries.
- **Not safe at replicas > 1** — different replicas have independent maps; a nonce issued by
  replica A can be replayed on replica B. Set `REDIS_URL` for scale-out.

**Redis / Dragonfly** (`REDIS_URL` set)
- `GETDEL` is atomic: a nonce is consumed exactly once fleet-wide (no replay across replicas).
- Expiry is the Redis key TTL; no background prune needed.
- Requires Redis ≥ 6.2 or Dragonfly for `GETDEL`. Older Redis needs `GET` + `DEL` (non-atomic —
  upgrade or use Dragonfly).
- `RedisNonceStore::insert` returns an error on a failed write; the challenge endpoint answers
  `503` instead of issuing a nonce that could never verify.
- Redemption release is a Lua compare-and-delete (only a `leased` value is removed), so it can
  never erase a concurrent commit.

## HTTP client

Uses `hyper 1.x + hyper-rustls` directly (not reqwest) to avoid the `url → idna → icu_normalizer`
compile-time dep chain (~10 min on GHA). All URLs are operator-configured ASCII domains —
`hyper::Uri` parses them without IDNA processing.

## Deployment targets

- **Docker:** Dockerfile uses a multi-stage build (builder → distroless). Published to quay.io and Docker Hub
  (signed, with an SBOM attestation) by `docker-publish.yml` on a `v*` tag.
- **Kubernetes:** no manifests live in this repo, and the gateway is not deployed (the paywall runs on
  `gateway-workers/`; audit F32, OQ9). Deploy by image digest with a non-root, read-only-root pod.
- **Bare metal / VM:** `cargo install nft-gate-gateway` or `cargo build --release`.

## Ownership cache

`OWNERSHIP_CACHE_TTL_MS` defaults to `0` (disabled — every gated check is live on-chain).
A small positive value collapses duplicate RPC lookups under load at the cost of a brief
staleness window on NFT transfer/burn. Never applied to single-use consume-event checks (always
live). Use with care on mainnet — a stolen/transferred NFT can still gate during the TTL window.

## Invariants

- `deny` always returns JSON `{"error": reason}`. Do not return plain-text error bodies.
- `extract_proof_token` prefers `Authorization: Bearer` over `X-Access-Proof`. This order is
  canonical — do not flip it without updating both impls and the client.
- The Rust verification logic (`verify.rs`) is a direct port of the Workers `verify.ts`. Any
  behavioural change in one must be reflected in the other; run conformance vectors to verify.
- `decode_access_proof` normalises `consumeDigest` (camelCase from JS) to `consume_digest`
  (snake_case for serde) before deserialising. If the JSON key ever changes on the client side,
  this must change too.

## What NOT to do

- Do not use `tokio::sync::Mutex` where `std::sync::Mutex` suffices — the nonce map and rate
  limiter only hold the lock for in-memory ops (no `.await` inside the critical section).
- Do not add per-path routing in the router — the single `fallback` handler keeps the logic
  co-located and mirrors the Workers structure.
- Do not change the Redis key prefix (`nftgate:nonce:`) without a migration plan — live nonces
  in Redis would be orphaned.
- Do not remove the hard entry cap from the in-memory store — unbounded growth under high issue
  rates is a DoS vector.
