# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.22] - 2026-10-10

Released with the Workers gateway 0.0.22 (one version for every artifact); parity fixes from the
2026-10-09 audit. Still undeployed.

### Fixed

- Ownership mode reads every page of the owner's `ListOwnedObjects` list (up to `MAX_OWNED_PAGES` =
  100 pages of 50, like the Workers gateway), stopping at the first usable pass; a longer list is a
  chain error (502, denied) and the whole check shares one `RPC_TIMEOUT_SECS` deadline (F17).
- Single-use verification requires the consume transaction's effects status to be success
  (`effects.status` is read and checked), as the Workers gateway does, instead of inferring it from the
  presence of events (F21).
- `REDEMPTION_LEASE_TTL_SECS` must exceed `UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS` (the lease is
  held while the body is read and uploaded); the startup check used the upstream deadline alone (F46).

### Security

- The startup log no longer prints `UPSTREAM_URL`, and `GatewayConfig`'s `Debug` redacts the upstream and
  RPC URLs; `UPSTREAM_URL` and `SUI_RPC_URL` carrying credentials (userinfo) are refused at startup, as
  on the Workers gateway (F26).

### Added

- Tests: router-level tests against a scripted local Sui node and a recording upstream (coded `409`
  redeemed/leased, `503` store errors, `502` chain error and lost lease, `403` failed or foreign consume,
  `413`/`408`/`504`, redirects, path policy; F47); hermetic gRPC-web fixtures pinning the field numbers
  of `GetTransaction`, `GetObject` and paged `ListOwnedObjects` (F45); the optional live checks take a
  fresh consume from `NFT_GATE_LIVE_*` instead of a fixed, prunable digest.
- The image ships `Cargo.lock` (so its SBOM lists the compiled crates), `.dockerignore` also excludes
  `.env*`, key files and `docs/`, and the publish workflow scans the merged image with Trivy before it
  is signed (F29).
- Dev-dependency `futures-util` (already in the graph via axum) for streamed test bodies.

## [0.0.21] - 2026-10-08

### Fixed

- No change: released with the Workers gateway 0.0.21.

## [0.0.20] - 2026-10-08

### Changed

- No change: released with the Workers gateway 0.0.20 (one version for every artifact).

## [0.0.19] - 2026-10-08

Parity with `gateway-workers` 0.0.19 (one version for every artifact). Still undeployed.

### Changed (breaking: protocol v2, configuration)

- Audience-bound proofs (`nft-gate:access:v2`; new required `GATEWAY_ORIGIN` and `NETWORK`), the
  strict token grammar, owner-bound redemption leases (Redis Lua compare-and-set), `SINGLE_USE`
  requiring `REDIS_URL` (or `ALLOW_VOLATILE_REDEMPTIONS`), store errors as `503`, `409` conflicts with
  `code`, consume age bound, usable-pass ownership, strict gate JSON, not-found-only retries with
  digest validation, strict configuration, the same header/redirect/method/path policy, a per-IP
  budget before verification, IPv6 /64 keys, a bounded ownership cache, Bearer parsing like the
  Workers gateway (any case, any whitespace). `UPSTREAM_TIMEOUT_SECS` defaults to 600 (`504`) and
  `REDEMPTION_LEASE_TTL_SECS` to 900; Sui RPC calls have `RPC_TIMEOUT_SECS`.
- Connection limits: a header read timeout, a body read timeout, `MAX_CONNECTIONS`, and a bounded
  graceful shutdown (`SHUTDOWN_GRACE_SECS`), via a hyper accept loop in place of `axum::serve`.
- Scoped to small-body upstreams (bodies are buffered); see the README.

## [0.0.17] - 2026-10-02

### Added

- CORS with an origin allowlist (`ALLOWED_ORIGINS`), matching the Workers gateway: the request
  `Origin` is reflected only on an exact match, every response (errors included) carries the
  grants and `Vary: Origin`, and a preflight is answered before rate limits and auth. Unset → no
  browser origin is granted.

### Fixed

- Redis connection attempts and commands time out after 5 s (`ConnectionManagerConfig`), so a
  store that accepts connections but stops answering fails requests closed instead of holding them.
- The `CHALLENGE_RATE_LIMIT_PER_MIN` doc described the old `X-Forwarded-For`-first keying; it now
  matches the code (TCP peer, or the hop added by the outermost trusted proxy).

## [0.0.16] - 2026-10-02

### Changed

- No crate changes: released with the Workers gateway 0.0.16 (one version for every artifact).

## [0.0.15] - 2026-10-02

### Security

- `decode_access_proof` matches the client and the Workers gateway: a token longer than 4096
  characters is rejected before decoding, and a non-ASCII `address`, `nonce` or `signature` is
  rejected. Both gateways assert the new shared `proofDecodeRejects` conformance vectors.

## [0.0.14] - 2026-10-02

### Changed

- The live consume test (`live_consume_tx_valid`) targets the version-gated testnet `access_gate`
  `0xa55789…6d41`, the hosted relay gate `0xfd6c3b2a…b8a6` and a consume on it. Operators of this
  gateway set `NFT_TYPE` and `GATE_ID` for their own gate; passes of the superseded `0x1a81ca…`
  package only match a gateway still configured for it.

## [0.0.13] - 2026-10-01

Versions are aligned from this release: the crate, the npm package and the image share one version
(the crate jumps from 0.0.5).

### Security

- Single-use: the consume event must be exactly `<NFT_TYPE package>::access_gate::AccessConsumedEvent`
  (previously any `…::access_gate::AccessConsumedEvent` suffix, which a look-alike package could
  emit). Sender and gate ids are compared in normalised form.
- secp256r1 high-S signatures are rejected (`p256` does not enforce low-S); secp256k1 checks it
  explicitly. ed25519 verification is ZIP-215 (`ed25519-consensus`), matching Sui.
- The client IP for pre-auth rate limits is the TCP peer unless `TRUSTED_PROXY_HOPS` is set
  (a spoofed `X-Forwarded-For` no longer selects the bucket).
- `#![forbid(unsafe_code)]`; release builds keep overflow checks and abort on panic.

### Added

- `MAX_CONCURRENT_REQUESTS` (default 64) with load shedding (`503 gateway overloaded`).
- `UPSTREAM_AUTH_HEADERS` (JSON) and `SUI_RPC_AUTH_HEADER`, at parity with `gateway-workers`.
- `UPSTREAM_TIMEOUT_SECS`, `MAX_RESPONSE_BYTES`, `ALLOW_INSECURE_HTTP`, `TRUSTED_PROXY_HOPS`.
- Connect/request timeouts and response caps on every outbound call; SIGTERM handling.
- Negative + ZIP-215 conformance vectors; property tests for the protobuf/gRPC-web readers; an
  ignored Redis/Dragonfly round-trip test (`redis_backend_round_trip`).
- `deny.toml` (cargo-deny in CI), an MSRV job, crates.io trusted publishing, SBOM attestation.

### Changed

- gRPC-web: a response without a `grpc-status` (header or trailer), with a truncated or compressed
  frame, or with a message over 4 MiB is an error; `GetTransaction` is retried 4× at 500 ms, then
  reported as a chain error (`502`), like the Workers gateway.
- A failed Redis nonce write returns `503`; Redis connect retries with backoff.
- `GatewayConfig`'s `Debug` output redacts the Redis URL and header values.

## [0.0.3] - 2026-08-29

### Changed

- Version aligned with `@meddleware/nft-gate-gateway-workers` npm package (`0.0.3`); no functional changes.

## [0.0.2] - 2026-08-29

### Added

- Inline rustdoc documentation on `challenge.rs` public API surface.
- `AGENTS.md` and `CLAUDE.md` developer documentation for `gateway-rust`.

## [0.0.1] - 2026-08-27

### Added

- Initial release: generic NFT-gated reverse proxy (Rust / Axum / Tokio)
- `GET /v1/challenge` — issues time-bound nonces (in-memory store; optional Redis for scale-out)
- Proof verification: ed25519, secp256k1, secp256r1 Sui personal-message signatures
- On-chain ownership check via Sui JSON-RPC (`getOwnedObjects`)
- Single-use mode: binds nonce to on-chain `AccessConsumedEvent`
- Per-address rate limiting + configurable body cap
- Public-path passthrough (e.g. `/v1/tip-config`)
- Configurable via environment variables (parity with the Cloudflare Workers sibling)
- Distroless multi-stage Dockerfile (`gcr.io/distroless/cc-debian12:nonroot`)
- Shared conformance vectors with `gateway-workers` (`conformance/vectors.json`)
