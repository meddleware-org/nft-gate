# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
