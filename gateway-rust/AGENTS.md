# AGENTS.md — gateway-rust

## Crate

`nft-gate-gateway` — Rust/Axum implementation of the nft-gate gateway.

## Key files

| File | Purpose |
| --- | --- |
| `src/main.rs` | Binary entry point; `AppState`; request dispatcher (`handle`); router |
| `src/config.rs` | `GatewayConfig` struct; `from_env()` loader; `is_public_path()` |
| `src/verify.rs` | `verify_personal_message_signature`; `ChainQuery` trait; `verify_access_request`; `Denied` enum |
| `src/challenge.rs` | `NonceStore` enum (in-memory / Redis); `InMemoryNonceStore`; `RedisNonceStore` |
| `src/proof.rs` | `AccessProof` struct; `decode_access_proof`; `personal_message_for_nonce` |
| `src/proxy.rs` | `forward` — reverse proxy to upstream |
| `src/ratelimit.rs` | `RateLimiter` — per-address fixed 60s window |
| `src/sui_rpc.rs` | `SuiRpc` — `ChainQuery` impl over Sui JSON-RPC |
| `src/http_client.rs` | `HttpClient` — shared hyper/rustls async client |
| `Dockerfile` | Multi-stage Docker build (builder → distroless) |
| `Cargo.toml` | Crate manifest; dependency versions |

## Build and test commands

```bash
cargo build               # debug build
cargo build --release     # release build
cargo test                # all tests (unit + conformance vectors)
cargo test -- --nocapture # with test output
```

## Docker build and run

```bash
cd gateway-rust

# Build image
docker build -t nft-gate-gateway .

# Run (minimum required env vars)
docker run \
  -e UPSTREAM_URL=https://your-relay.example.com \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
  -p 8080:8080 nft-gate-gateway

# With Redis for horizontal scale-out
docker run \
  -e UPSTREAM_URL=https://your-relay.example.com \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
  -e REDIS_URL=redis://dragonfly:6379 \
  -p 8080:8080 nft-gate-gateway
```

## Install from crates.io

```bash
cargo install nft-gate-gateway
UPSTREAM_URL=https://relay.example.com SUI_RPC_URL=https://... NFT_TYPE=0x... nft-gate-gateway
```

## Version

Current: `0.0.1` (Cargo.toml). Bump before publishing to crates.io.

To publish:
```bash
cargo publish --dry-run   # check first
cargo publish
```

## Conformance vectors

Tests in `src/verify.rs` and `src/proof.rs` load `../../conformance/vectors.json` via
`include_str!`. Run `node scripts/sync-vectors.mjs` (the vectors are generated and published by `@meddleware/nft-gate-client`)
(from the `nft-gate` repo root) to regenerate after any wire-format change.

## Relation to gateway-workers

The two implementations are wire-identical: same endpoints, same env var names (where applicable),
same proof format, same Sui RPC call shapes. Any wire-format change must be applied to both and
the conformance vectors regenerated. See `../CLAUDE.md` for the coupling invariants.
