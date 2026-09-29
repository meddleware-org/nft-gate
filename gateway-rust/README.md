# nft-gate-gateway

[![Crates.io](https://img.shields.io/crates/v/nft-gate-gateway)](https://crates.io/crates/nft-gate-gateway)
[![Docker Hub](https://img.shields.io/docker/v/meddleware/nft-gate-gateway?label=Docker%20Hub)](https://hub.docker.com/r/meddleware/nft-gate-gateway)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

A high-performance, generic **NFT-gated reverse proxy** (Rust / Axum / Tokio). Put it in front of
any HTTP upstream to restrict access to holders of an
[`access_gate`](https://github.com/meddleware-org/vault/tree/main/blockchain/sui/contracts/access-gate)
NFT — an upload relay, a website, a game API, anything.

Wire-identical to the [Cloudflare Workers gateway](../gateway-workers/): same routes, status codes,
proof format, Sui RPC calls, and env-var names. Switch between implementations transparently.

## Prerequisites

| Tool | Notes |
| --- | --- |
| Rust stable (≥ 1.82) | [rustup.rs](https://rustup.rs) — `rustup update stable` |
| Cargo | bundled with Rust |
| Docker (optional) | for the container deployment path |

## Getting started

### Option A — Docker (recommended for production)

```bash
docker pull meddleware/nft-gate-gateway:latest

docker run \
  -e UPSTREAM_URL=http://your-relay:8080 \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<PACKAGE_ID>::access_gate::AccessNFT \
  -e GATE_ID=0x<GATE_ID> \
  -p 8080:8080 \
  meddleware/nft-gate-gateway
```

For horizontal scale-out, add `REDIS_URL` pointing to a Redis or Dragonfly instance so
single-use nonce consumption is fleet-wide atomic:

```bash
docker run \
  -e UPSTREAM_URL=http://your-relay:8080 \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<PACKAGE_ID>::access_gate::AccessNFT \
  -e GATE_ID=0x<GATE_ID> \
  -e REDIS_URL=redis://redis:6379 \
  -p 8080:8080 \
  meddleware/nft-gate-gateway
```

### Option B — From crates.io

```bash
cargo install nft-gate-gateway

UPSTREAM_URL=http://your-relay:8080 \
SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
NFT_TYPE=0x<PACKAGE_ID>::access_gate::AccessNFT \
GATE_ID=0x<GATE_ID> \
nft-gate-gateway
```

### Option C — Build from source

```bash
git clone https://github.com/meddleware-org/nft-gate.git
cd nft-gate/gateway-rust
cargo build --release

UPSTREAM_URL=http://your-relay:8080 \
SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
NFT_TYPE=0x<PACKAGE_ID>::access_gate::AccessNFT \
GATE_ID=0x<GATE_ID> \
./target/release/nft-gate-gateway
```

### Verify

```bash
curl http://localhost:8080/v1/challenge
# → {"nonce":"...","expiresAt":...}
```

Any gated route without a valid proof token returns `401 Unauthorized`.

## Configuration (environment variables)

| Var | Required | Default | Meaning |
| --- | --- | --- | --- |
| `UPSTREAM_URL` | ✓ | — | Base URL of the protected upstream |
| `SUI_RPC_URL` | ✓ | — | Sui fullnode (queried over gRPC-web) for ownership and event queries |
| `NFT_TYPE` | ✓ | — | `<pkg>::access_gate::AccessNFT` (or the soulbound type); any other type — e.g. a fungible `Coin<T>` — is rejected at startup |
| `GATE_ID` | ✓ | — | The gate whose passes are accepted; also read live so a paused gate with `pause_blocks_access` denies holders (`403 the gate is paused`) |
| `SINGLE_USE` | | `false` | Require an on-chain `AccessConsumedEvent` bound to the nonce |
| `PUBLIC_PATHS` | | `/v1/tip-config` | Comma-separated paths served without authentication |
| `CHALLENGE_TTL_SECS` | | `300` | Nonce lifetime in seconds |
| `RATE_LIMIT_PER_MIN` | | `30` | Per-address request budget per 60s window (`0` disables) |
| `MAX_BODY_BYTES` | | `262144` | Request body cap (256 KiB); see [Request body limit](#request-body-limit) |
| `BIND_ADDR` | | `0.0.0.0:8080` | TCP listen address |
| `REDIS_URL` | | — | Redis/Dragonfly URL for a shared nonce store (required for `replicas > 1`) |
| `NONCE_MAX_ENTRIES` | | `1000000` | Hard cap on in-memory nonce entries (evict oldest when reached) |
| `NONCE_PRUNE_INTERVAL_SECS` | | `60` | Background prune cadence for the in-memory store |
| `OWNERSHIP_CACHE_TTL_MS` | | `0` | Ownership-check cache TTL (`0` = live check on every request) |

**Sui RPC URLs:**

| Network | Public fullnode |
| --- | --- |
| Mainnet | `https://fullnode.mainnet.sui.io:443` |
| Testnet | `https://fullnode.testnet.sui.io:443` |

For production, use an operator-run fullnode or a dedicated RPC provider rather than a public
fullnode, to avoid rate limits and avoid leaking access patterns.

## Request body limit

Same contract as `gateway-workers`: a declared `Content-Length` over `MAX_BODY_BYTES` gets
`413 {"error":"request body too large"}` before any byte is read, and a body without a declared
length (chunked) is read only up to the cap, then gets the same `413`. Upstream failures are `502`.

**Memory.** Unlike the Workers gateway, this one buffers: the request body is collected in full
before it is forwarded, and the upstream response is collected before it is returned. Per in-flight
gated request, expect about `MAX_BODY_BYTES` (transiently up to ~2× while a multi-chunk body is
joined into one buffer) plus the response size. There is no concurrency cap, so peak memory scales
with concurrent uploads — at the 100 MiB value used in front of the Walrus relay, 10 simultaneous
maximum uploads need roughly 1–2 GiB. Size the container's memory limit (and `MAX_BODY_BYTES`)
for the concurrency you expect.

**Follow-up (not implemented):** stream both directions — pass the request body to the hyper
client as a length-limited stream (`http_body_util::Limited`) instead of `to_bytes`, and return the
upstream `Incoming` body directly — so memory stays at one chunk per request regardless of size.
Until then, a `tower::limit::ConcurrencyLimitLayer` on the gated route is the cheap way to bound
peak memory.

## Signature scheme support

| Scheme | Flag | Status |
| --- | --- | --- |
| ed25519 | `0x00` | Verified |
| secp256k1 | `0x01` | Verified |
| secp256r1 | `0x02` | Verified |
| Multisig | `0x03` | Recognised, fails closed (not yet supported) |
| zkLogin | `0x05` | Recognised, fails closed (not yet supported) |

All three verified schemes cover every current Sui browser and hardware wallet keypair.

## Scaling and liveness

**Single replica** — in-memory nonce store; correct at one instance. This is the default and
sufficient for most deployments.

**Multiple replicas** — set `REDIS_URL` to a Redis or Dragonfly instance. The nonce store
becomes shared and fleet-wide; `GETDEL` ensures atomic single-use consumption.

**Ownership cache** — `OWNERSHIP_CACHE_TTL_MS=0` (default) performs a live Sui RPC check on
every gated request. Set a small value (e.g. `2000`) only to collapse burst duplicate lookups,
accepting that brief window of staleness. The cache is never applied to single-use consume checks.

## Build and test

```bash
cargo fmt --check                  # format check
cargo clippy -- -D warnings        # lint
cargo test                         # unit tests (crypto, decision matrix, nonce store, rate limit)
cargo build --release              # production binary
```

## Docker

```bash
# Build locally
docker build -t nft-gate-gateway .

# Multi-arch (for CI or arm64 hosts)
docker buildx build --platform linux/amd64,linux/arm64 -t nft-gate-gateway .
```

The image uses a distroless runtime (`gcr.io/distroless/cc-debian12:nonroot`). Pin base images
by digest in production to prevent supply-chain drift.
