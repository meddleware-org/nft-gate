# AGENTS.md — nft-gate

## Repo layout

```
nft-gate/
├── conformance/
│   └── vectors.json            # Shared golden wire-format test vectors (both impls consume this)
├── gateway-workers/            # Cloudflare Workers implementation (TypeScript)
│   ├── src/
│   │   ├── index.ts            # Worker entry point (fetch + scheduled handlers)
│   │   ├── config.ts           # Env binding types + config loading
│   │   ├── verify.ts           # Signature verification + access decision
│   │   ├── chain.ts            # Sui JSON-RPC ChainQuery implementation
│   │   ├── crypto.ts           # Low-level hash + encoding helpers (@noble)
│   │   ├── proxy.ts            # Reverse proxy to upstream
│   │   ├── quota.ts            # Optional free-tier quota guard (cron)
│   │   ├── wire.ts             # Re-exports from @meddleware/nft-gate-client
│   │   └── state/
│   │       ├── types.ts        # NonceBackend interface + helpers
│   │       ├── select.ts       # Backend selection (DO vs KV)
│   │       ├── durable_object.ts  # Durable Object backend (SQLite, default)
│   │       └── kv.ts           # Workers KV backend (fallback)
│   ├── test/                   # vitest unit + cloudflare-integration tests
│   ├── wrangler.toml           # Cloudflare Workers config (edit routes here)
│   └── package.json            # @meddleware/nft-gate-gateway v0.0.2
├── gateway-rust/               # Rust / Axum implementation
│   ├── src/
│   │   ├── main.rs             # Binary entry point + AppState + request dispatcher
│   │   ├── config.rs           # GatewayConfig from env vars
│   │   ├── verify.rs           # Signature verification + ChainQuery trait + access decision
│   │   ├── challenge.rs        # NonceStore (in-memory | Redis)
│   │   ├── proof.rs            # AccessProof wire format + decode
│   │   ├── proxy.rs            # Reverse proxy to upstream
│   │   ├── ratelimit.rs        # Per-address fixed-window rate limiter
│   │   ├── sui_rpc.rs          # SuiRpc ChainQuery implementation
│   │   └── http_client.rs      # Shared hyper/rustls HTTP client
│   ├── Dockerfile
│   └── Cargo.toml              # nft-gate-gateway v0.0.1
└── README.md                   # Top-level quickstart + wire protocol docs
```

## Common tasks

### Run all tests

```bash
# Workers (unit + conformance vectors)
cd gateway-workers && npm test

# Workers (all: unit + cloudflare integration)
cd gateway-workers && npm run test:all

# Rust (unit + conformance vectors)
cd gateway-rust && cargo test
```

### Type-check (Workers)

```bash
cd gateway-workers && npm run type-check
```

### Regenerate conformance vectors

```bash
node scripts/sync-vectors.mjs   # vectors come from @meddleware/nft-gate-client
```

Both test suites will pick up the new vectors automatically.

### Deploy to Cloudflare Workers

```bash
cd gateway-workers && npm run deploy

# Set the required secret after first deploy; NFT_TYPE, GATE_ID and SUI_RPC_URL are wrangler.toml [vars]
wrangler secret put UPSTREAM_URL
```

### Build and run Rust Docker image

```bash
cd gateway-rust
docker build -t nft-gate-gateway .
docker run -e UPSTREAM_URL=http://relay:8080 \
           -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
           -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
           -p 8080:8080 nft-gate-gateway
```

### Build Rust binary locally

```bash
cd gateway-rust && cargo build --release
UPSTREAM_URL=http://relay:8080 SUI_RPC_URL=https://... NFT_TYPE=0x... ./target/release/nft-gate-gateway
```

## Key environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `UPSTREAM_URL` | Yes | — | Base URL of the upstream to protect |
| `SUI_RPC_URL` | Yes | — | Sui JSON-RPC endpoint |
| `NFT_TYPE` | Yes | — | Fully-qualified NFT type to gate on |
| `GATE_ID` | No | — | Restrict to a specific gate object |
| `SINGLE_USE` | No | `false` | Require on-chain single-use consume |
| `PUBLIC_PATHS` | No | `/v1/tip-config` | Comma-separated public paths (no auth) |
| `RATE_LIMIT_PER_MIN` | No | `30` | Per-address request budget per minute |
| `CHALLENGE_TTL_SECS` | No | `300` | Nonce lifetime in seconds |

Workers-only extras: `NONCE_BACKEND`, `NONCE_KV` binding, `NONCE_STATE` binding, `QUOTA_GUARD_ENABLED`.  
Rust-only extras: `REDIS_URL`, `BIND_ADDR`, `MAX_BODY_BYTES`, `NONCE_MAX_ENTRIES`.

## CI

Both implementations have their own GitHub Actions CI:
- `gateway-workers`: type-check + vitest unit tests + Trivy scan on push/PR to `main`
- `gateway-rust`: `cargo test --release` + Trivy Docker scan on push/PR to `main`

The conformance vector tests run as part of the normal test suites in both impls.
