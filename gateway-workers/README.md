# @meddleware/nft-gate-gateway

[![npm](https://img.shields.io/npm/v/%40meddleware%2Fnft-gate-gateway)](https://www.npmjs.com/package/@meddleware/nft-gate-gateway)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

Cloudflare Workers implementation of the [nft-gate](../README.md) NFT-gated reverse proxy.
Wire-identical to the [Rust gateway](../gateway-rust/): same routes, status codes, proof format,
Sui RPC calls, and env-var names. Deploy it at the same URL the Rust gateway serves and nothing
else changes.

## Prerequisites

| Tool | Minimum version | Install |
| --- | --- | --- |
| Node.js | 22.x | [nodejs.org](https://nodejs.org) |
| npm | 10.x | bundled with Node |
| Wrangler | 4.x | `npm install -g wrangler` |
| Cloudflare account | — | [dash.cloudflare.com](https://dash.cloudflare.com) |

## Getting started

### 1. Get the source

Clone or fork the repo, then work from the `gateway-workers/` directory:

```bash
git clone https://github.com/meddleware-org/nft-gate.git
cd nft-gate/gateway-workers
npm install
```

Alternatively, the package is published to npm for reference:

```bash
npm install @meddleware/nft-gate-gateway
```

### 2. Configure `wrangler.toml`

Edit the `[[routes]]` stanza to bind the Worker to your hostname:

```toml
[[routes]]
pattern = "gate.example.com/*"
zone_name = "example.com"
```

The default `[vars]` block already contains safe defaults for all optional settings. Review
`SUI_RPC_URL` and change it to your preferred Sui fullnode:

| Network | Public fullnode URL |
| --- | --- |
| Mainnet | `https://fullnode.mainnet.sui.io:443` |
| Testnet | `https://fullnode.testnet.sui.io:443` |

### 3. Create the Worker (first deploy)

```bash
npm run deploy
```

Wrangler creates the Worker and the Durable Object namespace in your account. The Worker will
respond to requests immediately but will return errors until the required secrets are set.

### 4. Set required secrets

Run these once from the `gateway-workers/` directory after the Worker exists:

```bash
# The upstream origin the Worker proxies to.
wrangler secret put UPSTREAM_URL
# Value: https://your-relay.example.com

# The on-chain NFT type to check ownership against.
wrangler secret put NFT_TYPE
# Value: 0x<PACKAGE_ID>::access_gate::SoulboundAccessNFT

# CF Access service-token headers to authenticate to your origin (if Access-locked).
# Omit if your upstream is publicly reachable or uses another auth mechanism.
wrangler secret put UPSTREAM_AUTH_HEADERS
# Value (JSON): [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]
```

Secrets are encrypted at rest and never appear in `wrangler.toml` or workflow logs. They survive
`wrangler deploy` — setting them once is sufficient.

### 5. Verify

```bash
curl https://gate.example.com/v1/challenge
# → {"nonce":"...","expiresAt":...}
```

Any gated route without a valid proof token returns `401 Unauthorized`.

## Upstream reachability

The Rust gateway usually runs **inside** your network and reaches a private upstream directly.
This Worker runs at Cloudflare's **edge**, so `UPSTREAM_URL` must be **publicly routable**.

**Recommended pattern**: expose your upstream via a dedicated `cloudflared` public hostname
locked to this Worker via Cloudflare Access, then point `UPSTREAM_URL` at it.

### Locking the origin with a Cloudflare Access service token

1. Cloudflare Zero Trust → Access → Service Tokens → **Create Service Token**.
2. Create an Access **application** for your relay hostname (e.g. `relay.example.com`).
3. Add a policy: allow requests where **Service Token** is the token you just created.
4. Set the Worker secret — both token headers, as a JSON array (a malformed value makes the
   gateway fail closed with `500 gateway misconfigured` until it is fixed):

   ```bash
   wrangler secret put UPSTREAM_AUTH_HEADERS
   # [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]
   ```

5. The Worker injects these headers on every upstream `fetch`. Direct browser or bot traffic to
   the origin gets an Access login page or `403`, depending on the policy fallback.

## State backend

Single-use nonces and per-address rate limits need atomicity that a stateless isolate cannot
provide. Two backends are available:

| Backend | Binding | Consistency | Plan |
| --- | --- | --- | --- |
| `durable-object` (default) | `NONCE_STATE` (auto-created) | Strong — atomic single-use consume | Free tier |
| `kv` | `NONCE_KV` (create manually) | Eventual — weak cross-region replay window in `SINGLE_USE=false` | Free tier |

To use the KV backend, create a namespace and uncomment the binding in `wrangler.toml`:

```bash
wrangler kv namespace create NONCE_KV
# Copy the returned ID into wrangler.toml:
# [[kv_namespaces]]
# binding = "NONCE_KV"
# id = "<returned-id>"
```

Then set `NONCE_BACKEND = "kv"` in `[vars]`.

## Request body limit

`MAX_BODY_BYTES` is enforced twice, without buffering the body:

1. **Declared length.** A `Content-Length` above the cap gets `413 {"error":"request body too large"}`
   before the upstream is contacted.
2. **Streamed bytes.** Every body passes through a byte counter. A body with no declared length
   (`Transfer-Encoding: chunked`) that crosses the cap aborts the upstream request and gets the
   same `413`. Bodies within the cap are forwarded unchanged, still `Content-Length`-framed when the
   client declared one.

The **effective limit is the lower of `MAX_BODY_BYTES` and the zone's Cloudflare plan limit** on
request bodies (Free/Pro 100 MB, Business 200 MB, Enterprise configurable up to 5 GB — see
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/#request-and-response-limits)).
The deployed value, `104857600` (100 MiB), is at the Free/Pro plan limit, so the edge may reject an
oversized upload first — with Cloudflare's own `413`, not the gateway's JSON body. Raising
`MAX_BODY_BYTES` has no effect beyond the plan limit. Keep the relay origin's own cap
(e.g. `nginx.org/client-max-body-size` on its ingress) at least as large, so the gateway, not the origin, is the
binding limit.

The Rust gateway enforces the same cap with the same status codes (see
[`gateway-rust`](../gateway-rust/README.md)).

## Full configuration reference

| Var | Required | Default | Notes |
| --- | --- | --- | --- |
| `UPSTREAM_URL` | ✓ | — | Base URL of the protected upstream (set via `wrangler secret put`) |
| `SUI_RPC_URL` | ✓ | `https://fullnode.testnet.sui.io:443` | Sui fullnode (queried over gRPC-web); change to mainnet for production |
| `NFT_TYPE` | ✓ | — | `<pkg>::access_gate::AccessNFT` or `SoulboundAccessNFT` (set via `wrangler secret put`); any other type — e.g. a fungible `Coin<T>` — is rejected at startup |
| `GATE_ID` | ✓ | — | The gate whose passes are accepted; also read live so a paused gate with `pause_blocks_access` denies holders (`403 the gate is paused`) |
| `SINGLE_USE` | | `false` | Require a `consumeDigest` naming a successful `access_gate::consume` by the proof address on `GATE_ID`; each digest is redeemable once |
| `PUBLIC_PATHS` | | `/v1/tip-config` | Comma-separated paths served without authentication |
| `RATE_LIMIT_PER_MIN` | | `30` | Requests per verified address per 60s window (`0` disables) |
| `MAX_BODY_BYTES` | | `262144` | Request body cap (256 KiB); `wrangler.toml` sets `104857600` (100 MiB) for Walrus uploads. See [Request body limit](#request-body-limit) |
| `CHALLENGE_TTL_SECS` | | `300` | Nonce lifetime in seconds |
| `OWNERSHIP_CACHE_TTL_MS` | | `0` | Ownership-check cache TTL (`0` = live check on every request) |
| `NONCE_BACKEND` | | `durable-object` | `durable-object` or `kv` |
| `NONCE_SHARD` | | `region` | DO shard granularity: `region` (near users) or `global` (one instance) |
| `NONCE_MAX_ENTRIES` | | `1000000` | Hard nonce entry cap per DO shard (evict oldest when reached) |
| `UPSTREAM_AUTH_HEADERS` | | — | JSON array `[{"name":…,"value":…}]` of headers injected on every upstream request (secret); invalid JSON fails closed |
| `CHALLENGE_RATE_LIMIT_PER_MIN` | | `30` | Per-client-IP budget for `GET /v1/challenge` (0 disables) |
| `SUI_RPC_AUTH_HEADER` | | — | `Name: value` header added to Sui RPC calls (secret, for authenticated nodes) |
| `QUOTA_GUARD_ENABLED` | | `false` | Enable the scheduled free-tier quota guard |

Vars listed in `wrangler.toml` are overwritten on every `wrangler deploy`. Values that must
survive deployments (credentials, contract addresses) must be set with `wrangler secret put`.

## Local development

```bash
npm run dev          # wrangler dev — local Worker runtime with DO + KV stubs
npm test             # Vitest in the workerd runtime (tests DO, KV, crypto, routing)
npm run type-check   # tsc --noEmit
```

## Optional: quota guard

Setting `QUOTA_GUARD_ENABLED=true` and adding a cron trigger activates `src/quota.ts`. It reads
your account's Workers usage via the Cloudflare GraphQL Analytics API and logs a warning when
approaching the free-tier request or CPU-time limits. It can set a `quota:degrade` flag in KV to
prefer the lighter KV backend during high-load periods.

Uncomment in `wrangler.toml`:

```toml
[triggers]
crons = ["*/15 * * * *"]
```

Set the required secrets:

```bash
wrangler secret put CF_ANALYTICS_TOKEN   # read-only Analytics API token
wrangler secret put CF_ACCOUNT_ID        # your Cloudflare account ID
```

## Module layout

| Module | Rust analog | Role |
| --- | --- | --- |
| `src/index.ts` | `main.rs` | Request router (challenge / public / gated paths) |
| `src/config.ts` | `config.rs` | `env` → typed config (same var names as Rust) |
| `src/wire.ts` | `proof.rs` | Proof helpers reused from `@meddleware/nft-gate-client` |
| `src/verify.ts` | `verify.rs` | Signature verification + allow/deny decision |
| `src/chain.ts` | `sui_rpc.rs` | Sui gRPC ownership and consume-event queries |
| `src/proxy.ts` | `proxy.rs` | Body-capped reverse proxy; strips `Host`/`Authorization` |
| `src/state/` | `challenge.rs` + `ratelimit.rs` | Pluggable nonce store and rate limiter |
| `src/quota.ts` | — | Optional free-tier quota guard (scheduled cron) |
