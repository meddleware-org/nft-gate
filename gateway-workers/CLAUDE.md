# CLAUDE.md — gateway-workers

## What this package is

The Cloudflare Workers implementation of the nft-gate gateway. Wire-identical to `gateway-rust/`
on the client-facing contract — same routes, status codes, proof format, and env-var config.
Deployed via Wrangler; state backed by Durable Objects (default) or Workers KV (fallback).

## Chain access: gRPC, not JSON-RPC

`src/chain.ts` (`SuiGrpc`) queries Sui over the **gRPC** API via `@mysten/sui`'s `SuiGrpcClient`.
Public Sui fullnodes have **deprecated JSON-RPC** — `suix_queryEvents`, `sui_getTransactionBlock`,
and `suix_getOwnedObjects` now return `-32601 Method not found` — so the previous JSON-RPC
`SuiRpc` returned `502 on-chain verification failed` for every gated request. `SUI_RPC_URL` keeps
the same fullnode URL (`…:443`); only the transport changed.

Single-use verification is **digest-first**: the access proof carries the `access_gate::consume`
transaction digest, so `consumeEventMatches` fetches that exact transaction (`core.getTransaction`,
`include: { events: true }`) and confirms it succeeded and emitted a matching `AccessConsumedEvent`
(sender + nonce + gate). This is precise and needs no event-by-sender scan. Ownership (non
single-use) uses `fetchAccessNfts` from `@meddleware/nft-gate-client` over the same gRPC client.

The gRPC event shape differs from JSON-RPC (`eventType`/`json` vs `type`/`parsedJson`); the pure
helpers in `chain.ts` read both so they tolerate the documented `json`-shape variation. gRPC
`getTransaction` is retried briefly to absorb fullnode indexing lag after the client's finality
wait. **NOTE:** `gateway-rust/` still uses JSON-RPC and must be migrated to gRPC before it can be
deployed against a public fullnode (see the nft-gate CLAUDE.md deferred section).

## Cloudflare Workers constraints

- **No filesystem.** All config comes from env bindings and secrets, never from files.
- **Isolate-scoped state.** Module-level variables (`cached` in `index.ts`) persist across
  requests within the same isolate but are reset on cold start. Do not store mutable state there
  that requires durability — use Durable Objects or KV.
- **No long-running tasks.** `scheduled` handler is for the quota guard cron only; do not put
  request-path logic there.
- **`waitUntil` is available** but not used here — the quota guard runs in the `scheduled` handler,
  not on the request path.

## Secrets pattern

All sensitive config is injected via Wrangler secrets (never hardcoded in source or `wrangler.toml`):

```bash
wrangler secret put UPSTREAM_URL
wrangler secret put SUI_RPC_URL
wrangler secret put NFT_TYPE
wrangler secret put UPSTREAM_AUTH_HEADERS   # optional: CF Access service token
```

Non-sensitive defaults are set in `wrangler.toml` under `[vars]`. Do not put secrets in `[vars]`.

## State machine: Durable Objects vs KV

**Default: Durable Objects** (`NONCE_STATE` binding, `NONCE_BACKEND=durable-object`)
- Region-sharded: each continent shard (`nonce:<region>`) is a separate DO instance placed
  near its users.
- The nonce is embedded with a region tag (`<region>.<hex>`) so a consume call routes back to
  the issuing shard even under anycast drift.
- Single-threaded per DO → `takeIfValid` is atomic (the Redis-GETDEL analog): a nonce is
  consumed exactly once.
- Free-tier eligible (SQLite storage).

**Fallback: Workers KV** (`NONCE_KV` binding, `NONCE_BACKEND=kv`)
- Eventually consistent — `get` then `delete` is NOT atomic. In `SINGLE_USE=false` mode, a nonce
  could momentarily read valid in two regions within its TTL. In `SINGLE_USE=true` mode, the
  on-chain `AccessConsumedEvent` remains the authoritative single-use bind (unaffected).
- Use the DO backend when cross-region replay atomicity matters.

**Quota-degrade flag:** When the DO free-tier usage approaches a limit, the quota guard (cron)
sets a KV key `quota:degrade`. The per-isolate state bootstrap checks this flag once and
may switch to the KV backend for that isolate's lifetime.

## Single-use flow (SINGLE_USE=true)

1. Client calls `GET /v1/challenge` → receives `{ nonce, expiresAt }`.
2. Client signs `nft-gate:access:<nonce>` as a Sui personal message.
3. Client submits an on-chain `access_gate::consume` transaction, capturing the transaction
   digest (`consumeDigest`). It persists the digest locally so a retry/reload reuses the SAME
   consume (re-signing a fresh challenge is free) instead of spending another use.
4. Client sends `Authorization: Bearer base64(JSON { address, nonce, signature, consumeDigest })`
   to the gated endpoint.
5. Gateway: decode proof → verify signature → consume nonce (anti-replay) → `consumeTxValid`
   (`core.getTransaction`: the tx succeeded and emitted an `AccessConsumedEvent` for this
   **sender and gate**) → **lease the `consumeDigest`** → proxy → **commit** on a 2xx upstream
   response, else **release**.

If the client sends a proof without `consumeDigest` in single-use mode, it is denied with
`ConsumeMissing` (not `BadProof`) — a distinguishable misconfiguration signal.

### Redemption: the consumeDigest is the one-time token (a use is never lost)

The consume event is **not** bound to the challenge nonce — the nonce is only for signature
freshness/anti-replay. Single-use is enforced by the **redemption store** (see the state backend)
keying on the permanent on-chain `consumeDigest`:

- `tryLeaseRedemption` claims the digest for an in-flight upload (`ok` / `leased` / `redeemed`).
- On a **successful** upload (`response.ok`) the dispatcher `commitRedemption`s it — spent, and
  retained `REDEMPTION_RETENTION_SECS` (default 30d) to block re-redemption.
- On **failure** it `releaseRedemption`s it, so the same consume is immediately retryable — an
  interrupted upload (reload, tab close, wallet rejection, network blip) never burns a use.
- A `redeemed`/`leased` lease result → `409` (`code: "redeemed"` vs `"leased"`); the client clears
  its stored digest and consumes anew only on `redeemed`.

Security: decoupling from the nonce is safe because the event `sender` must equal the
signature-verified proof address (an attacker can't present someone else's consume; a soulbound NFT
can't be transferred), and each digest is redeemable exactly once. The lease self-expires
(`REDEMPTION_LEASE_TTL_SECS`, default 120s) so a crashed request can't strand a use — the rare cost
is at most one extra upload if a worker dies between upstream success and commit. **Parity note:**
`gateway-rust` does not yet implement redemption (or gRPC); see the nft-gate CLAUDE.md deferred
section.

## Conformance test workflow

```bash
npm run test:unit           # local vitest unit tests (including conformance vectors)
npm run test:integration    # vitest with cloudflare-integration pool (requires wrangler)
npm run test:all            # both
node scripts/gen-vectors.mjs > ../conformance/vectors.json   # regenerate after wire changes
```

Both test projects consume `../../conformance/vectors.json` — changes there automatically
propagate to both Workers and Rust test suites.

## Key dependency versions

- `@cloudflare/workers-types`: pinned closely (~5.x) — Cloudflare updates these frequently
  and breaking changes arrive without semver guarantees. Pin before deploying.
- `@noble/curves` / `@noble/hashes`: same family used by `@mysten/sui` — intentional for
  consistency (same audited primitives, same hash outputs).
- `@meddleware/nft-gate-client`: `wire.ts` re-exports `personalMessageForNonce`,
  `decodeAccessProof`, `AccessProof` directly — no duplication.

## Invariants

- `index.ts` must export `NonceRateState` (the Durable Object class) for Wrangler's DO migration
  to work. Do not rename or split this export.
- `crypto.ts` uses `atob`/`btoa` (present in the Workers runtime, not in Node.js without a
  polyfill). Tests in Node.js context must mock these if needed — unit tests already use the
  cloudflare-integration pool to get the correct runtime.
- Public paths (`isPublicPath`) are exact-string matches, not prefix matches. This is intentional
  — prefix matching would require careful escaping; exact matches are unambiguous.

## What NOT to do

- Do not use `fs`, `child_process`, or any Node.js built-in that is not available in Workers.
- Do not add a build step — the package ships TypeScript source consumed directly by Wrangler.
- Do not store secrets in `wrangler.toml` — use `wrangler secret put`.
- Do not change the nonce format (`<region>.<hex>`) without also changing the shard routing in
  `shardOfNonce` and the Rust gateway's nonce format (and regenerating conformance vectors).
