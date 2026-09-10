# CLAUDE.md — nft-gate

## What this repo is

A generic NFT-gated reverse proxy for the `access_gate` on-chain primitive. Any HTTP upstream —
upload relay, website, game API — can be placed behind this gateway to restrict access to holders
of an on-chain Meddleware access NFT. Two wire-identical implementations are provided.

## Architectural invariants

- **Fail closed.** Any ambiguous state (bad signature, missing nonce, chain error) must deny.
  Never grant access on error.
- **Single-use nonce.** Once a nonce passes signature verification, it is consumed immediately —
  before the chain call — so a replay with a valid signature still fails `NonceInvalid`.
- **Address normalization.** Sui addresses are case-insensitive and may lack leading zeros.
  Always normalize with `normalize_address` / `normalizeAddress` before comparing. Both impls
  implement the same rule: lower-case, 0x-prefix, zero-padded to 64 hex digits.
- **multisig / zkLogin fail closed.** Flags 0x03 and 0x05 are recognised but not supported by
  the bundled verifier (requires the official Sui verifier; see gateway audit F1). They always
  return false — the same posture in both impls.
- **Public paths bypass auth.** Configured in `PUBLIC_PATHS` (Workers) / the same env var (Rust).
  The default is `/v1/tip-config` so relay tip-config endpoints are publicly readable.

## Wire protocol coupling

Both implementations MUST produce identical decisions for any given proof token. The coupling is
enforced by the shared `conformance/vectors.json` golden vectors, which both test suites consume.

If you change any of the following, update BOTH implementations and regenerate the vectors:
- The signing message prefix (`nft-gate:access:<nonce>`)
- The proof token format (`base64(JSON { address, nonce, signature, consumeDigest? })`)
- The `Authorization: Bearer` / `X-Access-Proof` header preference logic
- The Sui signature wire format (flag || sig || pubkey)
- Address normalization rules

Regenerate conformance vectors after any wire-format change:
```bash
node gateway-workers/scripts/gen-vectors.mjs > conformance/vectors.json
```

## Conformance vectors (`conformance/vectors.json`)

Covers:
- `personalMessage` — the exact bytes the wallet signs for a given nonce
- `proofDecode` — base64(JSON) proof token → decoded fields
- `signatures[]` — one entry per signature scheme (ed25519, secp256k1, secp256r1) with a real
  Sui personal-message signature and the corresponding proof token

Both `gateway-workers` tests (vitest) and `gateway-rust` tests (`cargo test`) load and verify
`../../conformance/vectors.json`. A test failure here means the two impls have diverged on the
wire format.

## Commission and access-gate economics

The gateway enforces NFT ownership — it does not collect commission directly. Commission (20 bps
per access NFT purchase) is collected on-chain via the `access_gate` Move package's
`PlatformConfig` object. The gateway is the enforcement layer; the `access_gate` Move package
is the economic layer. See [`access-gate-sui`](https://github.com/meddleware-org/access-gate-sui)
for the on-chain side.

## Gateway selection guide

| Use `gateway-workers/` if | Use `gateway-rust/` if |
| --- | --- |
| Zero-infra Wrangler deploy | Docker / k8s / bare metal |
| Cloudflare edge distribution | Redis for horizontal scale-out |
| Already on Cloudflare | Lowest latency on own hardware |

Both are drop-in: same endpoints, same env vars, identical verification decisions.

> **Transport divergence (2026-09):** `gateway-workers/` queries the chain over **gRPC**
> (`@mysten/sui` `SuiGrpcClient`) because public Sui fullnodes deprecated JSON-RPC. `gateway-rust/`
> still uses JSON-RPC and will `502` against a public fullnode until it is migrated to gRPC (see
> Deferred). The client-facing wire contract (routes, proof format, status codes) is unchanged.

## Trust boundaries

The gateway trusts:
- The on-chain Sui state (NFT ownership, consume events) — verified live via RPC
- The client's signature (cryptographically verified against the claimed address)
- The configured Sui RPC endpoint (`SUI_RPC_URL`)

The gateway does NOT trust:
- Any header value the client sends beyond the proof token
- The claimed address in the proof token before signature verification
- The claimed `consumeDigest` before on-chain event verification

## Deferred / post-testnet

- **gateway-rust gRPC migration + redemption:** `gateway-rust/src/sui_rpc.rs` still calls
  deprecated JSON-RPC (`suix_queryEvents`, `sui_getTransactionBlock`, `suix_getOwnedObjects`) and
  will `502` against a public fullnode. `gateway-workers/` was migrated to gRPC (digest-first
  consume verification via `core.getTransaction`) AND to consumeDigest-keyed single-use
  **redemption** (lease→commit-on-success/release-on-failure, so an interrupted upload never burns
  a use — see gateway-workers CLAUDE.md). The Rust gateway must adopt both — gRPC and the
  redemption store (its Redis backend is the natural home for the lease/commit/release) — before it
  can be deployed. Not blocking today — the live paywall runs on the Workers gateway.
- **multisig / zkLogin support (audit F1):** Requires the official Sui verifier. Until then, both
  fail closed with a log warning.
- **Redis horizontal scale-out for Workers (F2):** The KV fallback has an eventual-consistency
  replay window in `SINGLE_USE=false` mode; the Durable Object backend is strongly consistent.
  The Rust gateway uses Redis for fleet-wide replay protection.

## What NOT to do

- Do not move commission logic into the gateway — the on-chain contract handles economics.
- Do not add custom auth flows — the whole point is the wire protocol is canonical.
- Do not skip conformance vector tests when changing signature verification.
- Do not hardcode secrets — all config is env-var / wrangler secrets.
