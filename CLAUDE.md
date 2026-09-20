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

> **Transport (2026-09):** both gateways query the chain over **gRPC** (public Sui fullnodes
> deprecated JSON-RPC). `gateway-workers/` uses `@mysten/sui`'s `SuiGrpcClient`; `gateway-rust/`
> uses a hand-rolled gRPC-web client (`grpc.rs`, no `tonic`/`prost`) to keep its lightweight build.
> Both are digest-first for single-use and implement consumeDigest **redemption** (a consumed use is
> never lost). The client-facing wire contract (routes, proof format, status codes) is unchanged.

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

- **gateway-rust gRPC migration + redemption — DONE (2026-09):** `gateway-rust/` now queries the
  chain over hand-rolled gRPC-web (`grpc.rs`) with digest-first single-use verification and the
  consumeDigest **redemption** store (`NonceStore` lease/commit/release, `main.rs` orchestration),
  at parity with `gateway-workers/`. Validated by `cargo test` + a live testnet check
  (`sui_rpc::tests::live_consume_tx_valid`, `--ignored`). It is buildable/deployable but not
  currently deployed — the live paywall still runs on the Workers gateway.
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

---

## Deferred documentation — NOT for the `docs.` website (planned here per Part 0.4)

> The gateway is inherently developer/operator infrastructure, so most of this repo's docs are
> already `dev.`-scoped. None of it belongs on the user-facing `docs.` site — an end user buying a
> gate pass never sees the gateway. The material below is the `dev.`/self-host outline to formalise
> later; it is largely already captured above (gateway selection, wire protocol, conformance,
> trust boundaries) and should be transcribed rather than rediscovered.

### `dev.` / self-host (to formalise later)

- **Deploy guides** for both impls (Workers via Wrangler; Rust via Docker/k8s + Redis), the shared
  env-var/secrets surface, `PUBLIC_PATHS`, and the gRPC `SUI_RPC_URL` requirement.
- **Wire-protocol spec + conformance vectors** as the canonical integration contract (shared with
  `@meddleware/nft-gate-client`).

### White-label

- Placing an operator's **own upstream** (relay, website, game API) behind the gateway; how gate
  ownership maps to access, with commission fixed on-chain by `access_gate` (never in the gateway).
