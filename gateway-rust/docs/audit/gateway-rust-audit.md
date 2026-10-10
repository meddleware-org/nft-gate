# nft-gate — `gateway-rust` Security Audit

**Classification:** Internal security review
**Project:** nft-gate/gateway-rust  (Rust/Axum reverse proxy that admits only holders of an on-chain
  `access_gate` pass, verified by a Sui personal-message signature and a live gRPC-web chain read;
  wire-identical sibling of `gateway-workers`)
**Project type:** Rust service (+ container image + crates.io crate)
**Template:** AUDIT_TEMPLATE.md (2026-10-08) + AUDIT_TEMPLATE_RUST.md (2026-10-08) +
  AUDIT_TEMPLATE_SUI_CLIENT.md (2026-10-08) + AUDIT_TEMPLATE_WALRUS.md (2026-09-30) +
  AUDIT_TEMPLATE_IMG.md (2026-10-08) + AUDIT_TEMPLATE_AUTH.md (2026-10-08) +
  AUDIT_TEMPLATE_PROXY.md (2026-10-08)
**Deployment status:**

- **Not deployed**, by decision: `gateway-rust` is kept at wire and behaviour parity with the live
  Workers gateway but is scoped to small-body upstreams (bodies are buffered, README "Scope"), so the
  paywall runs on `gateway-workers` only (root `CLAUDE.md`). No overlay, manifest or
  `config/images.yaml` entry exists.
- 0.0.22 (committed locally 2026-10-10, not yet tagged or published) carries the fixes recorded below: F17, F21,
  F26, F28, F29 (CI and Docker parts), F45, F46, F47; both gateways move together (D16).
- Crate `nft-gate-gateway` **0.0.21** on crates.io (published 2026-10-08T08:19Z; 0.0.18–0.0.21 since
  the first pass; trusted publishing, run of tag `v0.0.21` succeeded).
- Image `quay.io/meddleware-org/nft-gate-gateway:0.0.21` (multi-arch index
  `sha256:f7d627eb5a12cb6ae72c8804ddf7b6e6396ca87cbffa80f3af7d00b0138e9281`, pushed 2026-10-08T08:22Z by
  `docker-publish.yml`, run succeeded). The quay repository was read on 2026-10-10 through its public
  API (the first pass could not reach the registries). Signature, SBOM and provenance were **not**
  re-verified here (no `cosign` in the review environment; no verification command is published, F29).
- `main` carries commits after the `v0.0.21` tag (Dependabot merges of 2026-10-09: distroless base
  digest, cargo minor/patch group, `ed25519-dalek` 3.0.0 (dev-dependency), `blake2` 0.11.0, and the
  Actions group); they are in no published crate or image.
- Consumes the testnet `access_gate` `0xd7ddaa94…388c9` and relay gate `0x316f1bf9…faddc` (2026-10-09
  publication) **only through operator env**; the superseded `0xa55789…` / `0xfd6c3b…` appear only in
  the env-gated live test (F45, B.SC-1).

**Review date:** 2026-10-03 (re-verified 2026-10-09; fix wave 2026-10-10)
**Reviewer:** Internal review
**Severity ceiling:** High — a verification bypass would admit unpaid traffic to the protected
  upstream, and a redemption-store failure would let one paid single-use consume buy unlimited
  uploads. The gateway holds no user funds and signs nothing on-chain, so nothing here reaches
  Critical.
**Status:** fix wave 2026-10-10 (0.0.22, commit `40a7e89`) — 40 findings dispositioned (24 RESOLVED,
  3 MITIGATED, 6 ADJUDICATED, 4 ACCEPTED-RISK, 3 DEFERRED) plus 8 Positive; re-verified 2026-10-09, F42–F48
  added in that pass

**Toolchain:** `rust-version = "1.88"` (Cargo.toml; MSRV job in `rust-ci.yml`) — no
  `rust-toolchain.toml`   **Edition:** 2021
**Crates published:** yes — `nft-gate-gateway` on crates.io via trusted publishing
  (`crates-publish.yml`, `rust-lang/crates-io-auth-action`)
**Runtime:** tokio multi-thread (`rt-multi-thread`, `macros`, `net`, `signal`, `sync`, `time`); the
  server is a hyper HTTP/1 accept loop (`serve` in `main.rs`) with a `TokioTimer`

**Sui SDK:** none — hand-rolled gRPC-web + protobuf client (`src/grpc.rs`, `src/sui_rpc.rs`); crypto
  via `ed25519-consensus` 2.1.0, `k256` 0.13.4, `p256` 0.13.2 (the 0.14 major was declined on
  2026-10-09), `blake2` 0.11.0 on `main` (0.10.6 in the tagged 0.0.21)
**Transport:** gRPC-web (`application/grpc-web+proto`, HTTP/1.1) — no JSON-RPC
**Networks:** any — the network is `NETWORK` (signed into every proof) plus `SUI_RPC_URL` + `NFT_TYPE`
  + `GATE_ID` (operator env)
**On-chain packages consumed:** `access_gate` — type filter (`NFT_TYPE`) and event filter
  (`<NFT_TYPE package>::access_gate::AccessConsumedEvent`) both take the package prefix of
  `NFT_TYPE`, i.e. the **original-id**; no call targets (the gateway never builds a PTB). Sourced from
  operator env (`NFT_TYPE`, `GATE_ID`); the only in-repo values are the live-test fixtures in
  `src/sui_rpc.rs` (`live_consume_tx_valid`, lines 656-702), which deliberately still name the
  **superseded** `0xa55789…` package and `0xfd6c3b…` gate: both are immutable (upgrade caps burned
  2026-10-09) and the test replays a fixed historic consume (F45).

**Upstreams:** one, `UPSTREAM_URL` (env, `https://` unless `ALLOW_INSECURE_HTTP=1`; refused when its
  origin equals `GATEWAY_ORIGIN`); locked to this hop by whatever the operator configures at the
  upstream (an Access service token injected from `UPSTREAM_AUTH_HEADERS`, or a network policy) —
  nothing in this repo verifies the lock (F32, OQ9)
**Public paths:** `PUBLIC_PATHS` (default `/v1/tip-config`), `GET`/`HEAD` only (else 405 + `Allow`),
  rate-limited per client IP, never cached
**Body cap / timeouts:** `MAX_BODY_BYTES` 262,144 B (declared length pre-check, then a capped
  buffered read); header read 10 s, body read 30 s (408), `MAX_CONNECTIONS` 1,024, upstream total
  deadline 600 s (504), Sui RPC 15 s per call, shutdown grace 30 s
**Trusted forwarding hops:** `TRUSTED_PROXY_HOPS` (default 0 = the TCP peer); with N > 0 the Nth
  `X-Forwarded-For` entry from the right; IPv6 keyed by /64

**Walrus SDK:** none — the gateway fronts an upload relay; it never stores or reads blobs
**Package config source:** n/a   **Upload relays:** whatever `UPSTREAM_URL` names (operator relay)
**Aggregator / publisher hosts:** n/a   **Tip ceiling:** n/a (client-side; relay-enforced)
**Epoch default / maximum:** n/a   **Deletable default:** n/a

**Images:** `quay.io/meddleware-org/nft-gate-gateway:<semver>` (0.0.21 =
  `@sha256:f7d627eb…9281`, read 2026-10-10) and `docker.io/<DOCKERHUB_NAMESPACE>/nft-gate-gateway:<semver>`
  (multi-arch index, signed at the index digest by the workflow; not re-verified here); best-effort
  `<PRIVATE_REGISTRY>/<PRIVATE_NAMESPACE>/nft-gate-gateway:<sha>-<arch>` (unsigned)
**Base images:** build `rust:1-slim@sha256:4cd82946…71ab7`; runtime
  `gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d…f1c2` on `main` (Dependabot `5c34762`, 2026-10-09;
  the 0.0.21 image was built on `sha256:54df941e…3f97`)
**Runtime user:** `nonroot:nonroot` (distroless, uid 65532)   **Runtime FS:** no writable path needed
  (in-memory or Redis state); read-only root FS is a manifest setting — manifests are not in this repo
**Deployed by:** not deployed; no overlay or `config/images.yaml` entry exists
**Build args:** none

**Auth role(s):** holder and injector of operator credentials for the upstream (`UPSTREAM_AUTH_HEADERS`,
  e.g. a Cloudflare Access service token) and the RPC (`SUI_RPC_AUTH_HEADER`); credential-injecting
  proxy. Sui wallet proofs are out of the AUTH lens (Sui client lens home).
**Identity provider:** none (Cloudflare Access is the upstream's lock, not an IdP the gateway talks to)
**Token formats:** inbound: nft-gate access proof v2 (base64 JSON + Sui signature over an
  audience-bound message, F1); outbound: static headers
**Signing / client credentials:** `UPSTREAM_AUTH_HEADERS`, `SUI_RPC_AUTH_HEADER`, `REDIS_URL`
  (may embed a password) — env at runtime; none is held today (undeployed); rotation cadence to be
  recorded at deployment (F31)
**Authorization model:** static — possession of a pass of `NFT_TYPE` for `GATE_ID` (ownership mode) or
  a successful on-chain consume for it (single-use mode)

---

## Executive summary

`gateway-rust` is a ~5.6 kLOC Axum/hyper service (11 modules, `#![forbid(unsafe_code)]`) that sits in
front of an HTTP upstream and admits a request only when it carries a valid nft-gate access proof: a
Sui personal-message signature over the audience-bound `nft-gate:access:v2` message (this gateway's
origin, the gate, the network, a gateway-issued nonce and, in single-use mode, the consume digest),
plus either live ownership of a usable `access_gate` pass for the configured gate (ownership mode) or
the digest of a successful, recent on-chain `access_gate::consume` by the signer (single-use mode). In
single-use mode the consume digest is the one-time redemption token, leased under a random owner token
before proxying and committed on a 2xx. It is kept at parity with the live Workers gateway but is
**not deployed**, by decision: bodies are buffered, so it is scoped to small-body upstreams and the
Walrus relay paywall stays on `gateway-workers` (F6).

The first pass (2026-10-03) recorded 41 findings, all open by maintainer instruction. Between
2026-10-02 and 2026-10-08 they were fixed in the 0.0.17–0.0.21 releases (`6a601d3`, 0.0.19, is the main
wave, shared with the Workers gateway) and re-verified here against the code, tests, CHANGELOG and
`git log` (local checkout `367e673`; `origin/main` is `85b18e1`, one Dependabot commit later that
changes only `Cargo.toml`/`Cargo.lock`).

**What was fixed (all re-verified in code; tests cited per finding).**

1. **Audience binding** (F1): protocol v2 binds origin, gate, network, nonce and consume digest; v1 is
   refused; `GATEWAY_ORIGIN` and `NETWORK` are required; the shared vectors (published by
   `@meddleware/nft-gate-client`) carry a negative per bound field and pass in this suite.
2. **Single-use cannot weaken** (F2, F3, F4, F24): lease, commit and release are compare-and-set on a
   random owner token (Lua in Redis); the lease (900 s) is checked at startup to outlive the upstream
   deadline (600 s); `SINGLE_USE=true` is refused without `REDIS_URL` unless
   `ALLOW_VOLATILE_REDEMPTIONS=true`; a store error is `503` and never a conflict; `redeemed`/`leased`
   are coded `409`s; a consume older than five days is refused.
3. **Availability** (F5, F9, F19): a header-read timeout, a body-read timeout, a connection cap, a
   per-IP budget before signature verification and a bounded graceful shutdown, via a hyper accept loop.
4. **Proxy hygiene** (F12, F13, F42): method and path allowlists, hop-by-hop and `Connection`-named
   fields, cookies, spoofable forwarding fields and `cf-access-*` stripped inbound; hop-by-hop,
   cookies and every upstream CORS field stripped outbound; redirects never followed (a 3xx is `502`).
5. **Strict configuration and parsing** (F8, F14–F16, F18): a typo is a startup error, not a weaker
   mode; unrecognised gate JSON denies; `GetTransaction` retries only not-found; Bearer parsing matches
   the Workers gateway; the ownership cache is bounded.
6. **Ownership mode** (F7): counts only usable passes (unlimited, or single-use with uses left).

**What remains.** Nothing at Medium. The open items are Low/Info and concentrate in three groups, none
of which touches the live Workers deployment:

- *Accepted* (ACCEPTED-RISK): no `Via` loop marker, left open for parity with the Workers gateway (F43);
  the in-memory store's O(n) work and cap-eviction (F11, F34).
- *Supply chain and image*: the CI and Docker work is done in 0.0.22 (`--locked`, a coverage figure,
  the Redis round trip in CI, a Trivy image scan before signing, a lockfile in the image for the SBOM, a
  complete `.dockerignore`, a published `cosign verify` command; F28, F29). What remains is the
  unsigned private mirror and licence notices (F29, OQ8) and the registry credential inventory (F30,
  `OPERATOR_TASKS.md`).
- *Deployment* (DEFERRED, tied to OQ9, the decision to deploy): runtime credential rotation (F31) and
  manifests, pod security, limits and the origin-lock check (F32).

**Fix wave of 2026-10-10 (0.0.22).** The parity and pre-deployment gaps are closed: ownership reads every
page up to a bound (F17), single-use success is decided from the effects status (F21), the upstream
origin is never logged and URL credentials are refused (F26), the lease outlives the body-read and
upstream deadlines together (F46), and router-level tests pin the status and conflict mapping (F47). The
env-gated live test that failed on a pruned fixed transaction (F45) is replaced by hermetic wire-format
fixtures plus optional live checks that take a fresh consume from the environment; both live checks
passed against testnet on 2026-10-10.

**Verified strengths.** The cryptographic core is sound and pinned by shared vectors that include
negatives (high-S on both curves, a non-canonical ed25519 `s`, wrong intent, truncated input, flags
0x03/0x05/0x06, a ZIP-215 small-order vector and the audience-mismatch cases). Other strengths:

- the hand-rolled gRPC-web decoder is bounded and property-tested;
- every outbound call has a timeout and a response cap, and every inbound read is time-bounded;
- Redis operations are atomic and fail closed;
- the client-IP rule refuses client-chosen `X-Forwarded-For` entries and keys IPv6 by /64;
- the configuration `Debug` output is redacted and the configuration is strict;
- the CI and release chain is pinned and signed (cosign keyless at the index digest, SBOM and
  provenance attestations, crates.io OIDC), and the release job runs the same workflow as CI.

**Posture.** A hardened, parity-complete gateway for small-body upstreams that is deliberately not
deployed. Before it fronts anything, close the remaining pre-deployment gates in Section D (F31, F32) and
decide OQ9. No open finding is above Low; the Medium findings of the first pass
(F1–F5, F7) are resolved.

---

## Threat model / trust boundaries

**Primary trust anchor:** Sui chain state (pass ownership, the `AccessConsumedEvent` of a successful
`consume`), as reported by the operator-configured fullnode (`SUI_RPC_URL`), and the Sui signature
scheme that binds a proof to an address.

| Actor / authority | Holds / proves | Can do | Bounded by |
| --- | --- | --- | --- |
| End user (pass holder) | wallet key; an `access_gate` pass; consume digests | sign proofs; call gated paths | nonce single-use; per-address and per-IP limits; owner-bound redemption store |
| Network client (anyone) | request line, headers (incl. `X-Forwarded-For`), body, timing | hit `/v1/challenge`, public paths, gated paths with garbage | per-IP limits (challenge, public, gated pre-auth — F9); body cap; concurrency and connection caps; header-read and body-read timeouts (F5) |
| Phishing site / malicious dApp | the ability to show a victim a sign request | obtain a valid proof for a real gateway's nonce | audience-bound v2 message (F1): a proof for another origin, gate, network or consume is refused here |
| Sui fullnode (`SUI_RPC_URL`) | chain reads | lie about ownership/events, or withhold them | trusted (operator-chosen); fail closed on error; 4 MiB / `RPC_TIMEOUT_SECS` bounds |
| Upstream (relay) | responses | large/slow responses; redirects; arbitrary response headers | 16 MiB cap, `UPSTREAM_TIMEOUT_SECS` (504); redirects never followed; response headers filtered (F12, F13); error bodies pass through by decision (F44) |
| Shared store (Redis/Dragonfly) | nonce + redemption state | lose/expire state; be unavailable | atomic ops; fail closed (503) at request time; startup retries then exit; required for `SINGLE_USE` (F4) |
| Ingress / proxy in front | which `X-Forwarded-For` hop is trustworthy | collapse all clients into one IP if mis-set | `TRUSTED_PROXY_HOPS` (manifest not in repo — F32) |
| Operator (env) | `UPSTREAM_URL`, `NFT_TYPE`, `GATE_ID`, `SINGLE_USE`, secrets | choose what is gated and how | strict startup validation (F8) |
| Crate registry / CI | the compiled code and image | ship altered code | `Cargo.lock`, cargo-deny, pinned actions, Dependabot, cosign/SBOM/provenance |
| Gate admin (`AdminCap`) | pause / policy of the gate | block access while paused, only if the gate's immutable policy has `pause_blocks_access` | read live per request; fails **closed** on unrecognised JSON (F15) |

### Service actor matrix (RUST lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Network client | request line, headers, body size and framing, timing | §A I9/I10/I10b (body cap, concurrency, timeouts), I14 (rate limit), I19 (panics) |
| Upstream service | response size, status, timing | `http_client.rs` `Limited` + `tokio::time::timeout` (I11) |
| Sui fullnode (gRPC-web) | frames and payloads | `grpc.rs` caps, varint bound, depth 32, required `grpc-status` (I12) |
| Shared state store | nonce/redemption state; availability | `GETDEL`, `SET NX PX`, Lua compare-and-set; fail closed (I13) |
| Ingress / proxy in front | trustworthy forwarding headers | `client_ip` + `TRUSTED_PROXY_HOPS` (I14) |
| Crate registry and build pipeline | compiled code | `deny.toml`, `Cargo.lock`, B.RS-1 |

### Forwarding matrix (PROXY lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | method, path, query, every header, body bytes and timing | §A I9, I10b, I14, I15, I16, I25: method and path allowlists, header policy, body cap and read deadlines, per-IP limits |
| Upstream relay | status, headers, body, redirects, timing | response header policy (I16, I17), redirects never followed (I28), total deadline (I11, 504), 3xx → 502 |
| A party on the path to the upstream | the same, if the hop is unencrypted | `UPSTREAM_URL` must be `https://` unless `ALLOW_INSECURE_HTTP=1` (config, I21) |
| State store behind the gate | admission and single-use state | Redis (`SET NX PX` + Lua CAS) or the in-memory store (dev only for single-use); owner-bound, fail closed 503 (I6, I13) |
| Whoever can reach the upstream directly | bypass of the gate | the operator's lock at the upstream (F32, OQ9); not verifiable from this repo |

### On-chain dependency matrix (SUI_CLIENT lens)

| Object / package | ID per network (original-id · published-at) | Sourced from | Used as | If stale, wrong or attacker-supplied | Fails open / closed |
| --- | --- | --- | --- | --- | --- |
| `access_gate` package | operator env; testnet current `0xd7ddaa94…388c9` · same (v1, 2026-10-09) | `NFT_TYPE` prefix | type filter + event-type prefix | stale prefix ⇒ no pass/consume matches | closed (deny) |
| `…::access_gate::AccessNFT` / `SoulboundAccessNFT` | original-id | `NFT_TYPE` (validated by `is_access_gate_pass_type`) | `ListOwnedObjects` `object_type` filter | look-alike type rejected at config load | closed |
| `…::access_gate::AccessConsumedEvent` | original-id (derived, `consumed_event_type`) | derived from `NFT_TYPE` | exact-type event filter | look-alike package rejected (`rejects_a_look_alike_package_consume_event`) | closed |
| `Gate` shared object | operator env; testnet relay gate `0x316f1bf9…faddc` | `GATE_ID` | pause/policy read; `gate_id` match | wrong gate ⇒ no matches | closed; unrecognised JSON is an error ⇒ deny (F15) |
| Consume transaction | caller-supplied digest | proof `consumeDigest` | `GetTransaction` | shape-checked base58 before any call; unknown digest ⇒ 403 (F14) | closed (502 on RPC error, 403 on not-found) |

General actors added per the lens: **RPC fullnode** (above), **wallet** (displays and signs the
multi-line `nft-gate:access:v2` message, which names this gateway's origin), **relay** (the upstream),
**other dApps sharing the wallet** (the phishing vector of F1, now bounded by the audience binding).

### Walrus trust matrix (WALRUS lens — gateway-in-front row)

| Party | Power | Consequence / bound |
| --- | --- | --- |
| Gateway in front of a relay (this project) | admits requests carrying an access proof | bypass if the relay is reachable without it — the origin lock is the upstream's (Access/mTLS) and is not verifiable from this repo (B.WAL / OQ9). The Workers gateway's lock is recorded in its audit (F32 there). |
| Upload relay operator | receives the plaintext blob | out of scope here (walrus-relay/walrus-client audits) |
| User wallet | pays and signs the consume | the consume digest is the redemption token (F2–F4); the signed message is bound to this gateway (F1) |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse / compromise impact | Rotation / revocation plan |
| --- | --- | --- | --- | --- |
| `UPSTREAM_AUTH_HEADERS` (e.g. CF Access service token id+secret) | gateway process env (when deployed) | bypasses the upstream origin lock | anyone holding it reaches the relay ungated | rotate in Access and the secret store together — **to be written at deployment (F31)**; the Workers gateway's token procedure is in `docs/networking/CLOUDFLARE.md` §2.4 |
| `SUI_RPC_AUTH_HEADER` | gateway process env (when deployed) | credentialed RPC quota | RPC quota abuse | not recorded (F31) |
| `REDIS_URL` (may carry a password) | gateway process env (when deployed) | read/write nonce + redemption state | forge/erase redemptions ⇒ double-spend | not recorded (F31) |
| Access proof (bearer) | client, in transit | one gated request per nonce | replay prevented by nonce single-use; a relay by another site is useless: audience-bound (F1) | nonce TTL `CHALLENGE_TTL_SECS` (300 s) |

The AUTH lens's IdP, OAuth-client, BFF, JWT and user-token categories are N/A (no IdP, no tokens issued
or verified other than the Sui-signature proof, which is the Sui client lens's home); the signed-challenge
category is covered by F1 and AUTH-M11 below.

---

## Severity scale

Critical / High / Medium / Low / Info / Positive (unchanged across the corpus).

---

## Scope

**In scope (local checkout `367e673`, 2026-10-09; first pass at `db01d3e`, 2026-10-03):** the findings'
*Where* lines cite the first-pass locations (the code was largely rewritten by `6a601d3`); the
evidence paragraphs give the current ones. `origin/main` is `85b18e1` (blake2 0.11.0, `Cargo.toml`
and `Cargo.lock` only); its Rust CI run succeeded, and the local tree was not advanced (no git writes).

- `gateway-rust/`:
  - `src/{main,verify,sui_rpc,grpc,http_client,proxy,headers,ratelimit,challenge,config,proof}.rs`
    (`headers.rs` is new since the first pass)
  - `Cargo.toml`, `Cargo.lock`, `deny.toml`, `Dockerfile`, `.dockerignore`
  - `README.md`, `CLAUDE.md`, `AGENTS.md`, `CHANGELOG.md`
- Repo-level:
  - `conformance/vectors.json` (published by `@meddleware/nft-gate-client`; synced by
    `scripts/sync-vectors.mjs`), `SECURITY.md`, root `README.md` / `CLAUDE.md`
  - `scripts/check-versions.sh`, `.github/dependabot.yml`
  - `.github/workflows/{rust-ci,docker-publish,crates-publish}.yml`
- Cross-repo evidence (read-only):
  - `access-gate-sui/CLAUDE.md` (digest-first verifier contract) and `Published.toml`
  - `walrus-client/src/flow.ts` (409 handling: `code === 'redeemed'` / `'leased'`)
  - `nft-gate-client/src/contract.ts` (`GATEWAY_STATUS`, `GATEWAY_CONFLICT_CODES`)
  - `gateway-workers-audit.md` (shared fixes and the B.SC-3 home table)
  - `OPERATOR_TASKS.md` (registry credentials)

**Out of scope:**

- `gateway-workers/` — its own audit, `gateway-workers-audit.md`, which is the home of the B.SC-3
  parity table.
- The upstream relay, Cloudflare Access configuration and cluster manifests. None of these are in
  this repo; F32 tracks the manifests.
- The Move package (`access-gate-sui-audit.md`).

**Environment / commands (2026-10-09/10; rustc 1.100.0-nightly locally, `stable` in CI):**

| Command | Result |
| --- | --- |
| `cargo test --locked --offline` | 2026-10-09: 93 tests (91 passed, 2 ignored). **2026-10-10 (0.0.22): 117 tests: 114 passed, 0 failed, 3 ignored** (`live_gate_and_ownership_requests_are_accepted`, `live_consume_tx_valid`, `challenge::tests::redis_backend_round_trip`); first pass 71 / 69 / 2 |
| `cargo fmt --check` | clean |
| `cargo clippy --locked --offline --all-targets -- -D warnings` | clean |
| `cargo test --locked -- --ignored live_` | 2026-10-09: the old fixed-digest test **failed** (NOT_FOUND, `x-sui-lowest-available-checkpoint` 391126037: pruned; F45). 2026-10-10 after the fix: `live_gate_and_ownership_requests_are_accepted` passes; `live_consume_tx_valid` passes with a recent consume on the current relay gate (`NFT_GATE_LIVE_*`), which also confirms the `effects.status` field numbers (F21) |
| `cargo llvm-cov --locked --summary-only` | 2026-10-10, local: 90.7 % of lines, 91.4 % of functions, 90.1 % of regions (test code included in the denominator) |
| `redis_backend_round_trip` | not run (needs `REDIS_URL`; not in CI, S2) |
| `cargo deny` / `cargo audit` | not installed locally. `cargo-deny-action` is green in CI on `main` (Rust CI run of 2026-10-09T17:52Z on `85b18e1`); `cargo audit` is covered by cargo-deny's `advisories` check (same RustSec database, F28). Dependabot security alerts are disabled for the repository (API 403). |
| Published versions | crates.io `nft-gate-gateway` max 0.0.21 (2026-10-08T08:19Z, none yanked); npm sibling 0.0.21; quay.io `nft-gate-gateway:0.0.21` present (index `sha256:f7d627eb…9281`) |
| Dependabot | `.github/dependabot.yml`: weekly, grouped; npm (`/gateway-workers`), cargo and docker (`/gateway-rust`), github-actions. 2026-10-09 triage: merged cargo group, distroless digest, `ed25519-dalek` 3.0.0 (dev-dependency), `blake2` 0.11.0, Actions group; closed `k256`/`p256` 0.14 (PRs #4, #6, major declined), TypeScript 7 and vitest 5 (Workers). |

---

## Findings

### F1 — Access proof message is not bound to an audience (gateway, gate or consume)

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F1; OQ1 decided)
**Where:**

- `src/proof.rs` (`personal_message_for_nonce` → `nft-gate:access:<nonce>`)
- `src/verify.rs::verify_access_request` (`:285-350`)
- `conformance/vectors.json` `personalMessage`

**Issue:** The only signed content is the nonce. Nothing in the message identifies the gateway origin,
the gate, the network or (in single-use mode) the consume digest being redeemed. A nonce is issued to
anyone (`GET /v1/challenge`), and the wallet shows the user an opaque `nft-gate:access:<hex>` string.

**Impact:** A malicious site can fetch a nonce from the real gateway, ask a visitor to sign it (the
prompt is indistinguishable from any nft-gate service) and submit the proof itself.

- **Ownership mode:** this grants the attacker one request as the victim, using the victim's pass.
- **Single-use mode:** the attacker also needs a consume digest whose event sender is the victim.
  Consume transactions are public, so an un-redeemed or interrupted consume can be redeemed by the
  attacker first.
  - The victim loses a paid use.
  - Their own redemption then gets a 409, and per F2 may be treated as "redeemed", which spends a
    further use.

The exposure is bounded to one request per phished signature. The nonce TTL is 300 s.

**Remediation / evidence:** Protocol v2, one coordinated wire change (nft-gate-client 0.0.16 and both gateways, no v1
compatibility, per the pre-v0.2 policy):

- The signed message is `nft-gate:access:v2`, multi-line ASCII, binding the gateway origin, the gate
  id, the network, the nonce and (single-use) the consume digest (OQ1: all three options).
  `proof.rs::personal_message` builds it. `verify.rs::verify_access_request` (now `:287-382`)
  rebuilds it from `cfg.gateway_origin`, `normalize_address(cfg.gate_id)`, `cfg.network`, the proof's
  nonce and, in single-use mode, its digest, never from the token. New required variables
  `GATEWAY_ORIGIN` (a canonical https origin, refused otherwise) and `NETWORK`. A proof made for
  another gateway, gate, network or mode fails signature verification here; v1 is refused.
- Vectors are generated and published by nft-gate-client (`personalMessage`, `personalMessageRejects`
  13 cases, `audienceMismatch` 8, `signatures` 4, `negativeSignatures` 8, `zip215`), copied by
  `scripts/sync-vectors.mjs` and asserted by `verify::tests::conformance_shared_vectors`.
- Tests: `refuses_a_proof_made_for_another_gateway_gate_or_network`,
  `refuses_the_v1_message_and_a_cross_mode_signature`, `single_use_refuses_a_swapped_consume_digest`,
  `proof::tests::personal_message_is_the_documented_multi_line_ascii`,
  `personal_message_refuses_non_canonical_fields`,
  `config::validation_tests::audience_binding_inputs_are_required_and_canonical`.
- Live: the paywall e2e of 2026-10-09 passed with a v2 proof, but through the Workers gateway; this
  crate has no live v2 run (it is undeployed).
- Residual (not a code gap): the wallet prompt is only as useful as the user's attention to the
  origin line (see Risks).

### F2 — 409 redemption conflict has no machine-readable code and conflates "leased" with "redeemed"

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:**

- `src/main.rs:182-185` (`Lease::Redeemed | Lease::Leased` → one `deny(409, RedeemConflict.reason())`)
- `src/verify.rs` `Denied::RedeemConflict`

**Issue:** Both lease outcomes return the same `{"error": <reason>}` with no `code` field. The Workers
gateway returns `{"error": …, "code": "redeemed"}` or `{"error": …, "code": "leased"}`
(`gateway-workers/src/redemption.ts:30-35`).

The client decides whether to spend a fresh use as follows (`walrus-client/src/flow.ts` ~L96):

- `e.status === 409 && e.error?.code === 'redeemed'`;
- **otherwise** a message regex fallback on `/409/` and `/redeemed/`.

The Rust reason text contains "redeemed" for both cases.

Store errors aggravate this. `RedisNonceStore::try_lease_redemption` (`src/challenge.rs:264-292`)
maps a failed `SET` (or a failed follow-up `GET`) to `Lease::Leased`. A Redis outage during a lease
therefore surfaces as the same 409, while the Workers gateway answers 503 `gateway state unavailable`.

The nonce path has the same divergence: a Redis `GETDEL` error becomes `NonceInvalid`, a 403
(`:339-356`), where Workers answers 503.

**Impact:** Behind `gateway-rust`, a duplicate in-flight request (`Leased`), or even a Redis blip, is
indistinguishable from a spent consume. The client's fallback re-consumes on-chain, which spends another paid use, while the
first request may still succeed. This breaks the walrus lens's WAL-M8 ("never loses a consumed use")
and is a parity divergence from the vectors' intent: the same input gets a different client-visible
decision.

**Remediation / evidence:** `main.rs::redeem_and_forward` (`:238-286`) splits the arms and maps store errors:

- `Lease::Redeemed` → `409 {"error":"this consume has already been redeemed for an upload","code":"redeemed"}`;
- `Lease::Leased` → `409 {"error":"an upload for this consume is already in progress","code":"leased"}`;
- an `Err` from the store → `503 gateway state unavailable`.

This is the vocabulary walrus-client parses (`isRedeemedConflict`, `isLeasedConflict` in
`walrus-client/src/flow.ts`; `GATEWAY_CONFLICT_CODES` in nft-gate-client). A failed Redis `SET` or
follow-up `GET` in `RedisNonceStore::try_lease_redemption` is now an `Err`, not `Leased`; a `GETDEL`
error is `Denied::StateUnavailable` → `503`; a failed nonce write is `503` on `/v1/challenge`.

Tests: the store behaviour is tested (`redemption_*` in `challenge.rs`). **There is no router- or
dispatcher-level test of the 409 bodies or of the 503 mapping** (F47), no `redemptionConflict` section
in the shared vectors, and `GATEWAY_CONFLICT_CODES` is a TypeScript constant the Rust suite does not
consume. Dropping walrus-client's message-regex fallback is that audit's item.

### F3 — Redemption lease is not owner-bound and can expire while its request is still running

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F3)
**Where:**

- `src/main.rs:176-205`
- `src/challenge.rs:92-142` (in-memory) and `:264-320` (Redis)
- `src/config.rs:274-287`: `REDEMPTION_LEASE_TTL_SECS` 120, `UPSTREAM_TIMEOUT_SECS` 120

**Issue:**

- The lease is taken **before** the body is read (`proxy::forward` buffers the body after the lease).
- Its TTL (120 s) is not checked against the maximum request duration: the body read time (unbounded,
  F5) plus `UPSTREAM_TIMEOUT_SECS` (120 s).
- Lease values carry no owner token:
  - `commit_redemption` is an unconditional `SET`;
  - `release_redemption` deletes whatever lease is present (Lua compares only the literal `leased`).

**Impact:** A slow upload passes the 120 s lease. A duplicate request with the same digest then sees
an expired lease, takes a new one and uploads in parallel, giving two uploads for one paid consume.
When the first request finishes, its `release` (on failure) can delete the **second** request's lease,
reopening the window again. Each leak is bounded by how many requests the attacker can keep in flight,
but it defeats the single-use guarantee that `SECURITY.md` invariant 4 states.

**Remediation / evidence:** - `NonceStore::try_lease_redemption` returns `Lease::Ok(token)` (24-byte OsRng hex). Redis stores
  `leased:<token>` (`SET NX PX`), commit is a Lua compare-and-set to `committed`, release a Lua
  compare-and-delete; the in-memory store mirrors both (the token and an unexpired lease are
  required). A commit that finds its lease lapsed or replaced returns `Commit::Lost`, which
  `redeem_and_forward` reports as `502 redemption lease lost` without touching the newer holder.
- `REDEMPTION_LEASE_TTL_SECS` defaults to 900 and `from_lookup` refuses a value not above
  `UPSTREAM_TIMEOUT_SECS` (600), so a lease cannot lapse inside the forward. **Residual:** the check
  does not add the body-read time (default 30 s, configurable to 3,600 s) although the lease is taken
  before the body is read: F46.
- Tests: `a_stale_holder_cannot_release_or_commit_over_a_newer_lease`,
  `a_commit_after_the_lease_lapsed_is_lost`, `redemption_expired_lease_is_reclaimable`,
  `redemption_release_never_clears_commit`; `single_use_needs_a_durable_store_and_consistent_windows`
  (config). The Redis scripts run only in the env-gated `redis_backend_round_trip` (not in CI, S2).
- Mirrored in `gateway-workers` (its own audit).

### F4 — In-memory store with `SINGLE_USE=true` loses every redemption on restart

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ3 decided)
**Where:**

- `src/main.rs:300-311` (backend selection; only an `info!` log when `REDIS_URL` is unset)
- `src/challenge.rs:59-142`
- `Cargo.toml` `[profile.release] panic = "abort"`

**Issue:** The redemption store (committed digests retained 30 days) lives in process memory unless
`REDIS_URL` is set. Nothing prevents `SINGLE_USE=true` with the in-memory backend.

**Impact:** A restart erases the history, so every previously committed consume digest becomes
redeemable again. Restarts include:

- a deploy;
- an OOM kill (F6);
- `panic = "abort"`, deliberately chosen so a panic restarts the process.

With `replicas > 1`, each replica holds its own history, so any digest can be redeemed once per
replica. CLAUDE.md documents the replica caveat for nonces, but not that it also breaks single-use
redemption, the gateway's economic guarantee.

**Remediation / evidence:** - `GatewayConfig::from_lookup` fails startup when `SINGLE_USE=true` and `REDIS_URL` is unset unless
  `ALLOW_VOLATILE_REDEMPTIONS=true` (the audit proposed the name `ALLOW_EPHEMERAL_REDEMPTIONS`);
  `main.rs` logs a `warn!` when the override is used. README and CLAUDE.md document it.
- Decision (OQ3): never in production; the override is for development only.
- Test: `single_use_needs_a_durable_store_and_consistent_windows`.
- `panic = "abort"` still restarts the process; with Redis that no longer loses redemptions.

### F5 — No inbound header-read or body-read timeout and no connection cap (slowloris)

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:**

- `src/main.rs:341-348`: `axum::serve` 0.7.9 builds `hyper_util::server::conn::auto::Builder` with
  no timer, so hyper's 30 s `header_read_timeout` never applies.
- `src/proxy.rs:55` (`axum::body::to_bytes` with a size limit but no deadline).

**Issue:**

- Headers can be trickled indefinitely, and connections are not capped.
- Once a request is inside the service, its body is read with no time limit.
- `MAX_CONCURRENT_REQUESTS` (64) counts requests in the service, so 64 slow bodies hold every slot
  and later requests get `503 gateway overloaded`.
- In single-use mode the lease is held throughout (F3).

**Impact:** Cheap denial of service against the gated upstream from a single client. The pre-auth
per-IP limit does not apply to gated paths (F9), and nothing limits the connections that slow headers
open.

**Remediation / evidence:** - `main.rs::serve` replaces `axum::serve` with a hyper HTTP/1 accept loop: `http1::Builder` with a
  `TokioTimer` and `header_read_timeout` (`HEADER_READ_TIMEOUT_SECS`, default 10 s; it also bounds an
  idle keep-alive wait), a `Semaphore` of `MAX_CONNECTIONS` (default 1,024; later clients wait in the
  TCP backlog) and a `JoinSet` of connection tasks.
- `proxy::forward` wraps the body read in `tokio::time::timeout(BODY_READ_TIMEOUT_SECS)` (default
  30 s) → `408 request body timed out`. The deadline is one wall-clock limit, not a minimum throughput.
- Test: `the_server_drops_a_client_that_never_finishes_its_headers` (a stalled head is closed while a
  normal request is served). **No test** covers the body-read timeout or the connection cap (F47).

### F6 — Request and response bodies are fully buffered; Rust is not a drop-in for the 100 MiB relay

**Severity:** Low   **Disposition:** ADJUDICATED (decision: small-body scope; OQ4 decided)
**Where:**

- `src/proxy.rs:1-9`, `:55`
- `src/http_client.rs::send` (`Limited::new(...).collect()`)
- `src/config.rs:263-291`: `MAX_BODY_BYTES` 256 KiB, `MAX_RESPONSE_BYTES` 16 MiB
- `gateway-rust/README.md:130-147`

**Issue:** Peak memory is about `MAX_CONCURRENT_REQUESTS × (2 × MAX_BODY_BYTES + MAX_RESPONSE_BYTES)`.
This is documented, and the concurrency limit exists, so RS-M4 holds as stated. But the Walrus relay
deployment needs `MAX_BODY_BYTES` = 100 MiB (`gateway-workers/wrangler.toml`).

- At 64 slots that is ≈ 13.8 GiB.
- With the 256 KiB default, real uploads get 413.

Root `CLAUDE.md` calls both gateways "drop-in: same endpoints, same env vars".

**Impact:** Swapping the Rust gateway onto the relay hostname, which `wrangler.toml` line 3-4 invites,
either rejects uploads or OOM-kills the pod. With the in-memory store, an OOM kill also triggers F4.

**Remediation / evidence:** - Decision (OQ4, 2026-10-08): `gateway-rust` is not a drop-in for relay-sized bodies and is not
  deployed in front of the relay. The `proxy.rs` module doc and `README.md` "Scope" state it ("a
  large-upload relay belongs behind `gateway-workers`, which streams"); `MAX_BODY_BYTES` stays
  256 KiB, so a real upload gets `413`, not an OOM.
- Peak memory is about `MAX_CONCURRENT_REQUESTS × (2 × MAX_BODY_BYTES + MAX_RESPONSE_BYTES)` =
  64 × (0.5 + 16) MiB ≈ 1.03 GiB at the defaults; a deployment's memory limit must cover it (F32).
- Residual (documentation, F27): root `CLAUDE.md` still calls the two gateways "drop-in: same
  endpoints, same env vars, identical verification decisions" without the small-body caveat.
- No streaming work is planned; revisit if a large-body upstream is ever put behind this gateway.

### F7 — Ownership mode ignores `uses_remaining`; exhausted single-use passes and receipts are admitted

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ2 decided; shared with `gateway-workers` F7)
**Where:** `src/sui_rpc.rs::response_has_owned` (`:196`) and `owns_nft_live` (`:96`).

**Issue:** Ownership mode accepts any owned object of `NFT_TYPE` whose `gate_id` matches. An
`AccessVariant::SingleUse { uses_remaining: 0 }` receipt (gates with `auto_burn_at_zero = false` keep
it as a receipt per the access_gate invariant 4) passes.

`seal-policies-sui` `nft_gate` explicitly rejects exhausted passes ("an exhausted (zero-use) pass is
rejected"), so the two consumers of the same pass disagree.

**Impact:** On a gate configured with a positive `default_uses`, ownership mode gives unlimited access
to holders of spent passes. This is latent today: the only deployed gateway (Workers) runs
`SINGLE_USE=true`.

**Remediation / evidence:** - `sui_rpc.rs::pass_is_usable` reads the `AccessVariant` as a full node renders it (`@variant`):
  `UnlimitedPass` is usable, `SingleUse` only with `uses_remaining` > 0 (a decimal u64), and
  anything else (unknown tag, missing or non-numeric count) is not (fail closed).
  `response_has_owned` skips unusable objects. Decision (OQ2): ownership counts only usable passes,
  matching `seal_policies::nft_gate`.
- Tests: `only_usable_passes_count`, `an_exhausted_receipt_is_not_ownership`,
  `owned_response_matches_gate`.
- Caveat: pagination (F17). The one page read can hold exhausted receipts while a usable pass sits
  beyond the first 50 objects.

### F8 — Configuration parsing falls back silently on invalid values

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/config.rs:215-297`.

**Issue:**

- `SINGLE_USE` is `eq_ignore_ascii_case("true")`, so `TRUE `, `1`, `yes` or a typo all silently select
  **ownership mode**.
- Every numeric variable uses `.parse().unwrap_or(default)`, so `MAX_BODY_BYTES=100MiB` silently
  becomes 256 KiB and `REDEMPTION_RETENTION_SECS=30d` becomes 30 days by accident of the default.
- `env_or`'s doc says "absent or empty" but an empty value is returned as `""` (`std::env::var`
  succeeds).

**Impact:** One mistyped variable silently downgrades a paid single-use relay to "any pass holder,
unlimited", the most security-relevant switch in the service, with no startup error.

**Remediation / evidence:** - `config.rs` parses every variable strictly: `parse_bool` accepts exactly `true`/`false`;
  `parse_int` accepts a plain decimal inside a stated range and names the variable in the error;
  `ALLOW_INSECURE_HTTP` is `1` or unset; origins, public paths, `NFT_TYPE`, `GATE_ID` and `NETWORK`
  are validated; the cross-checks (lease > upstream deadline, consume age ≤ retention, single-use
  needs Redis) fail startup. `env_or` is gone. The startup log states `single_use` and, for the
  volatile store, a `warn!`.
- Tests: `a_typo_never_selects_a_weaker_mode`, `defaults_load_and_are_self_consistent`,
  `origins_and_public_paths_are_validated`, `single_use_needs_a_durable_store_and_consistent_windows`,
  `canonical_origin_rules`.
- Note: an empty `REDIS_URL` is treated as unset (deliberate); with `SINGLE_USE=true` that is refused.

### F9 — Gated path has no pre-authentication rate limit

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F9)
**Where:** `src/main.rs:162-171` (the per-address `limiter` runs only after `verify_access_request`
succeeds).

**Issue:** A request to a gated path with a syntactically valid token runs base64/JSON decoding,
signature verification and a nonce-store lookup (a Redis round trip) before any limit applies.

- A self-generated keypair produces valid signatures for random nonces at no cost to the attacker.
- `/v1/challenge` and public paths are IP-limited; gated paths are not.

**Impact:** Unbounded CPU work (ECDSA/ed25519 verification) and Redis traffic per attacker request.
It combines with F5 for denial of service.

**Remediation / evidence:** `handle` (`main.rs`) takes a per-client-IP budget (`preauth_limiter`,
`GATED_PREAUTH_RATE_LIMIT_PER_MIN`, default 120/min, 0 disables) after the method check and before
`verify_access_request`; the per-address limiter still runs after verification. The key is
`client_ip` (the TCP peer or the trusted hop, IPv6 by /64). Test:
`gated_requests_are_rate_limited_per_ip_before_verification` (three admitted, then `429`).

### F10 — Rate-limiter maps grow without bound

**Severity:** Low   **Disposition:** MITIGATED (IPv6 /64 keys; the sweep is not done)
**Where:** `src/ratelimit.rs:22-60` (`Mutex<HashMap<String, Window>>`; entries are only overwritten,
never removed).

**Issue:** `ip_limiter` creates one entry per distinct client IP, and `limiter` one per authenticated
address. Nothing prunes expired windows.

**Impact:** An IPv6 attacker rotating source addresses inside a /64 grows the map without limit, until
OOM. With the in-memory store, an OOM also means F4.

**Remediation / evidence:** IPv6 clients are keyed by their /64 (`main.rs::rate_key`; test `ipv6_clients_are_keyed_by_their_slash_64`),
so rotating source addresses inside a prefix no longer multiplies keys, and keys are the TCP peer (or
the trusted hop), never a client-chosen string. **Residual:** `ratelimit.rs` is unchanged: windows are
never removed, and the prune task in `main.rs` sweeps only the nonce store. Growth needs many distinct
real source addresses; revisit with the memory limit at deployment (F32).

### F11 — In-memory store does O(n) work under the mutex on every challenge and lease

**Severity:** Low   **Disposition:** ACCEPTED-RISK (in-memory backend is the single-replica/development store; revisit at deployment, OQ9)
**Where:** `src/challenge.rs:147-160` (`insert`: `m.retain` then `min_by_key` eviction) and `:92-122`
(`try_lease_redemption`: `retain` plus eviction scan).

**Issue:** Each challenge (≤ 30/min per IP, but unbounded across IPs) scans the whole map, up to
`NONCE_MAX_ENTRIES` = 1,000,000, while holding a `std::sync::Mutex` inside an async task.

**Impact:** At a large map, each call costs milliseconds of exclusive CPU and blocks a tokio worker.
Many IPs requesting challenges degrade every request (lock contention). The hard entry cap, which was
the fix for finding F3 of the earlier gateway audit, becomes a CPU amplifier.

**Remediation / evidence:** Unchanged: `challenge.rs::insert` and `try_lease_redemption` still `retain` or scan the whole map under
a `std::sync::Mutex`. Two things reduce it: `SINGLE_USE` now requires Redis, so the in-memory
redemption map is a development path (`ALLOW_VOLATILE_REDEMPTIONS`), and challenge issue is limited per
IP (30/min) with a 1,000,000-entry cap. A production deployment uses Redis, where this code does not
run. Accepted; revisit if the in-memory backend is ever sized for production.

### F12 — Upstream CORS headers pass through and can widen the allowlist

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F12)
**Where:** `src/main.rs:239-260` (`cors` inserts `Access-Control-Allow-Origin` only for an allowed
origin, and never removes one) and `src/proxy.rs:86-96` (response headers copied).

**Issue:** If the upstream sends `Access-Control-Allow-Origin: *` (or reflects origins), for example a
relay with permissive CORS, that header reaches the browser for **unlisted** origins too. The grants
are overwritten; ACAO is not.

**Impact:** The `ALLOWED_ORIGINS` boundary is defeated for any upstream with permissive CORS. Gated
endpoints still need a proof, but public paths and error bodies become readable cross-origin. The
gateway's stated CORS invariant ("reflected only on an exact match") does not hold end to end.

**Remediation / evidence:** `headers.rs::client_response_headers` removes every `access-control-*` field from the upstream response,
and the `cors` middleware (`main.rs`) also removes any `access-control-*` field an inner handler set
before applying the gateway's own grants, the exact-match `Access-Control-Allow-Origin` and
`Vary: Origin`. Tests: `response_strips_hop_by_hop_cookies_and_upstream_cors` (ACAO `*` and
`Allow-Credentials` removed) and the three `cors_*` router tests. There is no router-level test with an
upstream that answers `ACAO: *` (F47).

### F13 — Hop-by-hop header stripping is incomplete; `SECURITY.md` invariant 5 overstates it

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F13)
**Where:** `src/proxy.rs:67-71` (the request strips only `Host`, `Authorization`, `Content-Length`,
`X-Access-Proof`) and `:88-94` (the response strips only `Content-Length`, `Transfer-Encoding`,
`Connection`). Root `SECURITY.md` invariant 5.

**Issue:**

- Client-supplied `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Proxy-Authorization` and
  `Proxy-Connection` are forwarded upstream.
- Headers named in a `Connection` token list are forwarded in both directions.
- Upstream `Keep-Alive`, `Upgrade`, `Proxy-Authenticate` and `Trailer` are returned.

`SECURITY.md` states hop-by-hop headers are "stripped before forwarding".

**Impact:** Mostly protocol hygiene: request-smuggling-adjacent ambiguity with HTTP/1.1 upstreams and
leakage of proxy credentials a client sends. It is also a documentation contradiction, which is a
finding class under the base template's `SECURITY.md` rule.

**Remediation / evidence:** New `src/headers.rs`, the same lists as the Workers gateway:

- hop-by-hop set (RFC 9110 §7.6.1: connection, keep-alive, proxy-authenticate, proxy-authorization,
  proxy-connection, te, trailer, transfer-encoding, upgrade) plus every field named in `Connection`,
  removed in **both** directions;
- request also loses host, authorization, x-access-proof, content-length, cookie, forwarded, via,
  x-forwarded-for/host/proto, x-real-ip and every `cf-access-*` field;
- response also loses content-length, set-cookie(2), alt-svc and `access-control-*`.

Root `SECURITY.md` invariant 6 now describes exactly this. Tests:
`request_strips_hop_by_hop_connection_named_credentials_and_spoofable_fields`,
`response_strips_hop_by_hop_cookies_and_upstream_cors`. Forwarding fields are stripped, not rebuilt
(PX-M2 below).

### F14 — `GetTransaction` is retried on every error; the digest is not validated before the RPC call

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F14)
**Where:** `src/sui_rpc.rs:253-285` (`TX_FETCH_ATTEMPTS` 4, `TX_FETCH_RETRY` 500 ms, `Err(e) if attempt
< 4` for any error) and `src/proof.rs` (the `consumeDigest` only needs to be ASCII).

**Issue:**

- The Sui client lens requires indexing-lag retries **only for not-found errors**.
- Timeouts (30 s each) and other gRPC statuses are retried too, so one request can hold a slot for
  over two minutes.
- A random string is sent to the fullnode four times, then reported as `ChainError` → **502**, not 403.

**Impact:**

- Attacker-controlled amplification: 4 RPC calls per bogus request on a credentialed RPC quota.
- A misleading 502 for an invalid digest, which clients may retry.
- The retry policy matches Workers, so parity holds, but both deviate from SC lens §A *Execution
  result*.

**Remediation / evidence:** `consume_tx_valid` retries only gRPC `NOT_FOUND` (4 attempts × 500 ms) and the final not-found is
`Ok(false)` → `ConsumeMissing` (403); any other failure (network, timeout, auth, server) returns at once
as a chain error (502), so there is no amplification. The digest must pass `proof::is_tx_digest`
(32–44 base58 characters) in `decode_access_proof` and again in `personal_message`, so a malformed
digest never reaches the RPC (a shape check, not a decode to 32 bytes). Tests:
`rejects_everything_outside_the_field_grammar`, `decodes_with_and_without_consume_digest`,
`single_use_denies_missing_consume_digest`; the retry loop itself has no hermetic test (live only,
F45, F47).

### F15 — Pause enforcement fails open on unrecognised `Gate` JSON

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-workers` F15)
**Where:** `src/sui_rpc.rs:120-129` (`paused`/`pause_blocks_access` default to `false` when absent or
not a bool).

**Issue:** "A gate without a `policy` (pre-policy package version) never blocks." The only consumed
package (`0xa55789…`, v1) always has `policy`. Under the pre-v0.2 policy no old-package fallback is
owed, so a missing field now means a parse problem, not an old gate.

**Impact:** If the gRPC JSON rendering changes, for example the field is renamed or the bool is
encoded differently, an admin's pause stops being enforced, silently.

**Remediation / evidence:** `sui_rpc.rs::gate_blocks_access` returns an error unless `paused` is a bool and
`policy.pause_blocks_access` is a bool; `verify.rs` maps it to `ChainError` (denied). Tests:
`gate_blocks_only_when_paused_and_policy_opts_in` (a gate without a policy is an error),
`unrecognised_gate_json_is_an_error_not_unpaused`, `get_object_response_without_object_fails_closed`,
`single_use_paused_gate_denies_before_redemption`. Note that a pause blocks only when the gate's
immutable policy opts in; the live relay gate's does not (Workers audit F45).

### F16 — `Authorization: Bearer` parsing is case-sensitive and single-space; Workers is not

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/main.rs:115-129` (`strip_prefix("Bearer ")`) vs `gateway-workers/src/index.ts:124`
(`/^Bearer\s+(.+)$/i`).

**Issue:** `bearer <t>`, `Bearer\t<t>` and `Bearer  <t>` are accepted by Workers but fall through to
`X-Access-Proof` (absent) → 401 in Rust. Root `CLAUDE.md` says the header preference logic must
produce identical decisions.

**Impact:** Divergent decisions for the same request. Low practical impact (the first-party client
sends `Bearer `), but it is exactly the drift the conformance vectors exist to catch, and no vector
covers header extraction.

**Remediation / evidence:** `main.rs::extract_proof_token` splits on the first whitespace, compares the scheme case-insensitively and
trims, then falls back to `X-Access-Proof`; Bearer wins when both are present. Test:
`bearer_token_extraction_matches_the_workers_gateway`. There is still no shared `headerExtraction`
vector (S1).

### F17 — `ListOwnedObjects` reads one page of 50 without a cursor; Workers paginates

**Severity:** Low   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `src/sui_rpc.rs` (`scan_owned`, `build_list_owned`, `MAX_OWNED_PAGES`); before 0.0.22 `owns_nft_live`
sent `page_size` 50 and read the first page only.
**Issue:** A holder whose qualifying pass is beyond the first 50 objects of `NFT_TYPE` is denied. This
fails closed. `gateway-workers` reads every page via `ownsAccessNft` (up to `MAX_OWNED_PAGES`), so the
two gateways decide differently for the same address. This is the "one page of N is a GAP" case of
the Sui client lens §A *Events*.

**Impact:** Wrongful denial for large holders (bulk buyers) on the Rust gateway only.

**Remediation / evidence:** Fixed in 0.0.22. `sui_rpc.rs::scan_owned` reads `ListOwnedObjects` page by page (50 per page,
`page_token` = field 3, `next_page_token` = field 2, both checked against the `@mysten/sui` generated
proto), stops at the first usable pass for the gate, and errors past `MAX_OWNED_PAGES` = 100 (the Workers
gateway's bound: 5,000 objects of the pass type), so the two gateways decide alike. Past the bound the answer
is a chain error (502, denied), never "no" or "yes". The whole listing shares one `RPC_TIMEOUT_SECS`
deadline. Pinned by `ownership_is_read_across_pages_until_a_usable_pass` (an exhausted receipt on page one,
the usable pass on page two, token echoed), `a_pass_on_the_first_page_stops_the_scan`,
`the_last_page_without_a_usable_pass_is_not_ownership`, `an_endless_list_is_an_error_after_the_page_bound`
(exactly 100 calls), `a_node_error_on_a_later_page_fails_the_check` and
`build_list_owned_encodes_the_page_token_only_when_continuing`; live: `live_gate_and_ownership_requests_are_accepted`
(2026-10-10, passes). The Workers audit's B.SC-3 pagination row can now say "same".

### F18 — Ownership cache is unbounded when enabled

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `src/sui_rpc.rs:72-90` (`Mutex<HashMap<String, CacheEntry>>`, never pruned) when
`OWNERSHIP_CACHE_TTL_MS > 0`.

**Issue:** Each distinct `(address, type, gate)` adds an entry, and expired entries are only replaced
on a later hit.

**Impact:** The map grows without limit under many distinct signing addresses. This is off by default
(`0`).

**Remediation / evidence:** `sui_rpc.rs` bounds the cache at `MAX_CACHE_ENTRIES` (10,000): on each insert expired entries are
dropped and, past the cap, the soonest-to-expire entry is evicted. The cache is off by default
(`OWNERSHIP_CACHE_TTL_MS` 0). Code-only; there is no cache test.

### F19 — Graceful shutdown waits without a bound

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/main.rs:343-372` (`with_graceful_shutdown(shutdown_signal())` with no drain deadline).

**Issue:** SIGTERM is handled, but draining waits for every in-flight request. A slow client (F5)
holds shutdown open until the orchestrator SIGKILLs it, and SIGKILL drops any in-flight lease without
releasing it. The RUST lens requires draining "within a bound".

**Impact:** Unclean termination. It is safe for redemptions (leases expire) but unpredictable.

**Remediation / evidence:** `main.rs::serve` stops accepting on SIGINT or SIGTERM (`shutdown_signal`), logs the drain, waits up to
`SHUTDOWN_GRACE_SECS` (default 30 s) for in-flight connection tasks and then aborts the rest
(`tasks.abort_all()`); a lease dropped that way expires on its own (900 s). The shutdown path runs in
`the_server_drops_a_client_that_never_finishes_its_headers`; the grace bound itself has no test (F47).

### F20 — Commit failure after a successful upstream replaces the response with 502 and releases the lease

**Severity:** Info   **Disposition:** ADJUDICATED (shared semantics with `gateway-workers`; OQ6 — behaviour kept)
**Where:** `src/main.rs:186-200`; Workers `src/redemption.ts:46-55`.

**Issue:** If `commit_redemption` fails after the upstream answered 2xx, the client gets
`502 redemption commit failed` and the lease is released. The upload did happen.

**Impact:** The user retries with the same consume and uploads again: one extra upstream operation per
commit failure. The alternative, keeping the lease or failing the request open, would risk losing the
user's use. This is the WORKERS lens's "defined outcome shared with any sibling", and it holds
identically in both.

**Remediation / evidence:** Intentional, unchanged. `redeem_and_forward` still answers `502 redemption commit failed` and releases
the lease when the commit errors after a 2xx; a lost lease is `502 redemption lease lost` (nothing
released: the token no longer matches). Recorded so the operator-cost trade-off is a decision (OQ6:
502 + release kept).

### F21 — Single-use check relies on "events imply success" instead of the effects status

**Severity:** Low   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `src/sui_rpc.rs` (`build_get_transaction`, `effects_succeeded`, `response_has_consume`).
**Issue:** The Sui client lens §A *Execution result* requires success to be decided by the effects
status. On Sui a failed transaction emits no events, so the inference is correct today. But the
Workers gateway checks `$kind === 'Transaction' && status.success`, so the two gateways rely on
different properties.

**Impact:** No exploit today. It is a parity and lens-conformance gap.

**Remediation / evidence:** Fixed in 0.0.22. `build_get_transaction` masks `effects.status` and `events`, and
`response_has_consume` first requires `effects_succeeded` (`ExecutedTransaction.effects` = 4,
`TransactionEffects.status` = 4, `ExecutionStatus.success` = 1 with value 1; a missing effects block, a
missing status or `success`, or `false` all deny), as `gateway-workers` does with `status.success`.
Pinned by `only_a_successful_transaction_can_be_a_consume` (failed, no status, error-only status, each with a
matching event), `a_failed_transaction_with_a_matching_event_is_not_a_consume`,
`consume_verification_reads_a_response_in_the_pinned_wire_format` (literal field numbers) and the router test
`a_failed_or_unreadable_consume_never_reaches_the_upstream` (403). The field numbers were confirmed against the
real testnet fullnode with a recent consume on 2026-10-10 (`live_consume_tx_valid`, passes).

### F22 — Consume binding checks the event `sender`, not the event's `consumer` field

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/sui_rpc.rs:158-190`; `access_gate::consume` sets `consumer = ctx.sender()`.

**Issue:** The gateway compares the gRPC event envelope's `sender` with the signed address.
`AccessConsumedEvent.consumer` is by construction the same value.

**Impact:** None while `consume` is the only emitter of the event: the type is exact-matched to the
configured package. If a future package version emitted the event from a path where `consumer`
differs from the sender (e.g. a sponsored or delegated consume), the binding would follow the wrong
field.

**Remediation / evidence:** Intentional and equivalent today (unchanged at 0.0.21: `sui_rpc.rs::response_has_consume` compares the
event envelope `sender`). Re-check on any `access_gate` upgrade (B.SC-1). Optionally assert both
fields are equal.

### F23 — Challenge nonce is deliberately not bound to `AccessConsumedEvent.nonce`

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/sui_rpc.rs:8` (module doc) and `gateway-rust/CLAUDE.md`; cross-repo
`access-gate-sui/CLAUDE.md` invariant 2 ("A verifier binds a challenge to a consumption via that
`nonce` + `consumer`… never trust a bare address").

**Issue:** Digest-first redemption replaces nonce binding, so an interrupted upload can resume with a
fresh challenge. The Move package's documented verifier contract says the opposite.

**Impact:** The design is coherent: the redemption store enforces single use. But it is what makes the
single-use variant of F1 possible, because any fresh signature from the consumer redeems any of their
consumes. The cross-repo documentation disagrees with the implementation.

**Remediation / evidence:** Intentional (CLAUDE.md "Single-use redemption"). The documentation side is fixed: `access-gate-sui/CLAUDE.md`
invariant 2 now describes the digest-first binding that verifiers must use (the `nonce` optional) and the
redemption-store alternative. F1's fix restores an equivalent binding: in single-use mode the consume
digest is part of the signed v2 message, so a proof is bound to one consume, while the store still lets
an interrupted upload resume with a fresh nonce and a new signature over the same digest.

### F24 — A committed digest becomes redeemable again after the 30-day retention

**Severity:** Info   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ5 decided; shared with `gateway-workers` F24)
**Where:** `src/config.rs:277` (`REDEMPTION_RETENTION_SECS` 2,592,000) and `challenge.rs` commit TTL.

**Issue:** When a committed record expires, the next proof carrying that digest is checked again.
`GetTransaction` still returns the old transaction while the fullnode retains it, and if so the use is
redeemed a second time. `wrangler.toml` calls this "an obscure, low-value edge".

**Impact:** One extra upload per consume per 30 days, attacker-repeatable for their own old consumes
for as long as fullnodes serve old transactions.

**Remediation / evidence:** - `consume_tx_valid` refuses a consume whose event `timestamp_ms` is older than `CONSUME_MAX_AGE_SECS`
  (default 432,000 s = 5 days, inside the roughly 5.5-day transaction retention of public testnet
  fullnodes) or in the future beyond a 60 s skew; a missing or malformed timestamp is not recent
  (`sui_rpc.rs::event_is_recent`). `from_lookup` refuses an age above `REDEMPTION_RETENTION_SECS`
  (30 d), so no consume outlives its redemption record.
- Decision (OQ5): bound the consume age rather than extend the retention.
- Tests: `old_or_future_or_missing_timestamps_are_not_recent`, `a_consume_older_than_the_bound_is_refused`,
  `single_use_needs_a_durable_store_and_consistent_windows`.

### F25 — `now_ms()` unwraps `SystemTime::duration_since(UNIX_EPOCH)`

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/challenge.rs:20-24`.

**Issue:** This panics only if the system clock is before 1970. With `panic = "abort"` the process
restarts, and a restart triggers F4.

**Impact:** Requires host clock misconfiguration. The RUST lens's no-panic rule is met in spirit (not
attacker-reachable).

**Remediation / evidence:** Accepted, unchanged (`challenge.rs:23-28` still unwraps). Optionally use `unwrap_or_default()` with a log.

### F26 — Startup log prints `UPSTREAM_URL`

**Severity:** Info   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `src/main.rs` (startup `tracing::info!`), `src/config.rs` (`Debug`, `check_scheme`).
**Issue:** The full upstream URL is logged at `info`. The Workers deployment treats the same value as
a secret ("so the private origin never appears in this public file"), and an operator may embed
userinfo in it.

**Impact:** Disclosure of the private origin (bypass target if the origin lock is weak) or of
credentials to anyone who can read logs.

**Remediation / evidence:** Fixed in 0.0.22 by the single option that needs no decision about whether the origin is secret: it is
never logged. The startup `info` line no longer carries `UPSTREAM_URL`, `GatewayConfig`'s `Debug` prints
`<redacted>` for the upstream and the RPC URL (an RPC provider key may sit in its path), and
`check_scheme` refuses userinfo in `UPSTREAM_URL` and `SUI_RPC_URL` (credentials belong in
`UPSTREAM_AUTH_HEADERS` / `SUI_RPC_AUTH_HEADER`), as `gateway-workers` already did. Pinned by
`debug_redacts_credentials` (private origin and a path key are absent) and `urls_must_not_carry_credentials`.

### F27 — Documentation drift (deployment targets, links, module docs)

**Severity:** Info   **Disposition:** MITIGATED (fixed in 0.0.22 except the `wrangler.toml` comment in `gateway-workers/`; commit `40a7e89`)
**Where:**

- `gateway-rust/CLAUDE.md`: "Published to GHCR" (the workflow pushes to quay.io + Docker Hub); "See
  `infrastructure/k8s/` in the vault monorepo" (no such tree in this polyrepo workspace); "`limiter`:
  per-address" (omits `ip_limiter`).
- Root `README.md:7`: links `access_gate` to `github.com/meddleware-org/vault` (should be
  `access-gate-sui`).
- `gateway-workers/wrangler.toml:3`: "Rust gateway (../gateway)" (the path is `gateway-rust`).
- `src/config.rs:215`: `env_or` doc vs behaviour (F8).

**Impact:** Misleads operators and reviewers. This is the TS lens's "accurate comments" class.

**Remediation / evidence:** Fixed: `env_or` is gone; the README documents the small-body scope and the env table. Still stale:

- `gateway-rust/CLAUDE.md` (and `AGENTS.md`): "Published to GHCR" (the workflow pushes to quay.io and
  Docker Hub), "See `infrastructure/k8s/`" (no such tree), and `limiter` described as per-address only
  (it omits `ip_limiter` and `preauth_limiter`);
- root `README.md:7` links `access_gate` to `meddleware-org/vault`;
- root `CLAUDE.md` "drop-in" row lacks the small-body caveat (F6);
- `gateway-workers/wrangler.toml:3-4` calls the Rust gateway `../gateway`.

No behavioural effect; correct each line at the next docs pass.

Update 2026-10-10 (0.0.22 docs): fixed in `gateway-rust/CLAUDE.md` (quay.io and Docker Hub, no `k8s` tree,
the three limiters), root `README.md` (the `access-gate-sui` link and the small-body caveat), root `CLAUDE.md`
(the "drop-in" caveat, the live test name) and `gateway-rust/README.md` (the `distroless/cc-debian13` base).
Still stale: `gateway-workers/wrangler.toml:3-4` calls the Rust gateway `../gateway` (a Workers-side file,
left for the Workers pass); that is why this stays MITIGATED.

### F28 — CI omissions: `--locked` on test/clippy, `cargo audit`, coverage figure, toolchain-action pin

**Severity:** Info   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `.github/workflows/rust-ci.yml` (and `crates-publish.yml` for the toolchain step).
**Issue / Impact:** Lockfile drift would not fail CI. The lens's coverage-figure requirement is unmet.

**Remediation / evidence:** Fixed in `rust-ci.yml` (CI-only; not runnable locally, YAML validated and each command run by hand):
`cargo clippy --all-targets --locked` and `cargo test --locked`; `cargo audit` is not added as a second tool
because `cargo-deny`'s `advisories` check (already green in CI, `yanked = "deny"`) reads the same RustSec
database, which the job comment now states; a coverage step runs `cargo llvm-cov --locked --summary-only`
(`cargo-llvm-cov` 0.9.1 via `taiki-e/install-action`, pinned to the v2.87.27 SHA) and writes the figure to the job
summary (informational, not a gate; local figure 90.7 % of lines); the toolchain is installed with `rustup` on the runner
instead of `dtolnay/rust-toolchain`, whose only reference is a moving `master` branch (the MSRV job and
`crates-publish.yml` likewise), so no unpinnable action remains; and a Redis service container runs
`redis_backend_round_trip` (S2).

### F29 — Image supply chain: no image vulnerability scan; unsigned private-registry mirror; `.dockerignore` gaps

**Severity:** Low   **Disposition:** MITIGATED (0.0.22; commit `40a7e89`; the private mirror and licence notices need OQ8)
**Where:**

- `.github/workflows/docker-publish.yml` (Trivy image scan before signing, merge job); `build-docker-*-private`
  jobs: `continue-on-error: true`, no cosign, no SBOM (open, OQ8).
- `gateway-rust/Dockerfile` (`Cargo.lock` copied into the runtime stage), `gateway-rust/.dockerignore`.
**Issue:**

- The IMG lens requires the scanner on the **image** with its result recorded.
- The private-registry images are a best-effort, unsigned mirror. If the cluster deploys from that
  registry, it runs unsigned images.
- `.env*` is not excluded. `COPY . .` in the builder stage would copy a local `.env` into a builder
  layer. It is not in the runtime stage, but it is in the build cache and any pushed cache.

**Impact:** Unscanned published images, and a possible unsigned deployment path.

**Remediation / evidence:** Done in 0.0.22 (CI and Docker only): `docker-publish.yml` scans the merged public image by digest with
Trivy (`scan-type: image`, `vuln,secret`, HIGH and CRITICAL with a fix fail the job) before cosign signs or
attests anything; the image ships `Cargo.lock` so the SBOM (`anchore/sbom-action`) lists the compiled crates
rather than the Debian base alone (not re-fetched: needs a published 0.0.22); `.dockerignore` now excludes
`.env*`, `*.pem`, `*.key`, `docs/` and itself; the README publishes the `cosign verify` and
`verify-attestation` commands pinned to the `docker-publish.yml` tag identity, and says the mirror is
unsigned. The scan step cannot be exercised without registry credentials (not run here). Still open, all
tied to OQ8 or a toolchain choice: the self-hosted mirror stays an unsigned best-effort copy
(`build-docker-*-private`, `continue-on-error`) until the maintainer decides the cluster pulls from quay.io by
digest; licence notices for the compiled crates are not shipped; CI compiles with `stable`, the image with the
digest-pinned `rust:1-slim`, and the two are not compared.

### F30 — Registry credentials are long-lived tokens without a recorded inventory

**Severity:** Info   **Disposition:** DEFERRED (maintainer item: `OPERATOR_TASKS.md` "Image registry credentials — record scope and rotation", before mainnet)
**Where:** `docker-publish.yml` (`QUAY_TOKEN`, `DOCKERHUB_TOKEN`, `PRIVATE_REGISTRY_TOKEN` secrets).

**Issue:** Quay and Docker Hub do not offer OIDC trusted publishing here. The base §B.2 then requires
an inventory (name, scope, holder, expiry, rotation), and none exists in the repo.

**Impact:** A token leak lets an attacker push images under the project's name. Cosign verification at
deploy is the compensating control only if the cluster verifies signatures, which is not evidenced.

**Remediation / evidence:** Unchanged: `QUAY_TOKEN`, `DOCKERHUB_TOKEN` and `PRIVATE_REGISTRY_TOKEN` are long-lived secrets with no
inventory in this repo; the scopes are visible only in the quay and Docker Hub consoles. The inventory
(name, scope, holder, expiry, rotation) is the maintainer task above; prefer robot accounts scoped to
the one repository.

### F31 — Runtime credentials have no rotation plan

**Severity:** Low   **Disposition:** DEFERRED (deployment; OQ9 — nothing is held while undeployed)
**Where:** `UPSTREAM_AUTH_HEADERS`, `SUI_RPC_AUTH_HEADER`, `REDIS_URL` (`src/config.rs`; README env
table).

**Issue:** The AUTH lens B.AUTH-1 requires a rotation cadence and compromise procedure for every held
credential. A Cloudflare Access service token also has an **expiry**. When it lapses the upstream
rejects the gateway, failing closed, which is a full outage of the paid service.

**Impact:** An unplanned outage on token expiry, and no procedure on compromise.

**Remediation / evidence:** The gateway holds no runtime credential today because it is not deployed. At deployment, fill B.AUTH-1
(below) with a rotation cadence and compromise procedure for each of `UPSTREAM_AUTH_HEADERS`,
`SUI_RPC_AUTH_HEADER` and `REDIS_URL`, and record the Access token's expiry with an alert ahead of it.
The Workers gateway's inventory (token name, expiry 2027-09-09, rotation procedure with overlap) in
`docs/networking/CLOUDFLARE.md` §2.4 is the template.

### F32 — Deployment manifests, pod security and resource limits are not in this repo

**Severity:** Info   **Disposition:** DEFERRED (deployment; tracked to the platform workspace; OQ9)
**Where:** n/a. `gateway-rust/CLAUDE.md` points to a nonexistent `infrastructure/k8s/`.

**Issue:** The IMG lens §A *Runtime user & filesystem*, *Health & resources* and *Deployment pinning*,
and the value of `TRUSTED_PROXY_HOPS`, cannot be verified.

- Behind the ingress, `TRUSTED_PROXY_HOPS=0` keys every client on the ingress IP: one shared bucket,
  so 30 challenges/min for the whole internet.
- `1` is correct only if the ingress appends `X-Forwarded-For`.

**Impact:** Unknown. These rows are marked N/A or unmet in Sections A/D.

**Remediation / evidence:** Unchanged: there are no manifests in this repo and `gateway-rust/CLAUDE.md` points to a nonexistent
tree (F27). The sizing is now known: a memory limit of at least ≈1.1 GiB at the defaults (F6). When the
gateway is deployed, add `post-bootstrap/nft-gate-gateway/` with:

- `runAsNonRoot` and `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities
  dropped, `RuntimeDefault` seccomp and `automountServiceAccountToken: false`;
- `/healthz` probes (served outside the concurrency cap);
- the memory limit above;
- the image by digest from `config/images.yaml`;
- `TRUSTED_PROXY_HOPS` matching the ingress (`0` behind an ingress shares one bucket);
- the negative origin-lock check the PROXY lens requires.

Then re-verify.

### F33 — Upstream responses above 16 MiB fail with 502

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/http_client.rs::send` (`Limited` → error → `proxy.rs` 502).

**Issue:** Responses are buffered to `MAX_RESPONSE_BYTES`. Streaming reads (e.g. a blob through the
gateway) are impossible above it.

**Impact:** None for the relay (small JSON responses). It is documented in README.

**Remediation / evidence:** Intentional; follows from the small-body scope decision (F6): there is no streaming.

### F34 — Cap-pressure eviction can drop an active lease

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/challenge.rs:103-115` (evicts the soonest-to-expire **leased** entry when the
redemption map is full).

**Issue:** At the cap (1,000,000 entries), a new lease evicts an in-flight one, and a duplicate could
then lease it.

**Impact:** It needs ~10⁶ concurrent leases. Committed entries are never evicted.

**Remediation / evidence:** Accepted at the current scale, unchanged (`challenge.rs:117-127`; the redemption eviction picks the
soonest-to-expire lease). Committed entries are never evicted.

### F35 — Positive: memory safety and panic strategy

**Severity:** Positive

- `#![forbid(unsafe_code)]` (`main.rs:2`).
- The release profile sets `overflow-checks = true`, `panic = "abort"`, `lto`, `codegen-units = 1`.
- `lock().unwrap()` (challenge store, rate limiters, ownership cache) is acceptable under
  `panic = "abort"`: a poisoned lock cannot be observed (stated per the RUST lens).
- Proptests prove the decoders never panic on arbitrary bytes; `decode_access_proof`,
  `event_is_recent` and `pass_is_usable` reject malformed input without panicking (tests above).

### F36 — Positive: signature verification matches Sui's acceptance rules

**Severity:** Positive

- Intent `[3,0,0]` ‖ BCS length ‖ message, Blake2b-256 (`blake2` 0.10.6 in 0.0.21; 0.11.0 on `main`, CI
  green, `verify.rs` unchanged).
- ed25519 via `ed25519-consensus` (ZIP-215; `ed25519-dalek` 3.0.0 is a dev-dependency used to sign
  test fixtures only).
- secp256k1 and secp256r1 reject high-S explicitly (`normalize_s().is_some()` ⇒ reject).
- The address is `blake2b(flag ‖ pk)`, normalised.
- Flags 0x03/0x05 have named constants and fail closed; 0x06 falls to `_ => false`.
- Pinned by the shared vectors (`conformance_shared_vectors`), including every negative and the
  audience-mismatch cases.

### F37 — Positive: hand-rolled gRPC-web decoder is bounded and fuzzed

**Severity:** Positive

- Checked arithmetic; varint shift < 64.
- A 4 MiB message cap.
- Compressed or truncated frames rejected.
- `grpc-status` required (header for trailers-only, else a trailer frame); a non-zero status is an
  error carrying the code (`GRPC_NOT_FOUND` drives the retry policy, F14).
- JSON lookups depth-limited to 32.
- Four proptests plus unit tests (`unframe_fails_closed_without_a_status`, …).

### F38 — Positive: outbound hygiene

**Severity:** Positive

- A 10 s connect timeout.
- Whole-request timeouts: `RPC_TIMEOUT_SECS` (15 s) per Sui call, `UPSTREAM_TIMEOUT_SECS` (600 s,
  `504`) upstream.
- `Limited` response bodies.
- webpki roots.
- `https` required unless `ALLOW_INSECURE_HTTP=1`.
- Injected auth headers replace client ones, and client `cf-access-*` fields are stripped first.
- Redirects: hyper's client follows none, and a 3xx from the upstream is now an explicit `502` with
  nothing passed on (`proxy.rs`), so credentials never leave the configured origin. There is no
  redirect test (F47).

### F39 — Positive: shared-state atomicity

**Severity:** Positive

- Nonce `GETDEL` (fails closed on error: `503`).
- Lease `SET NX PX` with an owner token (`leased:<token>`).
- Commit and release are Lua compare-and-set / compare-and-delete on that token; release never clears
  a commit or a newer holder's lease.
- 5 s Redis timeouts; connect retries with backoff.
- Failed nonce persistence ⇒ challenge 503.
- In-memory semantics mirror Redis (`redemption_release_never_clears_commit`,
  `a_stale_holder_cannot_release_or_commit_over_a_newer_lease`, …).

### F40 — Positive: client-IP rule, CORS parity and configuration validation

**Severity:** Positive

- `client_ip` never trusts the leftmost `X-Forwarded-For` (tests), and keys IPv6 by /64.
- CORS: exact allowlist, `Vary: Origin`, preflight before auth, grants on error responses (three
  router tests); upstream CORS cannot widen it (F12).
- `NFT_TYPE` is restricted to the two `access_gate` pass types.
- `GATE_ID` must be an object ID; `GATEWAY_ORIGIN` must be a canonical https origin that is not the
  upstream.
- Upstream auth headers are JSON with header-token and CRLF checks; the RPC auth header is `Name: value`.
- `Debug` is redacted (`debug_redacts_credentials`).

### F41 — Positive: release chain

**Severity:** Positive

- Every action is SHA-pinned; `permissions: contents: read` by default.
- `id-token: write` only where needed.
- crates.io trusted publishing (idempotent: an existing version is skipped).
- Both publish workflows run `rust-ci.yml` as a `verify` job (`workflow_call`), so the release gate
  equals CI (fmt, clippy, tests, cargo-deny, MSRV, Trivy config).
- Images: digest-pinned bases, `cargo chef` 0.1.78 `--locked`, `cargo build --locked`, distroless
  non-root runtime, keyless cosign at the index digest, an SPDX SBOM attestation and build provenance
  on both public registries, none `continue-on-error` (gaps against the IMG lens: F29).
- `cargo-deny` (advisories, licences, bans, sources) and an MSRV job.
- `check-versions.sh` aligns crate, npm and tag versions.
- Dependabot (`.github/dependabot.yml`): weekly, grouped cargo, docker and github-actions for this
  crate; triaged 2026-10-09.

### F42 — No method or path policy before building the upstream URL (found and fixed; not in the first pass)

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/proxy.rs` `forward` and `src/main.rs` `handle` (first pass: `format!("{}{}", upstream,
path_and_query)` for any method and any path).

**Issue:** The PROXY lens §A *Route & method policy* was not recorded in the first pass. In that code
every authenticated method (`DELETE`, `PATCH`, …) was forwarded, public paths accepted any method, and
the path was appended to the upstream URL without rejecting encoded separators, NUL, backslashes or
empty segments.

**Impact:** A paid caller could exercise relay methods and path shapes the product never uses, and
encoded-separator paths could reach the relay in a form it might interpret differently from the
gateway. Low, because the caller must hold a paid pass and the relay is not trusted to be the only
control.

**Remediation / evidence:**

- `proxy::FORWARDED_METHODS` = `GET`, `HEAD`, `POST`, `PUT`: other methods get `405` before any
  verification work (`handle`) and again in `forward`; public paths are `GET`/`HEAD` only
  (`405` with `Allow: GET, HEAD`; OQ7 decided).
- `headers::is_safe_path` refuses `%2f`, `%5c`, `%00`, `%2e%2e`, backslashes, control characters,
  empty segments (`//`) and `..` segments with `400 invalid path` before the upstream URL is built;
  `PUBLIC_PATHS` entries are validated at startup (plain absolute paths). The upstream URL is the
  configured origin plus the validated path and the original query.
- Tests: `headers::tests::unsafe_paths_are_refused`,
  `main::tests::public_paths_are_read_only_and_gated_methods_are_listed`,
  `config::validation_tests::origins_and_public_paths_are_validated`. The `400` itself has no
  router-level test (F47).

### F43 — No `Via` loop marker; only the literal self-origin is refused

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/config.rs` (`UPSTREAM_URL must not be this gateway (request loop)`), `src/headers.rs`
(`via` is stripped from the request and never set).

**Issue:** The PROXY lens §A *Loop & self-reference* asks that a `Via` or loop-marker check refuse a
request that has already passed through. The gateway refuses an `UPSTREAM_URL` whose origin equals
`GATEWAY_ORIGIN` (test `audience_binding_inputs_are_required_and_canonical`), but an upstream hostname
that resolves back to the gateway would not be caught and no marker is added.

**Impact:** A loop needs an operator to point the upstream hostname at the gateway itself. Gated paths
would be refused for want of a proof on the second hop, and public paths are bounded by the per-IP
limiter and the concurrency cap. Operator-only misconfiguration, not attacker-reachable.

**Remediation / evidence:** Accepted, as in the Workers audit (F43 there). If the gateway is ever
offered white-label with operator-chosen upstreams, add a `Via`/marker check that returns `508`;
`registry-auth-proxy` 0.1.6 has one.

Update 2026-10-10: left open for parity. The single fix is a `Via`/marker check that returns `508` in both
gateways at once; doing it only here would make the two decide differently, and the Workers side is outside
this change. Recommendation: add it to both when a white-label deployment with operator-chosen upstreams is
planned.

### F44 — Upstream error statuses and bodies pass through to the client

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/proxy.rs` (`Ok(resp)` for every non-3xx status returns the upstream status and body
with filtered headers); `src/main.rs::redeem_and_forward` (a non-2xx releases the lease and returns the
response as is).

**Issue:** The PROXY lens §A *Error mapping* prefers fixed `502`/`503`/`504` bodies without upstream
detail. For 4xx/5xx answers from the relay the gateway returns the relay's status and body (headers
filtered, F12/F13); an upstream `WWW-Authenticate` is not stripped.

**Impact:** The relay's own error JSON (for example a tip-payment or size rejection) reaches the
client. The relay is first-party, its errors carry no secret, and the clients (`walrus-client`) need
them to react. Network failures, timeouts, redirects (including an Access login redirect after the
service token expires) and store errors are mapped to fixed `502`/`504`/`503` bodies, so no
interactive-login challenge is relayed.

**Remediation / evidence:** Intentional, as in the Workers audit (F44 there). A failed upload (non-2xx)
releases the lease so the consume is not lost. Revisit if a third-party upstream is ever fronted.

### F45 — The env-gated live test fails: its fixed historic transaction was pruned by the public fullnode (found 2026-10-10)

**Severity:** Low   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`; OQ10 decided)
**Where:** `src/sui_rpc.rs::tests` (hermetic fixtures, `live_*`); `README.md` "Build and test".
**Issue:** The test replays one fixed `access_gate::consume` on the **superseded** testnet package
`0xa55789d7…886d41` and gate `0xfd6c3b2a…0ab8a6` (digest `8br5PGrz…TgUkP`). Using the superseded ids is
deliberate and correct: both packages are immutable since 2026-10-09 (upgrade caps burned), so the
historic transaction is a fixed fixture, and `574fe70` updated the comment to say so. Public fullnodes
prune old checkpoints (the comment already warns of it). On 2026-10-10 the test fails at its first
assertion: a hand-built gRPC-web `GetTransaction` for the digest returns `grpc-status: 5` (NOT_FOUND)
with `x-sui-lowest-available-checkpoint: 391126037`, so `consume_tx_valid` returns `Ok(false)`
(fail closed, as designed).

**Impact:** This is the only check of the hand-rolled gRPC field numbers against a real fullnode, and it
is not in CI (`#[ignore]`). With it red, protobuf field-number or JSON-shape drift in `sui.rpc.v2`
would not be noticed. It is not a defect in the gateway code, and it does not affect the live Workers
gateway, which has its own integration test (3 passing on 2026-10-09).

**Remediation / evidence:** Decided and fixed in 0.0.22 (OQ10). The fixed historic digest is gone from the source. The wire format is
pinned by hermetic gRPC-web fixtures that need no network and no transaction, using literal field numbers
(not the constants): `consume_verification_reads_a_response_in_the_pinned_wire_format`,
`gate_read_uses_the_pinned_get_object_wire_format`, the paged `ListOwnedObjects` tests and
`only_not_found_is_retried_and_ends_as_denied`. The real-node check stays optional and `--ignored`:
`live_gate_and_ownership_requests_are_accepted` needs no fixture (it reads the long-lived testnet relay gate
and lists a pass-less address, so it cannot age out) and `live_consume_tx_valid` takes a recent consume from
`NFT_GATE_LIVE_DIGEST`, `_SENDER`, `_GATE`, `_PACKAGE` (and `_RPC`), documented in the README, and says so
and returns when no digest is given. Both passed on 2026-10-10 against `fullnode.testnet.sui.io` (a consume on
the current relay gate found with the GraphQL events query), which also confirmed the new `effects.status`
field numbers (F21). A localnet path was not chosen (it needs a fresh `access_gate` publication per run)
and an archival endpoint is an operator dependency.

### F46 — The lease startup check ignores the body-read time

**Severity:** Low   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `src/config.rs` (`from_lookup`: the lease check); `src/main.rs::redeem_and_forward` takes the lease before `proxy::forward` reads the body.
**Issue:** The PROXY lens §A *Admission state* wants the claim's lifetime to exceed the maximum request
time, checked at startup. The maximum request time here is the body-read deadline plus the upstream
deadline, but only the latter is checked. `BODY_READ_TIMEOUT_SECS` can be set up to 3,600 s, and
`REDEMPTION_LEASE_TTL_SECS` down to just above `UPSTREAM_TIMEOUT_SECS`.

**Impact:** With the defaults (30 + 600 < 900) the lease cannot lapse mid-request. An operator who
raises the body deadline or lowers the lease could let it lapse; a duplicate request would then lease
again, and both uploads would reach the relay, although only one commit succeeds (the other is
`Lost` → 502). Operator misconfiguration only.

**Remediation / evidence:** Fixed in 0.0.22. `from_lookup` requires `REDEMPTION_LEASE_TTL_SECS > UPSTREAM_TIMEOUT_SECS +
BODY_READ_TIMEOUT_SECS` (the lease is taken before the body is read and held until the upstream answers).
The defaults hold (900 > 600 + 30). Pinned by `single_use_needs_a_durable_store_and_consistent_windows`
(upstream 600 + body 400 refused against the default 900; 500 + 399 accepted; 500 + 400 refused at the edge).
README and the module docs state the rule.

### F47 — Test gaps against the RUST and PROXY lens coverage requirements

**Severity:** Info   **Disposition:** RESOLVED (0.0.22; commit `40a7e89`)
**Where:** `src/router_tests.rs`, `src/testkit.rs`, `src/main.rs` tests, `src/sui_rpc.rs` tests (117 tests, 3 ignored, in 0.0.22).
**Issue:** Present: store-level lease, commit, release and expiry; header policy and path unit tests;
router tests for CORS, public methods, the pre-auth limit and a stalled head; config validation; the
shared vectors. Missing (PROXY lens §C, RUST lens §C):

- a dispatcher/router test of the `409` bodies (`redeemed`, `leased`), the `503` store-error mapping and
  the `502` commit-failure and lost-lease outcomes (S1);
- a redirect test (a recording upstream asserting that no credential reaches a `Location`);
- a router-level `400` for an unsafe path and the `405` method list on a gated path with a fake chain;
- a stalled-body test (`408`), a chunked over-cap body (`413`), a stalled-upstream test (`504`), the
  connection cap and the shutdown grace bound;
- an upstream that answers `Access-Control-Allow-Origin: *` through the router (F12);
- the retry loop of `consume_tx_valid` and the Redis scripts in CI (`redis_backend_round_trip` is
  env-gated, S2);
- a coverage tool and figure (F28).

**Impact:** A regression in these paths would pass CI. Most are covered by construction or by unit
tests of the pieces.

**Remediation / evidence:** Fixed in 0.0.22 with `src/router_tests.rs` (the whole `build_router` stack, real signed proofs, a scripted
local Sui node and a recording upstream, `src/testkit.rs`): `a_spent_or_in_flight_consume_is_a_coded_409`
(`redeemed`, `leased`), `a_failed_upload_releases_the_consume_for_a_retry`,
`a_lease_lost_before_the_commit_is_a_502_not_a_success`, `a_broken_state_store_is_a_503_never_a_conflict`
(a RESP stub that fails every command but `GETDEL`: challenge and redemption lease), the 403/502
chain mapping in `a_failed_or_unreadable_consume_never_reaches_the_upstream`,
`the_upstream_sees_the_request_but_no_credential_and_its_cors_grants_are_dropped` (an upstream
`ACAO: *`), `an_upstream_redirect_is_refused_and_never_followed` (the redirect target receives nothing),
`unsafe_paths_and_oversize_or_stalled_bodies_are_refused_before_the_upstream` (400, declared and chunked 413,
408) and `a_stalled_upstream_is_a_504_at_its_deadline`; in `main.rs`,
`the_connection_cap_holds_extra_clients_until_a_slot_frees` and `shutdown_gives_in_flight_requests_a_bounded_grace`;
in `sui_rpc.rs`, the retry loop (`only_not_found_is_retried_and_ends_as_denied`). CI now runs the Redis
round trip against a service container (S2) and prints a coverage figure (F28). The 405 method list on a gated
path was already pinned. Not done: shared `headerExtraction` / `redemptionConflict` vectors, which belong to
`@meddleware/nft-gate-client` (S1).

### F48 — Positive: audience-bound proofs, owner-bound redemption and strict configuration

**Severity:** Positive

- The v2 message binds origin, gate, network, nonce and consume digest and is rebuilt from the
  gateway's own configuration; the vectors (with a negative per bound field) come from the client
  package and pass here.
- Leases carry a random owner token; commit and release are compare-and-set; a lapsed holder is told
  `502` and cannot disturb the next one; the lease outlives the upstream deadline by a startup check.
- Hop-by-hop and spoofable fields are stripped both ways, upstream CORS and cookies never reach the
  client, redirects are not followed, and methods and paths are allowlisted.
- Configuration is strict: a typo is a startup error, not a weaker mode; `SINGLE_USE` without Redis is
  refused.

---

## Section A — Invariant verification matrix

| # | Invariant | Enforced / asserted at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Any decode, signature, nonce, chain or store error denies | `verify.rs::verify_access_request`; `main.rs::handle` | `denies_bad_signature`, `denies_replayed_nonce`, `get_object_response_without_object_fails_closed`, `rejects_everything_outside_the_field_grammar` | HOLDS |
| I2 | A nonce is consumed exactly once, before any chain call | `verify.rs:326` (`take_if_valid`); `challenge.rs` (in-memory flag / Redis `GETDEL`) | `nonce_valid_once_then_used`, `denies_replayed_nonce`, `expired_nonce_rejected` | HOLDS |
| I3 | Signatures verified as Sui accepts them; 0x03/0x05/0x06 fail closed | `verify.rs:88-202` | `conformance_shared_vectors` (incl. negatives + ZIP-215), `multisig_and_zklogin_flags_fail_closed` | HOLDS |
| I4 | The address is normalised before every comparison | `verify.rs::normalize_address`; `sui_rpc.rs::same_address` | vectors `addressNormalization`; `compares_types_and_ids_in_normalised_form` | HOLDS |
| I5 | Consume binding: exact `<pkg>::access_gate::AccessConsumedEvent`, sender == signer, `gate_id` == `GATE_ID`, age ≤ `CONSUME_MAX_AGE_SECS`, tx succeeded | `sui_rpc.rs::response_has_consume`, `event_is_recent` | `matches_a_valid_consume_for_sender_and_gate`, `rejects_a_look_alike_package_consume_event`, `rejects_wrong_sender_gate_or_event_type`, `a_consume_older_than_the_bound_is_refused` | HOLDS (success from the effects status, F21; `only_a_successful_transaction_can_be_a_consume`, router 403) |
| I6 | Single use: a consume digest redeems exactly once; committed never cleared; interrupted upload releases; owner-bound | `main.rs::redeem_and_forward`; `challenge.rs` lease/commit/release | `redemption_*` and `a_stale_holder_…`, `a_commit_after_the_lease_lapsed_is_lost` store tests; router tests `a_spent_or_in_flight_consume_is_a_coded_409`, `a_failed_upload_releases_the_consume_for_a_retry`, `a_lease_lost_before_the_commit_is_a_502_not_a_success` (F47) | HOLDS — F2, F3 |
| I7 | Ownership mode admits only a usable pass for the gate | `sui_rpc.rs::pass_is_usable`, `response_has_owned`, `owns_nft_live` | `only_usable_passes_count`, `an_exhausted_receipt_is_not_ownership`, `owned_response_matches_gate`, `ownership_is_read_across_pages_until_a_usable_pass`, `an_endless_list_is_an_error_after_the_page_bound` | HOLDS — every page up to 100, error past it (F17); usable-only is F7 |
| I8 | A paused gate with `pause_blocks_access` admits no one; unrecognised gate JSON denies | `verify.rs:334-342`; `sui_rpc.rs::gate_blocks_access` | `denies_owner_while_gate_paused_with_access_policy`, `single_use_paused_gate_denies_before_redemption`, `unrecognised_gate_json_is_an_error_not_unpaused` | HOLDS (F15) |
| I9 | Body cap: declared length rejected before reading; read bounded by the cap and a deadline | `proxy.rs::forward`, `declared_too_large` | `declared_length_over_cap_is_rejected_up_front` (chunked path and the 408 untested) | HOLDS (code-only for chunked and the deadline) |
| I10 | Memory bounded by concurrency × caps | `main.rs::build_router` (`load_shed` + `concurrency_limit`) | `router_serves_healthz_and_routes_through_the_concurrency_layer` | HOLDS (code-only) — sizing F6, F32 |
| I10b | Inbound header and body reads are time-bounded; connections capped | `main.rs::serve` (`header_read_timeout`, `MAX_CONNECTIONS`); `proxy.rs` (`BODY_READ_TIMEOUT_SECS`) | `the_server_drops_a_client_that_never_finishes_its_headers` | HOLDS (code-only for the body deadline and the cap) — F5 |
| I11 | Every outbound call has a timeout and a bounded response | `http_client.rs::send`, `proxy.rs` (504) | — | HOLDS (code-only) |
| I12 | gRPC-web decoding bounded; missing `grpc-status` is an error | `grpc.rs` | 4 proptests; `unframe_*` tests | HOLDS |
| I13 | Store ops atomic; store unavailability fails closed (503, never a conflict) | `challenge.rs` Redis impl; `main.rs` | `redis_backend_round_trip` (ignored; env-gated) | HOLDS (code-only) |
| I14 | Pre-auth limits keyed on a trusted client address (IPv6 by /64); gated limited before verification | `main.rs::client_ip`, `rate_key`, `handle` | `client_ip_*`, `ipv6_clients_are_keyed_by_their_slash_64`, `gated_requests_are_rate_limited_per_ip_before_verification` | HOLDS (F9; limiter map not swept, F10) |
| I15 | Inbound `Authorization`/`X-Access-Proof`/`cf-access-*` stripped; injected headers replace client ones | `headers.rs::upstream_request_headers`; `http_client.rs::insert_auth` | `request_strips_hop_by_hop_connection_named_credentials_and_spoofable_fields`, `upstream_auth_headers_are_json_only` | HOLDS |
| I16 | Hop-by-hop (and `Connection`-named) fields stripped both directions; cookies stripped from responses (`SECURITY.md` inv. 6) | `headers.rs` | `request_strips_…`, `response_strips_hop_by_hop_cookies_and_upstream_cors` | HOLDS (F13) |
| I17 | CORS: exact allowlist only, `Vary: Origin`, preflight before auth, on errors; upstream CORS never survives | `main.rs::cors`, `headers.rs` | three `cors_*` tests; `response_strips_…`; router test `the_upstream_sees_the_request_but_no_credential_and_its_cors_grants_are_dropped` | HOLDS (F12) |
| I18 | No secrets in logs or `Debug` | `config.rs` redacting `Debug`; `main.rs` | `debug_redacts_credentials`, `urls_must_not_carry_credentials` | HOLDS — the upstream and RPC URLs are never logged or printed (F26) |
| I19 | No `unsafe`; no panic on attacker input | `main.rs:2`; release profile | proptests; `rejects_an_oversized_token_before_decoding`, `rejects_everything_outside_the_field_grammar` | HOLDS |
| I20 | SIGTERM handled; drain bounded | `main.rs::shutdown_signal`, `serve` (`SHUTDOWN_GRACE_SECS`) `shutdown_gives_in_flight_requests_a_bounded_grace` | HOLDS — F19 |
| I21 | Misconfiguration fails at startup | `config.rs::from_lookup` | `validation_tests::*` | HOLDS (F8) |
| I22 | Wire parity with `gateway-workers` | `conformance/vectors.json` (nft-gate-client) | `conformance_shared_vectors` | HOLDS (vector-covered fields; pagination and the effects-status check now match, F17, F21) |
| I23 | The proof is bound to the intended audience | `proof.rs::personal_message`; `verify.rs` (rebuilt from `cfg`) | `refuses_a_proof_made_for_another_gateway_gate_or_network`, vectors `audienceMismatch` | HOLDS (F1) |
| I24 | Single-use redemption state survives restarts and replicas | `config.rs` (Redis required, or `ALLOW_VOLATILE_REDEMPTIONS`) | `single_use_needs_a_durable_store_and_consistent_windows` | HOLDS (F4) |
| I25 | Only listed methods and safe paths are forwarded; public paths are `GET`/`HEAD` | `main.rs::handle`, `proxy.rs::FORWARDED_METHODS`, `headers.rs::is_safe_path` | `public_paths_are_read_only_and_gated_methods_are_listed`, `unsafe_paths_are_refused`, router `unsafe_paths_and_oversize_or_stalled_bodies_are_refused_before_the_upstream` | HOLDS (F42) |
| I26 | A request that has already passed through the gateway is refused | `config.rs` (literal self-origin only) | `audience_binding_inputs_are_required_and_canonical` | HOLDS (code-only) for the literal case; no `Via` marker — F43 |
| I27 | Upstream reachable only via the gateway (origin lock), verified negatively | the operator's upstream (outside this repo) | — | GAP — see F32 (deployment, OQ9) |
| I28 | Upstream redirects are not followed; a 3xx is `502` | `proxy.rs::forward`; hyper client `an_upstream_redirect_is_refused_and_never_followed` | HOLDS |
| I29 | Upstream and store failures map to fixed `502`/`503`/`504`; a store outage is never a conflict | `proxy.rs`, `main.rs::redeem_and_forward` | `unframe_*` (RPC side); router tests for `409`, `503`, `502`, `504`, `403` (F47) | HOLDS — F2, F44 |
| I30 | The redemption lease outlives the longest request (checked at startup) | `config.rs` (lease > `UPSTREAM_TIMEOUT_SECS` + `BODY_READ_TIMEOUT_SECS`) | `single_use_needs_a_durable_store_and_consistent_windows` | HOLDS (F46) |
| I31 | The hand-rolled gRPC field numbers still match a real fullnode | `sui_rpc.rs` constants | hermetic literal-field-number fixtures (CI); `live_*` (`--ignored`, fresh consume from `NFT_GATE_LIVE_*`) | HOLDS (F45) |

---

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

`Cargo.lock` is committed (235 packages at `367e673`; 228 in the first pass). `deny.toml`:

- `yanked = "deny"`, `unmaintained = "all"`;
- a licence allowlist;
- crates.io-only sources.

`cargo-deny-action` runs in CI and was green on `main` (Rust CI of 2026-10-09T17:52Z, `85b18e1`).
`cargo audit` is not run as a second tool: the `advisories` check reads the same RustSec database (F28); the RUST lens (2026-10-08) names both. There is no local cargo-deny or
cargo-audit binary in the review environment and GitHub Dependabot security alerts are disabled for the
repository, so the CVE status is as reported by the last CI run, not re-measured here. Dependabot
version updates are configured and were triaged on 2026-10-09 (Scope).

| Dependency | Pinned version (lockfile) | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `axum` | 0.7.9 | every request (router, extractors) | cargo-deny (CI) | 0.8.x current; the accept loop is a hyper `http1::Builder`, not `axum::serve`, so it sets its own timer (F5) |
| `hyper` / `hyper-util` | 1.11.1 / 0.1.21 | server + client | cargo-deny (CI) | client does not follow redirects; HTTP/1 only |
| `hyper-rustls` / `rustls` / `webpki-roots` | 0.27.10 / 0.23.45 / 1.0.9 | TLS to RPC + upstream | cargo-deny (CI) | baked-in roots; rebuild to refresh |
| `tokio` / `tower` | 1.53.2 / 0.5.3 | runtime; load shedding | cargo-deny (CI) | |
| `ed25519-consensus` | 2.1.0 | ed25519 verify path | cargo-deny (CI) | ZIP-215 |
| `k256` / `p256` / `ecdsa` | 0.13.4 / 0.13.2 / 0.16.9 | ECDSA verify path | cargo-deny (CI) | low-S enforced explicitly. The 0.14 major was declined 2026-10-09 (PRs #4, #6 closed); the repo's `dependabot.yml` carries no `ignore` entry, so an ignore, if set, lives on the GitHub side and is not verifiable here |
| `blake2` / `sha2` | 0.10.6 (0.11.0 on `main`, `85b18e1`, Dependabot) / 0.10.9 (+0.9.9, 0.11.0 transitive) | intent hash, address | cargo-deny (CI) | the 0.11 bump changed only `Cargo.toml`/`Cargo.lock`; CI (vectors included) green. The 0.0.21 crate and image still carry 0.10.6 |
| `redis` | 0.27.6 (`script`, `connection-manager`) | Redis backend — fails **closed** | cargo-deny (CI) | `GETDEL` needs Redis ≥ 6.2 / Dragonfly |
| `rand_core` (OsRng) | 0.6.4 | nonce and lease-token generation | cargo-deny (CI) | 24-byte tokens |
| `serde_json` / `base64` | 1.0.151 / 0.22.1 | proof decode | cargo-deny (CI) | token capped at 4096 B before decode |
| `proptest` (dev) / `ed25519-dalek` (dev) | 1.11.0 / 3.0.0 | tests only | — | dalek 3.0.0 merged 2026-10-09 (`367e673`); signs fixtures only |
| Sui fullnode (`SUI_RPC_URL`) | operator-chosen; public `fullnode.<net>.sui.io:443` | every gated request — fails **closed** (502) | n/a | gRPC-web; `SUI_RPC_AUTH_HEADER` optional; prunes old transactions (F45) |
| Redis / Dragonfly | operator-run | challenge + gated (when set) — fails **closed** (503) | n/a | required for `SINGLE_USE` |
| Upstream (relay) | operator-run | gated + public paths — 502/504 | n/a | origin lock not verifiable here (F32) |
| Base images | `rust:1-slim@sha256:4cd8…`; `distroless/cc-debian13:nonroot@sha256:e792…` (main) | build/runtime | Trivy image scan before signing (0.0.22, F29) | Dependabot docker group |
| `cargo-chef` | 0.1.78 `--locked` | build | — | |
| Image scanner | Trivy `v0.74.0`: `config` on the Dockerfile (CI) and `image` on the merged digest before signing (publish) | CI, publish | config scan clean; image scan runs from the next tag | F29 |

**Sui client lens rows:**

- **Sui SDK:** none (hand-rolled), so the ADR-0001 SDK baseline does not apply.
- **Transport:** gRPC-web only.
- **Conformance vectors:** `conformance/vectors.json` (published by `@meddleware/nft-gate-client`,
  copied by `scripts/sync-vectors.mjs`), asserted by `verify::tests::conformance_shared_vectors` here
  and by `gateway-workers/test/conformance.test.ts`.

**Walrus lens rows:** the upload relay is the upstream. The gateway's fail mode for uploads is
**closed**: no proof, no upload.

**AUTH lens rows:** there are no IdP components, no JWT/OIDC libraries and no session store. The one
third-party API reached with a held credential is the upstream origin (Cloudflare Access): when that is
unavailable or the token is rejected, the gateway returns 502 (closed); an Access login redirect is a
`502` too (F44).

### B.2 Publish authority, capabilities & secret custody

| Authority / capability / secret | Where minted / held | Custody | Gates | Immutability / rotation plan |
| --- | --- | --- | --- | --- |
| crates.io publish | `crates-publish.yml` (tag `v*`) | GitHub OIDC → crates.io trusted publishing | crate releases | n/a (no token) |
| quay.io push | `QUAY_USERNAME`/`QUAY_TOKEN` secrets | GitHub Actions secrets | image releases | **not recorded (F30, `OPERATOR_TASKS.md`)** |
| Docker Hub push | `DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN` | GitHub Actions secrets | image releases | **not recorded (F30)** |
| Private registry push | `PRIVATE_REGISTRY_USERNAME`/`PRIVATE_REGISTRY_TOKEN` | GitHub Actions secrets | best-effort mirror | **not recorded (F30)** |
| cosign keyless identity | Fulcio cert for the workflow | GitHub OIDC | image signatures, SBOM, provenance | n/a |
| `UPSTREAM_AUTH_HEADERS` | operator → pod env (when deployed) | k8s Secret (manifest not in repo) | upstream origin lock | nothing held today; write at deployment (F31) |
| `SUI_RPC_AUTH_HEADER` | operator → pod env (when deployed) | k8s Secret | RPC quota | same (F31) |
| `REDIS_URL` | operator → pod env (when deployed) | k8s Secret | nonce + redemption state | same (F31) |

On-chain capabilities: none (the gateway holds no `AdminCap` and signs nothing).

#### CI & release integrity

| Item | Holds? | Evidence |
| --- | --- | --- |
| Actions pinned | Yes | every `uses:` is a 40-char SHA (Dependabot's github-actions group keeps them current); the toolchain comes from `rustup` on the runner, so no unpinnable `dtolnay/rust-toolchain` remains (F28) |
| Least privilege | Yes | top-level `contents: read`; `id-token: write` only on crates publish and image sign/attest jobs; `attestations: write` only in the merge job |
| OIDC trusted publishing | Partly | crates.io OIDC; registry pushes use tokens with no inventory (F30) |
| Tag-gated, idempotent publish | Yes | `on: push: tags: v*`; crates publish skips an existing version; `check-versions.sh` enforces tag == crate == npm |
| Release gate equals CI | Yes | `docker-publish.yml` and `crates-publish.yml` run `rust-ci.yml` as a `verify` job (`workflow_call`) |
| Automated dependency updates | Yes | `.github/dependabot.yml` covers cargo and docker (`/gateway-rust`), npm and github-actions; weekly, grouped; triaged 2026-10-09 |
| Container images | Partly | per IMG lens: signed, SBOM and provenance on public registries; image scanned before signing and a published verification command (0.0.22); the private mirror stays unsigned (F29, OQ8) |
| Secrets never echoed | Yes | no `set -x`; secrets passed via `with:`/`env:` only |
| Real funds are manual | N/A | no job spends funds or signs on-chain |
| Test-only modes | N/A | no test-only build mode in the Rust binary (`#[cfg(test)]` only) |

### B.RS-1 Build & release

| Requirement | Holds? | Evidence |
| --- | --- | --- |
| `cargo fmt --check` in CI | Yes | `rust-ci.yml` |
| `cargo clippy --all-targets --locked -- -D warnings` in CI | Yes | `rust-ci.yml` |
| `cargo audit` and `cargo deny` in CI | Yes — deny, whose advisories check uses the RustSec database `cargo audit` reads (F28); coverage figure in the job summary | `rust-ci.yml` |
| MSRV job checks `rust-version` | Yes | `msrv` job, toolchain 1.88, `cargo check --locked` |
| Image per IMG lens | Mostly | B.IMG-1, F29 (private mirror, licence notices) |
| Crates via trusted publishing, no `--allow-dirty` | Yes | `crates-publish.yml` (`cargo publish --locked`) |

### B.IMG-1 Publish & attestation

| Requirement | Holds? | Evidence |
| --- | --- | --- |
| Keyless cosign signature at the index digest | Yes (public registries) | `docker-publish.yml` "Sign images (keyless)"; not re-verified here |
| SBOM as a signed attestation | Yes (content to verify on the next tag) | `anchore/sbom-action` SPDX → `cosign attest --type spdxjson`; the image now carries `Cargo.lock`, so the crates are listed (F29) |
| Build provenance | Yes | `actions/attest-build-provenance` ×2, `push-to-registry: true` |
| No `continue-on-error` on these steps | Yes | the merge job has none; only the private-mirror jobs carry it |
| Best-effort mirrors listed | Yes (here) | self-hosted registry, unsigned (F29) |
| Scan before sign (`trivy image`) | Yes (0.0.22; first exercised by the next tag) | `docker-publish.yml` "Scan the published image (Trivy)" precedes "Sign images" |
| Published `cosign verify` command pinning the workflow identity | Yes (0.0.22) | `gateway-rust/README.md` "Verify a published image" |

### B.SC-1 ID-constant trace

| Location | Network | Value | original-id / published-at | Matches latest on-chain (evidence) |
| --- | --- | --- | --- | --- |
| `gateway-rust/src/sui_rpc.rs` (live test defaults) | testnet | `0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9` | original-id | Matches the 2026-10-09 publication (`access-gate-sui/Published.toml`, `gateway-workers/wrangler.toml`). As of 0.0.22 the superseded `0xa55789…` package and its fixed consume are no longer in the source; the live defaults name the current package and are overridable (`NFT_GATE_LIVE_PACKAGE`) (F45) |
| `gateway-rust/src/sui_rpc.rs` (live test default gate) | testnet | gate `0x316f1bf9764db352e925bb598aff44ea77be4ab652f0bd2eb3fdcc0a378faddc` | object | The current relay gate (`gateway-workers/wrangler.toml`; read live by the passing `live_gate_and_ownership_requests_are_accepted`, 2026-10-10) |
| Operator env `NFT_TYPE` / `GATE_ID` / `GATEWAY_ORIGIN` / `NETWORK` | any | not in repo | original-id | not verifiable — no deployment |

The gateway uses the package id only as a **type prefix** (original-id), never as a call target, so the
SC-M1 published-at half is N/A. No production constant exists in this repo: the superseded ids are
confined to one env-gated test and recorded as such (maintainer decision: keep them, the package is
immutable). The consumer-side ids of the live deployment (`wrangler.toml`) are traced in the Workers audit.

### B.SC-2 Coupling table

N/A — the gateway builds no PTBs. The coupling it does have is read-side:

| Move item | Reader | Test |
| --- | --- | --- |
| `AccessConsumedEvent { nft_id, gate_id, nonce, consumer, uses_after, timestamp_ms }` | `response_has_consume` (`gate_id`, envelope `sender`, `timestamp_ms`) | `matches_a_valid_consume_for_sender_and_gate`, `a_consume_older_than_the_bound_is_refused` + env-gated `live_consume_tx_valid` (**failing: pruned fixture, F45**) |
| `Gate { paused, policy: GatePolicy { pause_blocks_access, … } }` | `gate_blocks_access` | `gate_blocks_only_when_paused_and_policy_opts_in`, `unrecognised_gate_json_is_an_error_not_unpaused` |
| `AccessNFT`/`SoulboundAccessNFT { data: AccessData { gate_id, variant, … } }` | `pass_is_usable`, `response_has_owned` (`gate_id`, `@variant`, `uses_remaining`) | `only_usable_passes_count`, `an_exhausted_receipt_is_not_ownership`, `owned_response_matches_gate` |

### B.SC-3 Cross-implementation parity

The parity table's home is `gateway-workers-audit.md` §B.SC-3; it covers both implementations, so it
is not duplicated here. Rows where this crate differs from, or the home table misstates, the Rust column
(checked against `367e673`):

| Behaviour | Divergence | Tracked |
| --- | --- | --- |
| Owned-object pagination | same since 0.0.22: both read every page, bounded at 100 pages (Rust: `scan_owned`; Workers: `MAX_OWNED_PAGES`); an overlong list is a chain error in both | F17 |
| Consume success check | same since 0.0.22: both require the effects status to be success (Rust: `effects_succeeded`; Workers: `status.success`) | F21 |
| Redemption conflict / store error | same vocabulary and statuses (`409` with `code`, `503`); dispatcher-level tests exist here since 0.0.22 (`router_tests.rs`) | F2, F47 |
| Public-path limit and cache | Rust: shares `ip_limiter` (`CHALLENGE_RATE_LIMIT_PER_MIN`, 30) with `/v1/challenge`, no cache; Workers: own `PUBLIC_RATE_LIMIT_PER_MIN` (120) + edge cache | Suggestion S9 |
| Body handling | Rust buffered (small-body scope); Workers streamed | F6 |
| Redemption backend | Rust: Redis (required for `SINGLE_USE`) or in-memory for development; Workers: Durable Object | F4 |
| `Via` loop marker | neither adds one | F43 |

All other rows of the home table (message bytes, proof decode, ed25519/ECDSA rules, flags, address
normalisation, header extraction, verification order, event type and binding, retry policy, usable-pass
check, pause parse, limits, strip lists, methods and paths, config validation, CORS, lease semantics,
redirects, timeouts) match this crate's code.

### B.PX-1 Route & header policy

| Route / path | Methods | Auth | Forwarded request fields | Stripped (both ways) | Response fields kept | Cache |
| --- | --- | --- | --- | --- | --- | --- |
| `/healthz` | any (answered locally, outside the concurrency cap) | none | not forwarded | n/a | `200 ok` | none |
| `OPTIONS` (any path) | `OPTIONS` | none | answered locally, before auth | n/a | CORS grants | none |
| `GET /v1/challenge` | `GET` | none; `ip_limiter` 30/min per client IP | answered locally | n/a | `{ nonce, expiresAt }` (`503` if the store fails) | none |
| `PUBLIC_PATHS` (`/v1/tip-config`) | `GET`, `HEAD` (else 405 + `Allow`) | none; `ip_limiter` 30/min per client IP (shared with the challenge, S9) | client fields minus the strip list; plus the injected upstream headers | request: hop-by-hop, `Connection`-named, `host`, `authorization`, `x-access-proof`, `content-length`, `cookie`, `forwarded`, `via`, `x-forwarded-for/host/proto`, `x-real-ip`, `cf-access-*`; response: hop-by-hop, `Connection`-named, `content-length`, `set-cookie(2)`, `alt-svc`, `access-control-*` | all other upstream fields; gateway CORS added | none |
| every other path (gated) | `GET`, `HEAD`, `POST`, `PUT` (else 405 before verification) | access proof v2 + live chain read + redemption lease; `preauth_limiter` 120/min per IP before verification, 30/min per address after | as above, query included | as above | as above; 3xx → 502; non-2xx passes through (F44) | never cached |
| unsafe path (`%2f`, `%5c`, `%00`, `%2e%2e`, `\`, control characters, `//`, `..`) | any | — | refused `400 invalid path` before the upstream URL is built | n/a | n/a | none |

### B.PX-2 Limits

| Limit | Value | Where enforced | Test |
| --- | --- | --- | --- |
| header-read timeout · body-read deadline · idle timeout | 10 s (`HEADER_READ_TIMEOUT_SECS`, also bounds keep-alive idle) · 30 s (`BODY_READ_TIMEOUT_SECS`, `408`) · the header timeout | `main.rs::serve`; `proxy.rs::forward` | `the_server_drops_a_client_that_never_finishes_its_headers`; router test for the `408` body deadline (F47) |
| request body cap (declared / streamed) | 262,144 B (`MAX_BODY_BYTES`); declared → `413` before reading; read capped at the same size (buffered) | `proxy.rs::forward` | `declared_length_over_cap_is_rejected_up_front`; router tests for declared and chunked `413` |
| concurrent connections / in-flight forwards | 1,024 connections (`MAX_CONNECTIONS`); 64 in-flight requests (`MAX_CONCURRENT_REQUESTS`, `503 gateway overloaded`); memory ≈ 64 × (2 × body cap + 16 MiB) ≈ 1.03 GiB | `main.rs::serve`, `build_router` | `router_serves_healthz_and_routes_through_the_concurrency_layer`, `the_connection_cap_holds_extra_clients_until_a_slot_frees` |
| upstream connect · response · total deadline | 10 s connect · (headers and body together) · 600 s total (`UPSTREAM_TIMEOUT_SECS`, 1–3600, `504`) | `http_client.rs::send` | `a_stalled_upstream_is_a_504_at_its_deadline` |
| Sui RPC per call | 15 s (`RPC_TIMEOUT_SECS`, 1–120); response cap 4 MiB | `grpc.rs`, `http_client.rs` | `unframe_*` |
| admission-state lifetime (must exceed the total deadline) | lease 900 s > 600 s upstream + 30 s body read (startup-checked, F46); retention 30 d ≥ consume age 5 d (startup-checked) | `config.rs` | `single_use_needs_a_durable_store_and_consistent_windows` |
| rate limits | challenge and public 30/min/IP; gated pre-auth 120/min/IP; per address 30/min | `main.rs`, `ratelimit.rs` | `gated_requests_are_rate_limited_per_ip_before_verification` |
| graceful shutdown | 30 s (`SHUTDOWN_GRACE_SECS`) then connections are aborted | `main.rs::serve` | `shutdown_gives_in_flight_requests_a_bounded_grace` |

### B.WAL-1 Coupling

| Format | Producer | Consumer | Test / vector |
| --- | --- | --- | --- |
| Access proof header for a gated relay | `@meddleware/nft-gate-client` (via walrus-client `uploadRelayAuthToken`) | this gateway | `conformance/vectors.json` (B.SC-3); paywall e2e PASS 2026-10-09 through the Workers gateway (not this one) |
| Redemption conflict (409 `code`) | gateway | walrus-client resume logic (`isRedeemedConflict`, `isLeasedConflict`) | gateway side: store tests and router tests (F47); vocabulary exported as `GATEWAY_CONFLICT_CODES` by nft-gate-client (TypeScript) |

B.WAL-2 (economics) is the relay's and walrus-ui's; the gateway's contribution is single-use
enforcement (I6).

### B.AUTH-1 Key & credential inventory

| Key / credential (name only) | Type | Where held | Who can read it | Rotation cadence · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `UPSTREAM_AUTH_HEADERS` | CF Access service token (client id + secret) | pod env from a k8s Secret (when deployed; not held today) | cluster operators; the pod | to be set at deployment · n/a | revoke in Zero Trust → new token → update Secret → roll (model: `CLOUDFLARE.md` §2.4; to be written, F31) |
| `SUI_RPC_AUTH_HEADER` | bearer / API key | same | same | to be set · n/a | rotate at the RPC provider |
| `REDIS_URL` | URL with optional password | same | same | to be set · n/a | rotate the Redis ACL user; restart |

### B.AUTH-2 Client & authorization inventory

| Client / relation | Type | Redirect URIs | Scopes / relations | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| Upstream Access application (service-token policy) | CF Access service auth | n/a | allow: this service token | operator | not applicable until deployed |
| Gate authorisation (on-chain) | static rule | n/a | owns a usable `NFT_TYPE` pass for `GATE_ID` / consumed it | gate admin (on-chain) | 2026-10-09 (this audit) |

### B.AUTH-3 Protocol conformance

| Protocol | Version followed | Deviations | Pinning test |
| --- | --- | --- | --- |
| nft-gate access proof v2 (`nft-gate:access:v2`, base64 JSON) | nft-gate-client 0.0.16; root `CLAUDE.md` + `vectors.json`; `SECURITY.md` inv. 5 | none; v1 refused (no fallback) | `conformance_shared_vectors`, `refuses_the_v1_message_and_a_cross_mode_signature` |
| Sui personal-message signing | docs.sui.io intent signing (retrieved 2026-09-29 per lens) | none found | vectors incl. negatives |
| HTTP bearer (`Authorization: Bearer`) | RFC 6750 / RFC 9110 §11 (case-insensitive scheme, any whitespace) | none | `bearer_token_extraction_matches_the_workers_gateway` |

---

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade

`cargo test --locked` gives **117 tests: 114 passed, 0 failed, 3 ignored** (2026-10-10, 0.0.22; 93 / 2 ignored on
2026-10-09, 71 / 2 in the first pass). Line coverage: 90.7 % (91.4 % of functions; test code included) (`cargo llvm-cov --locked --summary-only`,
run locally; CI prints it in the job summary, F28). Test pools: unit tests, hermetic gRPC-web fixtures
(`sui_rpc.rs`, a scripted local node) and router tests (`router_tests.rs`) in the one binary crate; the 3
ignored tests are env-gated (`live_gate_and_ownership_requests_are_accepted`, `live_consume_tx_valid`, both
passing against testnet on 2026-10-10, F45; `redis_backend_round_trip`, needs `REDIS_URL`, run in CI against
a Redis service container).

| Dimension | Assessment |
| --- | --- |
| Happy-path coverage | covered: proof decode, every signature scheme, ownership allow, single-use allow, challenge round trip, CORS, public-path methods |
| Error-path / failure-mode coverage | covered: bad / tampered / wrong-address signature, replay, expired/unknown nonce, missing consume, non-owner, paused gate, unrecognised gate JSON, missing gate object, gRPC status/truncation/compression, audience mismatch and v1 message, stale-holder lease, lapsed lease at commit, typo'd configuration. Dispatcher-level lease/commit/release and the 409/503/502 bodies, upstream timeout (504), redirect (502), chunked over-cap body and stalled body are covered by `router_tests.rs` (F47). **Missing:** a Redis outage against the real client library (the RESP stub covers the mapping) |
| Boundary / edge-case coverage | covered: token size cap, non-ASCII fields, field grammar, depth limit, nonce hard cap, declared length = cap, consume age window and clock skew, lease/deadline and retention/age config bounds, IPv6 /64 keying. multi-page owned objects (F17), the connection cap and the shutdown bound are covered since 0.0.22. **Missing:** none recorded |
| Security-relevant coverage | strong: shared vectors with negatives (high-S both curves, non-canonical s, wrong intent, truncated, 0x03/0x05/0x06, audience mismatch per bound field) and ZIP-215; look-alike package event; normalised compare; header-policy unit tests. **Missing:** header-extraction and redemption-conflict vectors (shared with Workers, S1) |

RUST lens §C:

- `cargo test` covers units, the shared vectors and env-gated live tests: yes.
- Property tests for every hand-rolled decoder: yes (four proptests in `grpc.rs`). Signature parsing is
  covered by vectors, not proptests.
- Coverage tool named: yes — `cargo llvm-cov` (F28), figure 90.7 % of lines.
- Malformed input does not panic: yes for token, frames and JSON; HTTP-level oversize is tested for
  declared and chunked bodies.

PROXY lens §C:

| Requirement | Holds? |
| --- | --- |
| Hop-by-hop and `Connection`-named fields stripped both ways; inbound credential replaced; upstream CORS stripped | yes (`headers.rs` unit tests and the recording-upstream router test); forwarding fields are stripped, not rebuilt |
| Redirect to a foreign origin is refused and no credential reaches it | yes (`an_upstream_redirect_is_refused_and_never_followed`: the target receives nothing) |
| Unlisted method, unsafe path, public path with `POST` refused | yes (`public_paths_are_read_only_and_gated_methods_are_listed`, `unsafe_paths_are_refused`, router `400`) |
| Oversize declared, oversize chunked, stalled body, stalled upstream release state | yes: declared and chunked `413`, stalled body `408`, stalled upstream `504` (F47) |
| Lease expiry; stale holder; store error is `503` | stale holder and lapsed-at-commit yes (store level and router); `503` mapping tested at router level (F47) |
| Shared vectors pass in every implementation | yes |

### C.2 Hermetic vs. live paths

| Path | Hermetic unit test? | Deferred to | Tracking |
| --- | --- | --- | --- |
| gRPC-web against a real fullnode (field numbers) | yes (literal-field-number fixtures against a scripted node) | `live_gate_and_ownership_requests_are_accepted`, `live_consume_tx_valid` (`--ignored`, testnet; fresh consume from `NFT_GATE_LIVE_*`) | F45 (both passed 2026-10-10) |
| Redis/Dragonfly backend (Lua CAS, `GETDEL`) | no | `redis_backend_round_trip` (`--ignored`, needs `REDIS_URL`) | run in CI against a Redis service container (0.0.22, S2) |
| Upstream origin lock (the upstream refuses direct requests; negative check) | n/a | live deployment only | F32, OQ9 |
| Pod memory under `MAX_CONCURRENT_REQUESTS × caps` (≈1.03 GiB) | no | staging load test | F6, F32 |
| Graceful shutdown under load | the bound is tested; load is not | staging | F19 |
| Wallet display of the v2 message | n/a | live wallet | Risks |
| Paywall end to end through this gateway | no | none — not deployed; the 2026-10-09 e2e ran through the Workers gateway | OQ9 |

---

## Section D — Deployment-readiness gates

The gateway is not deployed; "pre-testnet" below is the gate for putting it in front of any upstream
(OQ9, a maintainer decision). Items ticked have evidence in this pass.

### pre-localnet

- [x] builds; `cargo test --locked` green (114 passed, 0 failed, 3 ignored); fmt and clippy `-D warnings`
  clean — this pass
- [x] `#![forbid(unsafe_code)]`; no panics on attacker-reachable paths — F35, proptests
- [x] no secrets in source — the only IDs are the public current testnet package and gate used as optional live-test defaults (F45)
- [x] dependencies install clean (`--locked`) — `Cargo.lock`
- [x] cargo audit + cargo deny green — cargo-deny green in CI and its `advisories` check reads the RustSec database `cargo audit` uses, so no second tool (F28)
- [x] every `FROM` digest-pinned; lockfile installs; no secrets in ARG/ENV/COPY/RUN — `Dockerfile`
- [x] `.dockerignore` excludes local env files — `.env*`, `*.pem`, `*.key`, `docs/` (0.0.22, F29)
- [x] B.PX-1 and B.PX-2 complete (done below); hop-by-hop, route and path tests green (done); redirect
  and limit tests green — `router_tests.rs` (0.0.22, F47)
- [x] configuration fails startup on invalid values — F8

### pre-testnet

- [x] timeouts on every outbound call; response bodies bounded — F38
- [x] inbound header/body timeouts and a connection cap — F5 (router tests for the body deadline and cap, `the_connection_cap_holds_extra_clients_until_a_slot_frees`, F47)
- [x] low-S and ed25519 rules match the Sui client lens; parity vectors (incl. negatives) green — F36
- [x] parity complete across implementations — 409 code, Bearer parsing, status checks (F2, F16);
  pagination (F17) and the effects-status check (F21) in 0.0.22
- [x] rate limit keyed on a trusted address; SIGTERM handled and drained within a bound — I14, I20 (F19)
- [x] single-use redemption safe across restarts and replicas — F4
- [x] redemption lease owner-bound and longer than the body-read and upstream deadlines — F3, F46
- [x] consumed IDs: none in production code; the live-test defaults name the current package and gate — B.SC-1
- [x] ABI-drift test green — hermetic wire-format fixtures in CI; the optional live checks passed against testnet on 2026-10-10 (F45)
- [ ] non-root pod security context, probes and limits; deployment by digest — F32 (manifests absent)
- [x] `SECURITY.md` present — root `SECURITY.md`; invariants 4–7 describe the current behaviour
- [x] lockfile committed; SBOM and cosign on images; CI gates green — B.IMG-1, B.2 (verification command published; SBOM content to confirm on the next tag: F29)
- [ ] B.AUTH-1 credential inventory complete — F31 (deployment)
- [x] dispatcher-level admission-state tests (expiry, stale holder, store outage) and redirect/limit
  tests — `router_tests.rs` (F47)
- [ ] the negative origin-lock check — F32 (deployment)
- [x] pre-deployment closure of the accepted gaps F17, F21, F26, F46 — fixed in 0.0.22

### pre-mainnet

- [x] proof bound to an audience — F1 (decided: v2)
- [x] ownership mode rejects exhausted passes — F7 (decided: usable passes only)
- [x] decoders fuzzed / property-tested; maximum message size enforced — F37
- [x] concurrency limit sized against memory for the configured body cap — F6 (decided: small-body
  scope; 256 KiB cap ⇒ ≈1.03 GiB, to be set in the manifest)
- [ ] image signature, SBOM and provenance on every pushed image and a clean image scan — public images scanned before signing from 0.0.22 (to be seen on the next tag); the private mirror is unsigned (F29, OQ8)
- [x] crates.io trusted publishing — `crates-publish.yml`
- [ ] mainnet `NFT_TYPE`/`GATE_ID`/`NETWORK`/`GATEWAY_ORIGIN` from the canonical record; empty IDs fail
  closed — startup requires all of them (holds); a mainnet `access_gate` is not yet published
  (maintainer: `OPERATOR_TASKS.md` "Mainnet release custody")
- [ ] registry credential inventory and rotation — F30 (maintainer: `OPERATOR_TASKS.md` "Image registry
  credentials")
- [ ] secrets management verified; Access token expiry tracked — F31 (deployment)
- [ ] external review — not started (maintainer: `OPERATOR_TASKS.md` "Funding, grants and an external
  audit — after launch")

---

## Cross-project themes

- **Supply chain & release integrity:**
  - `Cargo.lock` is committed, and actions and base images are pinned by SHA/digest; Dependabot (weekly,
    grouped) keeps them current and was triaged on 2026-10-09 (`k256`/`p256` 0.14, TypeScript 7,
    vitest 5 declined; `blake2` 0.11 and `ed25519-dalek` 3 merged).
  - cargo-deny (advisories, licences, sources) and a coverage figure run in CI, and the published image is scanned with Trivy before it is signed (F28, F29).
  - crates.io uses OIDC; image registries use tokens without an inventory (F30, maintainer item).
  - The release job runs the same workflow as CI.
- **Wire-format coupling & conformance vectors:**
  - The format is defined in `@meddleware/nft-gate-client` (`proof.ts`), which also generates and
    publishes `conformance/vectors.json`.
  - It is implemented here in `proof.rs`/`verify.rs` and in `gateway-workers` (which imports
    nft-gate-client).
  - Drift is detected by the vectors in both suites (`sync-vectors --check` in CI for the Workers side).
  - Gaps: no shared vectors for header extraction, the redemption-conflict body or status mapping
    (per-suite tests only; S1).
- **On-chain-truth boundary:** authorisation is decided from live chain reads, with no client-side
  trust. Single-use accounting is in the gateway's redemption store by design (F23), now owner-bound and
  age-bounded. That is gateway-local state, not financial truth: commission and payment remain
  on-chain in `access_gate`.
- **Deployment readiness:** Section D. The crate and image are published (0.0.21), but there is no
  deployment, by decision. The remaining pre-deployment gates in Section D are F31 and F32 and need OQ9.
- **Chain-access layering & on-chain ID/ABI coupling:**
  - ADR-0001's "domain client" rule applies to TypeScript consumers. As a Rust service the gateway
    necessarily re-implements the read side (`sui_rpc.rs`).
  - Drift is controlled by the vectors, the hermetic wire-format fixtures and the optional live tests, not by sharing code. Record this
    as an accepted exception to SC-M10 (Suggestion S6). The hermetic fixtures and the optional live tests are green (F45).
  - IDs: no production constant is in the repo; the live-test defaults name the current publication
    `0xd7ddaa94…388c9` (gate `0x316f1bf9…faddc`) and are overridable (B.SC-1).
  - Move git dependencies: N/A.
  - ABI drift test: hermetic fixtures pin the field numbers and event shape in CI; `live_consume_tx_valid`
    is optional and takes a fresh consume from the environment.
  - **Pre-v0.2 policy:** no compatibility findings are raised. v1 is refused with no fallback (F1) and
    unrecognised gate JSON denies (F15); the old-package fallback was itself the defect.

---

## Normative requirements (MUST / MUST NOT)

**Before the Rust gateway fronts any upstream (pre-testnet deployment):**

1. MUST return distinct, coded 409 bodies (`redeemed` / `leased`) identical to Workers, and `503` for a
   store error — **holds** (F2), with router-level tests (F47).
2. MUST refuse `SINGLE_USE=true` without a persistent shared store (or with an explicit dev-only
   override) — **holds** (F4).
3. MUST make redemption leases owner-bound (token-checked commit/release) and longer than the maximum
   request duration — **holds** (F3, F46: the body-read and upstream deadlines are both counted).
4. MUST bound inbound header and body read time and cap connections — **holds** (F5).
5. MUST fail startup on invalid boolean/numeric configuration — **holds** (F8).
6. MUST rate-limit gated requests per client IP before signature verification — **holds** (F9).
7. MUST strip upstream CORS headers and the full hop-by-hop set in both directions, consistent with
   `SECURITY.md` — **holds** (F12, F13).
8. MUST read every page of owned objects, and decide consume success from the effects status — **holds**
   (F17, F21).
9. MUST have a green ABI-drift check against a real fullnode — **holds** (F45: hermetic fixtures in CI; optional live checks passed 2026-10-10).

**Before mainnet:**

10. MUST bind the signed message to the gateway origin and gate (and the consume digest in single-use
    mode) in both gateways and the client — **holds** (F1).
11. MUST reject exhausted passes in ownership mode or forbid that mode for multi-use gates — **holds**
    (F7: usable passes only).
12. MUST size memory limits to the documented product (small-body scope) and not carry relay-sized
    bodies — **holds as a scope decision** (F6); the manifest limit is unwritten (F32).
13. MUST scan published images, publish a verification command, and record a credential inventory with
    rotation — **partly holds** (scan before signing and the command: F29, 0.0.22); the inventory and
    rotation do not (F30, F31).

**Lens baseline MUST lists.**

RUST lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| RS-M1 | holds | F35 |
| RS-M2 | holds | F36 |
| RS-M3 | holds | F37 |
| RS-M4 | holds (declared-length pre-check, capped read, concurrency limit); sizing is the small-body scope | F6 |
| RS-M5 | holds (outbound and inbound) | F38, F5 |
| RS-M6 | holds for atomicity and fail-closed; `SINGLE_USE` requires Redis | F4, F39 |
| RS-M7 | holds (challenge, public and gated pre-auth; IPv6 /64) | F9 |
| RS-M8 | holds (`Debug` redaction, the upstream URL never logged, SIGTERM and a bounded drain) | F19, F26 |
| RS-M9 | holds (vector-covered behaviour; pagination and the status check now match) | F17, F21 |

SUI_CLIENT lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| SC-M1 | holds (original-id for type and event filters; no call targets) | B.SC-1 |
| SC-M2 | holds (exact normalised type) | `rejects_a_look_alike_package_consume_event` |
| SC-M3 | holds (success from the effects status) | F21 |
| SC-M4 | holds (no u64 math beyond decimal parsing; addresses normalised) | I4 |
| SC-M5 | holds by construction (one `SUI_RPC_URL`; `NETWORK`, `NFT_TYPE`, `GATE_ID` required, validated) | F8 |
| SC-M6 | holds | F36 |
| SC-M7 | holds for full type, sender, gate and age; success from the effects status; nonce binding replaced by the redemption store and the signed digest | F23, F1, F21 |
| SC-M8, SC-M9 | N/A (no PTBs) | |
| SC-M10 | N/A for a Rust service; recorded exception | Suggestion S6 |

WALRUS lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| WAL-M1, M2, M4, M5, M6, M7 | N/A — relay/client concerns | |
| WAL-M3 | holds on this side: the gateway cannot be bypassed by selection, as selection is client-side; the origin lock is the upstream's | F32 |
| WAL-M8 | holds in code (release keeps the use; owner-bound lease; redeemed/leased codes) | F2, F3 |
| WAL-M9 | holds for the declared and buffered size under the small-body scope; not for relay-sized bodies | F6 |

IMG lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| IMG-M1 | holds | |
| IMG-M2 | holds (`.env*`, keys and `docs/` excluded) | F29 |
| IMG-M3 | holds | |
| IMG-M4 | holds | |
| IMG-M5 | image non-root holds; pod context unverified | F32 |
| IMG-M6 | unverified | F32 |
| IMG-M7 | holds for public registries; private mirror unsigned | F29 |
| IMG-M8 | partly (scan before signing, lockfile in the image for the SBOM and a published verification command from 0.0.22; licence notices not shipped; SBOM content to confirm on the next tag) | F29 |

AUTH lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| AUTH-M1, M3, M5, M6, M7, M9 | N/A (no tokens issued/verified, no IdP, no BFF, no user tokens) | |
| AUTH-M2 | partly (env from Secret; nothing held today; rotation to be recorded) | F31 |
| AUTH-M4 | N/A; fail-closed on the upstream holds | |
| AUTH-M8 | holds (client `Authorization` and `cf-access-*` stripped; injected only to `UPSTREAM_URL`; redirects not followed) | F13, I28 |
| AUTH-M10 | holds for rate limits and log hygiene; deny reasons are deliberately distinct (chain facts are public and the client must react) | F9 |
| AUTH-M11 | holds (versioned, domain-separated, audience-bound, rebuilt from configuration; negative vectors consumed) | F1 |

PROXY lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| PX-M1 | holds (method list, safe-path check, URL from configuration) | F42 |
| PX-M2 | holds for removal in both directions; forwarding fields are stripped, not rebuilt | F13 |
| PX-M3 | holds | F12 |
| PX-M4 | holds | I28, F47 |
| PX-M5 | holds (header, body, connections, upstream and RPC deadlines) | F5, B.PX-2 |
| PX-M6 | holds for network, timeout, redirect and store failures; relay error statuses pass through by decision | F44 |
| PX-M7 | holds (upstream deadline and body-read time) | F3, F46 |
| PX-M8 | does not hold in this repo (lock and negative check are the deployment's) | F32 |
| PX-M9 | holds | F8 |

## Implementation suggestions (SHOULD / MAY)

- **S1** (dispatcher-level tests done in 0.0.22; the shared-vector sections remain) SHOULD add dispatcher-level tests (router + fake chain + recording upstream) for lease → commit,
  lease → release on 5xx, duplicate → 409 `leased`, commit failure → 502, lost lease → 502, store
  error → 503, redirect → 502 with no credential sent, and an upstream `ACAO: *`; and SHOULD add
  `headerExtraction` and `redemptionConflict` sections to the shared vectors (published by
  nft-gate-client).
- **S2** (done in 0.0.22) SHOULD run `redis_backend_round_trip` in CI with a Redis service container, so the atomic
  paths are exercised on every push.
- **S3** (done in 0.0.22) SHOULD add a chunked over-cap request test, a slow-body test, a stalled-upstream test and a
  shutdown-bound test.
- **S4** MAY upgrade to axum 0.8.
- **S5** MAY expose Prometheus-style counters for denials by reason, 409s, commit failures and
  upstream timeouts.
- **S6** SHOULD record in ADR-0001 that the Rust gateway is an accepted second read-side
  implementation, guarded by the shared vectors plus the live test.
- **S7** MAY name `FLAG_PASSKEY = 0x06` explicitly so the fail-closed arm is self-documenting
  (behaviour already correct and vector-pinned).
- **S8** (userinfo refused in 0.0.22) SHOULD validate `UPSTREAM_URL` has no path, query or userinfo, so `format!("{}{}", upstream,
  path)` can never produce surprising URLs.
- **S9** SHOULD give public paths their own limiter and `PUBLIC_RATE_LIMIT_PER_MIN` (env parity with
  Workers). Today a client polling `/v1/tip-config` spends its `/v1/challenge` budget and vice versa.
- **S10** (scan, lockfile and verification command done in 0.0.22; licence notices remain) SHOULD build the image with `cargo auditable` (or ship `Cargo.lock` and licence notices) so
  the SBOM lists the compiled crates, add `trivy image` before signing, and publish a `cosign verify`
  command that pins the publish workflow identity (F29).
- **S11** (decided in 0.0.22: hermetic fixtures plus an env-supplied fresh consume) SHOULD make the live test self-refreshing (find a recent `AccessConsumedEvent` at run time,
  or consume on localnet) so it cannot age out (F45).

## Open questions

- **OQ1** Access message v2: which fields are bound? Options:
  - (a) gateway origin + gate ID;
  - (b) (a) + network;
  - (c) (a)/(b) + the consume digest in single-use mode.

  Should the message also be human-readable for wallet display (e.g. "Sign in to
  <origin> for gate <short-id>")? Decided once for both gateways and nft-gate-client.
  *(Decided 2026-10-08: all of (a)–(c), multi-line ASCII so the wallet shows it; 0.0.19, see F1.)*
- **OQ2** Ownership mode semantics: either reject `SingleUse` passes with `uses_remaining == 0` (match
  `seal_policies::nft_gate`), or allow ownership mode only for gates whose `default_uses == 0`
  (unlimited passes)?
  *(Decided 2026-10-08: ownership counts only usable passes; see F7.)*
- **OQ3** Is the in-memory backend ever acceptable in production with `SINGLE_USE=true`? (Options:
  never, the startup refusal of F4; or allowed with a documented, accepted restart risk.)
  *(Decided 2026-10-08: never; only `ALLOW_VOLATILE_REDEMPTIONS=true` for development; see F4.)*
- **OQ4** Must `gateway-rust` support relay-sized (100 MiB) bodies before it may replace
  `gateway-workers`? If not, should root `CLAUDE.md` scope it to small-body upstreams?
  *(Decided 2026-10-08: no; it is scoped to small-body upstreams, kept at parity and not deployed. The
  gateway README and `proxy.rs` state it; root `CLAUDE.md` still needs the caveat, F27; see F6.)*
- **OQ5** Redemption retention: bound consume age to the retention window (reject older consumes), or
  extend retention to match fullnode transaction retention?
  *(Decided 2026-10-08: bound the consume age, 5 days ≤ retention 30 days; see F24.)*
- **OQ6** On a commit failure after a 2xx upstream, keep today's 502 + release (the user may upload
  twice), or keep the lease and retry the commit asynchronously (the user may lose the use if it
  never lands)? Decided once for both gateways.
  *(Behaviour kept: 502 + release; F20.)*
- **OQ7** Should `PUBLIC_PATHS` be method-restricted (GET/HEAD only)? Today any method on a public path
  is forwarded unauthenticated.
  *(Decided 2026-10-08: yes; see F42.)*
- **OQ8** Will the cluster pull `nft-gate-gateway` from the self-hosted registry, which needs signing
  and SBOM there, or only from quay.io by digest? *(Open; maintainer, with OQ9.)*
- **OQ9** Deployment plan for the Rust gateway: target cluster, owner of manifests,
  `TRUSTED_PROXY_HOPS` value, and how the upstream's origin lock (Access service token or in-cluster
  network policy) is verified. *(Open; maintainer. The gateway stays undeployed until decided; the
  pre-deployment gates are in Section D.)*
- **OQ10** How should the live ABI-drift test get a fixture that does not age out of public fullnode
  retention (a consume made at run time on localnet, a recent testnet consume refreshed by hand, or an
  archival endpoint)? *(Decided 2026-10-10: hermetic wire-format fixtures in CI plus optional live checks
  that take a fresh consume from `NFT_GATE_LIVE_*`, and a fixture-free live gate/ownership check; see F45.)*

## Risks

- **Fullnode honesty and availability.** The gateway trusts one operator-chosen fullnode. A lying node
  can admit non-holders, and an unavailable one denies everyone (fail closed). No quorum or
  light-client verification exists. This is a research item in the trustless roadmap.
- **Signature-scheme coverage.** Multisig, zkLogin and passkey holders cannot use the gateway (fail
  closed) until an official verifier is integrated.
- **Wallet UX.** The v2 message names the origin, gate and network, but users must still read what
  they sign. A binding only helps if wallets display it and users notice a wrong origin.
- **Redis as a single point of state.** Redis data loss (flush, failover without persistence) recreates
  the double-spend of the in-memory store at fleet scale. Persistence and replication are the operator's
  responsibility.
- **Supply chain.** Baked-in webpki roots and the base images age between rebuilds, and crate
  advisories may appear after release. The mitigation is Dependabot, scheduled rebuilds and an image
  scan (before signing from 0.0.22, F29). The published image may lag `main` (it does today: Dependabot merges).
- **Upstream origin lock.** If the upstream is reachable without the gateway, every guarantee here is
  moot. That is verifiable only against a live deployment.
- **An undeployed gateway ages.** Parity with the live Workers gateway is checked by the shared
  vectors and per-suite tests (the pagination and status-check divergences were closed in 0.0.22, F17,
  F21). Untested divergence can accumulate until a deployment is decided.

---

## Re-verification log

- 2026-10-03 — First-pass baseline at nft-gate `db01d3e` (crate 0.0.17).
  - Measured: `cargo test --locked` 69 passed / 2 ignored; fmt + clippy clean; live gRPC test not
    runnable from the review sandbox (egress denied for `fullnode.testnet.sui.io`).
  - Recorded F1–F41 (F35–F41 Positive) and OQ1–OQ9.
  - **No findings resolved:** by maintainer instruction, this pass only records findings; remediation
    (including single-solution fixes the resolve-inline rule would normally apply) is to be done
    separately, after which each finding's disposition moves to RESOLVED with the diff cited.
  - Pre-save consistency checklist run.
- 2026-10-09 — Re-verified against the local checkout `367e673` (`origin/main` `85b18e1`, one Dependabot
  commit later; tag `v0.0.21` = `83349b8`; crate and image 0.0.18–0.0.21 and the Dependabot commits
  since).
  - Every finding F1–F41 re-checked in code, tests, CHANGELOG and `git log`: **16 RESOLVED** (F1–F5, F7–F9,
    F12–F16, F18, F19, F24), **2 MITIGATED** (F10, F27), **5 ADJUDICATED** (F6, F20, F22, F23, F33),
    **6 ACCEPTED-RISK** (F11, F17, F21, F25, F26, F34), **5 DEFERRED** (F28–F32); F35–F41 Positive. The
    main fix wave is 0.0.19 (`6a601d3`, shared with the Workers gateway): protocol v2 audience binding,
    owner-bound redemption leases, `SINGLE_USE` requires Redis, coded `409`s and `503` for store errors,
    a hyper accept loop with header/body timeouts, a connection cap and a bounded shutdown, strict
    configuration, `headers.rs`, usable-pass ownership, a consume age bound. 0.0.17 (`a621a16`) added
    CORS and Redis timeouts; 0.0.20 (`11aa7c9`, access-gate-client 0.0.6) and 0.0.21 (`83349b8`) carry
    no Rust change. `574fe70` only updates the live-test comment.
  - **New:** F42 (method and path policy, RESOLVED), F43 (no `Via` marker, ACCEPTED-RISK), F44 (upstream
    error passthrough, ADJUDICATED), F45 (live test fails on a pruned fixture, DEFERRED), F46 (lease check
    ignores the body-read time, ACCEPTED-RISK), F47 (test gaps against the RUST/PROXY lenses,
    ACCEPTED-RISK), F48 (Positive). Final counts: **17 RESOLVED, 2 MITIGATED, 6 ADJUDICATED,
    9 ACCEPTED-RISK, 6 DEFERRED**; 8 Positive (F35–F41, F48).
  - Lens coverage: added PROXY (2026-10-08: forwarding matrix, I25–I30, B.PX-1, B.PX-2, PX-M1–M9, PROXY
    coverage), updated AUTH to the completed lens (2026-10-08: signed-challenge protocols, AUTH-M11,
    B.AUTH-3 row), RUST (2026-10-08: `cargo audit` + deny, coverage figure, bounded drain, IMG-M8), and
    re-dated base, SUI_CLIENT and IMG. TS, GO, WORKERS, SEAL, SUI, VUE, SITE, OPS and PLATFORM are not
    triggered (no TypeScript, Go, Worker, Seal, Move, UI, site, signing script or platform scope);
    WALRUS stays at 2026-09-30.
  - Measured: `cargo test --locked --offline` 93 tests (91 passed, 2 ignored); fmt and clippy `-D
    warnings` clean; `Cargo.lock` 235 packages. `cargo deny` / `cargo audit` not installed; cargo-deny
    green in CI on `main` (run of 2026-10-09T17:52Z). crates.io max 0.0.21; quay.io `0.0.21` present.
  - Live, read-only: `live_consume_tx_valid` run on 2026-10-10 **fails** (first assertion): the public
    fullnode answers NOT_FOUND for the fixed digest (lowest available checkpoint 391126037), confirmed
    with a hand-built gRPC-web request (F45). The test still uses the superseded `0xa55789…` /
    `0xfd6c3b…` ids **deliberately** (immutable package, fixed historic fixture; `574fe70`): recorded
    in B.SC-1, not a defect.
  - Maintainer decisions recorded: access message v2 (OQ1); ownership counts only usable passes (OQ2);
    volatile redemptions development-only (OQ3); small-body scope, kept at parity, not deployed (OQ4);
    consume age bound (OQ5); commit-failure behaviour kept (OQ6); public paths `GET`/`HEAD` (OQ7);
    vectors published by nft-gate-client; GatePolicy and pass kind immutable; `k256`/`p256` 0.14 major
    declined; repo-local audit canonical. OQ8, OQ9 and the new OQ10 stay open (image source, the
    decision to deploy, the live-test fixture).
  - Cross-audit note: `gateway-workers-audit.md` B.SC-3 lists a success check and full pagination for
    Rust; the code has neither (F17, F21). That table needs a correction on the Workers side.
  - Template dates reconciled to the lens registry; pre-save consistency checklist run.

- 2026-10-10 — Fix wave (0.0.22, commit `40a7e89`; the local checkout is `7f512d9` plus the audit edit).
  - Fixed and re-measured: F17 (paged ownership, bound 100), F21 (effects status), F26 (no upstream URL in
    logs or `Debug`; userinfo refused), F46 (lease > upstream + body-read), F47 (`router_tests.rs`, connection
    cap, shutdown bound, Redis in CI), F45 (hermetic fixtures; optional live checks; OQ10 decided), F28
    (`--locked`, coverage figure, `rustup` toolchain, Redis service) and the CI/Docker parts of F29 (Trivy
    image scan before signing, lockfile in the image, `.dockerignore`, published `cosign verify`). F27
    mitigated (the `wrangler.toml` comment is a Workers-side file). F43 left open for parity.
  - Measured: `cargo fmt --check` clean; `cargo clippy --all-targets --locked -- -D warnings` clean; `cargo test
    --locked` 114 passed, 0 failed, 3 ignored (the 27 shared `proofDecodeRejects` cases, 11 of them new,
    pass in `conformance_shared_vectors`); coverage 90.7 % of lines.
  - Live, read-only, 2026-10-10: `live_gate_and_ownership_requests_are_accepted` and `live_consume_tx_valid`
    (a recent consume on the current relay gate) pass against `fullnode.testnet.sui.io`, confirming the
    `effects.status` field numbers; paging field numbers checked against the `@mysten/sui` generated proto.
  - Counts: **24 RESOLVED, 3 MITIGATED** (F10, F27, F29), **6 ADJUDICATED, 4 ACCEPTED-RISK** (F11, F25, F34,
    F43), **3 DEFERRED** (F30, F31, F32); 8 Positive. Still unticked in Section D: F29 (private mirror, OQ8),
    F30, F31, F32 and the maintainer items.
  - Not exercised here: the Trivy image scan and the cosign steps (registry credentials), `cargo deny` (not
    installed locally; green in CI on the previous tag).

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings — every GAP row cites an accepted or deferred finding (I27 F32 only); HOLDS rows cite a RESOLVED/ADJUDICATED finding or none.
- [x] Finding header ↔ body — no stale status lines; remediation text describes what was done.
- [x] Template line: base + RUST + SUI_CLIENT + WALRUS + IMG + AUTH + PROXY, each dated as in the
  registry.
- [x] Closing structure present in order.
- [x] Open questions: OQ8–OQ10 open; the others carry a recorded decision note, the dispositions moved
  on the findings.
- [x] Section D ↔ dispositions — ticked only for RESOLVED/ADJUDICATED/MITIGATED-with-evidence items;
  unticked items cite F29–F32 or maintainer items.
- [x] Executive summary reflects current dispositions.
- [x] Counts and versions re-measured 2026-10-10 (0.0.22 locally; published versions as read 2026-10-10).
- [x] Re-verification log entry added.
