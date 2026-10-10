# nft-gate — `gateway-workers` Security Audit

**Classification:** Internal security review
**Project:** nft-gate/gateway-workers  (Cloudflare Worker reverse proxy that admits only holders of an
  on-chain `access_gate` pass, verified by a Sui personal-message signature and a live gRPC chain read;
  the **live** NFT-gated front of the Meddleware Walrus upload relay; wire-identical sibling of
  `gateway-rust`)
**Project type:** Cloudflare Worker (TypeScript) + npm package (ships source)
**Template:** AUDIT_TEMPLATE.md (2026-10-08) + AUDIT_TEMPLATE_WORKERS.md (2026-10-02) +
  AUDIT_TEMPLATE_TS.md (2026-10-08) + AUDIT_TEMPLATE_SUI_CLIENT.md (2026-10-08) +
  AUDIT_TEMPLATE_WALRUS.md (2026-09-30) + AUDIT_TEMPLATE_AUTH.md (2026-10-08) +
  AUDIT_TEMPLATE_PROXY.md (2026-10-08)
**Deployment status:**

- **Live on testnet** at route `sui-walrus-relay-testnet.meddleware.co.uk/*` (zone
  `meddleware.co.uk`, route ID `63427e4d…7551`). The Worker was redeployed from `main` on 2026-10-09:
  `Deploy Workers` run of 2026-10-09T17:49Z on `367e673` succeeded (the run of 14:13Z on `574fe70`, the
  config change below, also succeeded). The deployed version itself cannot be read from the repo;
  `deploy-workers.yml` tags each version `<tag>-code`.
- npm `@meddleware/nft-gate-gateway` 0.0.21 (tag `v0.0.21` = `83349b8`), published 2026-10-08T08:19Z.
  `main` carries later commits (the config change `574fe70` and Dependabot merges) that are deployed
  but not in a tag.
- `SINGLE_USE=true` against the access_gate republished on 2026-10-09,
  `0xd7ddaa94…388c9` (v1), and its relay gate `0x316f1bf9…faddc`. The gate was read live on
  2026-10-09: type `0xd7ddaa94…::access_gate::Gate`, `default_uses` 10, `paused` false,
  `policy.pause_blocks_access` false (F45). Config commit `574fe70`. Superseded: gate `0xfd6c3b2a…` on
  `0xa55789…` (both immutable, caps burned).
- Paywall e2e (operator relay, live dashboard) PASSED 2026-10-09: pass bought on gate `0x316f1bf9…`,
  consumed, `nft-gate:access:v2` proof, upload through this Worker; the indexer shows minted=1
  consumed=1.

**Review date:** 2026-10-03 (re-verified 2026-10-09)
**Reviewer:** Internal review
**Severity ceiling:** High — the gateway is the only paywall in front of the operator's Walrus relay.
  A verification bypass gives unpaid uploads at the operator's cost, and a redemption flaw lets one
  paid consume buy many uploads. It holds no user funds and signs nothing on-chain, so nothing reaches
  Critical.
**Status:** re-verified 2026-10-09 — 40 findings dispositioned (23 RESOLVED, 5 MITIGATED, 5 ADJUDICATED,
  5 ACCEPTED-RISK, 2 DEFERRED) plus 6 Positive; F42–F46 added in this pass

**Wrangler / compatibility:** wrangler `^4.143.0` (lockfile 4.147.0, workerd 1.20260815.1);
  `compatibility_date = "2026-06-01"`; `compatibility_flags = ["nodejs_compat"]`; `workers_dev = false`,
  `preview_urls = false`
**Cloudflare plan:** **not declared** in the repo. Comments say "free-tier" (DO SQLite, the quota
  guard), and the declared body cap (100 MiB) equals the Free/Pro request-body limit (OQ3, F11).
**Bindings:**

- Durable Object `NONCE_STATE` → class `NonceRateState`, migration tag `v1`
  (`new_sqlite_classes`).
- KV `NONCE_KV`: commented out, not bound.
- Secrets (names only): `UPSTREAM_URL`, `UPSTREAM_AUTH_HEADERS`; optional `SUI_RPC_AUTH_HEADER`,
  `CF_ANALYTICS_TOKEN`, `CF_ACCOUNT_ID`.
- Plain vars include `GATEWAY_ORIGIN`, `NETWORK`, `NFT_TYPE`, `GATE_ID` (public values).

**Routes / zones:** `sui-walrus-relay-testnet.meddleware.co.uk/*` on `meddleware.co.uk`; `workers_dev` and
  `preview_urls` pinned off in `wrangler.toml` (F29).
**Deploy mechanism:** `.github/workflows/deploy-workers.yml`. It is `workflow_dispatch`, runs only from
  `main`, re-runs `node-ci.yml` first and runs in environment `production` (deployment branch policy:
  `main` only; no required reviewers — F16). The credential is the `CLOUDFLARE_API_TOKEN` secret.
  Deploy steps: `wrangler versions upload` → `versions secret put UPSTREAM_AUTH_HEADERS` →
  `versions deploy`, or `wrangler deploy` when that secret is unset.

**Package manager / lockfile:** npm (Node 24 in CI; publish pins `npm@11.20.0`); `package-lock.json`
  committed
**Module format:** ESM (`"type": "module"`)
**Publish model:** ships TS source (`main: src/index.ts`; `files: src, wrangler.toml, tsconfig.json`)
**Runtime targets:** workerd (tests also on Node via the `unit` project)
**Peer dependencies:** none (a deployable Worker bundles its own single copy of `@mysten/sui`)

**Sui SDK:** `@mysten/sui` `^2.33.1` (lockfile 2.35.0; one copy, `npm ls` deduped) — `SuiGrpcClient`
**Transport:** gRPC (`@mysten/sui/grpc`) — no JSON-RPC
**Networks:** any, selected by `SUI_RPC_URL` + `NETWORK` + `NFT_TYPE` + `GATE_ID`; deployed: testnet
**On-chain packages consumed:**

- testnet `access_gate`, original-id = published-at `0xd7ddaa94…388c9` (v1, 2026-10-09).
- `NFT_TYPE` uses it as a type prefix, and the derived `AccessConsumedEvent` type uses it as an event
  filter.
- Sourced from `wrangler.toml` `[vars]`.
- There are no call targets.

**Walrus SDK:** none — the gateway fronts the operator's upload relay (`UPSTREAM_URL`, secret)
**Package config source:** n/a   **Upload relays:** operator relay behind Cloudflare Access
  (`walrus-relay-origin.meddleware.co.uk`, `docs/networking/CLOUDFLARE.md` §2.4)
**Aggregator / publisher hosts:** n/a   **Tip ceiling:** n/a (client SDK)   **Epoch default / maximum:**
  n/a   **Deletable default:** n/a

**Auth role(s):** credential-injecting proxy (CF Access service token to the upstream; optional RPC
  auth header); verifier of signed access proofs; holder of a Cloudflare Analytics API token (quota
  guard, disabled)
**Identity provider:** none (Cloudflare Access protects the upstream origin)
**Token formats:** inbound nft-gate access proof v2 (base64 JSON + Sui signature over an
  audience-bound message); outbound static headers
**Signing / client credentials:** `UPSTREAM_AUTH_HEADERS`, `SUI_RPC_AUTH_HEADER`, `CF_ANALYTICS_TOKEN`
  (Worker secrets); `CLOUDFLARE_API_TOKEN`, `UPSTREAM_AUTH_HEADERS` (GitHub secrets) — Access token
  inventory and rotation recorded in `docs/networking/CLOUDFLARE.md` §2.4; API-token scopes unrecorded
  (F31)
**Authorization model:** on-chain — owning a usable pass of `NFT_TYPE` for `GATE_ID` (ownership mode), or
  a successful `consume` by the signer, redeemed once (single-use mode, deployed)

**Upstreams:** one, `UPSTREAM_URL` (Worker secret, https only, must not be this gateway's own origin);
  locked to this hop by a Cloudflare Access service-token policy (a direct request is refused, F32)
**Public paths:** `PUBLIC_PATHS` = `/v1/tip-config`, `GET`/`HEAD` only, rate-limited per IP, GET cached
  60 s
**Body cap / timeouts:** 104,857,600 B (declared and streamed); upstream total deadline 600 s; Sui RPC
  15 s per call; header-read and idle timeouts are the Cloudflare edge's (B.PX-2)
**Trusted forwarding hops:** Cloudflare only; the client address is `CF-Connecting-IP`, IPv6 keyed by /64

---

## Executive summary

`gateway-workers` is a ~2.4 kLOC TypeScript Worker. It is the **live** paywall of the Meddleware Walrus
upload relay on testnet. A request reaches the relay only if:

- it carries a Sui personal-message signature over the audience-bound `nft-gate:access:v2` message
  (this gateway's origin, the gate, the network, a gateway-issued region-sharded nonce held in a SQLite
  Durable Object, and the consume digest), rebuilt by the Worker from its own configuration; and
- it carries the digest of a successful, recent on-chain `access_gate::consume` by the signer for the
  configured gate.

That digest is leased under a random owner token in a global Durable Object, the request is streamed to
the relay with a Cloudflare Access service token under a total deadline, and the digest is committed on
a 2xx.

The first pass (2026-10-03) recorded 41 findings, almost all open. Between 2026-10-08 and 2026-10-09
they were fixed in the 0.0.18–0.0.21 releases (`6a601d3` is the main wave, 0.0.19) and re-verified here
against `main` (`367e673`).

**What was fixed (all re-verified in code and tests).**

1. **Audience binding** (F1): protocol v2 binds origin, gate, network, nonce and consume digest; v1 is
   refused; vectors with a negative per bound field are shared with the client package.
2. **Single-use cannot weaken** (F2, F3, F24): `SINGLE_USE=true` refuses the KV backend and ignores the
   degrade flag; leases are owner-bound compare-and-set and outlive the upstream deadline (startup
   checked); a consume older than five days is refused so none outlives its redemption record.
3. **Credential exposure** (F4): redirects are never followed (a 3xx is a 502).
4. **Proxy hygiene** (F10, F12, F13, F42): method and path allowlists, hop-by-hop and `Connection`-named
   fields, cookies, spoofable forwarding fields and `cf-access-*` stripped inbound; hop-by-hop, cookies
   and every upstream CORS field stripped outbound, including from the edge cache.
5. **Limits and strict config** (F5, F6, F8, F9, F17–F19): timeouts on the upstream and every RPC call,
   a pre-verification per-IP limit, a swept rate table, bounded caches, strict configuration.
6. **Ownership mode** (F7): counts only usable passes.

**What remains.** Nothing above Info/Low is unresolved in code. The one DEFERRED item is
maintainer-owned: the **Cloudflare plan** and body/CPU sizing (F11, OQ3). Three items are MITIGATED with
a stated residual: deploy-environment reviewers and API-token scopes (F16, F31, OQ4) and the `unknown`
IP bucket (F29). Fixed after the first re-verification (2026-10-10, unreleased, commit pending): the
**scheduled negative origin-lock check** (F32: `origin-lock.yml`), the cosmetic stale comments (F21),
the residual test gaps (F30) and the base64/UTF-8/JSON layers of proof decoding (F47,
nft-gate-client 0.0.17).

**Verified strengths.**

- The body cap is enforced on streamed bytes and on `Content-Length`, with workerd tests for both.
- Shard names are allowlisted, with a forged-shard test.
- State is strongly consistent in Durable Objects, and every store failure fails closed (503).
- The public cache key is normalised.
- CORS is an exact allowlist (default none) with `Vary: Origin` on every response.
- Signature verification is canonical (`@noble/curves` with `zip215: true` and `lowS: true`) and pinned
  by the shared vectors, negatives included.
- Wire and ownership logic is reused from `@meddleware/nft-gate-client` and
  `@meddleware/access-gate-client` (ADR-0001 layering).
- Both test pools run in CI. The deploy is manual, CI-gated and branch-restricted. npm publishing
  uses OIDC with provenance.

**Posture.** A hardened, live testnet gateway. The remaining mainnet work is operational: confirm the
Cloudflare plan against the body cap and CPU budget (F11), decide deploy reviewers and record token
scopes (F16, F31), and obtain an external review. The negative origin check is scheduled (F32); confirm
its first run after the release.

---

## Threat model / trust boundaries

**Primary trust anchor:** Sui chain state (pass ownership, the `AccessConsumedEvent` of a successful
`consume`) as reported by `SUI_RPC_URL`, and the Sui signature scheme. Second anchor: the Cloudflare
platform (execution, `CF-Connecting-IP`, Durable Object consistency, Access).

| Actor / authority | Holds / proves | Can do | Bounded by |
| --- | --- | --- | --- |
| End user (pass holder) | wallet key; consume digests | redeem a consume once | nonce single-use; redemption DO; per-address limit |
| Any client | headers, body, framing, query, nonce/token strings | challenge, public path, gated garbage | per-IP limits (challenge, public, gated pre-auth), streamed body cap |
| Phishing site / malicious dApp | a sign prompt shown to a victim | relay a real nonce, take the proof | audience-bound v2 message (F1): a proof for another origin, gate, network or digest is refused here |
| Sui fullnode (`SUI_RPC_URL`, public testnet) | chain reads | lie/withhold | trusted; 15 s per-call deadline; fail closed (502) |
| Upstream relay | responses, redirects, headers | redirect the gateway; widen CORS | redirects never followed (F4); response headers filtered (F12, F13) |
| Cloudflare platform | execution, limits, Access, cache | — | trust anchor |
| Holder of `CLOUDFLARE_API_TOKEN` | deploy + secrets | ship any code to the live route | B.CF-1; branch policy `main` only; reviewers undecided (F16) |
| Holder of the Access service token | origin access | bypass the gateway entirely | secret custody; expiry 2027-09-09 recorded, rotation procedure in `CLOUDFLARE.md` (F31) |
| Gate admin | pause / policy | block access (only where the gate's immutable policy opts in) | live read; fails closed on unrecognised JSON (F15); this gate's `pause_blocks_access` is false (F45) |

### Edge actor matrix (WORKERS lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | every header, body + framing, nonce/token strings, query | §A I9 (body), I14 (client identity), I12/I13 (state), I19 (cache); Sui client lens verification (I3–I5) |
| Cloudflare platform | execution, limits, `CF-Connecting-IP`, cache, Access | trust anchor; plan limits (OQ3) |
| Upstream origin | responses; reachability without the gateway | origin lock (I17 — refused directly on 2026-10-09; positive check in every deploy; daily negative check `origin-lock.yml`, F32) |
| Sui RPC | chain reads | Sui client lens rows |
| Holder of the deploy token | production code + secrets | B.CF-1 |
| Readers of `wrangler.toml` | non-secret config | I16 — the config discloses only public values |

### Forwarding matrix (PROXY lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | method, path, query, every header, body bytes and timing | §A I9, I14, I15, I21, I26: method and path allowlists, header policy, body cap, per-IP limits |
| Upstream relay | status, headers, body, redirects, timing | response header policy (I21), redirects never followed (I11), total deadline (I10), 3xx → 502 |
| A party on the path to the upstream | the same, if the hop is unencrypted | `UPSTREAM_URL` must be https (config, I22) |
| State store behind the gate | admission and single-use state | Durable Object, owner-bound CAS, fail closed 503 (I6, I13) |
| Whoever can reach the upstream directly | bypass of the gate | Cloudflare Access service-token policy (I17, F32) |

### On-chain dependency matrix (SUI_CLIENT lens)

| Object / package | ID (original-id · published-at) | Sourced from | Used as | If stale / wrong / attacker-supplied | Fails |
| --- | --- | --- | --- | --- | --- |
| `access_gate` package | testnet `0xd7ddaa94…388c9` · same (v1) | `wrangler.toml` `NFT_TYPE` prefix | type prefix, event-type prefix | no matches ⇒ deny | closed |
| `…::access_gate::SoulboundAccessNFT` | original-id | `NFT_TYPE` (`NFT_TYPE_RE`) | `listOwnedObjects` type (ownership mode) | non-`access_gate` type refused at load | closed |
| `…::access_gate::AccessConsumedEvent` | original-id (derived) | `consumedEventType(cfg.nftType)` | exact-type event filter | look-alike package rejected (test) | closed |
| `Gate` `0x316f1bf9…faddc` | object | `wrangler.toml` `GATE_ID` | pause read; `gate_id` match | no matches | closed; unrecognised JSON throws → 502 (F15) |
| Consume transaction | caller digest | proof `consumeDigest` | `core.getTransaction` | malformed digest never reaches the RPC; unknown digest → 403 (F14) | closed |

### Walrus trust matrix (gateway row)

| Party | Power | Consequence / bound |
| --- | --- | --- |
| This gateway in front of the relay | admits requests carrying an access proof | bypass if the relay is reachable without it. The relay origin is behind Cloudflare Access (`docs/networking/CLOUDFLARE.md` §2.4), `deploy-workers.yml` checks that the origin **accepts** the token (`scripts/check-upstream-auth.mjs`, repository variable `UPSTREAM_CHECK_URL` set), and a direct request was refused with 401 on 2026-10-09. A daily negative check (`origin-lock.yml`, F32) requires Access to refuse direct requests with and without an unknown token. |
| User wallet | pays and signs the consume | the consume digest is the redemption token (F2, F3); the signed message is bound to this gateway (F1) |

### Supply chain & input matrix (TS lens)

| Actor / source | Controls | Bounded by |
| --- | --- | --- |
| Dependency authors | install/build/runtime code | lockfile; `npm audit --audit-level=high` in CI and publish; Dependabot weekly groups; `allowScripts` (esbuild, workerd) |
| npm registry | tarballs | lockfile integrity; OIDC provenance on publish |
| CI runner | build, deploy, publish credentials | base §B.2 |
| Untrusted inputs: proof token, headers, RPC responses, upstream responses | shapes/sizes | `decodeAccessProof` (4096 B cap, ASCII, strict grammar, canonical base64, strict UTF-8, bounded JSON; nft-gate-client 0.0.17); typed gRPC client; strict gate/event decoding; streamed body counter |
| Embedding host | n/a — a Worker, not a library | — |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | Confers | Compromise impact | Rotation / revocation |
| --- | --- | --- | --- | --- |
| CF Access service token (`UPSTREAM_AUTH_HEADERS`) | Worker secret + GitHub secret | origin access | full gateway bypass | token `nft-gate-worker-relay-origin-v2`, expires 2027-09-09, procedure in `CLOUDFLARE.md` §2.4 (F31) |
| `CLOUDFLARE_API_TOKEN` | GitHub `production` environment secret | deploy Workers + secrets | arbitrary code on the live route | scopes and rotation unrecorded (F31) |
| `SUI_RPC_AUTH_HEADER` (optional) | Worker secret | RPC quota | quota abuse | unrecorded (unused today) |
| `CF_ANALYTICS_TOKEN` (optional, unused) | Worker secret | account analytics read | analytics read | unrecorded (unused today) |
| Access proof | client | one gated request per nonce, one upload per consume | relay by a third party is useless: audience-bound (F1) | nonce TTL 300 s |

---

## Severity scale

Critical / High / Medium / Low / Info / Positive (unchanged across the corpus).

---

## Scope

**In scope (HEAD `367e673`, 2026-10-09; first pass at `db01d3e`, 2026-10-03):** findings' *Where* lines
cite the first-pass locations; the evidence paragraphs give the current ones.

- `gateway-workers/src/`:
  - `index.ts`, `verify.ts`, `chain.ts`, `proxy.ts`, `headers.ts`, `redemption.ts`, `cors.ts`,
    `config.ts`, `crypto.ts`, `quota.ts`, `wire.ts`
  - `state/{types,durable_object,kv,select}.ts`
- `gateway-workers/test/**`, `scripts/check-upstream-auth.mjs`, `scripts/check-origin-locked.mjs`, `wrangler.toml`, `package.json`,
  `package-lock.json`, `tsconfig.json`, `vitest.config.ts`, `eslint.config.ts`, `README.md`,
  `CLAUDE.md`, `CHANGELOG.md`
- Repo-level: `conformance/vectors.json`, `scripts/sync-vectors.mjs` (replaced `gen-vectors.mjs`),
  `SECURITY.md`, `scripts/check-versions.sh`, `.github/dependabot.yml`,
  `.github/workflows/{node-ci,npm-publish,deploy-workers,origin-lock}.yml`
- Dependencies read at the installed version: `@meddleware/access-gate-client` 0.0.6
  (`ownsAccessNft`, usable passes only) and `@meddleware/nft-gate-client` 0.0.17 (protocol v2, strict proof decoding, vectors,
  gateway response contract)
- Cross-repo evidence (read-only):
  - `access-gate-sui/Published.toml` and `CLAUDE.md`
  - `walrus-client/src/flow.ts` (409 handling)
  - `docs/networking/CLOUDFLARE.md` §2.4 (Access application and token)
  - the dashboard and token-deployer-ui audits (app-side gate id)

**Out of scope:**

- `gateway-rust/` — its own audit, `gateway-rust-audit.md`.
- The relay itself.
- The Cloudflare dashboard configuration (Access application and policy, WAF, plan). Recorded as OQs
  where the lens needs them.

**Environment / commands (2026-10-09; the 2026-10-10 re-run is in the log; node_modules as installed — wrangler 4.143.0 and eslint 10.11.0,
one Dependabot bump behind the lockfile's 4.147.0 / 10.12.0; `npm ci` was not re-run):**

| Command | Result |
| --- | --- |
| `npx vitest run` (both projects) | **179 tests: 176 passed, 3 skipped**; files 8 passed + 1 skipped (`test/integration/grpc-chain.integration.test.ts`, gated on `GRPC_TESTNET=1`) |
| `GRPC_TESTNET=1 npx vitest run test/integration/grpc-chain.integration.test.ts` | 3 passed against `fullnode.testnet.sui.io` (egress available this time) |
| `npx tsc --noEmit` | clean |
| `npx eslint .` | clean |
| `npm audit --audit-level=high` | 0 vulnerabilities |
| `npm pack --dry-run` | 20 files: `LICENSE`, `README.md`, `package.json`, `src/**` (15 files incl. `headers.ts`), `tsconfig.json`, `wrangler.toml`; no tests, env files or keys |
| Read-only `curl` of the live route | `/healthz` 200; `POST /v1/tip-config` 405 with `allow: GET, HEAD`; gated path without proof 401; `Origin: https://evil.example` receives no `Access-Control-Allow-Origin`; `/v1/tip-config` with an allowed Origin receives exactly that origin, `Cache-Control: public, max-age=60`, `Vary` includes `Origin` |
| Direct request to the relay origin (`walrus-relay-origin.meddleware.co.uk`, `/` and `/v1/tip-config`, no token) | 401 both (origin lock holds, F32) |
| `gh api` (read-only) | `production` environment: deployment branch policy `main` only, no required reviewers, `can_admins_bypass` true; repository variable names include `UPSTREAM_CHECK_URL` |
| Live gate read (`SuiGrpcClient.core.getObject`) | `0x316f1bf9…faddc` is an `0xd7ddaa94…::access_gate::Gate`, `default_uses` 10, `paused` false, `policy.pause_blocks_access` false |

---

## Findings

### F1 — Access proof message is not bound to an audience (gateway, gate or consume)

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F1; OQ1
decided)
**Where:**

- `src/wire.ts` (re-exports `personalMessageForNonce` from `@meddleware/nft-gate-client`)
- `src/verify.ts:212-280`
- `conformance/vectors.json` `personalMessage`

**Issue:** The signed message is `nft-gate:access:<nonce>`, with no gateway origin, gate, network or
consume digest. Anyone can obtain a nonce from `GET /v1/challenge`, and the wallet prompt identifies no
service.

**Impact:** A malicious site requests a nonce from this gateway and has a visitor sign it. In the
deployed single-use mode the attacker then submits the proof with one of the victim's public consume
digests that is not yet committed: a freshly consumed one, or one whose upload was interrupted
(`release`). This spends the victim's paid use on the attacker's upload. The victim's own attempt then
gets `409 redeemed`, so their client consumes again, spending a second paid use.

The exposure is one request per phished signature, within the 300 s nonce TTL.

**Remediation / evidence:** Protocol v2, one coordinated wire change (nft-gate-client 0.0.16 and both
gateways, no v1 compatibility, per the pre-v0.2 policy):

- The signed message is `nft-gate:access:v2`, multi-line ASCII, binding the gateway origin, the gate
  id, the network, the nonce and (single-use) the consume digest (OQ1: all three of its options).
- `verifyAccessRequest` (`src/verify.ts`) rebuilds the message from `cfg.gatewayOrigin`,
  `normalizeAddress(cfg.gateId)`, `cfg.network`, the proof's nonce and, in single-use mode, its
  digest — never from the token. New required vars `GATEWAY_ORIGIN` and `NETWORK` (set in
  `wrangler.toml`; `GATEWAY_ORIGIN` must equal the route hostname). A proof made for another gateway,
  gate, network or mode simply fails signature verification here. v1 is refused.
- Vectors are generated and published by nft-gate-client (`personalMessage`, `personalMessageRejects`
  13 cases, `audienceMismatch` 8 cases, 4 golden signatures, `negativeSignatures` 8), copied by
  `scripts/sync-vectors.mjs` and checked in CI with `--check`.
- Tests: `test/verify.test.ts` "audience binding (protocol v2)" (accepts a proof for exactly this
  gateway, gate and network; refuses v1; an ownership gateway refuses a single-use proof; a swapped
  digest is refused because it is signed; a malformed digest never reaches the chain);
  `test/conformance.test.ts` (every `audienceMismatch` and `personalMessageRejects` vector);
  `test/config.test.ts` "audience binding".
- Live: the paywall e2e of 2026-10-09 passed with a v2 proof through this Worker.
- Residual (not a code gap): the wallet prompt is only as useful as the user's attention to the origin
  line (see Risks).

### F2 — KV backend and the quota-guard "degrade" switch weaken single-use redemption; switching drops all history

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ8 decided)
**Where:**

- `src/index.ts:45-63` (`getState`: if `NONCE_KV` is bound and `quota:degrade` is set, the backend
  becomes KV for that isolate)
- `src/quota.ts:60-80` (sets `quota:degrade` for 3600 s)
- `src/state/kv.ts:1-8` (module doc) and its redemption methods
- `wrangler.toml` (`NONCE_BACKEND`, `QUOTA_GUARD_ENABLED`)

**Issue:**

1. KV's `get`-then-`put` lease is not atomic and is eventually consistent across colos, so two
   concurrent requests with the same `consumeDigest` in different regions can both lease and both
   upload.
2. A switch between backends (operator change, or the automatic degrade flag) starts from an empty
   store. Every digest committed in the Durable Object (30-day retention) becomes redeemable once more
   in KV, and back again.
3. The switch is per isolate, so DO and KV isolates coexist during the flag window and each accepts a
   digest the other has committed.
4. `kv.ts` states "In `SINGLE_USE=true` mode the on-chain `AccessConsumedEvent` remains the
   authoritative single-use bind, so that mode is unaffected". That is no longer true: single use is
   enforced by the redemption store (`chain.ts` `consumeTxValid` doc; root `CLAUDE.md`).

**Impact:** Today the impact is latent: KV is unbound and `QUOTA_GUARD_ENABLED = "false"`. Enabling
the documented free-tier fallback, or the quota guard, silently turns "redeemed exactly once"
(`SECURITY.md` invariant 4) into "redeemed once per backend, plus race windows". An automatic process
can trigger it without an operator noticing.

**Remediation / evidence:**

- `loadConfig` throws `SINGLE_USE=true requires NONCE_BACKEND=durable-object` (`src/config.ts`).
- `getState` (`src/index.ts:47-60`) ignores the degrade flag when `cfg.singleUse`; `makeBackends`
  (`src/state/select.ts`) always puts redemptions on the Durable Object and the KV backend no longer
  implements `RedemptionStore`.
- The `kv.ts` module doc now says redemptions are not stored in KV; `SECURITY.md` invariant 4 and the
  `CLAUDE.md` Redemption section state the DO-only rule.
- Tests: `test/config.test.ts` "refuses the KV backend, whose lease cannot be atomic"; since 2026-10-10
  `test/gateway-state.test.ts` pins the degrade-flag branch (moves ownership-mode nonces to KV, ignored
  in single-use mode; F30).
- The `CLAUDE.md` sentence that called the single-use bind "unaffected" was corrected 2026-10-10 (F21).

### F3 — Redemption lease is not owner-bound and can lapse during a slow upload

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F3)
**Where:**

- `src/redemption.ts:23-58`
- `src/state/durable_object.ts:115-160` (`tryLeaseRedemption`, `commitRedemption`,
  `releaseRedemption`)
- `wrangler.toml` `REDEMPTION_LEASE_TTL_SECS = "120"`, `MAX_BODY_BYTES = "104857600"`

**Issue:**

- The lease (120 s) covers the whole streamed upload of up to 100 MiB. There is no upstream timeout
  (F6), so a slow client or relay keeps the request running past 120 s.
- Lease rows carry no owner token:
  - `commitRedemption` writes `committed` unconditionally;
  - `releaseRedemption` deletes any `leased` row.

**Impact:**

- After the lease lapses, a duplicate request with the same digest leases again, and two uploads
  proceed for one paid consume.
- The first request's `release` (on failure) can delete the second request's lease.
- This breaks `SECURITY.md` invariant 4 for slow uploads, including legitimately slow ones that a
  retrying client duplicates.

**Remediation / evidence:**

- `tryLeaseRedemption` returns `ok` with a random owner token (`crypto.randomUUID()`);
  `commitRedemption(key, token, retention)` and `releaseRedemption(key, token)` are compare-and-set on
  `state = 'leased' AND token = ?` (and, for commit, an unexpired lease). A commit that finds its lease
  lapsed or replaced returns `lost`, which `redeemAndForward` reports as `502` without touching the
  newer holder. The table gained a `token` column (idempotent `ALTER TABLE`).
- `REDEMPTION_LEASE_TTL_SECS` defaults to 900 and must exceed the new `UPSTREAM_TIMEOUT_SECS` (600,
  total deadline, F6): `loadConfig` throws otherwise, so a lease cannot lapse inside a forward.
- Tests: `test/state.test.ts` "a stale holder can neither release nor commit over a newer lease", "a
  commit after the lease lapsed is lost, never recorded"; `test/redemption.test.ts` "a stale holder
  cannot release or commit over a newer lease", "a holder whose lease lapsed before commit is told 502,
  never success, and leaves the row alone"; `test/config.test.ts` "the lease must outlive the upload
  deadline, and a consume must not outlive its retention".
- Mirrored in `gateway-rust` (its own audit).

### F4 — Upstream `fetch` follows redirects with the Access service-token headers attached

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/proxy.ts:115-129` (`fetch(upstreamUrl, { method, headers, body, signal, duplex })` with
no `redirect` option, so the default is `'follow'`).

**Issue:**

- `UPSTREAM_AUTH_HEADERS` (`CF-Access-Client-Id`/`CF-Access-Client-Secret`) are set on the request
  headers, and the runtime re-sends custom headers on followed redirects. Only `Authorization` is
  dropped cross-origin by the Fetch standard.
- `scripts/check-upstream-auth.mjs` correctly uses `redirect: 'manual'` for its probe, but the
  production path does not.
- The Rust gateway follows no redirects (hyper), so behaviour diverges.

**Impact:** Any 3xx from the relay origin sends the service token to the `Location` host. Sources
include:

- a misconfiguration;
- an open redirect in the relay;
- an Access login redirect when the token is wrong or expired;
- a compromised origin.

The token holder can then reach the relay directly, a full bypass of the gate. A followed redirect also
turns the gateway into a fetcher of arbitrary URLs on the client's behalf.

**Remediation / evidence:**

- `forward` (`src/proxy.ts`) passes `redirect: 'manual'`; any 3xx response is cancelled and returned
  as `502 upstream error`, with nothing from the response passed on. This also covers an Access login
  redirect after the service token expires.
- Test: `test/proxy.test.ts` "never follows a redirect: the service-token headers must not reach the
  Location host" (workerd; upstream answers a 302 to a foreign host, no second request is made).
- B.SC-3 now has the `Upstream redirects` row: both gateways identical.

### F5 — Durable Object `rate` table is never pruned

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/state/durable_object.ts:57-60` (table) and `:96-111` (`rateCheck`: `INSERT OR REPLACE`,
no delete).

**Issue:**

- Rows keyed `chal:<ip>`, `ip:<ip>` and `<address>` accumulate forever in each regional shard.
- Nonces and redemptions are pruned on write; rate rows are not.
- An IPv6 attacker rotating source addresses inside a /64 adds rows indefinitely.

**Impact:** Unbounded DO SQLite growth, which raises storage cost and eventually approaches the
per-object storage limit, and slower writes over time.

**Remediation / evidence:**

- `rateCheck` sweeps `DELETE FROM rate WHERE start < now - 60000` on about 2% of calls, so the table is
  bounded by the keys seen in the last minute. Test: `test/state.test.ts` "rate windows older than a
  minute are swept (the table is bounded by recent keys)".
- `clientIp` (`src/index.ts`) keys IPv6 clients by their /64; pinned by `gateway-state.test.ts` since 2026-10-10 (F30).

### F6 — No timeout on the upstream `fetch` or on gRPC calls

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:**

- `src/proxy.ts:120-129`: the `signal` aborts only on body over-limit.
- `src/chain.ts`: `SuiGrpcClient` calls (`getObject`, `getTransaction`, `listOwnedObjects` via
  access-gate-client) carry no `AbortSignal`.

Only `quota.ts:103` sets `AbortSignal.timeout(15_000)`.

**Issue:** TS lens §A *Network I/O* (TS-M5) requires a timeout on every fetch. The Rust sibling has
30 s (RPC) and `UPSTREAM_TIMEOUT_SECS` (upstream).

**Impact:**

- A hung fullnode or relay holds the request and the redemption lease (F3) until the client
  disconnects or the platform ends the invocation.
- Retries ×4 (F14) multiply a slow RPC.
- Parity divergence.

**Remediation / evidence:**

- Upstream: `UPSTREAM_TIMEOUT_SECS` (default 600, bounds 1–3600) is a **total** deadline for the
  exchange, body in and response out (`AbortSignal.timeout` combined with the over-limit controller);
  past it the answer is `504 upstream timed out`. Test: `test/proxy.test.ts` "ends a stalled upstream
  with 504 once the total deadline passes". Trade-off: an upload slower than the deadline (100 MiB in
  600 s is about 1.4 Mbit/s) is cut; the lease is sized above it (F3).
- Chain: `RPC_TIMEOUT_SECS` (default 15) wraps `getObject`, `getTransaction` and the ownership query in
  `withDeadline` and is passed to the client. Tests: `test/chain.test.ts` "rejects a call that never
  settles, and passes a fast one through", "a hung node is bounded".
- The quota guard keeps its own 15 s timeout.

### F7 — Ownership mode ignores `uses_remaining`; exhausted single-use passes and receipts are admitted

**Severity:** Medium   **Disposition:** RESOLVED (0.0.19/0.0.20, `6a601d3`, `11aa7c9`; OQ2 decided; shared
with `gateway-rust` F7)
**Where:** `src/chain.ts::ownsNftLive` → `@meddleware/access-gate-client` `ownsAccessNft`
(`ownership.ts:133-146`). It parses `usesRemaining` (`:46-90`) but never filters on it.

**Issue / Impact:** On a gate with a positive `default_uses` and `auto_burn_at_zero = false`, a holder
of a spent (`uses_remaining = 0`) receipt gets unlimited access in ownership mode.
`seal_policies::nft_gate` rejects such passes. Latent here, because the deployment is single-use.

**Remediation / evidence:**

- access-gate-client 0.0.5 (`8435927` in that repo) replaced `usesRemaining` with a discriminated
  `PassVariant` (`unlimited` | `singleUse` with an exact `bigint` remaining) and made `ownsAccessNft`
  match only usable passes; an unparseable variant is rejected. This Worker depends on `^0.0.6`
  (lockfile 0.0.6; strict event decoding and exact variants, 0.0.20 `11aa7c9`).
- Decision (OQ2): ownership counts only usable passes. `ownsNftLive` documents it.
- The pinning tests live in access-gate-client; this repo's verify tests use a fake chain (the live
  read suites of access-gate-client passed against the new package on 2026-10-09).

### F8 — Lenient configuration parsing silently selects weaker modes

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/config.ts:117-121` (`numOr`) and `:205` (`singleUse: (env.SINGLE_USE ??
'false').toLowerCase() === 'true'`), and `:221`.

**Issue:**

- `SINGLE_USE` values other than `true` (any case), including `1`, `yes`, `"true "` or a typo,
  silently select ownership mode.
- `numOr` accepts any finite number: negative, fractional or zero values for `MAX_BODY_BYTES`,
  `REDEMPTION_LEASE_TTL_SECS`, rate limits (0 disables), `NONCE_MAX_ENTRIES`, and so on. Only
  non-finite values fall back to the default.

**Impact:** A config typo in `wrangler.toml` or a secret downgrades the paywall, or disables limits,
with no error. Misconfiguration otherwise fails closed (500), which is good, but these values are not
validated.

**Remediation / evidence:**

- `src/config.ts` has strict helpers: `bool` (exactly `true` or `false`), `int` (`/^\d{1,15}$/` within
  per-variable bounds, e.g. lease TTL ≥ 30, body cap ≥ 1; rate limits ≥ 0 with 0 documented as "off"),
  `oneOf` (case-sensitive enumerations), https-only URLs, canonical origins, plain `PUBLIC_PATHS`,
  `NETWORK` from a fixed list, and cross-field checks (lease > upstream deadline, consume age ≤
  retention). Any failure is a startup error (`500 gateway misconfigured`, detail only in the log).
- Tests: `test/config.test.ts` "SINGLE_USE and QUOTA_GUARD_ENABLED are exactly true or false", "numbers
  are integers within bounds", "enumerations reject unknown values", "upstream and RPC URLs must be
  https", "PUBLIC_PATHS are plain absolute paths".
- `config.ts` stays import-free so the deploy pre-check can load it under Node (0.0.21, `83349b8`;
  test "has no imports").

### F9 — Gated path has no pre-authentication rate limit

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F9)
**Where:** `src/index.ts:239-250` (the per-address `rateCheck` runs only after `verifyAccessRequest`
succeeds).

**Issue:**

- Each gated request with a well-formed token costs a signature verification, which is CPU-billed,
  and for a valid self-made signature a DO `takeIfValid` call.
- `CF-Connecting-IP` limits exist for the challenge and public paths only.

**Impact:**

- An attacker with their own keypair can generate unlimited DO requests and CPU time, which is billed
  and counts toward Free-plan daily limits.
- This can push the deployment into the quota guard's degrade path (F2).

**Remediation / evidence:**

- `handle` (`src/index.ts`) checks `rateCheck('pre:' + clientIp)` against
  `GATED_PREAUTH_RATE_LIMIT_PER_MIN` (default and deployed 120) after the method and token-presence
  checks and **before** `verifyAccessRequest`; the per-address limit stays after it.
- Test: `test/router.test.ts` "rate-limits gated requests per client IP BEFORE verifying the proof".
- A Cloudflare WAF rate-limiting rule remains an optional coarse layer (S5).

### F10 — Public paths forward any method unauthenticated

**Severity:** Info   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ7 decided)
**Where:** `src/index.ts:159-170` (non-GET public requests are rate-limited and forwarded, not cached).

**Issue / Impact:** `PUBLIC_PATHS` is exact-match, which is good. But `POST /v1/tip-config` with a body
of up to 100 MiB reaches the relay without a proof. The relay is expected to reject it, but the
gateway relies on that.

**Remediation / evidence:** Public paths accept `GET` and `HEAD` only; anything else is `405` with
`allow: GET, HEAD`, before any rate-limit or upstream work (`src/index.ts`). Test:
`test/router.test.ts` "public paths are read-only: a body-carrying method is 405 and never reaches the
upstream". Live 2026-10-09: `POST /v1/tip-config` returned 405 with `allow: GET, HEAD`. Parity with
Rust.

### F11 — Plan tier, CPU budget and the exact body limit are undeclared

**Severity:** Low   **Disposition:** DEFERRED (pending OQ3; maintainer item — the Cloudflare plan —
and the pre-mainnet gate "plan tier confirmed"; the mainnet cost estimate in `OPERATOR_TASKS.md`
"Funding, grants and an external audit" names the Cloudflare plan)
**Where:** `wrangler.toml` (`MAX_BODY_BYTES = "104857600"`, comments "free-tier") and `README.md:149-163`.

**Issue:** WORKERS lens §A *Limits* and the pre-mainnet gate need the plan recorded. The facts below
are from the Cloudflare docs, retrieved 2026-09-29 per the lens; re-check them.

- Free: 10 ms CPU per request, 50 subrequests.
- Free/Pro request body: 100 MB.
- `MAX_BODY_BYTES` is 104,857,600 B (100 MiB). If Cloudflare's "100 MB" is 10⁸ B, bodies between
  10⁸ and 1.048 × 10⁸ B get the platform's own 413 first. That fails closed, but the cap the gateway
  declares does not match the cap clients actually get.
- Signature verification cost (secp256r1 in JS) against 10 ms CPU is unmeasured.

**Impact:** Unexpected 413s, or CPU-limit errors (1102), on the live relay; inaccurate documentation.

**Remediation / evidence:**

- Documentation is now accurate about the interaction: `README.md` "Request body limit" states that
  the effective limit is the lower of `MAX_BODY_BYTES` and the plan limit, and the variable table
  documents that the code default is 256 KiB (`262144`) while `wrangler.toml` sets `104857600` for
  Walrus uploads.
- Not done, and not doable from the repo: record the plan (OQ3), set `MAX_BODY_BYTES` to
  `min(plan limit, relay cap)` in exact bytes, and measure p99 CPU per gated request from Workers
  analytics. The operator needs to do these before mainnet; the plan is also an input to the mainnet
  cost estimate.

### F12 — Upstream CORS headers pass through and can widen the allowlist; cached responses retain them

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F12)
**Where:** `src/cors.ts:39-48` (`withCors` sets ACAO only when allowed and never deletes an upstream
one), `src/proxy.ts:139-145` and `src/index.ts:181-188` (the public cache stores upstream headers).

**Issue / Impact:**

- An upstream `Access-Control-Allow-Origin: *` reaches unlisted origins.
- On public paths the permissive header is stored in the edge cache and served to everyone for
  `PUBLIC_CACHE_TTL_SECS`.
- The allowlist invariant (CF-M6) does not hold end to end.

**Remediation / evidence:**

- `clientResponseHeaders` (`src/headers.ts`) deletes every `access-control-*` field from the upstream
  response in `forward`, so the copy stored by `cache.put` in `forwardPublic` is already clean.
  `withCors` (`src/cors.ts`) additionally deletes any `access-control-*` field before setting the
  gateway's own, and appends `Vary: Origin`.
- Tests: `test/router.test.ts` "upstream-supplied CORS never widens the allowlist" (upstream returns
  `ACAO: *`; a disallowed origin gets none), `test/proxy.test.ts` "filters the response: no hop-by-hop,
  cookies or upstream CORS".
- Live 2026-10-09: an unlisted origin receives no `Access-Control-Allow-Origin`; a listed one receives
  exactly itself.

### F13 — Hop-by-hop header stripping is incomplete; `SECURITY.md` invariant 5 overstates it

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F13)
**Where:** `src/proxy.ts:109-118`: the request strips `host`, `authorization`, `x-access-proof`,
`content-length`. `:139-143`: the response strips `content-length`, `transfer-encoding`, `connection`.

**Issue / Impact:**

- Client `Connection`-listed headers, `Keep-Alive`, `TE`, `Upgrade` and `Proxy-*` are forwarded,
  except for what the workerd runtime itself drops.
- Upstream `Keep-Alive`, `Proxy-Authenticate` and `Trailer` are returned.
- `SECURITY.md` claims full stripping.

**Remediation / evidence:**

- New `src/headers.ts`: the RFC 9110 §7.6.1 set (`connection`, `keep-alive`, `proxy-authenticate`,
  `proxy-authorization`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`) plus every
  field named in `Connection` is stripped in both directions. The request also drops `host`,
  `authorization`, `x-access-proof`, `content-length`, `cookie`, `forwarded`, `via`,
  `x-forwarded-for/-host/-proto`, `x-real-ip` and the whole `cf-access-*` namespace before the
  gateway's own injected headers are set; the response also drops `content-length`, `set-cookie(2)`,
  `alt-svc` and `access-control-*`.
- The gateway strips client forwarding fields and does not add its own; the relay does not use the
  client address. `SECURITY.md` invariant 6 now describes exactly this policy.
- Tests: `test/proxy.test.ts` "strips hop-by-hop (and Connection-named), credential and spoofable
  request fields" (the gateway's own credential is set last), "filters the response…".

### F14 — `getTransaction` is retried on every error; the digest is not validated before the RPC call

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F14)
**Where:** `src/chain.ts:148-164` (4 attempts, 500 ms, any error) and `consumeTxValid` (`:183-196`).

**Issue / Impact:**

- The Sui client lens requires not-found-only retries.
- An arbitrary `consumeDigest` string costs four RPC subrequests and returns 502 rather than 403.
- Free-plan subrequest budget: 4 + `getObject` + DO calls + upstream ≈ 8 of 50, so the budget is not
  at risk, but every failure is amplified.

**Remediation / evidence:**

- `decodeAccessProof` validates the digest shape and `verifyAccessRequest` re-checks it with
  `isTransactionDigest` before any RPC call (a malformed digest is `ConsumeMissing`, 403).
- `SuiGrpc.getTransaction` retries (4 × 500 ms) only when the SDK reports `reason === 'notFound'`; a
  final not-found returns `null` and denies with 403; any other failure is thrown at once and surfaces
  as `ChainError` (502).
- Tests: `test/chain.test.ts` "retries only "not found", then denies (false) instead of erroring", "a
  late-indexed transaction is found on a retry", "any other failure is thrown at once (no
  amplification)…"; `test/verify.test.ts` "a malformed digest never reaches the chain…".

### F15 — Pause enforcement fails open on unrecognised `Gate` JSON

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; shared with `gateway-rust` F15)
**Where:** `src/chain.ts:250-253` (`gateBlocksAccess` returns `false` unless `paused === true` and
`policy.pause_blocks_access === true`). Test "never blocks a gate without a policy (pre-policy package)
or missing JSON".

**Issue / Impact:**

- The consumed package always has `policy`, and under the pre-v0.2 policy no pre-policy fallback is
  owed.
- A rendering change (field rename, non-bool encoding) silently disables an admin's pause.

**Remediation / evidence:**

- `gateBlocksAccess` (`src/chain.ts`) requires a boolean `paused` and an object `policy` with a boolean
  `pause_blocks_access`; anything else throws, which `verifyAccessRequest` maps to `ChainError` (502,
  deny). The old test was inverted.
- Tests: `test/chain.test.ts` "blocks only when paused AND the policy opts in", "fails closed on JSON
  it does not understand (a rendering change must not disable a pause)"; `test/verify.test.ts`
  "treats a failed gate read as a chain error (fail closed)".
- Deployment note: the live relay gate opts out of pause-blocking (F45).

### F16 — Deploy environment protection is asserted in comments, not evidenced

**Severity:** Info   **Disposition:** MITIGATED (branch policy verified 2026-10-09; reviewer choice
pending OQ4 — maintainer item; token scopes F31; pre-mainnet gate "deploys gated on CI and a protected
environment")
**Where:** `deploy-workers.yml:3-6` ("executes in the protected `production` environment (configure
required reviewers in the repository settings)") and `:37` (`environment: production`).

**Issue:** B.CF-1 requires either configured reviewers or a recorded decision. Neither is in the repo,
and environment settings are not readable from it. The API token's scopes and the route/zone owner are
also unrecorded.

**Impact:** If the environment has no protection rules, anyone with `workflow_dispatch` permission on
`main` can deploy. With a single maintainer that may be acceptable, but it must be a recorded choice.

**Remediation / evidence:**

- Read from the GitHub API on 2026-10-09: environment `production` exists with a **deployment branch
  policy limited to `main`** (custom policy; the workflow's own `if: github.ref == refs/heads/main` is
  the second layer), no required reviewers, `can_admins_bypass` true. Deploys are `workflow_dispatch`
  only and re-run `node-ci.yml` first (`needs: ci`).
- Open, maintainer-owned: record in OQ4 whether a required reviewer or wait timer is wanted (with one
  maintainer a reviewer adds a confirmation, not a second person) and record the
  `CLOUDFLARE_API_TOKEN` scopes (ideally Workers Scripts:Edit and Workers Routes:Edit for the one zone,
  with an expiry), F31.

### F17 — `SUI_RPC_AUTH_HEADER` is parsed without validation

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/config.ts:123-129` (`parseAuthHeader`: split at the first `:`, trim; no token or CRLF
check) vs Rust `config.rs::parse_rpc_auth_header` (validated) and Workers' own
`parseUpstreamAuthHeaders` (validated).

**Issue / Impact:**

- A malformed value becomes gRPC metadata, which may throw per request (500/502) or send an
  unintended header name.
- A bare value defaults to `Authorization`.
- Parity divergence in supported configuration (B.SC-3).

**Remediation / evidence:** `parseAuthHeader` now requires `Name: value` with an RFC 9110 token name
(`HEADER_NAME_RE`), a non-empty value and no CR/LF; a bare value is refused (it used to be sent as
`Authorization`). A bad value is a startup error. Test: `test/config.test.ts` "parses "Name: value" and
refuses anything else". The secret is unused today.

### F18 — Code-default `ALLOWED_ORIGINS` is three Meddleware hosts; Rust defaults to none

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ9 decided)
**Where:** `src/config.ts:131-143` (`DEFAULT_ALLOWED_ORIGINS`) and the test "defaults to the three
Meddleware app origins".

**Issue / Impact:**

- An operator deploying the published npm package (white-label) with `ALLOWED_ORIGINS` unset grants
  CORS to Meddleware's apps.
- The Rust default is empty, so the "same env vars ⇒ same decisions" contract breaks.
- WORKERS lens §A *Config disclosure* requires code defaults to match the committed config, or the
  divergence to be documented. They do match `wrangler.toml` today, but the white-label default is
  surprising.

**Remediation / evidence:** `ALLOWED_ORIGINS` defaults to none (fail closed, like Rust); each entry must
be a canonical https origin; `wrangler.toml` keeps the three Meddleware origins. Test:
`test/config.test.ts` "defaults to no cross-origin access (fail closed, like the Rust gateway)",
"rejects an entry that is not a canonical https origin".

### F19 — Ownership cache is unbounded when enabled

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/chain.ts:40` (`Map<string, CacheEntry>`), `ownsNft` (`:117-131`), when
`OWNERSHIP_CACHE_TTL_MS > 0`.

**Issue / Impact:** Per-isolate growth with distinct addresses. Expired entries are only overwritten.
It is off by default (`"0"`). Isolate memory is 128 MB.

**Remediation / evidence:** `ownsNft` drops expired entries on write and evicts the oldest past
`MAX_CACHE_ENTRIES` (10,000). Test: `test/chain.test.ts` "the ownership cache stays bounded and drops
expired entries". Still off by default.

### F20 — Commit failure after a successful upstream returns 502 and releases the lease

**Severity:** Info   **Disposition:** ADJUDICATED (shared semantics; OQ6)
**Where:** `src/redemption.ts:46-56`; test "reports a failed commit as 502 (never success) and
releases the lease".

**Issue / Impact:** The relay processed the upload, but the client sees 502 and may upload again with
the same consume. This is the defined, shared outcome WORKERS lens §A *State consistency* requires. The
trade-off is one possible duplicate upload per commit failure versus a lost use.

**Remediation / evidence:** Intentional; decision recorded as OQ6. Re-verified: `redeemAndForward` still
answers `502 redemption commit failed` and releases (token-bound) on a commit exception, and since
0.0.19 also answers `502 redemption lease lost` when the commit finds the lease gone (the newer
holder is left alone). Tests: `test/redemption.test.ts` "reports a failed commit as 502 (never success)
and releases the lease", "a holder whose lease lapsed before commit is told 502…".

### F21 — Stale and misleading comments, and dead code

**Severity:** Info   **Disposition:** RESOLVED (binding-model statements 0.0.19; the remaining cosmetic items
2026-10-10, unreleased, commit pending)
**Where:**

- `src/chain.ts:9-12` (module doc: "bound to the challenge nonce + sender + gate") contradicts
  `consumeTxValid`'s doc and behaviour (not nonce-bound).
- `src/chain.ts:264-285` `nonceMatches` is exported and unit-tested but unused in production.
- `src/state/kv.ts:1-8` (F2).
- `src/cors.ts:4-5` names `sui.meddleware.co.uk` (not an allowed origin).
- `wrangler.toml:3` ("Rust gateway (../gateway)", actually `gateway-rust`).
- `src/proxy.ts:127` `@ts-expect-error` comment says "without 'duplex'" while passing `duplex`.

**Issue / Impact:** This is TS lens §A *Accurate comments*. These mislead reviewers about the binding
model in exactly the area where F1/F23 matter.

**Remediation / evidence:** Re-checked 2026-10-09.

- Fixed: `kv.ts` doc (0.0.19); `consumeTxValid`, `redeemAndForward`, `SECURITY.md` invariants 4–6 and the
  `CLAUDE.md` Redemption section describe the digest-first, owner-bound model.
- Still present (comments only, no behaviour): the `chain.ts` module doc ("bound to the challenge
  nonce"); `nonceMatches` (`chain.ts:320`) is exported, unused and no longer tested; `cors.ts:4-5`;
  `wrangler.toml:3`; the `proxy.ts` `@ts-expect-error` comment; and `CLAUDE.md`'s "Fallback: Workers KV"
  bullet that calls the single-use bind "unaffected" (contradicts F2's fix).
- 2026-10-10 (unreleased, commit pending): the `chain.ts` module doc now says the event is not
  nonce-bound (F23); `nonceMatches` and its import are deleted (no caller, no test); `cors.ts` no longer
  names `sui.meddleware.co.uk`; `wrangler.toml` points at `../gateway-rust`; the `proxy.ts`
  `@ts-expect-error` note says what is missing from the type; `CLAUDE.md`'s KV bullet now says
  `SINGLE_USE=true` refuses the KV backend. `tsc` and `eslint` clean (an unused import would fail lint).

### F22 — Consume binding uses the event `sender`, not the `consumer` field

**Severity:** Info   **Disposition:** ADJUDICATED (shared with `gateway-rust` F22)
**Where:** `src/chain.ts` `eventMatches`; `access_gate::consume` sets `consumer = ctx.sender()`.

**Issue / Impact:** Equivalent by construction today. Re-check on any `access_gate` upgrade.

**Remediation / evidence:** Intentional. Re-verified 2026-10-09: `eventMatches` still compares the
normalised event `sender` and `gate_id`; the republished `access_gate` (v1 of `0xd7ddaa94…`) did not
change `consume`. Optionally assert `json.consumer` equals the sender as well.

### F23 — Challenge nonce deliberately not bound to `AccessConsumedEvent.nonce`

**Severity:** Info   **Disposition:** ADJUDICATED (shared with `gateway-rust` F23)
**Where:** `src/chain.ts:166-180` (doc), root `CLAUDE.md`; cross-repo `access-gate-sui/CLAUDE.md`
invariant 2.

**Issue / Impact:**

- Digest-first redemption lets an interrupted upload resume with a fresh challenge. The redemption
  store enforces single use instead.
- This is coherent, but it is the precondition for F1's single-use variant.
- It contradicts the Move package's documented verifier contract.

**Remediation / evidence:**

- `access-gate-sui/CLAUDE.md` now describes the digest-first binding verifiers must use, with the
  `nonce` optional, so the Move package's documented contract matches the gateway.
- F1's fix restores an equivalent binding: in single-use mode the consume digest is part of the signed
  v2 message, so a proof is bound to one consume, and the redemption store still allows a resume with a
  fresh nonce and a new signature over the same digest.
- `consumeTxValid` keeps binding sender, exact event type, gate and age (F24), not the nonce.

### F24 — A committed digest becomes redeemable again after the 30-day retention

**Severity:** Info   **Disposition:** RESOLVED (0.0.19, `6a601d3`; OQ5 decided; shared with `gateway-rust`
F24)
**Where:** `wrangler.toml` `REDEMPTION_RETENTION_SECS = "2592000"` (its comment acknowledges the edge);
`durable_object.ts:123` deletes expired commits.

**Issue / Impact:** After 30 days, an old consume (still served by fullnodes) redeems once more,
repeatably every 30 days.

**Remediation / evidence:**

- `consumeTxValid` refuses a consume whose event `timestamp_ms` is older than `CONSUME_MAX_AGE_SECS`
  (default and deployed 432,000 s = 5 days, inside the roughly 5.5-day transaction retention of public
  testnet fullnodes) or in the future beyond a 60 s skew; a missing or malformed timestamp is not
  recent. `loadConfig` throws if `CONSUME_MAX_AGE_SECS` exceeds `REDEMPTION_RETENTION_SECS`, so no
  consume can outlive its redemption record.
- Decision (OQ5): bound the consume age to the retention rather than extend the retention.
- Tests: `test/chain.test.ts` "accepts an event inside the age window and rejects an older or a future
  one", "a missing or malformed timestamp is not recent", "refuses a consume older than the age bound…";
  `test/config.test.ts` "…a consume must not outlive its retention".

### F25 — All redemptions go through one global Durable Object

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/state/durable_object.ts:18` (`REDEEM_SHARD = 'redeem'`) and `:206-217`.

**Issue / Impact:**

- A single DO serialises every lease, commit and release worldwide, which costs cross-region latency
  and a throughput ceiling of roughly 1,000 requests per second per object.
- Correctness requires it: one digest must never be accepted in two shards, the lens's sharding rule.
  At current volume it is fine.

**Remediation / evidence:** Accepted. Re-verified: `REDEEM_SHARD` and the three redemption methods are
unchanged in shape (now token-bound). If volume grows, shard by a hash of the digest, which is still
deterministic per digest.

### F26 — RPC network label is inferred from the URL

**Severity:** Info   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/chain.ts:55-58` (`/mainnet/i.test(rpcUrl) ? 'mainnet' : 'testnet'`).

**Issue / Impact:** The label is cosmetic with an explicit `baseUrl` (documented). A mainnet RPC behind
a host without "mainnet" in its name is labelled testnet. There is no ID-selection impact, because IDs
come from `NFT_TYPE`/`GATE_ID`.

**Remediation / evidence:** The network is now an explicit, validated `NETWORK` var
(`localnet|devnet|testnet|mainnet`), passed to `SuiGrpcClient` and signed into every access proof (F1);
nothing is inferred from the URL. Test: `test/config.test.ts` "requires a canonical https origin and a
known network". Not added: a check of `NETWORK` against the RPC's chain identifier (optional SC-M5
hardening; a wrong pairing fails closed, because the object reads find nothing).

### F27 — `compatibility_date` is 18 months old

**Severity:** Info   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `wrangler.toml:31` (`2025-04-01`).

**Issue / Impact:** Runtime fixes and behaviour changes behind later dates are not applied. Some
streaming and fetch semantics are flag-gated.

**Remediation / evidence:** `compatibility_date = "2026-06-01"` (CHANGELOG 0.0.19). Both test pools
(`test:all`, 176 passed) run green against it, including the streamed-body and redirect tests. The
cadence stays with S6.

### F28 — Publish workflow's verify job omits lint

**Severity:** Info   **Disposition:** RESOLVED (nft-gate main, after 0.0.17)
**Where:** `npm-publish.yml:15-40` (versions, `npm ci`, audit, type-check `--if-present`, `test:all`;
no `npm run lint`) vs `node-ci.yml` (which lints).

**Issue / Impact:** A tag pushed from a commit that never passed `node-ci` publishes unlinted source.
The impact is low because lint is style plus a few correctness rules.

**Remediation / evidence:** The `verify` job in `npm-publish.yml` now runs the same checks as
`node-ci.yml`: versions aligned, `npm ci`, `npm audit --audit-level=high`, `sync-vectors --check`,
type-check, **`npm run lint`**, `npm run test:all` (base §B.2 "Release gate equals CI"). Minor leftover:
the type-check step still carries `--if-present` although the script exists (harmless).

### F29 — `workers_dev` / preview URLs not pinned off; `'unknown'` IP fallback

**Severity:** Info   **Disposition:** MITIGATED (first half RESOLVED 0.0.19; the `unknown` bucket remains
by design)
**Where:** `wrangler.toml` (no `workers_dev` / `preview_urls`) and `src/index.ts:146-148` (`clientIp`
falls back to `'unknown'`).

**Issue / Impact:**

- Depending on wrangler defaults, the Worker may also answer on `nft-gate-gateway.<account>.workers.dev`
  (and on preview URLs for uploaded versions), outside the zone's WAF and rate-limiting rules.
- `CF-Connecting-IP` is present there too. The `'unknown'` bucket arises only off-platform, but it
  would merge all such clients into one bucket.

**Remediation / evidence:**

- `wrangler.toml` sets `workers_dev = false` and `preview_urls = false` (0.0.19). The account's
  `workers.dev` subdomain is not recorded in the repo, so the live effect was not probed.
- `clientIp` (`src/index.ts:167-169`) still returns the shared `unknown` bucket when
  `CF-Connecting-IP` is absent. Cloudflare sets it on every routed request, so this arises only
  off-platform (local dev, tests); the shared bucket then throttles rather than bypasses. Left as is.

### F30 — Coverage gaps against the WORKERS and TS lens requirements

**Severity:** Info   **Disposition:** RESOLVED (most gaps closed in 0.0.19; the residual tests 2026-10-10,
unreleased, commit pending)
**Where:** `test/**`.

**Issue:** The following required tests are missing:

- rate limit on **public** paths;
- cache **bypass for gated paths**: gated responses are never cached. This is true by construction,
  since only `forwardPublic` caches, but untested;
- commit failure at the router level (tested at the unit level only);
- lease expiry **during** a forward (F3);
- redirect handling (F4);
- failed-transaction status (`FailedTransaction` / `status.success = false`) in `consumeTxValid`;
- multi-page ownership;
- CORS with an upstream ACAO (F12).

No coverage tool or figure is configured.

**Impact:** Regressions in these paths would pass CI.

**Remediation / evidence:** Re-checked against the 179 tests (176 passed, 3 env-gated).

- Now covered: redirects (`proxy.test.ts`); failed transaction, foreign sender and age bound in
  `consumeTxValid` (`chain.test.ts`); upstream ACAO (`router.test.ts`); stale-holder release/commit and
  lapsed lease at commit (`state.test.ts`, `redemption.test.ts`); upstream deadline (`proxy.test.ts`);
  hop-by-hop, cookie and method/path policy (`proxy.test.ts`, `router.test.ts`); pre-auth limit
  (`router.test.ts`); strict config (`config.test.ts`); multi-page ownership lives in
  access-gate-client's own suite.
- Still missing: a rate-limit test on the **public** path; a test that **gated responses are never
  cached**; a router-level test that a store outage is `503` (only the unit-level propagation is
  tested); a test of the IPv6 /64 keying and of the degrade-flag branch (F2). No coverage tool is
  configured (`@vitest/coverage-v8` on the Node pool remains a suggestion).
- 2026-10-10 (unreleased, commit pending), all in the workerd project, `test/gateway-state.test.ts`:
  public-path rate limit (120 pass, the 121st is 429 with CORS, another IP unaffected); IPv6 `clientIp`
  cases and a 30-request rotation inside one /64 that is then limited while a neighbouring /64 is not;
  `forward()` of a gated request neither calls `cache.match` nor `cache.put`; a throwing Durable Object
  binding answers JSON 503 `gateway state unavailable` with CORS; the degrade flag moves ownership-mode
  nonces to KV and is ignored in single-use mode. The file notes why its tests are ordered (a fresh
  module copy invalidates the Durable Object host). The coverage tool stays a suggestion.

### F31 — Credential inventory, Access token expiry and API-token scopes are unrecorded

**Severity:** Low   **Disposition:** MITIGATED (Access token inventory and rotation recorded; the
`CLOUDFLARE_API_TOKEN` scopes/expiry and a pre-expiry reminder are maintainer items, pre-mainnet gate
"secrets-management verified")
**Where:** `wrangler.toml` header (secret names, setup steps) and `deploy-workers.yml`
(`CLOUDFLARE_API_TOKEN`, `UPSTREAM_AUTH_HEADERS`).

**Issue:**

- AUTH lens B.AUTH-1 and WORKERS lens B.1 (Access application, policy and service-token IDs, token
  expiry) are not recorded.
- Cloudflare Access service tokens expire (one year by default). When this one does, the relay
  rejects the gateway: fail closed, and a full outage of paid uploads.
- `deploy-workers.yml` makes GitHub the source of truth for `UPSTREAM_AUTH_HEADERS`, which helps
  rotation but needs a documented cadence.

**Impact:** Unplanned outage at token expiry, and an undefined compromise response.

**Remediation / evidence:**

- `docs/networking/CLOUDFLARE.md` §2.4 now records the Access application ("Walrus relay origin
  (nft-gate Worker only)", `walrus-relay-origin.meddleware.co.uk`, Service Auth, the Worker's token
  only), the token (`nft-gate-worker-relay-origin-v2`, client id `e7530ffb…`, **expires 2027-09-09**,
  secret rotated 2026-10-01, held in the GitHub secret `UPSTREAM_AUTH_HEADERS`) and the rotation
  procedure (new token, add to policy, update the GitHub secret, run `Deploy Workers`, verify the Worker
  path, remove and revoke the old token). B.AUTH-1 below mirrors it.
- Remaining, maintainer-owned and not yet in `OPERATOR_TASKS.md`: the `CLOUDFLARE_API_TOKEN` scopes,
  expiry and rotation (F16), and a calendar reminder ahead of 2027-09-09.

### F32 — Origin lock is verified positively, not negatively

**Severity:** Low   **Disposition:** RESOLVED (2026-10-10, unreleased, commit pending; first GitHub run
to be confirmed after the push)
**Where:** `scripts/check-upstream-auth.mjs` (asserts the origin **accepts** the token, with
`redirect: 'manual'`), `deploy-workers.yml` (`UPSTREAM_CHECK_URL`), `README.md:96-125`.

**Issue:** CF-M2 requires proof that the upstream is reachable **only** with the gateway's credential,
"verified by a direct request that is refused". The deploy check proves the positive case only.

**Impact:** If the Access policy on the relay hostname is removed or misconfigured, every guarantee of
this gateway is moot, and nothing would notice.

**Remediation / evidence:**

- Evidence of the property today: a direct request without the token to
  `walrus-relay-origin.meddleware.co.uk` (`/` and `/v1/tip-config`) was refused with **401** on
  2026-10-09; the positive check runs on every deploy (`UPSTREAM_CHECK_URL` is set as a repository
  variable; the deploys of 2026-10-09 succeeded). This is a one-off manual check, not a repeatable one.
- Done 2026-10-10: `.github/workflows/origin-lock.yml` runs daily (05:17 UTC), on demand and on pull
  requests that touch it. It runs `scripts/check-origin-locked.mjs` with the repository **variable**
  `UPSTREAM_CHECK_URL` (a public URL, already set; no secret, no credential sent). Three GET probes with
  `redirect: 'manual'`: the check path and `/` without a token, and the check path with a made-up
  service token. Each must be refused **by Access** (`scripts/origin-lock.ts`: 401/403 carrying
  `cf-access-domain`, or a redirect to `*.cloudflareaccess.com` / `/cdn-cgi/access/`). A 2xx, a refusal
  by anything else, a 5xx or three failed attempts fails the run; a zone challenge (`cf-mitigated:
  challenge`, Bot Fight Mode) is inconclusive and only warns, as in the deploy check. A missing
  variable also fails, so the schedule cannot silently stop checking.
- Pinned by `test/origin-lock.test.ts` (verdict table; the script fails closed without a URL or on
  non-https). Run locally against the live origin 2026-10-10: three probes, all `401` with
  `cf-access-domain`, exit 0; against `https://example.com/` the script exits 1.
- Not changed: `check-upstream-auth.mjs` stays the positive deploy check (it needs the secret); the
  negative check is kept out of the deploy job so a lock problem cannot block a code fix. GitHub
  pauses scheduled workflows after 60 days without repository activity (noted in the workflow).

### F33 — `@mysten/sui` uses a tilde range one minor behind; TS shared-dependency matrix row

**Severity:** Info   **Disposition:** RESOLVED (0.0.18, `4743c7b`)
**Where:** `package.json` (`"@mysten/sui": "~2.33.1"`, `"@noble/*": "~2.4.0"`, `"typescript": "^6.0.0"`,
`"vitest": "~4.1.11"`).

**Issue / Impact:**

- The ADR-0001 baseline is `^2.33.0`. The tilde pins this Worker to 2.33.x while 2.34.0 is current.
  This is acceptable for a deployable, but it must be recorded in the TS lens matrix (B.1).
- The first-party `^0.0.4` / `^0.0.15` ranges resolve exactly and are the latest published (per the
  TS lens rule).

**Remediation / evidence:** `@mysten/sui` is `^2.33.1` (0.0.18 CHANGELOG), the ADR-0001 baseline
(`^2.33.1`, one copy per bundle); the lockfile resolves 2.35.0 and `npm ls @mysten/sui` shows a single
deduped copy shared with access-gate-client. First-party ranges are `^0.0.6` and `^0.0.16` (`^0.0.17` since 2026-10-10, F47), the latest
published. The `@noble/*` `~2.4.0` pins stay (same family as `@mysten/sui`, on the verification path).

### F34 — KV backend has a documented cross-region nonce replay window (ownership mode)

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/state/kv.ts:1-8`; root `CLAUDE.md` "Deferred / post-testnet" (F2 of the earlier gateway
audit).

**Issue / Impact:** With `NONCE_BACKEND=kv`, a nonce may validate twice across regions within its TTL.
This affects ownership mode only, and KV is not bound in the deployment. Distinct from F2, which covers
single-use redemption.

**Remediation / evidence:** Accepted and documented. The Durable Object backend is the default.
Re-verified: KV is still unbound and now unreachable in single-use mode (F2), so the window can only
exist in an ownership-mode deployment that opts in.

### F35 — Cap-pressure eviction can drop an active lease

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/state/durable_object.ts:133-139` (evicts the soonest-to-expire **leased** row when
`redemptions` reaches `NONCE_MAX_ENTRIES`).

**Issue / Impact:** Requires ~10⁶ concurrent leases. Committed rows are never evicted.

**Remediation / evidence:** Accepted. With owner tokens (F3) a holder whose lease was evicted gets
`502 redemption lease lost` at commit and cannot clear a newer lease, so the eviction fails safe.

### F36 — Commit happens when upstream headers arrive, before the response body is delivered

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/redemption.ts:42-57` (`resp.ok` → commit → return the streamed `resp`).

**Issue / Impact:**

- A 2xx whose body then fails mid-stream is still committed.
- For the relay, the upload body has been fully sent before the response, and the response is small
  JSON, so the commit reflects the upload.
- Rust buffers the response before committing. This is a minor parity nuance with no economic impact.

**Remediation / evidence:** Intentional (streaming). Re-verified: `redeemAndForward` still commits on
`resp.ok` and returns the streamed response.

### F37 — Positive: the body cap is enforced on streamed bytes and on declared length

**Severity:** Positive

- `limitBody` is a counting `TransformStream` that aborts the upstream fetch via `AbortController`,
  with no buffering.
- `Content-Length` is pre-checked, and the declared length is re-attached with `FixedLengthStream`.
- workerd tests cover:
  - chunked over-limit → 413 + abort;
  - under-limit chunked and CL intact;
  - declared over-limit before contacting the upstream;
  - upstream failure → 502.

### F38 — Positive: state consistency and fail-closed storage

**Severity:** Positive

- SQLite Durable Objects; nonces sharded by continent with an allowlist (`NONCE_SHARDS`); a forged
  shard tag is rejected without touching a shard (test).
- Redemptions live in one deterministic DO, so a digest can never be accepted in two shards.
- Hard caps on nonce and redemption rows.
- Every backend call is wrapped (`guardBackend`, `guardRedemptions`) so failures become
  `503 gateway state unavailable` with CORS, never a conflict.
- DO migration versioned (`v1`, `new_sqlite_classes`); the added `token` column is migrated in place.

### F39 — Positive: signature verification and wire reuse

**Severity:** Positive

- `@noble/curves` ed25519 with `{ zip215: true }`, and ECDSA with `{ lowS: true }` on both curves.
- Intent + Blake2b-256; address = `blake2b(flag ‖ pk)`, normalised.
- Flags 0x03/0x05/0x06 fail closed.
- Wire helpers are imported from `@meddleware/nft-gate-client`, so client and gateway cannot drift.
- `test/conformance.test.ts` asserts every vector, including all negatives and the ZIP-215
  small-order case.

### F40 — Positive: edge hygiene

**Severity:** Positive

- `CF-Connecting-IP` keys the per-IP limits for the challenge (`chal:`), public (`ip:`) and gated
  pre-auth (`pre:`) paths.
- The public cache key drops the query string, so it cannot be cache-busted (test).
- CORS: exact allowlist (default none), `Vary: Origin` on every response, preflight before
  config/auth, headers on error responses (tests).
- Misconfiguration → `500 gateway misconfigured`, with details only in the Worker log.
- `NFT_TYPE` is restricted to the two `access_gate` pass types; `GATE_ID` must be an object ID;
  `UPSTREAM_AUTH_HEADERS` is strict JSON with header-token and CRLF checks (tests).
- The committed `wrangler.toml` holds only public values, and documents every secret by name.

### F41 — Positive: CI, publish and deploy chain

**Severity:** Positive

- Actions are SHA-pinned; `permissions: contents: read`; `id-token: write` only on the npm publish job.
- `npm ci` everywhere; `npm audit --audit-level=high` in CI and publish.
- Both vitest projects (`unit` on Node and `cloudflare-integration` on workerd) run in CI
  (`test:all`).
- npm publishes via OIDC with `--provenance`, is idempotent and tag-gated (`v*`, with
  `check-versions.sh`), and the npm client is pinned (`npm@11.20.0`).
- The deploy is manual (`workflow_dispatch`), `main`-only, re-runs CI and is serialised
  (`concurrency`). Code and secret go live together through versions.
- `tsconfig` has `strict` and `noUncheckedIndexedAccess`.

### F42 — No method or path policy before building the upstream URL (found and fixed; not in the first pass)

**Severity:** Low   **Disposition:** RESOLVED (0.0.19, `6a601d3`)
**Where:** `src/proxy.ts` `forward` (first pass: `cfg.upstreamUrl + url.pathname + url.search` for any
method and any path); `src/index.ts` router.

**Issue:** PROXY lens §A *Route & method policy* was not recorded. In the first-pass code every
authenticated method (`DELETE`, `PATCH`, …) was forwarded, and the path was appended to the upstream
URL without rejecting encoded separators, NUL, backslashes or empty segments.

**Impact:** A paid caller could exercise relay methods and path shapes the product never uses, and
encoded-separator paths could reach the relay in a form it might interpret differently from the
gateway. Low, because the caller must hold a paid pass and the relay is not trusted to be the only
control.

**Remediation / evidence:**

- `FORWARDED_METHODS = GET, HEAD, POST, PUT` (`src/proxy.ts`): gated requests with another method get
  `405` before any verification work; public paths are `GET`/`HEAD` only (F10).
- `isSafePath` (`src/headers.ts`) refuses `%2f`, `%5c`, `%00`, `%2e%2e`, backslashes, control
  characters and empty segments (`//`) with `400 invalid path`; the WHATWG URL parser has already
  collapsed plain dot segments. The upstream URL is built from the configured origin plus the validated
  path.
- Tests: `test/proxy.test.ts` "refuses a method outside the list and an unsafe path before contacting
  the upstream"; `test/router.test.ts` "gated paths refuse methods outside the list before any
  verification work".

### F43 — No `Via` loop marker; only the literal self-origin is refused

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `src/config.ts` (`UPSTREAM_URL must not be this gateway (request loop)`), `src/headers.ts`
(`via` is stripped from the request and never set).

**Issue:** PROXY lens §A *Loop & self-reference* asks that a `Via` or loop-marker check refuse a request
that has already passed through. The Worker refuses an `UPSTREAM_URL` whose origin equals
`GATEWAY_ORIGIN`, but an upstream hostname that resolves back to the route would not be caught, and no
marker is added.

**Impact:** A loop needs an operator to point the Access-locked origin hostname at the gateway's own
route. Gated paths would then be refused for want of a proof on the second hop, and public paths are
bounded by the platform's subrequest limits and the rate limiter. Operator-only misconfiguration, not
attacker-reachable.

**Remediation / evidence:** Accepted. If the gateway is ever offered as a white-label package with
operator-chosen upstreams, add a `Via`/marker check that returns `508`. The Go sibling
`registry-auth-proxy` 0.1.6 has such a check (508).

### F44 — Upstream error statuses and bodies pass through to the client

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `src/proxy.ts` (`new Response(upstream.body, { status: upstream.status, … })` for every
non-3xx response); `src/redemption.ts` (non-2xx releases the lease and returns the response as is).

**Issue:** PROXY lens §A *Error mapping* prefers fixed `502`/`503`/`504` bodies without upstream detail.
For 4xx/5xx answers from the relay the gateway returns the relay's status and body (headers filtered,
F12/F13).

**Impact:** The relay's own error JSON (for example a tip-payment or size rejection) reaches the
client. The relay is first-party, its errors carry no secret, and the clients (`walrus-client`)
need them to react. Network failures, timeouts, redirects and store errors are mapped to fixed
`502`/`504`/`503` bodies.

**Remediation / evidence:** Intentional; a failed upload (non-2xx) releases the lease so the consume is
not lost (`redemption.test.ts` "a failed upload or a thrown error releases the lease…"). Revisit if a
third-party upstream is ever fronted.

### F45 — The live relay gate does not let a pause block access

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** gate `0x316f1bf9…faddc` (read live 2026-10-09): `paused` false,
`policy.pause_blocks_access` false; `src/chain.ts::gateBlocksAccess`.

**Issue:** The gateway honours a pause only when the gate's immutable `GatePolicy` has
`pause_blocks_access = true` (decision: GatePolicy and pass kind are immutable, `access_gate` E15/E16).
This gate was created with it false, so pausing the gate will not stop the paywall from admitting
holders.

**Impact:** The on-chain kill switch for this gate does not exist; to cut access in an emergency the
operator must remove the Worker route or revoke the Access service token (B.CF-1). Holders of already
bought passes are otherwise admitted until their uses are spent.

**Remediation / evidence:** Accepted: the policy cannot be changed after creation. Recorded so the
operator runbook (`post-bootstrap/walrus/README.md`) does not rely on gate pause for this relay. A gate
created for mainnet should set `pause_blocks_access` deliberately.

### F46 — Positive: audience-bound proofs, owner-bound redemption and proxy hygiene

**Severity:** Positive

- The v2 message binds origin, gate, network, nonce and consume digest and is rebuilt from the Worker's
  own configuration; vectors with a negative per bound field come from the client package and are
  checked for drift in CI (`sync-vectors --check`).
- Leases carry a random owner token; commit and release are compare-and-set; a lapsed holder is told
  502 and cannot disturb the next one; the lease outlives the upstream deadline by a startup check.
- Redirects are never followed, hop-by-hop and spoofable fields are stripped both ways, upstream CORS
  and cookies never reach the client or the edge cache, and methods and paths are allowlisted.
- Configuration is strict: a typo is a startup error, not a weaker mode.

### F47 — Proof-token base64, UTF-8 and JSON layers were lenient in the client decoder (parity with `gateway-rust`)

**Severity:** Low   **Disposition:** RESOLVED (nft-gate-client 0.0.17 adopted 2026-10-10, unreleased, commit
pending). Not the same finding as `gateway-rust` F47. Origin: nft-gate-client audit F24.
**Where:** `decodeAccessProof` in `@meddleware/nft-gate-client` (imported by `src/wire.ts`), through
`atob` / `TextDecoder` / `JSON.parse`.

**Issue:** Up to 0.0.16 the shared decoder checked size, ASCII and the field grammar but let `atob`
forgive unpadded, whitespace-split and non-canonical base64, accept a UTF-8 BOM and invalid UTF-8 in
unknown keys, and parse unpaired surrogate escapes, overflowing numbers and deep nesting. The Rust
gateway (`BASE64_STANDARD.decode`, `serde_json`) already refused these, so the two gateways could decide
differently on a crafted token. No signature check is bypassed (the fields are validated afterwards),
so this is a parity and robustness gap, not an admission bug.

**Remediation / evidence:** `@meddleware/nft-gate-client` ^0.0.17 decodes strictly (canonical padded
standard-alphabet base64, fatal UTF-8 without BOM, bounded JSON) and adds 11 vectors to
`proofDecodeRejects`. Here: dependency bumped (lockfile entry only; the `overrides` for `sharp` and
`undici` are kept), `conformance/vectors.json` refreshed with `node ../scripts/sync-vectors.mjs`
(`--check` passes). `test/conformance.test.ts` (Node) runs every reject case through `decodeAccessProof`;
`test/router.test.ts` (workerd, where `atob`/`TextDecoder` are the runtime's own) runs the same cases
through the decoder and, except the newline case that cannot ride in a header, through
`POST /v1/blob-upload` expecting `403 malformed access proof`. All 27 reject cases pass in both runtimes.
`gateway-rust` already rejected these cases (its `conformance_shared_vectors` reads the same list); the
second gateway's re-run belongs to its own audit.

---

## Section A — Invariant verification matrix

| # | Invariant | Enforced / asserted at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Any decode, signature, nonce, chain or store error denies | `verify.ts::verifyAccessRequest`; `index.ts` `guardBackend`/`StoreError` | verify tests ("denies malformed proof", "treats a failed gate read as a chain error"); router "malformed proof → 403"; `redemption.test.ts` store error propagates | HOLDS |
| I2 | A nonce is consumed exactly once, before the chain call | `verify.ts` (`takeIfValid` after signature, before chain); DO `takeIfValid` (single-threaded object) | state tests "a nonce is valid once, then used", "expired", "unknown"; verify "denies a replayed nonce"; router round trip | HOLDS |
| I3 | Signatures verified as Sui accepts them; 0x03/0x05/0x06 fail closed | `verify.ts` + `crypto.ts` | `conformance.test.ts` (positives, negatives, ZIP-215) | HOLDS |
| I4 | The address is normalised before comparison | `verify.ts::normalizeAddress` | vectors `addressNormalization`; chain "compares sender and gate ids in normalised form" | HOLDS |
| I5 | Consume binding: tx success, exact event type, sender == signer, `gate_id`, age | `chain.ts::consumeTxValid`, `isConsumedEvent`, `eventMatches`, `eventIsRecent` | chain "matches the event type exactly: a look-alike package cannot forge a consume", "refuses a consume older than the age bound, a failed transaction and a foreign sender"; verify "single-use requires a valid consume" | HOLDS |
| I6 | Single use: a digest redeems once; committed never cleared; interrupted releases; owner-bound | `redemption.ts`; DO redemptions; `config.ts` (DO only, lease > deadline) | redemption + state tests (lease/commit/release/expiry; stale holder; lost lease → 502); config single-use invariants | HOLDS (F2, F3) |
| I7 | Ownership mode admits only valid, usable passes | `chain.ts::ownsNft` → `ownsAccessNft` (access-gate-client ≥ 0.0.5) | verify "allows an owner"/"denies a non-owner" (fake chain); access-gate-client suite | HOLDS (F7) |
| I8 | A paused gate with `pause_blocks_access` admits no one; unrecognised gate JSON denies | `verify.ts` pause check; `chain.ts::gateBlocksAccess` | verify paused-gate tests; chain "fails closed on JSON it does not understand" | HOLDS (F15; this gate's policy opts out, F45) |
| I9 | Body cap on streamed bytes and on `Content-Length`; never buffered | `proxy.ts::limitBody`, `forward` | `proxy.test.ts` (workerd body-limit tests) | HOLDS |
| I10 | Every outbound call has a timeout | `proxy.ts` (total deadline, 504); `chain.ts::withDeadline`; `quota.ts` | proxy "ends a stalled upstream with 504"; chain "rejects a call that never settles" | HOLDS (F6) |
| I11 | Upstream credentials go only to the upstream origin; redirects never followed | `proxy.ts` (`redirect: 'manual'`, 3xx → 502) | proxy "never follows a redirect…" | HOLDS (F4) |
| I12 | Replay/single-use state strongly consistent; shard names allowlisted | `state/types.ts::shardOfNonce`; DO backend; config refuses KV for single-use | "the Durable Object backend rejects a forged shard tag"; "a region-sharded nonce is accepted by the shard that issued it"; config "refuses the KV backend…" | HOLDS (KV only in ownership mode, F34) |
| I13 | Lease/commit/release fail closed; commit failure has a shared defined outcome | `redemption.ts` | "reports a failed commit as 502…", "releases and rethrows…", "a holder whose lease lapsed before commit is told 502…" | HOLDS (see F20) |
| I14 | Abuse keys from `CF-Connecting-IP` (IPv6 by /64); every state-allocating public endpoint limited; gated limited before verification | `index.ts::clientIp`, challenge + public + `pre:` `rateCheck` | router "rate-limits GET /v1/challenge per client IP", "rate-limits gated requests per client IP BEFORE verifying the proof"; gateway-state "rate-limits public paths…", "keys IPv6 clients by their /64" | HOLDS (F30) |
| I15 | Inbound `Authorization`/`X-Access-Proof`/`cf-access-*` stripped; injected headers override | `headers.ts::upstreamRequestHeaders` | proxy "strips hop-by-hop … request fields" | HOLDS |
| I16 | Committed config holds only public values; secrets inventoried | `wrangler.toml` | review | HOLDS |
| I17 | Upstream reachable only via the gateway (origin lock) | Cloudflare Access (external) | `check-upstream-auth.mjs` (positive, every deploy); `check-origin-locked.mjs` (negative, daily, `origin-lock.yml`); direct request refused 401 on 2026-10-09 and 2026-10-10 | HOLDS (code-only: Access itself is external; F32) |
| I18 | CORS: exact allowlist, `Vary: Origin`, preflight before config/auth, on errors; upstream CORS never survives | `cors.ts`, `headers.ts`, `index.ts` | router CORS tests, "upstream-supplied CORS never widens the allowlist" | HOLDS (F12) |
| I19 | Only public paths cached, under a normalised key, without upstream CORS/cookies; gated never cached | `index.ts::forwardPublic` | router "drops the query string from the cache key…"; gateway-state "forwarding a gated request neither reads nor writes the edge cache" | HOLDS (F30) |
| I20 | No proofs, signatures or secrets in logs or error bodies | `index.ts` (misconfig detail to log only), `deny` bodies | review | HOLDS (code-only) |
| I21 | Hop-by-hop (and `Connection`-named) fields stripped both directions; cookies and CORS stripped from responses (`SECURITY.md` inv. 6) | `headers.ts` | proxy header-policy tests | HOLDS (F13) |
| I22 | Misconfiguration fails closed | `config.ts::loadConfig` → 500 | config tests | HOLDS (F8, F17) |
| I23 | Scheduled job safe | `quota.ts` `scheduled` (catches own errors; 15 s timeout; cron commented out; never moves single-use redemptions) | review | HOLDS (code-only) |
| I24 | The proof is bound to the intended audience | `verify.ts` (message rebuilt from `cfg`) | verify "audience binding (protocol v2)"; vectors `audienceMismatch` | HOLDS (F1) |
| I25 | Wire parity with `gateway-rust` | `conformance/vectors.json` (published by nft-gate-client, `--check` in CI) | `conformance.test.ts` | HOLDS for covered fields; remaining uncovered rows in B.SC-3 |
| I26 | Only listed methods and safe paths are forwarded; public paths are `GET`/`HEAD` | `index.ts`, `proxy.ts::FORWARDED_METHODS`, `headers.ts::isSafePath` | router "public paths are read-only…", "gated paths refuse methods…"; proxy "refuses a method outside the list and an unsafe path…" | HOLDS (F10, F42) |
| I27 | A request that has already passed through the gateway is refused | `config.ts` (literal self-origin only) | config "refuses an upstream that is the gateway itself" | HOLDS (code-only) for the literal case; no `Via` marker — F43 |

---

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

`package-lock.json` is committed. `npm audit --audit-level=high`: **0 vulnerabilities** (2026-10-09).
Overrides: `sharp` `^0.35.5` and `undici` 7.29.1, both transitive dev-tooling (wrangler/miniflare) CVE
pins. `allowScripts`: `esbuild`, `workerd`. Dependabot (weekly, grouped; npm, cargo, docker, actions)
merged the Worker group on 2026-10-09 (`dd9b146`).

| Dependency | Pinned (lockfile) | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `@mysten/sui` | `^2.33.1` (2.35.0) | every gated request (gRPC) | clean | ADR-0001 baseline `^2.33.1`; single copy |
| `@noble/curves` / `@noble/hashes` | `~2.4.0` (2.4.0) | signature verify path | clean | `zip215`, `lowS` options |
| `@meddleware/nft-gate-client` | `^0.0.17` (0.0.17) | wire format, vectors | clean | first-party; exact resolution |
| `@meddleware/access-gate-client` | `^0.0.6` (0.0.6) | ownership mode | clean | usable passes only (F7) |
| wrangler / workerd | `^4.143.0` (4.147.0 / 1.20260815.1) | deploy, test pool | clean | |
| `@cloudflare/vitest-pool-workers` | `~0.22.0` (0.22.0) | CI tests | clean | |
| `@cloudflare/workers-types` | `~5.20261005.1` | types | clean | |
| `typescript` / `vitest` / `eslint` | `^6.0.0` (6.0.3) / `~4.1.11` (4.1.11) / `^10.11.0` (10.12.0) | dev | clean | TS 7 and vitest 5 declined by decision |
| Sui fullnode `https://fullnode.testnet.sui.io:443` | public (Mysten) | gated — fails **closed** (502) | n/a | 15 s per-call deadline |
| Upstream relay | `UPSTREAM_URL` (secret) | gated + public — 502/504 | n/a | Access-locked |
| Cloudflare Access | application "Walrus relay origin (nft-gate Worker only)"; token `nft-gate-worker-relay-origin-v2`, expires 2027-09-09 | upstream reachability — fails **closed** | n/a | `docs/networking/CLOUDFLARE.md` §2.4 |
| Cloudflare GraphQL Analytics | quota guard only (disabled) | none in the request path | n/a | 15 s timeout |

**TS lens: shared-dependency matrix row (this repo).**

| Package | dependency | devDependency | peer |
| --- | --- | --- | --- |
| `@mysten/sui` | `^2.33.1` | — | — |
| `@mysten/walrus`, `@mysten/walrus-wasm`, `@mysten/seal`, `@mysten/wallet-standard`, `@mysten/bcs` (direct) | — | — | — |
| `vue` | — | — | — |
| `typescript` | — | `^6.0.0` | — |
| `vitest` | — | `~4.1.11` | — |

No deviation from ADR-0001 (F33). The repo has a single nested manifest (`gateway-workers/package.json`);
first-party ranges are `^0.0.x` (exact), which is compliant. TS-M9 is N/A: a deployable Worker has no
embedding host; access-gate-client's `@mysten/sui` peer range (`^2.33.2`) is satisfied by the single
installed copy.

### B.2 Publish authority, capabilities & secret custody

| Authority / capability / secret | Where minted / held | Custody | Gates | Rotation plan |
| --- | --- | --- | --- | --- |
| npm publish `@meddleware/nft-gate-gateway` | `npm-publish.yml` (tag `v*`, `NPM_PUBLISH=true`) | GitHub OIDC → npm trusted publisher, `--provenance` | package releases | n/a (no token) |
| `CLOUDFLARE_API_TOKEN` | GitHub secret (`production` env) | GitHub | Worker code + secrets on the live route | **scopes and rotation unrecorded (F16, F31)** |
| `UPSTREAM_AUTH_HEADERS` | GitHub secret (source of truth) → Worker secret | GitHub + Cloudflare | origin lock | token expires 2027-09-09; procedure in `CLOUDFLARE.md` §2.4 (F31) |
| `UPSTREAM_URL` | Worker secret | Cloudflare | which origin is gated | n/a (not a credential) |
| `SUI_RPC_AUTH_HEADER` (opt.) | Worker secret | Cloudflare | RPC quota | unrecorded; unused today |
| `CF_ANALYTICS_TOKEN`, `CF_ACCOUNT_ID` (opt.) | Worker secrets | Cloudflare | quota guard | unused while disabled |
| Route `sui-walrus-relay-testnet.meddleware.co.uk/*` | Cloudflare zone `meddleware.co.uk` | zone owner | which traffic hits the Worker | n/a |

#### CI & release integrity

| Item | Holds? | Evidence |
| --- | --- | --- |
| Actions pinned | Yes | `actions/checkout@3d3c42e5…`, `actions/setup-node@82076278…` (SHA + version comment); Dependabot `github-actions` group keeps them current |
| Least privilege | Yes | top-level `contents: read`; `id-token: write` only in `npm-publish.yml`'s publish job |
| OIDC trusted publishing | Yes (npm) | `npm publish --provenance` via OIDC; Cloudflare deploy uses an API token (no OIDC option) — inventory in B.AUTH-1 |
| Tag-gated, idempotent publish | Yes | `on: push: tags: v*`; registry existence check and "cannot publish over" treated as success |
| Release gate equals CI | Yes | `npm-publish.yml` `verify`: versions, `npm ci`, audit, `sync-vectors --check`, type-check, lint, `test:all` (F28); `deploy-workers.yml` calls `node-ci.yml` |
| Automated dependency updates | Yes | `.github/dependabot.yml`: weekly grouped npm (`/gateway-workers`), cargo, docker and github-actions; 2026-10-09 triage merged the groups |
| Container images | N/A | no image for the Worker (the Rust gateway's image: `gateway-rust-audit.md`) |
| Secrets never echoed | Yes | the secret is piped via `printf '%s'` into `wrangler versions secret put`; no `set -x` |
| Real funds are manual | N/A (no funds); the deploy is manual | `workflow_dispatch`, `environment: production` |
| Test-only modes | Yes | none in the Worker; `vitest.config.ts` bindings are test-only |

### B.CF-1 Deploy authority

| Item | State |
| --- | --- |
| Who can deploy | anyone who can run `workflow_dispatch` on `main` in `meddleware-org/nft-gate`, subject to the `production` environment (deployment branch policy `main` only, **verified 2026-10-09**; no required reviewers, admins may bypass); anyone holding `CLOUDFLARE_API_TOKEN` or Cloudflare dashboard access |
| Who can `wrangler secret put` | the same token (the workflow uses `versions secret put`/`delete`) |
| Token scopes | **unrecorded** (F16, F31) |
| Deploy only after CI | Yes — `needs: ci` (`node-ci.yml`: audit, vectors check, type-check, lint, both test pools); `if: github.ref == 'refs/heads/main'` |
| Protected environment with reviewers | branch policy configured; reviewers not configured and the choice is not recorded (OQ4) |
| Route / zone owner | `meddleware.co.uk` zone; route ID `63427e4d…`; owner not recorded |
| Recent deploys | 2026-10-08 `4743c7b` success, `11aa7c9` failure (deploy pre-check could not load `config.ts`; fixed by `83349b8`, success), 2026-10-09 `574fe70` and `367e673` success |

### B.SC-1 ID-constant trace

| Location | Network | Value | original-id / published-at | Matches latest on-chain (evidence) |
| --- | --- | --- | --- | --- |
| `gateway-workers/wrangler.toml:52` `NFT_TYPE` | testnet | `0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9::access_gate::SoulboundAccessNFT` | original-id (= published-at, v1) | Y — `access-gate-sui/Published.toml` `[published.testnet]` version 1, 2026-10-09 |
| `gateway-workers/wrangler.toml:56` `GATE_ID` | testnet | `0x316f1bf9764db352e925bb598aff44ea77be4ab652f0bd2eb3fdcc0a378faddc` | object | Y — read live 2026-10-09: an `0xd7ddaa94…::access_gate::Gate` (`default_uses` 10, not paused) |
| `gateway-workers/vitest.config.ts:51` | test binding | same `NFT_TYPE` | original-id | Y |
| Apps' `VITE_ACCESS_GATE_ID_TESTNET` (dashboard, token-deployer-ui; walrus-ui) | testnet | `0x316f1bf9…faddc` | object | Y for dashboard and token-deployer-ui (their audits, 2026-10-09); `post-bootstrap/walrus/README.md:47` records the gate; the walrus-ui build arg is not in its repo tree — must equal `GATE_ID` (`wrangler.toml` coupling note) |

### B.SC-2 Coupling table

N/A — no PTBs. Read-side coupling:

| Move item | Reader | Test |
| --- | --- | --- |
| `AccessConsumedEvent { …, gate_id, nonce, consumer, timestamp_ms, … }` | `chain.ts::eventMatches`, `eventIsRecent` (sender, `gate_id`, age) | chain helper tests; env-gated `grpc-chain.integration.test.ts` (`GRPC_TESTNET=1`; 3 passed 2026-10-09) |
| `Gate { paused, policy.pause_blocks_access }` | `gateBlocksAccess` | `gateBlocksAccess` tests |
| `AccessNFT`/`SoulboundAccessNFT` `data.gate_id`, `data.variant` | `access-gate-client` `parseOwnedAccessNft` / `ownsAccessNft` | that package's tests; the variant now decides usability (F7) |

### B.SC-3 Cross-implementation parity (home table for both gateways)

Rust column from `gateway-rust` 0.0.21 (its own audit is canonical for it; rows marked **none** or **one page** are gaps recorded there, corrected here on 2026-10-10 — an earlier version of this table over-stated parity).

| Behaviour | `gateway-workers` | `gateway-rust` | Shared vector / test |
| --- | --- | --- | --- |
| Personal message bytes (v2) | via nft-gate-client | `proof.rs` | `personalMessage` + rejects + `audienceMismatch` ✓ |
| Proof decode (4096 B cap, ASCII, strict grammar, camelCase `consumeDigest`) | nft-gate-client `decodeAccessProof` | `proof.rs` | `proofDecode` + 27 rejects (base64/UTF-8/JSON layers included, F47) ✓ |
| ed25519 (ZIP-215) | noble `zip215: true` | `ed25519-consensus` | `zip215` + non-canonical-s negative ✓ |
| secp256k1 / r1 low-S | noble `lowS: true` | `normalize_s()` reject | high-S negatives ✓ |
| Flags 0x03 / 0x05 / 0x06 | fail closed | fail closed | negatives ✓ |
| Wrong intent, truncated signature | reject | reject | negatives ✓ |
| Address derivation + normalisation | `deriveAddress`, `normalizeAddress` | same | `addressNormalization` ✓ |
| Header extraction | `/^Bearer\s+(.+)$/i`, then `X-Access-Proof` | Bearer parsed like Workers (0.0.19), then `X-Access-Proof` | none (unit tests in both) |
| Verification order | decode → sig → normalise → nonce → pause → consume/own | same | per-suite unit tests; no vector |
| Status mapping | missing 401; ChainError 502; others 403; store 503 | same | none shared (`GATEWAY_STATUS` constants in nft-gate-client are not imported by either) |
| Redemption conflict | 409 with `code: redeemed \| leased` | 409 with `code` | Workers router tests; Rust has no router-level test of the mapping (gateway-rust F47); vocabulary `GATEWAY_CONFLICT_CODES` in nft-gate-client |
| Store error | 503 (`StoreError`) | 503 | Workers router tests; no router-level Rust test (gateway-rust F47) |
| Consume success check | `$kind === 'Transaction'` + `status.success` | **none** — event match only (gateway-rust F21, DEFERRED to the deploy decision) | Workers unit tests only |
| Event type | exact normalised `<pkg>::access_gate::AccessConsumedEvent` | same | look-alike tests in both ✓ |
| Event binding | sender + `gate_id` + age (not nonce) | same | unit tests in both |
| `GetTransaction` retry | not-found only, 4 × 500 ms; malformed digest never sent | same | unit tests in both |
| Owned-object pagination | all pages ≤ `MAX_OWNED_PAGES` (100) | **one page of 50** (gateway-rust F17, DEFERRED to the deploy decision) | — |
| Ownership uses check | usable passes only | usable passes only | unit tests in both |
| Pause parse | strict; unrecognised JSON denies | strict | unit tests in both |
| Nonce | 24 B random, `<shard>.<hex>` | 24 B OsRng, hex | each self-consistent |
| Nonce TTL / challenge limit / per-address limit | 300 s / 30 per IP / 30 per address | same | config tests in both |
| Gated pre-auth limit | `GATED_PREAUTH_RATE_LIMIT_PER_MIN` (120), IPv6 /64 | same | router tests |
| Public-path limit + cache | `PUBLIC_RATE_LIMIT_PER_MIN` (120) + edge cache | per its audit; no cache | none |
| Body cap | streamed counter + CL | CL pre-check + buffered body (small-body scope, undeployed) | per-suite tests |
| Request strip / response strip | `headers.ts` policy (F13) | same policy | unit tests in both |
| Methods / paths | `GET`/`HEAD`/`POST`/`PUT`; safe-path check; public `GET`/`HEAD` | same | unit tests in both |
| Upstream auth headers | JSON, validated | JSON, validated | config tests in both |
| RPC auth header | `Name: value`, validated | validated | config tests in both |
| Default `ALLOWED_ORIGINS` | none | none | config tests in both |
| CORS | exact match, grants, `Vary`, preflight first | same | router tests in both |
| Lease / commit / release; commit failure | owner-bound, 900 s > 600 s deadline; 502 + release; lost lease 502 | same | unit tests in both |
| Upstream redirects | **not followed** (3xx → 502) | not followed | proxy test (Workers) |
| Timeouts | upstream 600 s total (504); RPC 15 s | upstream 600 s; RPC `RPC_TIMEOUT_SECS` | per-suite tests |
| Misconfiguration | 500 per request | exit at startup | each suite |

### B.WAL-1 Coupling

| Format | Producer | Consumer | Test / vector |
| --- | --- | --- | --- |
| Access proof header for the gated relay | walrus-client `uploadRelayAuthToken` (nft-gate-client v2) | this gateway | `conformance/vectors.json` (published by nft-gate-client, `--check` in CI); paywall e2e PASS 2026-10-09 |
| Redemption conflict `code` | this gateway (`redemption.ts`) | walrus-client resume (`code === 'redeemed'`, plus a regex fallback) | pinned by `redemption.test.ts` (`redeemed`, `leased`); vocabulary also exported as `GATEWAY_CONFLICT_CODES` by nft-gate-client, which this Worker does not import (S7) |
| Body cap / 413 | this gateway | walrus-client / relay | `proxy.test.ts` |

### B.PX-1 Route & header policy

| Route / path | Methods | Auth | Forwarded request fields | Stripped (both ways) | Response fields kept | Cache |
| --- | --- | --- | --- | --- | --- | --- |
| `/healthz` | any (answered locally) | none | not forwarded | n/a | `200 ok` | none |
| `OPTIONS` (any path) | `OPTIONS` | none | answered locally, before config or auth | n/a | CORS grants | none |
| `GET /v1/challenge` | `GET` | none; `chal:<ip>` 30/min | answered locally | n/a | `{ nonce, expiresAt }` | none |
| `PUBLIC_PATHS` (`/v1/tip-config`) | `GET`, `HEAD` (else 405 + `allow`) | none; `ip:<ip>` 120/min | client fields minus the strip list, query dropped for GET; plus the injected Access headers | request: hop-by-hop, `Connection`-named, `host`, `authorization`, `x-access-proof`, `content-length`, `cookie`, `forwarded`, `via`, `x-forwarded-*`, `x-real-ip`, `cf-access-*`; response: hop-by-hop, `Connection`-named, `content-length`, `set-cookie(2)`, `alt-svc`, `access-control-*` | all other upstream fields; gateway CORS added | edge cache, GET only, 60 s, key without query |
| every other path (gated) | `GET`, `HEAD`, `POST`, `PUT` (else 405 before verification) | access proof v2 + live chain read + redemption lease; `pre:<ip>` 120/min before verification, 30/min per address after | as above | as above | as above; 3xx → 502; non-2xx passes through (F44) | never cached |
| unsafe path (`%2f`, `%5c`, `%00`, `%2e%2e`, `\`, control characters, `//`) | any | — | refused `400 invalid path` before the upstream URL is built | n/a | n/a | none |

### B.PX-2 Limits

| Limit | Value | Where enforced | Test |
| --- | --- | --- | --- |
| header-read timeout · body-read deadline · idle timeout | none in the Worker; the Cloudflare edge terminates client connections and applies its own timeouts | platform | live-only (C.2) |
| request body cap (declared / streamed) | 104,857,600 B both; declared → `413` before the upstream is contacted; streamed → counter aborts the fetch | `proxy.ts::forward`, `limitBody` | `proxy.test.ts` (5 workerd tests) |
| concurrent connections / in-flight forwards | no gateway cap; isolate concurrency is the platform's (the Rust gateway has `MAX_CONNECTIONS`); memory is one chunk per forward (streaming) | platform | live-only |
| upstream connect · response · total deadline | one total deadline, 600 s (`UPSTREAM_TIMEOUT_SECS`, 1–3600), body included; `504`; no separate connect or header deadline | `proxy.ts` | "ends a stalled upstream with 504…" |
| Sui RPC per call | 15 s (`RPC_TIMEOUT_SECS`, 1–120) | `chain.ts::withDeadline` | chain deadline tests |
| admission-state lifetime (must exceed the total deadline) | lease 900 s > 600 s; retention 30 d ≥ consume age 5 d; both startup-checked | `config.ts` | config "the lease must outlive the upload deadline…" |
| rate limits | challenge 30/min/IP; public 120/min/IP; gated pre-auth 120/min/IP; per address 30/min | `index.ts`, DO `rateCheck` | router tests |

### B.AUTH-1 Key & credential inventory

| Credential (name) | Type | Where held | Who can read | Rotation · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `UPSTREAM_AUTH_HEADERS` | CF Access service token (id + secret), `nft-gate-worker-relay-origin-v2` | GitHub secret → Worker secret | repo admins; Cloudflare account members | rotated 2026-10-01; **expires 2027-09-09**; no reminder yet | revoke the token in Zero Trust → create a new one → add it to the app policy → update the GitHub secret → run Deploy Workers → verify → revoke the old (`CLOUDFLARE.md` §2.4) |
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token | GitHub `production` env secret | repo admins | **unrecorded** (F16, F31) | roll the token in the Cloudflare dashboard → update the secret |
| `SUI_RPC_AUTH_HEADER` | bearer/API key | Worker secret | Cloudflare account members | unused today | rotate at the provider |
| `CF_ANALYTICS_TOKEN` | Cloudflare API token (analytics read) | Worker secret | same | unused today | roll |

### B.AUTH-2 Client & authorization inventory

| Client / relation | Type | Redirect URIs | Scopes / relations | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| Relay Access application + service-token policy | CF Access service auth | n/a | allow: the gateway's service token only (`walrus-relay-origin.meddleware.co.uk`) | Meddleware (zone owner) | recorded in `CLOUDFLARE.md` §2.4; origin refused a direct request 2026-10-09 |
| Gate authorisation | on-chain rule | n/a | `SoulboundAccessNFT` of gate `0x316f1bf9…`; single-use consume | gate admin | 2026-10-09 (this audit) |

### B.AUTH-3 Protocol conformance

| Protocol | Version | Deviations | Pinning test |
| --- | --- | --- | --- |
| nft-gate access proof v2 (`nft-gate:access:v2`) | nft-gate-client 0.0.17; root `CLAUDE.md`; `SECURITY.md` inv. 5 | none; v1 refused (no fallback) | `conformance.test.ts`, `verify.test.ts` "audience binding (protocol v2)" |
| HTTP bearer | RFC 6750 / RFC 9110 §11 | none (case-insensitive, any whitespace) | none |
| Cloudflare Access service tokens | `CF-Access-Client-Id` / `CF-Access-Client-Secret` headers | never sent on redirects (redirects not followed, F4); client `cf-access-*` fields stripped | `proxy.test.ts`; `check-upstream-auth.mjs` (shape + positive check) |

---

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade

`npx vitest run` gives **230 tests: 227 passed, 3 skipped** (2026-10-10; 179/176/3 on 2026-10-09; first pass 112/109/3).

- `unit` project (Node): verify, conformance, redemption, config, chain, origin-lock.
- `cloudflare-integration` project (workerd via `@cloudflare/vitest-pool-workers`): router, state,
  proxy, gateway-state.
- 1 file skipped: `test/integration/grpc-chain.integration.test.ts`, env-gated `GRPC_TESTNET=1`
  (`npm run test:grpc`); its 3 tests passed against the public testnet fullnode on 2026-10-09.

Both pools run in CI (`test:all`). No coverage tool is configured (F30).

| Dimension | Assessment |
| --- | --- |
| Happy-path coverage | covered: each scheme, owner allow, single-use allow + redemption key, challenge round trip, public cache, under-limit bodies |
| Error-path coverage | covered: malformed proof, bad signature, replay, expired/unknown nonce, non-owner, paused gate, gate read failure and unrecognised JSON → chain error, failed transaction, upstream unreachable / stalled (502/504), redirect, commit failure → 502, lost lease → 502, release on throw, KV + single-use rejection, store error propagation. router-level 503 for a store outage (`gateway-state.test.ts`), proof-decode rejects in workerd |
| Boundary coverage | covered: CL at/over cap, chunked over cap, hard nonce cap, rate limit 0 disables, consume age window, lease/deadline and retention/age config bounds, config integer bounds, malformed digest, IPv6 /64 keying |
| Security-relevant coverage | strong: shared vectors with negatives (per bound audience field) + ZIP-215, look-alike package, forged shard tag, query-string cache-busting, CORS denial and upstream ACAO, stale-holder lease, header policy, public-path rate limit, gated non-caching (F30), the 27 shared proof-decode rejects in both runtimes (F47) |

WORKERS lens §C:

| Requirement | Holds? |
| --- | --- |
| Three layers named and in CI | unit and workerd run in CI (`test:all`); live gRPC is env-gated and **not** in CI. It is live-only by nature, so recorded in C.2, but schedule it (Suggestion S3). |
| Replay within and across shards with a forged prefix | yes |
| Lease expiry and commit failure | yes (expiry at lease time, stale holder, lapsed lease at commit; the startup check makes expiry inside a forward impossible) |
| Body limit for CL and chunked | yes |
| CORS denial | yes |
| Cache bypass for gated paths | yes (`forward()` never touches the Cache API; F30) |
| Query-string cache-busting | yes |
| Rate limits on public and challenge endpoints | yes (F30) |

PROXY lens §C:

| Requirement | Holds? |
| --- | --- |
| Hop-by-hop and `Connection`-named fields stripped both ways; inbound credential replaced; upstream CORS stripped | yes (`proxy.test.ts`); forwarding fields are stripped, not rebuilt |
| Redirect to a foreign origin is refused and no credential reaches it | yes |
| Unlisted method, unsafe path, public path with `POST` refused | yes |
| Oversize declared, oversize chunked, stalled upstream release state | declared and chunked yes; stalled upstream ends in 504 and `redeemAndForward` releases on a non-2xx; a stalled **client** body is the edge's timeout (live-only) |
| Lease expiry during a forward; stale holder; store error is 503 | stale holder yes; expiry during a forward is excluded by the startup check; store error 503 at router level (`gateway-state.test.ts`) |
| Shared vectors pass in every implementation | yes |

### C.2 Hermetic vs. live paths

| Path | Hermetic test? | Deferred to | Tracking |
| --- | --- | --- | --- |
| gRPC field shapes against a real fullnode | fakes only | `grpc-chain.integration.test.ts` (`GRPC_TESTNET=1`) | passed manually 2026-10-09; add a scheduled CI job (S3) |
| Paywall end to end (buy, consume, v2 proof, upload through the Worker) | no | live testnet run by the maintainer | PASS 2026-10-09 |
| Access enforcement at the origin (direct request refused) | n/a | live only | refused 401 on 2026-10-09 and 2026-10-10; daily `origin-lock.yml` (F32) |
| Plan limits (413 at the platform, CPU 1102, subrequests) | n/a | live only | F11 / OQ3 |
| Client header-read, body-read and idle timeouts | n/a | live only (Cloudflare edge) | — |
| Cross-colo cache behaviour, DO cross-region latency | n/a | live only | F25 |
| Quota-guard GraphQL | no | live only (disabled) | F2 |

---

## Section D — Deployment-readiness gates

### pre-localnet

- [x] builds; type-check + lint + both test pools green (227 passed, 3 env-gated skipped) — 2026-10-10
- [x] body cap enforced on streamed bytes and on Content-Length, with tests for both — F37
- [x] no secrets in committed config; secret inventory written (names in `wrangler.toml`) — I16
- [x] dependencies install clean (`npm ci`); `npm audit` high clean — B.1
- [x] untrusted parsers validate every config field — F8, F17 (0.0.19, `6a601d3`)
- [x] no swallowed promises on security paths — the one `.catch(() => {})` (`proxy.ts` `body.pipeTo`) is
  justified in a comment; the release `.catch` in `redemption.ts` is best-effort after a failure path,
  and that path still returns 502
- [x] B.PX-1 and B.PX-2 complete; hop-by-hop, redirect, route and limit tests green — F13, F4, F42, F6
- [x] configuration fails startup on invalid values — F8

### pre-testnet *(the deployment already runs on testnet)*

- [x] origin lock verified (a direct request to the origin is refused) — refused 401 on 2026-10-09;
  positive check in every deploy; the daily negative check (`origin-lock.yml`) is ticked below (F32)
- [x] workerd tests run in CI; replay and lease tests green — F41, F38, F3
- [x] challenge / nonce issuer rate-limited; shard names allowlisted — F38, F40
- [x] gated pre-auth rate limit — F9
- [x] npm pack contents verified; B.TS-2 inventory (`allowScripts`: esbuild, workerd; `overrides`:
  sharp, undici; no lifecycle scripts in this package) — Scope, B.1
- [x] shared-dependency matrix aligned with ADR-0001 — F33
- [x] every test project runs in CI (unit + workerd; live is env-gated by design) — F41
- [x] consumed IDs verified as the latest version — B.SC-1 (gate read live 2026-10-09; the walrus-ui
  build arg is recorded only in `post-bootstrap/walrus/README.md`)
- [x] parity vectors cover all decision-affecting behaviour — vectors with negatives per audience field
  from nft-gate-client; the remaining unshared rows in B.SC-3 are covered by per-suite unit tests (S1)
- [x] `SECURITY.md` present — root; invariants 4–7 describe the current behaviour
- [x] B.AUTH-1 inventory complete; Access token expiry tracked — F31 (inventory and expiry date in
  `CLOUDFLARE.md`; API-token scopes remain the maintainer's, pre-mainnet below)
- [x] single-use cannot weaken through backend choice — F2
- [x] redemption lease owner-bound and longer than the maximum request — F3
- [x] upstream credentials never follow redirects — F4
- [x] admission-state tests (stale holder, lapsed lease, store error) green; sibling passes the shared
  vectors — F3, I25

### pre-mainnet

- [x] proof bound to an audience — F1 (decided: v2)
- [x] ownership mode rejects exhausted passes — F7 (decided: usable passes only)
- [ ] plan tier confirmed against the declared body cap and CPU budget — F11 / OQ3 (maintainer: the
  Cloudflare plan; measure p99 CPU)
- [ ] deploys gated on CI **and** a protected environment (reviewers configured or the choice
  recorded); token scopes minimal — branch policy done; reviewer choice and token scopes F16 / F31 /
  OQ4 (maintainer)
- [x] cache key normalised; CORS sends `Vary: Origin`; errors reveal no configuration; upstream CORS
  stripped — F40, F12
- [x] every fetch has a timeout — F6
- [x] no raw `btoa`/`atob` on untrusted text — `crypto.ts:44-56` uses `atob`/`btoa` only for bytes ↔
  base64 through binary strings (`charCodeAt`/`fromCharCode`), which is correct for arbitrary bytes.
  Invalid base64 throws and is caught (`verify.ts` → bad signature; token decode → `BadProof`),
  and the proof's fields are ASCII-checked
  (nft-gate-client `isAscii`).
- [x] no `any`/`as`/`!` at trust boundaries without justification — gRPC JSON is cast to
  `Record<string, Json>` and then field-checked; `@ts-expect-error` on `duplex` (comment stale, F21)
- [x] the negative origin check runs on a schedule — F32 / OQ10 (`origin-lock.yml`, daily; the
  repository variable `UPSTREAM_CHECK_URL` already exists; run locally against the live origin
  2026-10-10, first GitHub run to confirm after the release; commit pending)
- [ ] mainnet `access_gate` published and `NFT_TYPE`/`GATE_ID`/`NETWORK`/`GATEWAY_ORIGIN` populated from
  the canonical record — not yet (mainnet publication is a maintainer step, `OPERATOR_TASKS.md`
  "Mainnet release custody")
- [ ] external review — not started (maintainer: `OPERATOR_TASKS.md` "Funding, grants and an external
  audit — after launch")

---

## Cross-project themes

- **Supply chain & release integrity:**
  - The lockfile is committed and actions are SHA-pinned; Dependabot keeps them current.
  - `npm audit` gates CI and publish; npm publishes via OIDC with provenance; the publish verify job
    equals CI.
  - Deploys use a Cloudflare API token behind a `main`-only environment, with scopes and rotation
    unrecorded (F16, F31).
  - The dev-tool CVE pins in `overrides` are recorded in B.1.
- **Wire-format coupling & conformance vectors:**
  - The format is defined in `@meddleware/nft-gate-client`, which this Worker **imports** (zero drift
    on the client side) and which also publishes the vectors (`sync-vectors --check` in CI).
  - The Rust gateway re-implements it; drift is caught by `conformance/vectors.json`.
  - Gaps: header extraction, status mapping and the conflict body are covered by per-suite tests, not
    shared vectors (B.SC-3, S1).
- **On-chain-truth boundary:** authorisation comes from live chain reads. Single-use is enforced
  off-chain in the redemption DO by design (F23), now owner-bound and age-bounded. Commission and
  payment stay on-chain.
- **Deployment readiness:** Section D. It runs live on testnet; the open items are maintainer-owned
  (F11, F16, F31).
- **Chain-access layering & on-chain ID/ABI coupling:**
  - It conforms to ADR-0001: ownership parsing comes from `@meddleware/access-gate-client` and the
    wire format from `@meddleware/nft-gate-client`.
  - Gateway-specific reads (`getTransaction` consume check, gate pause read) live in `chain.ts`.
    These are candidates to move into access-gate-client (`consumeTxValid`, `gateBlocksAccess`) so
    the Rust gateway's vectors and the TS client share one reference (Suggestion S4).
  - IDs trace to `Published.toml` (B.SC-1).
  - ABI drift: env-gated gRPC integration test.
  - Pre-v0.2 policy: no compatibility fallback was kept (F15, F1: v1 refused).

---

## Normative requirements (MUST / MUST NOT)

**Now (the deployment is live on testnet):**

1. MUST NOT forward Cloudflare Access credentials across redirects (`redirect: 'manual'`) — **holds**
   (F4).
2. MUST keep single-use redemptions on a strongly consistent store; KV and the degrade switch MUST NOT
   apply to redemptions — **holds** (F2).
3. MUST make leases owner-bound and longer than the maximum request (with an upstream deadline) —
   **holds** (F3, F6).
4. MUST prove the origin refuses requests without the service token, and track the token's expiry —
   **holds**: refused on 2026-10-09 and 2026-10-10, checked daily by `origin-lock.yml` (F32), and expiry
   recorded (2027-09-09, F31; no reminder yet).
5. MUST rate-limit gated requests per `CF-Connecting-IP` before verification — **holds** (F9).
6. MUST strip upstream `access-control-*` headers (including in the edge cache) and the full
   hop-by-hop set, consistent with `SECURITY.md` — **holds** (F12, F13).
7. MUST validate every configuration value strictly (booleans, bounded integers, the RPC auth header) —
   **holds** (F8, F17).
8. MUST prune the DO rate table — **holds** (F5).

**Before mainnet:**

9. MUST bind the signed message to the gateway origin and gate (and the consume digest) — **holds**
   (F1).
10. MUST reject exhausted passes in ownership mode or restrict the mode — **holds** (F7).
11. MUST confirm the plan tier against the body cap and CPU, and record deploy protection and token
    scopes — **does not hold yet** (F11, F16, F31 / OQ3, OQ4; maintainer items).
12. MUST schedule the negative origin check — **holds** (F32; confirm the first scheduled run).

**Lens baseline MUST lists.**

WORKERS lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| CF-M1 | holds | I16 |
| CF-M2 | holds (origin refused 2026-10-09 and 2026-10-10, negative check scheduled daily; expiry tracked) | F32, F31 |
| CF-M3 | holds (DO only for single-use) | F2 |
| CF-M4 | holds on streamed bytes; plan limit unconfirmed | F11 |
| CF-M5 | holds (challenge, public, gated pre-auth) | F9 |
| CF-M6 | holds (upstream ACAO stripped, also in the cache) | F12 |
| CF-M7 | holds | F40 |
| CF-M8 | holds | I20 |
| CF-M9 | holds for test pools in CI and CI-gated, branch-restricted deploy; reviewers undecided | F16 |

TS lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| TS-M1 | holds (`strict`, `noUncheckedIndexedAccess`) | |
| TS-M2 | holds (proof, config, upstream and RPC auth headers, gate and event JSON) | F8, F15, F17 |
| TS-M3 | N/A (no amounts) | |
| TS-M4 | holds | |
| TS-M5 | holds (upstream deadline, RPC deadline, quota timeout) | F6 |
| TS-M6 | holds | |
| TS-M7 | holds (explicit `files`; B.TS-2 inventory above) | |
| TS-M8 | holds (`npm ci`, audit gate, ADR-0001 alignment) | F33 |
| TS-M9 | N/A (deployable Worker, single bundled copy) | |

SUI_CLIENT lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| SC-M1 | holds (original-id for types and events; no call targets) | |
| SC-M2 | holds | |
| SC-M3 | holds (`status.success`; finality is the client's) | |
| SC-M4 | holds | |
| SC-M5 | holds (explicit `NETWORK`; IDs required and validated) | F26 |
| SC-M6 | holds | F39 |
| SC-M7 | holds (success, exact type, sender, gate, age; nonce replaced by the redemption store and the signed digest) | F23, F1 |
| SC-M8, SC-M9 | N/A | |
| SC-M10 | holds (uses access-gate-client and nft-gate-client) | S4 |

WALRUS lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| WAL-M3 | holds on the gateway side | |
| WAL-M8 | holds (release keeps the use; owner-bound lease, DO only) | F2, F3 |
| WAL-M9 | holds (streamed cap at the edge) | F37 |
| Others | N/A (relay/client concerns) | |

AUTH lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| AUTH-M2 | partly (secrets in the secret store, Access token rotation procedure with overlap recorded; API-token rotation unrecorded) | F31 |
| AUTH-M8 | holds (client credentials stripped, `cf-access-*` included; credentials never sent on redirects) | F4, F13 |
| AUTH-M10 | holds for rate limits and log hygiene; deny reasons are deliberately distinct (chain facts are public and the client must react) | F9 |
| AUTH-M11 | holds (versioned, domain-separated, audience-bound, rebuilt from configuration; negative vectors in both implementations) | F1 |
| AUTH-M1, M3, M4, M5, M6, M7, M9 | N/A | |

PROXY lens:

| ID | Holds? | Evidence |
| --- | --- | --- |
| PX-M1 | holds (method list, safe-path check, URL from configuration) | F42 |
| PX-M2 | holds for removal in both directions; forwarding fields are stripped, not rebuilt | F13 |
| PX-M3 | holds | F12 |
| PX-M4 | holds | F4 |
| PX-M5 | partly (body cap, upstream total deadline, RPC deadline; client-side header/idle timeouts and connection caps are the Cloudflare edge's) | F6, B.PX-2 |
| PX-M6 | holds for network, timeout, redirect and store failures; relay error statuses pass through by decision | F44 |
| PX-M7 | holds | F3 |
| PX-M8 | holds (lock refused directly, checked daily) | F32 |
| PX-M9 | holds | F8 |

## Implementation suggestions (SHOULD / MAY)

- **S1** SHOULD add a `redirectPolicy`, `timeouts`, `headerExtraction` and `redemptionConflict`
  section to the shared vectors (published by nft-gate-client), so B.SC-3's remaining unshared rows
  become test failures. The audience cases are already shared.
- **S2** SHOULD emit structured logs (or Analytics Engine data points) per denial reason, 409 code,
  commit failure and upstream status, without proofs. This helps detect abuse.
- **S3** SHOULD run `npm run test:grpc` on a schedule (read-only, public testnet) to catch gRPC shape
  drift before users do.
- **S4** MAY move `consumeTxValid` and `gateBlocksAccess` into `@meddleware/access-gate-client`
  (ADR-0001 home for typed reads), leaving `chain.ts` a thin adapter.
- **S5** MAY add Cloudflare WAF rate-limiting rules on the route as a coarse layer under F9 (plan
  quota permitting).
- **S6** SHOULD bump `compatibility_date` regularly (F27), tied to the wrangler upgrade cadence.
- **S7** SHOULD import `GATEWAY_CONFLICT_CODES` / `GATEWAY_STATUS` from nft-gate-client in the Worker
  and assert the emitted codes against them, so the 409 vocabulary cannot drift from what walrus-client
  parses (B.WAL-1).
- **S8** *(done 2026-10-10)* the negative origin check runs on a schedule (F32, `origin-lock.yml`) and
  the missing tests of F30 exist (public-path rate limit, gated non-caching, router-level 503, IPv6 /64).
- **S9** MAY add a `Via`/marker loop check (F43) if the package is offered white-label.

## Open questions

- **OQ1** Access message v2 binding fields: (a) origin + gate; (b) + network; (c) + consume digest.
  Should it also have a human-readable form? Shared with `gateway-rust` OQ1; decided once.
  *(Decided 2026-10-08: all of (a)–(c), multi-line ASCII so the wallet shows it; 0.0.19, see F1.)*
- **OQ2** Ownership-mode semantics: reject zero-use `SingleUse` passes, or allow ownership mode only
  on unlimited-pass gates? Shared with `gateway-rust` OQ2.
  *(Decided 2026-10-08: ownership counts only usable passes; see F7.)*
- **OQ3** Which Cloudflare plan serves the live route? This decides the body limit (and whether
  `MAX_BODY_BYTES` should be 10⁸ B), the CPU budget per request and the rule quotas. *(Open; maintainer.)*
- **OQ4** Does the `production` environment have required reviewers or a wait timer? If not, record
  the single-maintainer decision. What are `CLOUDFLARE_API_TOKEN`'s scopes and expiry? *(Open;
  maintainer. Branch policy `main` only is verified.)*
- **OQ5** Redemption retention vs consume age: bound consume age to retention, or extend retention?
  Shared with `gateway-rust` OQ5. *(Decided 2026-10-08: bound the consume age, 5 days ≤ retention 30
  days; see F24.)*
- **OQ6** On a commit failure after a 2xx upstream: keep 502 + release, or keep the lease and retry
  the commit? Shared with `gateway-rust` OQ6. *(Behaviour kept: 502 + release; F20.)*
- **OQ7** Restrict `PUBLIC_PATHS` to GET/HEAD? Shared with `gateway-rust` OQ7. *(Decided 2026-10-08:
  yes; see F10.)*
- **OQ8** KV and the quota guard: remove the KV fallback for single-use deployments, keep redemptions
  on the DO while nonces degrade, or drop the quota guard entirely? *(Decided 2026-10-08: single-use
  refuses KV and ignores the degrade flag; ownership mode keeps the optional fallback; see F2, F34.)*
- **OQ9** Should code-default `ALLOWED_ORIGINS` be empty (fail closed, Rust parity, white-label safe),
  with Meddleware's origins only in `wrangler.toml`? *(Decided 2026-10-08: yes; see F18.)*
- **OQ10** Where is the relay's Cloudflare Access application recorded (application / policy / token
  IDs, expiry), and who reviews it? Should the negative origin check (F32) run on a schedule?
  *(Recorded in `docs/networking/CLOUDFLARE.md` §2.4. Decided 2026-10-10: yes, daily, as a separate
  secret-free workflow — `origin-lock.yml`, F32.)*

## Risks

- **Fullnode trust.** One public Mysten fullnode is trusted for every decision. If it lies, it can
  admit; if it is unavailable, it denies everyone (502). There is no quorum or light-client check.
- **Cloudflare platform.** The platform is the second trust anchor: `CF-Connecting-IP`, DO
  consistency, Access enforcement and plan limits. Outages fail closed.
- **Wallet display.** The audience-bound message helps only if users notice an unexpected origin in
  the sign prompt.
- **Unsupported schemes.** Multisig, zkLogin and passkey users cannot use the gateway (fail closed).
- **Single global redemption object** (F25). A regional outage of the object's location blocks all
  redemptions, which fails closed.
- **Supply chain.** wrangler/workerd and transitive dev tooling (pinned via `overrides`) are large.
  Advisories can land between audits; the CI audit gate and Dependabot are the controls.
- **Origin lock is external configuration.** A dashboard change to Access can remove the gate; F32's
  daily check (`origin-lock.yml`) notices within a day, but only if its schedule is alive (GitHub pauses
  scheduled workflows after 60 days without repository activity) and the zone does not challenge the
  runner (a challenge only warns).
- **Access token expiry (2027-09-09)** stops every paid upload until rotated; there is no reminder yet
  (F31).
- **No on-chain kill switch on the live relay gate** (F45): emergency stop is the route or the Access
  token.
- **Deploy authority.** Anyone who can dispatch the workflow on `main`, or holds the API token, can
  ship code to the paywall; reviewers are undecided (F16).

---

## Re-verification log

- 2026-10-03 — First-pass baseline at nft-gate `db01d3e` (npm 0.0.17).
  - Measured: vitest 112 tests (109 passed, 3 skipped; gRPC integration env-gated); tsc and eslint
    clean; `npm audit` 0 vulnerabilities; `npm pack --dry-run` 19 files.
  - The live gRPC test could not run from the review sandbox (egress denied).
  - Recorded F1–F41 (F37–F41 Positive) and OQ1–OQ10. Shared IDs (F1, F3, F7, F9, F12–F15, F20, F22–F24
    and OQ1, OQ2, OQ5–OQ7) align with `gateway-rust-audit.md`.
  - **No findings resolved:** by maintainer instruction this pass only recorded findings; remediation
    was to be applied separately and each disposition moved to RESOLVED with the diff cited.
  - Pre-save consistency checklist run.
- 2026-10-09 — Re-verified against `main` `367e673` (tag `v0.0.21` = `83349b8`; 0.0.18–0.0.21 and the
  config/Dependabot commits since).
  - Every finding F1–F36 re-checked in code, tests, CHANGELOG and `git log`: **22 RESOLVED** (F1–F10,
    F12–F15, F17–F19, F24, F26–F28, F33), **4 MITIGATED** (F16, F21, F29–F31 → see counts below),
    ADJUDICATED F20, F22, F23, F36, ACCEPTED-RISK F25, F34, F35, DEFERRED F11, F32. The main fix wave is
    0.0.19 (`6a601d3`): protocol v2 audience binding, owner-bound redemption leases, strict config,
    proxy hygiene, deadlines; 0.0.20 (`11aa7c9`, access-gate-client 0.0.6); 0.0.21 (`83349b8`,
    import-free `config.ts` for the deploy pre-check); `574fe70` points the Worker at the 2026-10-09
    `access_gate` and relay gate.
  - **New:** F42 (method and path policy, RESOLVED), F43 (no `Via` loop marker, ACCEPTED-RISK), F44
    (upstream error passthrough, ADJUDICATED), F45 (live gate does not let a pause block access,
    ACCEPTED-RISK), F46 (Positive). Final counts: 23 RESOLVED, 5 MITIGATED (F16, F21, F29, F30, F31), 5
    ADJUDICATED (F20, F22, F23, F36, F44), 5 ACCEPTED-RISK (F25, F34, F35, F43, F45), 2 DEFERRED (F11,
    F32); 6 Positive (F37–F41, F46).
  - Lens coverage: added PROXY (2026-10-08; forwarding matrix, I26–I27, B.PX-1, B.PX-2, PX-M1–M9,
    PROXY coverage and gates), updated AUTH to the completed lens (2026-10-08; signed-challenge row,
    AUTH-M11), and re-dated base, TS and SUI_CLIENT to 2026-10-08. IMG, VUE, SEAL, GO, RUST, SITE and
    OPS are not triggered (no image, UI, Seal, Go/Rust code, site or signing script).
  - Measured: vitest 179 tests (176 passed, 3 skipped; the 3 gRPC tests passed with `GRPC_TESTNET=1`);
    tsc and eslint clean; `npm audit` 0 vulnerabilities; `npm pack --dry-run` 20 files. node_modules
    was one Dependabot bump behind the lockfile (wrangler 4.143.0 vs 4.147.0).
  - Live, read-only: route behaviour (405 on public `POST`, 401 without proof, CORS only for listed
    origins), the relay origin refusing a direct request (401), the live gate object, the `production`
    environment (branch policy `main`, no reviewers) and the Deploy Workers runs (all of 2026-10-09
    succeeded).
  - Maintainer decisions recorded: access message v2; ownership counts only usable passes; GatePolicy
    and pass kind immutable; vectors published by nft-gate-client; repo-local audit canonical. OQ3, OQ4
    and the scheduling half of OQ10 stay open (Cloudflare plan, deploy reviewers and token scopes,
    scheduled negative origin check, external review, mainnet publication). *(The scheduled check was
    added 2026-10-10; see the last log entry.)*
  - Template dates reconciled to the lens registry; pre-save consistency checklist run.

- 2026-10-10 — Fix wave on `main` `9e33df6` (unreleased, no version bump here; commit pending).
  - Fixed: F32 (RESOLVED: `origin-lock.yml` + `check-origin-locked.mjs`, daily, secret-free), F21
    (RESOLVED: comments and dead `nonceMatches`), F30 (RESOLVED: five missing tests,
    `gateway-state.test.ts`) and new F47 (RESOLVED: nft-gate-client 0.0.17 strict proof decoding, 27
    shared reject vectors green in Node and workerd).
  - Left open by decision: F11 (Cloudflare plan, OQ3 — maintainer), F16 and F31 (reviewers, API-token
    scopes, token-expiry reminder — maintainer), F29 (the `unknown` bucket stays by design), F43 (no
    `Via` marker; only if offered white-label), F45, F25, F34, F35 (accepted), adjudicated F20, F22, F23,
    F36, F44.
  - Final counts: 27 RESOLVED (the 23 above plus F21, F30, F32, F47), 3 MITIGATED (F16, F29, F31), 5
    ADJUDICATED (F20, F22, F23, F36, F44), 5 ACCEPTED-RISK (F25, F34, F35, F43, F45), 1 DEFERRED (F11); 6
    Positive (F37–F41, F46). 47 findings.
  - Measured: vitest 230 tests (227 passed, 3 skipped; unit 145/3, workerd 82); `tsc` and `eslint` clean;
    `npm ci` and `npm audit --audit-level=high` 0 vulnerabilities; `wrangler deploy --dry-run` builds;
    `npm pack --dry-run` unchanged (the new scripts are not shipped); `scripts/sync-vectors.mjs --check`
    and `scripts/check-versions.sh` pass.
  - Live, read-only: `check-origin-locked.mjs` against the relay origin: three probes, all 401 from
    Access. Not run: the GitHub workflow itself (nothing is pushed); the Worker is not deployed.
  - OQ10 scheduling decided (daily, separate workflow). OQ3 and OQ4 stay open.

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings — every row's status matches its linked finding (HOLDS beside RESOLVED;
  no GAP rows remain; I17, I27 carry their residual in the note).
- [x] Finding header ↔ body — no stale status lines; remediation text describes what was done.
- [x] Template line: base + WORKERS + TS + SUI_CLIENT + WALRUS + AUTH + PROXY, each dated as in the
  registry. IMG is not triggered (no image).
- [x] Closing structure in order.
- [x] Open questions: OQ3 and OQ4 open; the others carry a recorded decision note (OQ10 decided
  2026-10-10), the dispositions moved on the findings.
- [x] Section D ↔ dispositions — ticked only for RESOLVED/MITIGATED-with-evidence items; unticked items
  cite F11, F16/F31 and the maintainer items.
- [x] Executive summary reflects current dispositions.
- [x] Counts and versions re-measured 2026-10-10.
- [x] Re-verification log entry added.
