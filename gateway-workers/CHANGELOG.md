# Changelog

All notable changes to `@meddleware/nft-gate-gateway` are documented here.

## [0.0.17] - 2026-10-02

### Changed

- No Worker changes: released with the Rust gateway 0.0.17 (one version for every artifact).

## [0.0.16] - 2026-10-02

### Changed

- `@meddleware/access-gate-client` 0.0.3: `ownsAccessNft` compares the configured `GATE_ID`
  normalised, and an NFT whose gate id is not an address is ignored.

## [0.0.15] - 2026-10-02

### Changed

- `@meddleware/access-gate-client` 0.0.2 (the version-gated `access_gate` client; `ownsAccessNft`
  is unchanged) and `@meddleware/nft-gate-client` 0.0.14.
- The shared `proofDecodeRejects` conformance vectors (oversized token, non-ASCII fields) are
  asserted here and in the Rust gateway.
- ESLint (typescript-eslint recommended) runs in CI.

## [0.0.14] - 2026-10-02

### Changed

- Testnet: the relay gate is `0xfd6c3b2a…b8a6` on the version-gated `access_gate` `0xa55789…6d41`
  (`NFT_TYPE` `0xa55789…::access_gate::SoulboundAccessNFT`). Passes from the superseded `0x1a81ca…`
  package and gate `0xcb8206…` are no longer accepted.
- `NFT_TYPE` is a `[vars]` entry in `wrangler.toml` instead of a Worker secret: it is a public on-chain
  type. The Deploy Workers workflow retires the old secret from a pending version first (a secret and a
  var may not share a name), so the switch has no downtime.
- `ALLOWED_ORIGINS` (and the code default) adds `https://sui-token-deployer.meddleware.co.uk`: the
  standalone token deployer uploads icons through the gated relay too (workspace decision D21).

- The `Deploy Workers` workflow also accepts `UPSTREAM_AUTH_HEADERS` as a GitHub secret: when set it
  is validated and deployed with the code as one Worker version; when unset the deploy is unchanged
  (`wrangler deploy`, Cloudflare-stored secrets).

## [0.0.13] - 2026-10-01

Versions are aligned from this release: the npm package, the crate and the image share one version.

### Security

- Single-use: the consume event must be exactly `<NFT_TYPE package>::access_gate::AccessConsumedEvent`
  (previously any `…::access_gate::AccessConsumedEvent` suffix, which a look-alike package could
  emit for free). Sender and gate ids are compared in normalised form.

### Changed

- **Breaking (operator):** `UPSTREAM_AUTH_HEADERS` is a JSON array of `{name, value}`; the old
  comma-separated `Name: value` string fails closed at startup. See the walrus runbook for the
  migration order.
- `ALLOWED_ORIGINS` code default matches `wrangler.toml` (`sui-walrus.` and `dash.`).
- A misconfigured gateway answers `500 gateway misconfigured` without echoing the config error.
- Public GET paths drop the query string from the edge-cache key and the forwarded request.
- ed25519 verification is explicitly ZIP-215 (Sui's rule).

### Added

- `GET /v1/challenge` per-IP rate limit (`CHALLENGE_RATE_LIMIT_PER_MIN`, default 30; Rust parity).
- Nonce shard tags are validated against the continent allowlist; forged tags are `NonceInvalid`.
- State-backend failures return a JSON `503` with CORS; a failed redemption commit releases the
  lease and returns `502` (Rust parity).
- `Vary: Origin` on every response.
- Conformance: `negativeSignatures` (high-S k1/r1, non-canonical ed25519 s, wrong intent,
  truncated, flags 0x03/0x05/0x06) and a `zip215` acceptance vector.

- Ownership checks use `@meddleware/access-gate-client` `ownsAccessNft`: exact NFT type at the
  package's original id, and every owned-object page is read (previously only the first page, so a
  holder with many objects could be denied). `@meddleware/nft-gate-client` 0.0.13 supplies only the
  wire format.

### Fixed

- The quota guard no longer throws when the KV degrade-flag write fails.

## [0.0.3] - 2026-08-29

### Added

- Inline TSDoc documentation on `chain.ts`, `config.ts`, `crypto.ts`, and `verify.ts`.
- `AGENTS.md` and `CLAUDE.md` developer documentation for `gateway-workers`.

## [0.0.2] - 2026-08-28

### Changed

- Bumped `@meddleware/nft-gate-client` peer dependency to `0.0.2`.
- Updated `wrangler.toml` operator placeholder values (upstream URL, route pattern, zone name).

## [0.0.1] - 2026-08-27

### Added

- `UPSTREAM_AUTH_HEADERS` env var: comma-separated `Name: value` header pairs injected on every
  upstream relay request. Enables Cloudflare Access service-token authentication when the relay
  origin is CF-Access-locked. Set via `wrangler secret put UPSTREAM_AUTH_HEADERS` — never in
  `wrangler.toml`.
- `wrangler.toml` operator placeholders for `UPSTREAM_URL`, route pattern, and zone name.
- `test/config.test.ts`: unit tests for `UPSTREAM_AUTH_HEADERS` parsing (single entry, two CF
  Access entries, whitespace trimming, value-internal colons).
