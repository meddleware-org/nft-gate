# AGENTS.md — gateway-workers

## Package

`@meddleware/nft-gate-gateway` — Cloudflare Workers implementation of the nft-gate gateway.

## Key files

| File | Purpose |
| --- | --- |
| `src/index.ts` | Worker fetch + scheduled entry points; per-isolate state cache |
| `src/config.ts` | `Env` bindings interface; `Config` type; `loadConfig` |
| `src/verify.ts` | `verifyPersonalMessageSignature`, `verifyAccessRequest`, `ChainQuery` interface |
| `src/chain.ts` | `SuiRpc` — production `ChainQuery` over Sui JSON-RPC |
| `src/crypto.ts` | Hash + encoding helpers (`blake2b256`, `base64ToBytes`, etc.) |
| `src/proxy.ts` | `forward` — reverse proxy to upstream |
| `src/quota.ts` | `runQuotaGuard` — optional free-tier quota check (cron) |
| `src/wire.ts` | Re-exports from `@meddleware/nft-gate-client` |
| `src/state/types.ts` | `NonceBackend` interface; `shardOfNonce`; `randomHex24` |
| `src/state/select.ts` | `makeBackend` — picks DO or KV backend |
| `src/state/durable_object.ts` | `NonceRateState` (DO class); `DurableObjectBackend` |
| `src/state/kv.ts` | `KvBackend` (Workers KV fallback) |
| `scripts/gen-vectors.mjs` | Generate `../conformance/vectors.json` |
| `wrangler.toml` | Cloudflare Workers config: routes, bindings, cron trigger |

## Build and test commands

```bash
npm install           # install dependencies
npm run type-check    # TypeScript type check (no emit)
npm test              # vitest unit tests (includes conformance vector checks)
npm run test:all      # unit + cloudflare integration tests
npm run dev           # wrangler dev (local preview)
npm run deploy        # deploy to Cloudflare (requires wrangler login)
```

## Post-deploy secrets setup (first deploy only)

```bash
wrangler secret put UPSTREAM_URL         # e.g. https://your-relay.example.com
wrangler secret put UPSTREAM_AUTH_HEADERS  # optional: CF Access service token headers
# NFT_TYPE, GATE_ID and SUI_RPC_URL are public: set them in wrangler.toml [vars]
```

## Version

Current: `0.0.2`. Bump version in `package.json` whenever changes are published.

## Relation to gateway-rust

The two implementations are wire-identical: same endpoints, same env var names (where applicable),
same proof format, same Sui RPC call shapes. Any wire-format change must be applied to both and
the conformance vectors regenerated.
