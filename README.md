# nft-gate

[![npm](https://img.shields.io/npm/v/%40meddleware%2Fnft-gate-gateway)](https://www.npmjs.com/package/@meddleware/nft-gate-gateway)
[![Crates.io](https://img.shields.io/crates/v/nft-gate-gateway)](https://crates.io/crates/nft-gate-gateway)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

A generic NFT-gated reverse proxy for the [access_gate](https://github.com/meddleware-org/vault) primitive on Sui. Put it in front of any HTTP upstream — an upload relay, a website, a game API — to restrict access to holders of an on-chain access NFT.

Two wire-identical implementations are provided. Choose one based on your deployment target:

| Implementation | Directory | Distributed as | Deploy target | State backend |
| --- | --- | --- | --- | --- |
| Cloudflare Workers | [`gateway-workers/`](gateway-workers/) | [npm package](https://www.npmjs.com/package/@meddleware/nft-gate-gateway) | Wrangler deploy | Durable Objects or KV |
| Rust / Axum | [`gateway-rust/`](gateway-rust/) | [crates.io](https://crates.io/crates/nft-gate-gateway) / Docker | Docker / k8s | In-memory or Redis |

Both implementations serve the same wire protocol and verify the same [conformance vectors](conformance/).

The client-side counterpart — challenge fetching, proof construction, PTB builders — lives in [`@meddleware/nft-gate-client`](https://github.com/meddleware-org/nft-gate-client) on npm.

## Quickstart (Cloudflare Workers)

> Prerequisites: Node.js ≥ 22, Wrangler 4.x, a Cloudflare account.

```bash
# 1. Clone or fork this repo
git clone https://github.com/meddleware-org/nft-gate.git
cd nft-gate/gateway-workers

# 2. Install dependencies
npm install

# 3. Create the Worker in your Cloudflare account (first deploy only)
npm run deploy

# 4. Set the required secrets (run once after the Worker exists)
wrangler secret put UPSTREAM_URL        # e.g. https://your-relay.example.com
wrangler secret put NFT_TYPE            # e.g. 0x<pkg>::access_gate::SoulboundAccessNFT
# …and set GATE_ID = "0x<gate id>" in wrangler.toml [vars]
wrangler secret put UPSTREAM_AUTH_HEADERS  # JSON: [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]

# 5. Configure the route (edit wrangler.toml, then redeploy)
npm run deploy
```

See [gateway-workers/README.md](gateway-workers/README.md) for the full configuration reference.

## Quickstart (Rust / Docker)

> Prerequisites: Docker, or Rust stable + Cargo.

```bash
# Docker
docker pull meddleware/nft-gate-gateway:latest
docker run -e UPSTREAM_URL=http://relay:8080 \
           -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
           -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
           -e GATE_ID=0x<gate id> \
           -p 8080:8080 meddleware/nft-gate-gateway

# Or from crates.io (requires Rust stable)
cargo install nft-gate-gateway
UPSTREAM_URL=http://relay:8080 SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  NFT_TYPE=0x<pkg>::access_gate::AccessNFT GATE_ID=0x<gate id> nft-gate-gateway
```

See [gateway-rust/README.md](gateway-rust/README.md) for the full configuration reference.

## Wire protocol

**Challenge** — `GET /v1/challenge` returns `{ nonce, expiresAt }`.

**Signed message** — the client signs `nft-gate:access:<nonce>` as a Sui personal message (ed25519, secp256k1, or secp256r1).

**Proof token** — `base64(JSON { address, nonce, signature, consumeDigest? })`, sent as `Authorization: Bearer <token>` or `X-Access-Proof`.

**Verification** — the gateway checks the signature recovers the claimed address, the nonce is fresh and unused, and the address owns the required NFT (or, in single-use mode, has submitted a matching on-chain consume transaction). Then it proxies to the upstream.

**Scope** — the gateway gates only on `access_gate` passes of one gate (`NFT_TYPE` must be an
`access_gate` pass type and `GATE_ID` is required), so every admitted user holds a pass that gate
sold or granted. If the gate's immutable policy has `pause_blocks_access`, pausing the gate denies
all holders (`403`) until it is unpaused; in single-use mode the check runs before the consume is
redeemed, so no use is lost.

## Conformance

`conformance/vectors.json` contains golden wire-format vectors signed with real Sui keypairs for all three signature schemes. Both gateway implementations test against these vectors. Regenerate with:

```bash
node gateway-workers/scripts/gen-vectors.mjs > conformance/vectors.json
```

## Choosing an implementation

**Use `gateway-workers/` if:**

- You want zero-infrastructure deployment via Wrangler
- Cloudflare's global edge distribution suits your topology
- You are already using Cloudflare for DNS / CDN

**Use `gateway-rust/` if:**

- You are deploying to Kubernetes or any container-based infrastructure
- You need Redis-backed nonce state for horizontal scale-out
- You want the lowest possible latency on your own hardware

Both are drop-in: they expose the same endpoints, accept the same environment variables, and produce identical verification decisions for any given proof token.

## License

[0BSD](LICENSE)
