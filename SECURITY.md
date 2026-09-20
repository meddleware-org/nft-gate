# Security Policy

## Scope

This policy covers security issues in:

- The two gateway implementations — `gateway-workers/` (TypeScript, Cloudflare Workers) and
  `gateway-rust/` (Rust/Axum) — including signature-verification bypass, nonce replay, single-use
  double-spend, consume-event forgery, open-proxy/SSRF, header injection, secret disclosure, and any
  behavioural divergence between the two implementations
- The shared wire protocol and conformance vectors (`conformance/vectors.json`)
- The published artifacts (`@meddleware/nft-gate-gateway` npm package, `nft-gate-gateway` crate,
  container images)

It does not cover:

- The Sui fullnode / gRPC endpoint, Redis/Dragonfly, or Cloudflare platform (report to those
  projects) — these are trusted liveness dependencies
- The upstream origin the gateway proxies to, and the operator's `UPSTREAM_URL` / RPC / NFT-type
  configuration (config is authoritative and operator-owned)
- The `access-gate-sui` on-chain package (see that repo's `SECURITY.md`)

## Security model (invariants)

These invariants are load-bearing and must hold **identically in both implementations**. A report
demonstrating that any is violated — or that the two implementations decide differently for the same
input — is in scope and treated as high severity:

1. **Fail closed.** Any ambiguous, malformed, or error state denies access. Unknown signature
   schemes (including multisig and zkLogin) are rejected, never accepted by default.
2. **Nonce is consumed before the chain call.** A replayed nonce fails even with a valid signature.
3. **Signatures are verified canonically.** Sui personal-message intent, `blake2b256(flag||pubkey)`
   address derivation, and low-S enforcement on ECDSA; the address used for signature recovery and
   the address used for the on-chain sender/owner comparison must be the same normalized value.
4. **Single-use is redeemed exactly once.** The on-chain consume digest is leased before proxying
   and committed on success; a committed redemption is never cleared, and an interrupted upload
   releases the lease so the use is not lost.
5. **The proxy does not leak or amplify.** Inbound `Authorization`/proof headers and hop-by-hop
   headers are stripped before forwarding; request bodies are size-bounded; secrets are never logged.

## Supported versions

Only the latest published image / package receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by emailing **<security@meddleware.co.uk>**. Include:

- A description of the vulnerability and its impact, and which implementation(s) it affects
- Steps to reproduce or a proof-of-concept (if available)
- The image tag, package version, or commit SHA you tested against

You will receive an acknowledgement within **3 business days** and a resolution plan within
**14 days** for confirmed issues. Critical issues (CVSS ≥ 9.0) are prioritised for same-day
acknowledgement.

## Disclosure

Once a fix is released, a security advisory will be published on the GitHub repository. Reporters
may be credited by name unless they prefer to remain anonymous.
