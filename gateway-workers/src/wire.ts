/**
 * The shared wire-format helpers, REUSED from `@meddleware/nft-gate-client` rather than
 * re-implemented — there must be exactly one source for `personalMessageForNonce` and the
 * proof token shape across the toolkit (the "one contract that spans all three" rule in
 * nft-gate/CLAUDE.md).
 *
 * Imported from the published package entry. That entry also exports the PTB and ownership
 * helpers (which use `@mysten/sui`); the Worker already depends on `@mysten/sui` for its gRPC
 * client (`chain.ts`), so this adds no new dependency, and Wrangler's bundler tree-shakes the
 * unused exports.
 *
 * Self-contained-mirror alternative (documented for future review): if the Worker must ship
 * fully decoupled from the client package, replace these two lines with a local copy of
 * `personalMessageForNonce` + `decodeAccessProof` guarded by `conformance/vectors.json`.
 */

export {
  personalMessageForNonce,
  decodeAccessProof,
} from '@meddleware/nft-gate-client'
export type { AccessProof } from '@meddleware/nft-gate-client'
