/**
 * The shared wire-format helpers, REUSED from `@meddleware/nft-gate-client` rather than
 * re-implemented: there must be exactly one source for the signed message (`personalMessage`) and
 * the proof token shape across the toolkit (the "one contract that spans all three" rule in
 * nft-gate/CLAUDE.md). The conformance vectors are the same package's `vectors.json`.
 *
 * Imported from the published package entry. That entry is dependency-free, so this adds nothing
 * to the bundle beyond the protocol itself.
 */

export {
  personalMessage,
  decodeAccessProof,
  isTransactionDigest,
  ACCESS_MESSAGE_VERSION,
} from '@meddleware/nft-gate-client'
export type { AccessProof, AccessMessageContext } from '@meddleware/nft-gate-client'
