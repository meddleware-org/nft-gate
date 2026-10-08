/**
 * The pluggable state backends — the Workers analog of the Rust gateway's `NonceStore` enum
 * (in-memory | Redis). {@link NonceBackend} holds the single-use nonce store and the rate-limit
 * windows; {@link RedemptionStore} holds single-use redemptions. Both need per-key atomicity a
 * stateless isolate cannot give.
 *
 * Two implementations:
 * - `DurableObjectBackend` (default): region-sharded, SQLite-backed Durable Objects. Strongly
 *   consistent, atomic single-use consume (the Redis-`GETDEL` analog). Free-tier eligible.
 * - `KvBackend`: Workers KV + best-effort rate limit. Eventually consistent (documented weaker
 *   cross-region replay window in the `SINGLE_USE=false` ownership mode; refused when
 *   `SINGLE_USE=true`).
 */

/**
 * Outcome of a redemption-lease attempt (single-use mode). `ok` carries the owner `token` the
 * caller must present to `commit`/`release`. `leased` — another in-flight request holds the lease.
 * `redeemed` — it was already committed (the use is spent).
 */
export type LeaseResult = { status: 'ok'; token: string } | { status: 'leased' } | { status: 'redeemed' }

/**
 * Outcome of a commit. `ok` — recorded as spent by the lease holder. `lost` — the lease had lapsed
 * or belongs to another request, so nothing was changed (the caller must not report success).
 */
export type CommitResult = 'ok' | 'lost'

/** Nonce issuance, single-use nonce consumption and rate-limit windows. */
export interface NonceBackend {
  /**
   * Issue a fresh, time-bound nonce. `region` selects the DO shard (ignored by KV, which is
   * global). Returns the opaque `<region>.<hex>` nonce and its unix-ms expiry.
   */
  issue(region: string, ttlSecs: number): Promise<{ nonce: string; expiresAt: number }>
  /** Consume a nonce exactly once; true iff it was valid, unexpired, and unused. */
  takeIfValid(nonce: string): Promise<boolean>
  /** Fixed 60s window per key. `maxPerMin === 0` disables limiting. */
  rateCheck(address: string, maxPerMin: number, region: string): Promise<boolean>
}

/**
 * Single-use redemption (the permanent on-chain `consumeDigest` is the one-time token). A use is
 * only spent when an upload actually succeeds: lease the digest, proxy, then commit on success or
 * release on failure. Every transition is a compare-and-set on the owner token the lease returned,
 * so a stale holder can never clear or overwrite a newer lease. Only the Durable Object backend
 * implements it: it needs per-key atomicity that eventually-consistent KV cannot give.
 */
export interface RedemptionStore {
  /**
   * Atomically claim `key` for an in-flight upload. `ok` on a fresh/expired-lease/released key,
   * `leased` if another request holds an unexpired lease, `redeemed` if already committed. The
   * lease self-expires after `leaseTtlSecs`; the config guarantees that exceeds the upload deadline.
   */
  tryLeaseRedemption(key: string, leaseTtlSecs: number): Promise<LeaseResult>
  /** Mark `key` redeemed (retained `retentionSecs`) iff `token` still owns the lease. */
  commitRedemption(key: string, token: string, retentionSecs: number): Promise<CommitResult>
  /** Release the lease on `key` iff `token` still owns it (upload failed); never clears a commit. */
  releaseRedemption(key: string, token: string): Promise<void>
}

/**
 * The shard tags a nonce may carry: Cloudflare's continent codes (lower-cased) plus `g` (global).
 * Anything else was not issued by this gateway, and routing on it would let a client mint Durable
 * Object instances at will.
 */
export const NONCE_SHARDS: ReadonlySet<string> = new Set(['af', 'an', 'as', 'eu', 'na', 'oc', 'sa', 'g'])

/**
 * Parse the shard tag embedded in a `<region>.<hex>` nonce so a consume call always routes
 * back to the shard that issued it, even under anycast region drift.
 *
 * @param nonce - A nonce in `<region>.<hex>` format.
 * @returns The region prefix (e.g. `"eu"`), `"g"` if no dot is present, or `null` when the prefix
 *   is not a known shard (the nonce is then invalid).
 */
export function shardOfNonce(nonce: string): string | null {
  const dot = nonce.indexOf('.')
  if (dot <= 0) return 'g'
  const shard = nonce.slice(0, dot)
  return NONCE_SHARDS.has(shard) ? shard : null
}

/**
 * Generate a cryptographically random 48-character hex string (24 bytes of entropy). Matches
 * the Rust gateway's `random_nonce()` entropy so conformance vectors apply to both. Nonces are
 * **ASCII by contract** — this hex plus an ASCII `<region>.` prefix — and the client's
 * `decodeAccessProof` enforces ASCII, so the proof-token base64 never carries non-ASCII bytes.
 *
 * @returns A 48-character lowercase hex string.
 */
export function randomHex24(): string {
  const buf = new Uint8Array(24)
  crypto.getRandomValues(buf)
  let out = ''
  for (const b of buf) out += b.toString(16).padStart(2, '0')
  return out
}
