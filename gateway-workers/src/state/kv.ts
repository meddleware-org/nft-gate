/**
 * Workers KV nonce store + best-effort rate limiter — the pure free-tier fallback backend
 * (`NONCE_BACKEND=kv`). KV has native per-key TTL, but is **eventually consistent**: `get`
 * then `delete` is not atomic, so a nonce could momentarily read valid in two regions within
 * its TTL — a weaker cross-region replay window in the `SINGLE_USE=false` ownership mode. (In
 * `SINGLE_USE=true` mode the on-chain `AccessConsumedEvent` remains the authoritative single-
 * use bind, so that mode is unaffected.) Use the Durable Object backend when this matters.
 */

import type { LeaseResult, NonceBackend } from './types.js'
import { randomHex24 } from './types.js'

/** KV key prefix for nonce entries. */
const NONCE_PREFIX = 'nonce:'
/** KV key prefix for per-address rate-limit windows. */
const RATE_PREFIX = 'rate:'
/** KV key prefix for redemption entries. */
const REDEEM_PREFIX = 'redeem:'
/** Workers KV minimum `expirationTtl` (seconds). Sub-60s logical TTLs are enforced in-value. */
const KV_MIN_TTL_SECS = 60

/**
 * {@link NonceBackend} implementation backed by Workers KV. Purely free-tier with no
 * additional bindings beyond a `KVNamespace`. See the module doc for consistency caveats.
 */
export class KvBackend implements NonceBackend {
  /**
   * @param kv - The `KVNamespace` binding to use for nonce and rate-limit storage.
   */
  constructor(private readonly kv: KVNamespace) {}

  async issue(_region: string, ttlSecs: number): Promise<{ nonce: string; expiresAt: number }> {
    // KV is global; the shard tag is cosmetic here (kept for a uniform nonce format).
    const nonce = `g.${randomHex24()}`
    const expiresAt = Date.now() + ttlSecs * 1000
    // The logical expiry is stored IN the value and enforced on read, so sub-60s TTLs are
    // honoured exactly; KV's own `expirationTtl` (min 60s) is only a GC backstop.
    await this.kv.put(NONCE_PREFIX + nonce, JSON.stringify({ e: expiresAt }), {
      expirationTtl: Math.max(KV_MIN_TTL_SECS, ttlSecs),
    })
    return { nonce, expiresAt }
  }

  async takeIfValid(nonce: string): Promise<boolean> {
    const key = NONCE_PREFIX + nonce
    const v = await this.kv.get(key)
    if (v === null) return false
    // Best-effort single-use: delete after a positive read (not atomic — see module note).
    await this.kv.delete(key)
    let expiry = 0
    try {
      expiry = (JSON.parse(v) as { e: number }).e
    } catch {
      return false
    }
    return expiry > Date.now()
  }

  async rateCheck(address: string, maxPerMin: number, _region: string): Promise<boolean> {
    if (maxPerMin === 0) return true
    const key = RATE_PREFIX + address
    const raw = await this.kv.get(key)
    const now = Date.now()
    let start = now
    let count = 0
    if (raw) {
      try {
        const p = JSON.parse(raw) as { start: number; count: number }
        if (now - p.start < 60000) {
          start = p.start
          count = p.count
        }
      } catch {
        /* treat as a fresh window */
      }
    }
    if (count >= maxPerMin) return false
    await this.kv.put(key, JSON.stringify({ start, count: count + 1 }), {
      expirationTtl: KV_MIN_TTL_SECS,
    })
    return true
  }

  // Best-effort redemption on KV (eventually consistent — the get→put lease is not atomic, so a
  // narrow concurrent-duplicate window exists; the Durable Object backend is strongly consistent
  // and preferred when this matters). Committed always wins over a lease on read.
  async tryLeaseRedemption(key: string, leaseTtlSecs: number): Promise<LeaseResult> {
    const k = REDEEM_PREFIX + key
    const raw = await this.kv.get(k)
    if (raw) {
      try {
        const r = JSON.parse(raw) as { s: string; e: number }
        if (r.s === 'committed') return 'redeemed'
        if (r.s === 'leased' && r.e > Date.now()) return 'leased'
      } catch {
        /* fall through and re-lease */
      }
    }
    await this.kv.put(k, JSON.stringify({ s: 'leased', e: Date.now() + leaseTtlSecs * 1000 }), {
      expirationTtl: Math.max(KV_MIN_TTL_SECS, leaseTtlSecs),
    })
    return 'ok'
  }

  async commitRedemption(key: string, retentionSecs: number): Promise<void> {
    await this.kv.put(
      REDEEM_PREFIX + key,
      JSON.stringify({ s: 'committed', e: Date.now() + retentionSecs * 1000 }),
      { expirationTtl: Math.max(KV_MIN_TTL_SECS, retentionSecs) },
    )
  }

  async releaseRedemption(key: string): Promise<void> {
    // Only clear a lease — never a committed marker (that would allow the use to be re-redeemed).
    const raw = await this.kv.get(REDEEM_PREFIX + key)
    if (!raw) return
    try {
      if ((JSON.parse(raw) as { s: string }).s === 'committed') return
    } catch {
      /* malformed — safe to delete */
    }
    await this.kv.delete(REDEEM_PREFIX + key)
  }
}
