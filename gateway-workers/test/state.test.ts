import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'
import { DurableObjectBackend } from '../src/state/durable_object.js'
import { KvBackend } from '../src/state/kv.js'
import type { NonceRateState } from '../src/state/durable_object.js'
import type { NonceBackend, RedemptionStore } from '../src/state/types.js'
import { shardOfNonce } from '../src/state/types.js'

interface TestEnv {
  NONCE_STATE: DurableObjectNamespace<NonceRateState>
  NONCE_KV: KVNamespace
}
const e = env as unknown as TestEnv

function doBackend(max = 10_000): DurableObjectBackend {
  return new DurableObjectBackend(e.NONCE_STATE, 'global', max)
}
function kvBackend(): NonceBackend {
  return new KvBackend(e.NONCE_KV)
}

// Mirror challenge.rs tests, run against BOTH backends where the semantics are identical.
describe.each([
  ['durable-object', () => doBackend()],
  ['kv', () => kvBackend()],
])('nonce backend: %s', (_name, make) => {
  it('a nonce is valid once, then used', async () => {
    const store = make()
    const { nonce } = await store.issue('g', 300)
    expect(await store.takeIfValid(nonce)).toBe(true)
    expect(await store.takeIfValid(nonce)).toBe(false)
  })

  it('an unknown nonce is rejected', async () => {
    const store = make()
    expect(await store.takeIfValid('g.never-issued')).toBe(false)
  })

  it('an expired nonce is rejected', async () => {
    const store = make()
    const { nonce } = await store.issue('g', 0) // immediate expiry
    expect(await store.takeIfValid(nonce)).toBe(false)
  })
})

// Single-use redemption: the consumeDigest is the one-time token. Durable Object only: the KV
// backend no longer implements redemptions (SINGLE_USE=true is refused with it).
describe('redemption store: durable-object', () => {
  const store = (): RedemptionStore => doBackend()
  const key = () => '0xdigest' + Math.random().toString(16).slice(2)
  const lease = async (s: RedemptionStore, k: string, ttl = 120) => {
    const r = await s.tryLeaseRedemption(k, ttl)
    if (r.status !== 'ok') throw new Error(`expected a lease, got ${r.status}`)
    return r.token
  }

  it('leases once; a concurrent lease is rejected; commit marks it redeemed', async () => {
    const s = store()
    const k = key()
    const token = await lease(s, k)
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('leased') // in-flight duplicate
    expect(await s.commitRedemption(k, token, 3600)).toBe('ok')
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('redeemed') // spent: never reusable
  })

  it('release makes an interrupted consume immediately re-leasable (use not lost)', async () => {
    const s = store()
    const k = key()
    await s.releaseRedemption(k, await lease(s, k)) // upload failed
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('ok')
  })

  it('release never clears a committed redemption', async () => {
    const s = store()
    const k = key()
    const token = await lease(s, k)
    await s.commitRedemption(k, token, 3600)
    await s.releaseRedemption(k, token) // must be a no-op on a committed key
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('redeemed')
  })

  it('an expired lease is reclaimable (crashed in-flight upload)', async () => {
    const s = store()
    const k = key()
    await lease(s, k, 0) // lease expires immediately
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('ok')
  })

  it('a stale holder can neither release nor commit over a newer lease', async () => {
    const s = store()
    const k = key()
    const stale = await lease(s, k, 0) // lapses at once
    const fresh = await lease(s, k, 120) // a newer holder
    expect(stale).not.toBe(fresh)
    await s.releaseRedemption(k, stale) // must not clear the newer lease
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('leased')
    expect(await s.commitRedemption(k, stale, 3600)).toBe('lost') // and must not commit over it
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('leased')
    expect(await s.commitRedemption(k, fresh, 3600)).toBe('ok')
    expect((await s.tryLeaseRedemption(k, 120)).status).toBe('redeemed')
  })

  it('a commit after the lease lapsed is lost, never recorded', async () => {
    const s = store()
    const k = key()
    const token = await lease(s, k, 0)
    expect(await s.commitRedemption(k, token, 3600)).toBe('lost')
  })
})

describe('durable-object rate limiter', () => {
  it('allows up to the limit then denies, per address', async () => {
    const store = doBackend()
    const a = '0xaaa' + Math.random().toString(16).slice(2)
    expect(await store.rateCheck(a, 3, 'g')).toBe(true)
    expect(await store.rateCheck(a, 3, 'g')).toBe(true)
    expect(await store.rateCheck(a, 3, 'g')).toBe(true)
    expect(await store.rateCheck(a, 3, 'g')).toBe(false) // 4th within window
    const b = '0xbbb' + Math.random().toString(16).slice(2)
    expect(await store.rateCheck(b, 3, 'g')).toBe(true) // independent key
  })

  it('rate limit of 0 disables', async () => {
    const store = doBackend()
    for (let i = 0; i < 50; i++) expect(await store.rateCheck('0xzero', 0, 'g')).toBe(true)
  })

  it('rate windows older than a minute are swept (the table is bounded by recent keys)', async () => {
    const store = doBackend()
    // Many one-off keys; the sweep is probabilistic, so just require that heavy use keeps working.
    for (let i = 0; i < 200; i++) await store.rateCheck(`0xk${i}-${Math.random()}`, 5, 'g')
    expect(await store.rateCheck('0xafter', 5, 'g')).toBe(true)
  })

  it('hard cap keeps the nonce store bounded', async () => {
    const store = doBackend(4) // cap 4
    for (let i = 0; i < 20; i++) await store.issue('g', 300)
    // Can't read the row count through the backend, but issue/take must still work after
    // repeated eviction — a broken cap would error or corrupt state.
    const { nonce } = await store.issue('g', 300)
    expect(await store.takeIfValid(nonce)).toBe(true)
  })
})

describe('nonce shard tags', () => {
  it('routes only known continent shards and the global shard', () => {
    expect(shardOfNonce('eu.abc')).toBe('eu')
    expect(shardOfNonce('g.abc')).toBe('g')
    expect(shardOfNonce('abc')).toBe('g')
    expect(shardOfNonce('zz.abc')).toBeNull()
    expect(shardOfNonce('EU.abc')).toBeNull() // issued tags are lower-case
  })

  it('the Durable Object backend rejects a forged shard tag without touching a shard', async () => {
    const store = new DurableObjectBackend(e.NONCE_STATE, 'region', 10_000)
    expect(await store.takeIfValid('attacker-shard-1.deadbeef')).toBe(false)
  })

  it('a region-sharded nonce is accepted by the shard that issued it', async () => {
    const store = new DurableObjectBackend(e.NONCE_STATE, 'region', 10_000)
    const { nonce } = await store.issue('eu', 300)
    expect(nonce.startsWith('eu.')).toBe(true)
    expect(await store.takeIfValid(nonce)).toBe(true)
  })
})
