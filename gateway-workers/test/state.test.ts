import { describe, it, expect } from 'vitest'
import { env } from 'cloudflare:test'
import { DurableObjectBackend } from '../src/state/durable_object.js'
import { KvBackend } from '../src/state/kv.js'
import type { NonceRateState } from '../src/state/durable_object.js'
import type { NonceBackend } from '../src/state/types.js'

interface TestEnv {
  NONCE_STATE: DurableObjectNamespace<NonceRateState>
  NONCE_KV: KVNamespace
}
const e = env as unknown as TestEnv

function doBackend(max = 10_000): NonceBackend {
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

// Single-use redemption: the consumeDigest is the one-time token. Same semantics on both backends.
describe.each([
  ['durable-object', () => doBackend()],
  ['kv', () => kvBackend()],
])('redemption backend: %s', (_name, make) => {
  const key = () => '0xdigest' + Math.random().toString(16).slice(2)

  it('leases once; a concurrent lease is rejected; commit marks it redeemed', async () => {
    const store = make()
    const k = key()
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok') // first claim
    expect(await store.tryLeaseRedemption(k, 120)).toBe('leased') // in-flight duplicate
    await store.commitRedemption(k, 3600)
    expect(await store.tryLeaseRedemption(k, 120)).toBe('redeemed') // spent — never reusable
  })

  it('release makes an interrupted consume immediately re-leasable (use not lost)', async () => {
    const store = make()
    const k = key()
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok')
    await store.releaseRedemption(k) // upload failed
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok') // retry with the same consume
  })

  it('release never clears a committed redemption', async () => {
    const store = make()
    const k = key()
    await store.tryLeaseRedemption(k, 120)
    await store.commitRedemption(k, 3600)
    await store.releaseRedemption(k) // must be a no-op on a committed key
    expect(await store.tryLeaseRedemption(k, 120)).toBe('redeemed')
  })

  it('an expired lease is reclaimable (crashed in-flight upload)', async () => {
    const store = make()
    const k = key()
    expect(await store.tryLeaseRedemption(k, 0)).toBe('ok') // lease expires immediately
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok') // reclaimed, not stuck 'leased'
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

  it('hard cap keeps the nonce store bounded', async () => {
    const store = doBackend(4) // cap 4
    for (let i = 0; i < 20; i++) await store.issue('g', 300)
    // Can't read the row count through the backend, but issue/take must still work after
    // repeated eviction — a broken cap would error or corrupt state.
    const { nonce } = await store.issue('g', 300)
    expect(await store.takeIfValid(nonce)).toBe(true)
  })
})
