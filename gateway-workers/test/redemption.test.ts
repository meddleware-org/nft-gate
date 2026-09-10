import { describe, it, expect } from 'vitest'
import { KvBackend } from '../src/state/kv.js'

/**
 * Exercise the REAL `KvBackend` redemption state machine against a Map-backed fake `KVNamespace`
 * (only `get`/`put`/`delete` are used; the logical expiry is stored in-value and checked on read,
 * so the fake need not honour `expirationTtl`). This runs in the Node unit pool — the Durable
 * Object variant is covered by `state.test.ts` in the cloudflare-integration pool.
 */
function fakeKv(): KVNamespace {
  const m = new Map<string, string>()
  return {
    async get(key: string) {
      return m.get(key) ?? null
    },
    async put(key: string, value: string) {
      m.set(key, value)
    },
    async delete(key: string) {
      m.delete(key)
    },
  } as unknown as KVNamespace
}

describe('KvBackend redemption state machine', () => {
  const key = () => '0xdigest' + Math.random().toString(16).slice(2)

  it('leases once; a concurrent lease is rejected; commit marks it redeemed', async () => {
    const store = new KvBackend(fakeKv())
    const k = key()
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok')
    expect(await store.tryLeaseRedemption(k, 120)).toBe('leased')
    await store.commitRedemption(k, 3600)
    expect(await store.tryLeaseRedemption(k, 120)).toBe('redeemed')
  })

  it('release makes an interrupted consume immediately re-leasable (use not lost)', async () => {
    const store = new KvBackend(fakeKv())
    const k = key()
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok')
    await store.releaseRedemption(k)
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok')
  })

  it('release never clears a committed redemption', async () => {
    const store = new KvBackend(fakeKv())
    const k = key()
    await store.tryLeaseRedemption(k, 120)
    await store.commitRedemption(k, 3600)
    await store.releaseRedemption(k)
    expect(await store.tryLeaseRedemption(k, 120)).toBe('redeemed')
  })

  it('an expired lease is reclaimable (crashed in-flight upload)', async () => {
    const store = new KvBackend(fakeKv())
    const k = key()
    expect(await store.tryLeaseRedemption(k, 0)).toBe('ok') // lease already expired
    expect(await store.tryLeaseRedemption(k, 120)).toBe('ok')
  })
})
