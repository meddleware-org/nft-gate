import { describe, it, expect } from 'vitest'
import { KvBackend } from '../src/state/kv.js'
import { redeemAndForward } from '../src/redemption.js'
import type { Config } from '../src/config.js'

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

describe('redeemAndForward (lease → proxy → commit / release)', () => {
  const cfg = { redemptionLeaseTtlSecs: 120, redemptionRetentionSecs: 3600 } as Config
  const ok = () => Promise.resolve(new Response('stored', { status: 200 }))

  it('commits after a successful upload, so the same consume is then redeemed', async () => {
    const store = new KvBackend(fakeKv())
    expect((await redeemAndForward(cfg, store, '0xd1', ok)).status).toBe(200)
    const again = await redeemAndForward(cfg, store, '0xd1', ok)
    expect(again.status).toBe(409)
    expect(await again.json()).toMatchObject({ code: 'redeemed' })
  })

  it('releases after an upstream failure, so the consume stays usable', async () => {
    const store = new KvBackend(fakeKv())
    const fail = await redeemAndForward(cfg, store, '0xd2', () => Promise.resolve(new Response('no', { status: 503 })))
    expect(fail.status).toBe(503)
    expect((await redeemAndForward(cfg, store, '0xd2', ok)).status).toBe(200)
  })

  it('reports a failed commit as 502 (never success) and releases the lease', async () => {
    const store = new KvBackend(fakeKv())
    const released: string[] = []
    const failingCommit = Object.assign(Object.create(store), {
      commitRedemption: async () => {
        throw new Error('storage down')
      },
      releaseRedemption: async (k: string) => {
        released.push(k)
        await store.releaseRedemption(k)
      },
    }) as KvBackend
    const res = await redeemAndForward(cfg, failingCommit, '0xd3', ok)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'redemption commit failed' })
    expect(released).toEqual(['0xd3'])
    // The consume was not spent: it can be redeemed once storage recovers.
    expect((await redeemAndForward(cfg, store, '0xd3', ok)).status).toBe(200)
  })

  it('releases and rethrows when the upstream request itself throws', async () => {
    const store = new KvBackend(fakeKv())
    await expect(redeemAndForward(cfg, store, '0xd4', () => Promise.reject(new Error('network')))).rejects.toThrow(
      'network',
    )
    expect(await store.tryLeaseRedemption('0xd4', 120)).toBe('ok')
  })
})

