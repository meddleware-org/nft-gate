import { describe, it, expect, vi } from 'vitest'
import { redeemAndForward } from '../src/redemption.js'
import type { Config } from '../src/config.js'
import type { CommitResult, LeaseResult, RedemptionStore } from '../src/state/types.js'

/**
 * An in-memory {@link RedemptionStore} with the same owner-token compare-and-set semantics as the
 * Durable Object (`state.test.ts` runs the real one in workerd). `clock` lets a test lapse a lease.
 */
class MemoryStore implements RedemptionStore {
  rows = new Map<string, { state: 'leased' | 'committed'; expiry: number; token: string | null }>()
  clock = 0
  failCommit = false
  private n = 0
  async tryLeaseRedemption(key: string, leaseTtlSecs: number): Promise<LeaseResult> {
    const r = this.rows.get(key)
    if (r?.state === 'committed') return { status: 'redeemed' }
    if (r?.state === 'leased' && r.expiry > this.clock) return { status: 'leased' }
    const token = `t${++this.n}`
    this.rows.set(key, { state: 'leased', expiry: this.clock + leaseTtlSecs * 1000, token })
    return { status: 'ok', token }
  }
  async commitRedemption(key: string, token: string, retentionSecs: number): Promise<CommitResult> {
    if (this.failCommit) throw new Error('store down')
    const r = this.rows.get(key)
    if (!r || r.state !== 'leased' || r.token !== token || r.expiry <= this.clock) return 'lost'
    this.rows.set(key, { state: 'committed', expiry: this.clock + retentionSecs * 1000, token: null })
    return 'ok'
  }
  async releaseRedemption(key: string, token: string): Promise<void> {
    const r = this.rows.get(key)
    if (r?.state === 'leased' && r.token === token) this.rows.delete(key)
  }
}

const cfg = { redemptionLeaseTtlSecs: 900, redemptionRetentionSecs: 3600 } as Config
const ok = () => new Response('stored', { status: 200 })
const body = async (r: Response) => (await r.json()) as { error?: string; code?: string }

describe('redeemAndForward (owner-bound lease)', () => {
  it('leases, forwards, commits; a second attempt is redeemed', async () => {
    const store = new MemoryStore()
    const first = await redeemAndForward(cfg, store, 'k', async () => ok())
    expect(first.status).toBe(200)
    const again = await redeemAndForward(cfg, store, 'k', async () => ok())
    expect(again.status).toBe(409)
    expect((await body(again)).code).toBe('redeemed')
  })

  it('a concurrent duplicate gets 409 leased and does not forward', async () => {
    const store = new MemoryStore()
    const send = vi.fn(async () => ok())
    let release!: () => void
    const slow = redeemAndForward(cfg, store, 'k', () => new Promise<Response>((r) => (release = () => r(ok()))))
    await Promise.resolve()
    const dup = await redeemAndForward(cfg, store, 'k', send)
    expect(dup.status).toBe(409)
    expect((await body(dup)).code).toBe('leased')
    expect(send).not.toHaveBeenCalled()
    release()
    expect((await slow).status).toBe(200)
  })

  it('a failed upload or a thrown error releases the lease so the consume stays usable', async () => {
    const store = new MemoryStore()
    expect((await redeemAndForward(cfg, store, 'k', async () => new Response('no', { status: 500 }))).status).toBe(500)
    await expect(redeemAndForward(cfg, store, 'k', async () => { throw new Error('boom') })).rejects.toThrow('boom')
    expect((await redeemAndForward(cfg, store, 'k', async () => ok())).status).toBe(200)
  })

  it('a stale holder cannot release or commit over a newer lease', async () => {
    const store = new MemoryStore()
    // A's lease lapses mid-forward; B then leases the same consume.
    let finishA!: (r: Response) => void
    const a = redeemAndForward(cfg, store, 'k', () => new Promise<Response>((r) => (finishA = r)))
    await Promise.resolve()
    store.clock += 901_000
    let finishB!: (r: Response) => void
    const b = redeemAndForward(cfg, store, 'k', () => new Promise<Response>((r) => (finishB = r)))
    await Promise.resolve()
    // A finishes with a failure: its release must not clear B's lease.
    finishA(new Response('no', { status: 500 }))
    expect((await a).status).toBe(500)
    expect((await redeemAndForward(cfg, store, 'k', async () => ok())).status).toBe(409) // B still leased
    // B succeeds and commits.
    finishB(ok())
    expect((await b).status).toBe(200)
    expect((await redeemAndForward(cfg, store, 'k', async () => ok())).status).toBe(409)
  })

  it('a holder whose lease lapsed before commit is told 502, never success, and leaves the row alone', async () => {
    const store = new MemoryStore()
    const lapsed = await redeemAndForward(cfg, store, 'k', async () => {
      store.clock += 901_000 // the lease expires while the upload runs
      return ok()
    })
    expect(lapsed.status).toBe(502)
    expect(store.rows.get('k')?.state).toBe('leased') // untouched, not committed by the stale holder
  })

  it('reports a failed commit as 502 (never success) and releases the lease', async () => {
    const store = new MemoryStore()
    store.failCommit = true
    const res = await redeemAndForward(cfg, store, 'k', async () => ok())
    expect(res.status).toBe(502)
    expect(store.rows.has('k')).toBe(false)
  })

  it('a store error while leasing propagates (the router answers 503, never a conflict)', async () => {
    const store = new MemoryStore()
    store.tryLeaseRedemption = async () => {
      throw new Error('store down')
    }
    await expect(redeemAndForward(cfg, store, 'k', async () => ok())).rejects.toThrow('store down')
  })
})
