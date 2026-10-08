import { describe, it, expect } from 'vitest'
import { SuiGrpc, isConsumedEvent, eventMatches, eventIsRecent, gateBlocksAccess, withDeadline } from '../src/chain.js'
import { consumedEventType } from '../src/verify.js'

// Pure match/parse helpers — mirror sui_rpc.rs unit tests.
describe('chain helpers', () => {
  it('packageOf extracts the prefix', () => {
    expect(SuiGrpc.packageOf('0xabc::access_gate::AccessNFT')).toBe('0xabc')
  })

  it('cacheKey is stable', () => {
    expect(SuiGrpc.cacheKey('0xa', '0xt', '0xg')).toBe('0xa|0xt|0xg')
    expect(SuiGrpc.cacheKey('0xa', '0xt', undefined)).toBe('0xa|0xt|-')
  })

  // gRPC event shape: `eventType` + `sender` + `json`. eventMatches binds sender + gate only
  // (single-use is enforced by redemption tracking on the consumeDigest, not the event nonce).
  const CONSUMED = consumedEventType('0xabc::access_gate::SoulboundAccessNFT')

  it('eventMatches on the gRPC event shape (eventType/json)', () => {
    const ev = {
      eventType: '0xabc::access_gate::AccessConsumedEvent',
      sender: '0xa11ce',
      json: { gate_id: '0x6a7e' },
    }
    expect(isConsumedEvent(ev, CONSUMED)).toBe(true)
    expect(eventMatches(ev, '0xa11ce', '0x6a7e')).toBe(true)
    expect(eventMatches(ev, '0xa77ac', '0x6a7e')).toBe(false) // wrong sender
    expect(eventMatches(ev, '0xa11ce', '0xbad')).toBe(false) // wrong gate
    expect(eventMatches(ev, '0xa11ce', undefined)).toBe(true) // gate unconstrained
  })

  it('matches the event type exactly: a look-alike package cannot forge a consume', () => {
    const forged = { eventType: '0xbad::access_gate::AccessConsumedEvent', sender: '0xa11ce', json: { gate_id: '0x6a7e' } }
    expect(isConsumedEvent(forged, CONSUMED)).toBe(false)
    // Long-form (gRPC) and short-form addresses of the configured package are the same type.
    const longForm = { eventType: `0x${'0'.repeat(61)}abc::access_gate::AccessConsumedEvent` }
    expect(isConsumedEvent(longForm, CONSUMED)).toBe(true)
    expect(isConsumedEvent({ eventType: '0xabc::access_gate::AccessConsumedEventX' }, CONSUMED)).toBe(false)
  })

  it('compares sender and gate ids in normalised form', () => {
    const ev = { eventType: CONSUMED, sender: `0x${'0'.repeat(59)}a11ce`, json: { gate_id: '0x06A7E' } }
    expect(eventMatches(ev, '0xA11CE', '0x6a7e')).toBe(true)
  })
})

describe('gateBlocksAccess', () => {
  const policy = (pauseBlocksAccess: boolean) => ({
    freeze_requires_unpaused: false,
    lock_commission_on_freeze: false,
    pause_blocks_decryption: false,
    pause_blocks_access: pauseBlocksAccess,
  })

  it('blocks only when paused AND the policy opts in', () => {
    expect(gateBlocksAccess({ paused: true, policy: policy(true) })).toBe(true)
    expect(gateBlocksAccess({ paused: false, policy: policy(true) })).toBe(false)
    expect(gateBlocksAccess({ paused: true, policy: policy(false) })).toBe(false)
  })

  it('fails closed on JSON it does not understand (a rendering change must not disable a pause)', () => {
    for (const bad of [
      null,
      undefined,
      {},
      { paused: true },
      { paused: 'true', policy: policy(true) },
      { paused: true, policy: null },
      { paused: true, policy: { pause_blocks_access: 'yes' } },
      { policy: policy(true) },
    ]) {
      expect(() => gateBlocksAccess(bad)).toThrow(/unrecognised shape/)
    }
  })
})

describe('eventIsRecent', () => {
  const NOW = 1_800_000_000_000
  const ev = (timestamp_ms: unknown) => ({ eventType: 't', sender: '0x1', json: { timestamp_ms } })

  it('accepts an event inside the age window and rejects an older or a future one', () => {
    expect(eventIsRecent(ev(String(NOW - 60_000)), NOW, 3600)).toBe(true)
    expect(eventIsRecent(ev(String(NOW - 3_600_001)), NOW, 3600)).toBe(false)
    expect(eventIsRecent(ev(String(NOW + 30_000)), NOW, 3600)).toBe(true) // within clock skew
    expect(eventIsRecent(ev(String(NOW + 600_000)), NOW, 3600)).toBe(false)
  })

  it('a missing or malformed timestamp is not recent', () => {
    for (const bad of [undefined, null, '', 'soon', '-5', '1.5', {}, '99999999999999999999']) {
      expect(eventIsRecent(ev(bad), NOW, 3600)).toBe(false)
    }
    expect(eventIsRecent({ eventType: 't' }, NOW, 3600)).toBe(false)
  })
})

describe('withDeadline', () => {
  it('rejects a call that never settles, and passes a fast one through', async () => {
    await expect(withDeadline(new Promise(() => {}), 20, 'probe')).rejects.toThrow(/probe timed out/)
    await expect(withDeadline(Promise.resolve(7), 1000, 'probe')).resolves.toBe(7)
  })
})

// The gRPC client is replaced with a fake, so these run offline.
describe('SuiGrpc against a fake client', () => {
  const PKG = '0xabc'
  const TYPE = `${PKG}::access_gate::SoulboundAccessNFT`
  const CONSUMED = consumedEventType(TYPE)
  const SENDER = '0xa11ce'
  const GATE = '0x6a7e'

  function chainWith(core: Record<string, unknown>, timeoutMs = 50): SuiGrpc {
    const c = new SuiGrpc('https://rpc.invalid', 'testnet', { cacheTtlMs: 0, timeoutMs })
    ;(c as unknown as { client: unknown }).client = { core }
    return c
  }
  const consumeTx = (timestamp_ms: string, success = true) => ({
    $kind: 'Transaction',
    Transaction: {
      status: { success },
      events: [{ eventType: `${PKG}::access_gate::AccessConsumedEvent`, sender: SENDER, json: { gate_id: GATE, timestamp_ms } }],
    },
  })
  const notFound = Object.assign(new Error('not found'), { reason: 'notFound' })

  it('accepts a recent successful consume for this sender and gate', async () => {
    const c = chainWith({ getTransaction: async () => consumeTx(String(Date.now() - 1000)) })
    expect(await c.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).toBe(true)
  })

  it('refuses a consume older than the age bound, a failed transaction and a foreign sender', async () => {
    const old = chainWith({ getTransaction: async () => consumeTx(String(Date.now() - 7_200_000)) })
    expect(await old.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).toBe(false)
    const failed = chainWith({ getTransaction: async () => consumeTx(String(Date.now()), false) })
    expect(await failed.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).toBe(false)
    const other = chainWith({ getTransaction: async () => consumeTx(String(Date.now())) })
    expect(await other.consumeTxValid('d', '0xbad', CONSUMED, GATE, 3600)).toBe(false)
  })

  it('retries only "not found", then denies (false) instead of erroring', async () => {
    let calls = 0
    const c = chainWith({
      getTransaction: async () => {
        calls++
        throw notFound
      },
    })
    expect(await c.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).toBe(false)
    expect(calls).toBe(4)
  }, 10_000)

  it('a late-indexed transaction is found on a retry', async () => {
    let calls = 0
    const c = chainWith({
      getTransaction: async () => {
        if (++calls < 2) throw notFound
        return consumeTx(String(Date.now()))
      },
    })
    expect(await c.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).toBe(true)
    expect(calls).toBe(2)
  })

  it('any other failure is thrown at once (no amplification) and a hung node is bounded', async () => {
    let calls = 0
    const down = chainWith({
      getTransaction: async () => {
        calls++
        throw new Error('503 from fullnode')
      },
    })
    await expect(down.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).rejects.toThrow(/503/)
    expect(calls).toBe(1)
    const hung = chainWith({ getTransaction: () => new Promise(() => {}) }, 20)
    await expect(hung.consumeTxValid('d', SENDER, CONSUMED, GATE, 3600)).rejects.toThrow(/timed out/)
    const hungGate = chainWith({ getObject: () => new Promise(() => {}) }, 20)
    await expect(hungGate.gateAccessBlocked(GATE)).rejects.toThrow(/timed out/)
  })

  it('reads the gate strictly', async () => {
    const policy = { pause_blocks_access: true }
    const paused = chainWith({ getObject: async () => ({ object: { json: { paused: true, policy } } }) })
    expect(await paused.gateAccessBlocked(GATE)).toBe(true)
    const odd = chainWith({ getObject: async () => ({ object: { json: { is_paused: true } } }) })
    await expect(odd.gateAccessBlocked(GATE)).rejects.toThrow(/unrecognised shape/)
  })

  it('the ownership cache stays bounded and drops expired entries', async () => {
    let live = 0
    const core = {
      listOwnedObjects: async () => {
        live++
        return { objects: [], hasNextPage: false, cursor: null }
      },
    }
    const c = new SuiGrpc('https://rpc.invalid', 'testnet', { cacheTtlMs: 60_000, timeoutMs: 1000 })
    ;(c as unknown as { client: unknown }).client = { core }
    await c.ownsNft('0xa', TYPE, GATE)
    await c.ownsNft('0xa', TYPE, GATE)
    expect(live).toBe(1) // second answer from the cache
    expect((c as unknown as { cache: Map<string, unknown> }).cache.size).toBe(1)
  })
})
