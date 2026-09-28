import { describe, it, expect } from 'vitest'
import { SuiGrpc, nonceMatches, isConsumedEvent, eventMatches, gateBlocksAccess } from '../src/chain.js'
import { bytesToBase64 } from '../src/crypto.js'

// Pure match/parse helpers — mirror sui_rpc.rs unit tests.
describe('chain helpers', () => {
  it('nonceMatches byte array', () => {
    expect(nonceMatches([110, 111, 110, 99, 101], 'nonce')).toBe(true)
    expect(nonceMatches([1, 2, 3], 'nonce')).toBe(false)
  })

  it('nonceMatches base64', () => {
    const b64 = bytesToBase64(new TextEncoder().encode('nonce'))
    expect(nonceMatches(b64, 'nonce')).toBe(true)
  })

  it('packageOf extracts the prefix', () => {
    expect(SuiGrpc.packageOf('0xabc::access_gate::AccessNFT')).toBe('0xabc')
  })

  it('cacheKey is stable', () => {
    expect(SuiGrpc.cacheKey('0xa', '0xt', '0xg')).toBe('0xa|0xt|0xg')
    expect(SuiGrpc.cacheKey('0xa', '0xt', undefined)).toBe('0xa|0xt|-')
  })

  // gRPC event shape: `eventType` + `sender` + `json`. eventMatches binds sender + gate only
  // (single-use is enforced by redemption tracking on the consumeDigest, not the event nonce).
  it('eventMatches on the gRPC event shape (eventType/json)', () => {
    const ev = {
      eventType: '0xabc::access_gate::AccessConsumedEvent',
      sender: '0xowner',
      json: { nonce: bytesToBase64(new TextEncoder().encode('nonce')), gate_id: '0xgate' },
    }
    expect(isConsumedEvent(ev)).toBe(true)
    expect(eventMatches(ev, '0xowner', '0xgate')).toBe(true)
    expect(eventMatches(ev, '0xattacker', '0xgate')).toBe(false) // wrong sender
    expect(eventMatches(ev, '0xowner', '0xwrong')).toBe(false) // wrong gate
    expect(eventMatches(ev, '0xowner', undefined)).toBe(true) // gate unconstrained
  })

  // Legacy JSON-RPC shape (`type`/`parsedJson`) stays supported so the helpers tolerate the
  // transport/shape variation the SDK documents for the parsed event `json`.
  it('eventMatches still accepts the legacy type/parsedJson shape', () => {
    const ev = {
      type: '0xabc::access_gate::AccessConsumedEvent',
      sender: '0xowner',
      parsedJson: { nonce: [110, 111, 110, 99, 101], gate_id: '0xgate' },
    }
    expect(isConsumedEvent(ev)).toBe(true)
    expect(eventMatches(ev, '0xowner', '0xgate')).toBe(true)
    expect(eventMatches(ev, '0xowner', '0xwrong')).toBe(false)
  })

  // nonceMatches is retained (exported helper) even though the single-use path no longer calls it.
  it('nonceMatches remains available for byte-array and base64 nonces', () => {
    expect(nonceMatches([110, 111, 110, 99, 101], 'nonce')).toBe(true)
    expect(nonceMatches(bytesToBase64(new TextEncoder().encode('x')), 'x')).toBe(true)
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

  it('never blocks a gate without a policy (pre-policy package) or missing JSON', () => {
    expect(gateBlocksAccess({ paused: true })).toBe(false)
    expect(gateBlocksAccess(null)).toBe(false)
  })
})
