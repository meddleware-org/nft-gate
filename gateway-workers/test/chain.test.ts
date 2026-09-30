import { describe, it, expect } from 'vitest'
import { SuiGrpc, nonceMatches, isConsumedEvent, eventMatches, gateBlocksAccess } from '../src/chain.js'
import { bytesToBase64 } from '../src/crypto.js'
import { consumedEventType } from '../src/verify.js'

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
  const CONSUMED = consumedEventType('0xabc::access_gate::SoulboundAccessNFT')

  it('eventMatches on the gRPC event shape (eventType/json)', () => {
    const ev = {
      eventType: '0xabc::access_gate::AccessConsumedEvent',
      sender: '0xa11ce',
      json: { nonce: bytesToBase64(new TextEncoder().encode('nonce')), gate_id: '0x6a7e' },
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

  // Legacy JSON-RPC shape (`type`/`parsedJson`) stays supported so the helpers tolerate the
  // transport/shape variation the SDK documents for the parsed event `json`.
  it('eventMatches still accepts the legacy type/parsedJson shape', () => {
    const ev = {
      type: '0xabc::access_gate::AccessConsumedEvent',
      sender: '0xa11ce',
      parsedJson: { nonce: [110, 111, 110, 99, 101], gate_id: '0x6a7e' },
    }
    expect(isConsumedEvent(ev, CONSUMED)).toBe(true)
    expect(eventMatches(ev, '0xa11ce', '0x6a7e')).toBe(true)
    expect(eventMatches(ev, '0xa11ce', '0xbad')).toBe(false)
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
