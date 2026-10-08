import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import {
  verifyPersonalMessageSignature,
  verifyAccessRequest,
  signingDigest,
  deriveAddress,
  FLAG_ED25519,
  FLAG_SECP256K1,
  FLAG_SECP256R1,
  FLAG_MULTISIG,
  FLAG_ZKLOGIN,
  type ChainQuery,
} from '../src/verify.js'
import { personalMessage } from '../src/wire.js'
import { bytesToBase64, concatBytes } from '../src/crypto.js'
import type { Config } from '../src/config.js'
import type { NonceBackend } from '../src/state/types.js'

const DIGEST = '5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL'
const ORIGIN = 'https://gateway.example.com'
const GATE = '0x' + '0'.repeat(63) + '2'

/** The message a client signs for this gateway (audience: ORIGIN, gate 0x2, testnet). */
function msgFor(nonce: string, consumeDigest?: string): Uint8Array {
  return personalMessage({ origin: ORIGIN, gateId: GATE, network: 'testnet', nonce, consumeDigest })
}

// ── helpers to build real signed proof tokens (mirrors verify.rs test helpers) ──────────────
function tokenB64(obj: Record<string, unknown>): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(obj)))
}

function ed25519Token(seed: number, nonce: string, consumeDigest?: string, signedMessage?: Uint8Array) {
  const priv = new Uint8Array(32).fill(seed)
  const pub = ed25519.getPublicKey(priv)
  const address = deriveAddress(FLAG_ED25519, pub)
  const sig = ed25519.sign(signingDigest(signedMessage ?? msgFor(nonce, consumeDigest)), priv)
  const signature = bytesToBase64(concatBytes(Uint8Array.of(FLAG_ED25519), sig, pub))
  const obj: Record<string, unknown> = { address, nonce, signature }
  if (consumeDigest) obj.consumeDigest = consumeDigest
  return { token: tokenB64(obj), address, signature }
}

// ── FakeBackend + MockChain (mirror the Rust in-memory store + MockChain) ────────────────────
class FakeBackend implements NonceBackend {
  private nonces = new Map<string, { expiry: number; used: boolean }>()
  constructor(private ttlSecs = 300) {}
  issueSpecific(nonce: string) {
    this.nonces.set(nonce, { expiry: Date.now() + this.ttlSecs * 1000, used: false })
  }
  async issue(_region: string, ttl: number) {
    const nonce = 'g.' + Math.random().toString(16).slice(2)
    this.nonces.set(nonce, { expiry: Date.now() + ttl * 1000, used: false })
    return { nonce, expiresAt: Date.now() + ttl * 1000 }
  }
  async takeIfValid(nonce: string) {
    const e = this.nonces.get(nonce)
    if (e && !e.used && e.expiry > Date.now()) {
      e.used = true
      return true
    }
    return false
  }
  async rateCheck() {
    return true
  }
}

class MockChain implements ChainQuery {
  constructor(
    private owns: boolean,
    private consumed: boolean,
    private blocked: boolean = false,
  ) {}
  async ownsNft() {
    return this.owns
  }
  /** The event type the verifier asked for (asserted by the exact-type test). */
  lastConsumedEventType: string | undefined
  lastMaxAgeSecs: number | undefined
  consumeCalls = 0
  async consumeTxValid(_digest: string, _address: string, consumedEventType: string, _gate: string | undefined, maxAgeSecs: number) {
    this.consumeCalls++
    this.lastConsumedEventType = consumedEventType
    this.lastMaxAgeSecs = maxAgeSecs
    return this.consumed
  }
  async gateAccessBlocked() {
    return this.blocked
  }
}

function cfg(singleUse: boolean): Config {
  return {
    upstreamUrl: 'http://upstream',
    suiRpcUrl: 'http://rpc',
    gatewayOrigin: ORIGIN,
    network: 'testnet',
    nftType: '0x1::access_gate::AccessNFT',
    gateId: '0x2',
    challengeTtlSecs: 300,
    singleUse,
    publicPaths: ['/v1/tip-config'],
    challengeRateLimitPerMin: 30,
    rateLimitPerMin: 30,
    publicRateLimitPerMin: 120,
    publicCacheTtlSecs: 60,
    maxBodyBytes: 262144,
    upstreamTimeoutMs: 600_000,
    rpcTimeoutMs: 15_000,
    gatedPreauthRateLimitPerMin: 120,
    consumeMaxAgeSecs: 432000,
    ownershipCacheTtlMs: 0,
    redemptionLeaseTtlSecs: 900,
    redemptionRetentionSecs: 2592000,
    nonceBackend: 'durable-object',
    nonceShard: 'global',
    nonceMaxEntries: 10000,
    quotaGuardEnabled: false,
    upstreamAuthHeaders: [],
    allowedOrigins: ['https://example.com'],
  }
}

describe('signature verification (all schemes)', () => {
  it('ed25519 verifies and recovers the address', () => {
    const { address, signature } = ed25519Token(7, 'nonce-1')
    const msg = msgFor('nonce-1')
    expect(verifyPersonalMessageSignature(address, msg, signature)).toBe(true)
    expect(verifyPersonalMessageSignature('0xdead', msg, signature)).toBe(false) // wrong addr
    const other = msgFor('nonce-2')
    expect(verifyPersonalMessageSignature(address, other, signature)).toBe(false) // tampered
  })

  it('secp256k1 verifies and recovers the address', () => {
    const priv = new Uint8Array(32).fill(9)
    const pub = secp256k1.getPublicKey(priv, true) // 33-byte compressed
    const address = deriveAddress(FLAG_SECP256K1, pub)
    const msg = msgFor('k1-nonce')
    // noble v2: sign() returns compact Uint8Array directly (no .toCompactRawBytes())
    const sig = secp256k1.sign(signingDigest(msg), priv, { lowS: true })
    const signature = bytesToBase64(concatBytes(Uint8Array.of(FLAG_SECP256K1), sig, pub))
    expect(verifyPersonalMessageSignature(address, msg, signature)).toBe(true)
    expect(verifyPersonalMessageSignature('0xdead', msg, signature)).toBe(false)
  })

  it('secp256r1 verifies and recovers the address', () => {
    const priv = new Uint8Array(32).fill(11)
    const pub = p256.getPublicKey(priv, true)
    const address = deriveAddress(FLAG_SECP256R1, pub)
    const msg = msgFor('r1-nonce')
    // noble v2: sign() returns compact Uint8Array directly (no .toCompactRawBytes())
    const sig = p256.sign(signingDigest(msg), priv, { lowS: true })
    const signature = bytesToBase64(concatBytes(Uint8Array.of(FLAG_SECP256R1), sig, pub))
    expect(verifyPersonalMessageSignature(address, msg, signature)).toBe(true)
    expect(verifyPersonalMessageSignature('0xdead', msg, signature)).toBe(false)
  })

  it('multisig and zkLogin flags fail closed', () => {
    const msg = msgFor('n')
    const ms = bytesToBase64(concatBytes(Uint8Array.of(FLAG_MULTISIG), new Uint8Array(96)))
    const zk = bytesToBase64(concatBytes(Uint8Array.of(FLAG_ZKLOGIN), new Uint8Array(96)))
    expect(verifyPersonalMessageSignature('0x1', msg, ms)).toBe(false)
    expect(verifyPersonalMessageSignature('0x1', msg, zk)).toBe(false)
  })
})

describe('verifyAccessRequest decision', () => {
  it('allows an owner with a valid proof', async () => {
    const store = new FakeBackend()
    store.issueSpecific('real-nonce')
    const built = ed25519Token(7, 'real-nonce')
    const res = await verifyAccessRequest(cfg(false), store, built.token, new MockChain(true, false))
    expect(res).toEqual({ ok: true, address: built.address })
  })

  it('denies a non-owner', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n2')
    const built = ed25519Token(7, 'n2')
    const res = await verifyAccessRequest(cfg(false), store, built.token, new MockChain(false, false))
    expect(res).toEqual({ ok: false, denied: 'NotOwner' })
  })

  it('denies a replayed nonce', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n3')
    const built = ed25519Token(7, 'n3')
    const first = await verifyAccessRequest(cfg(false), store, built.token, new MockChain(true, false))
    expect(first.ok).toBe(true)
    const again = await verifyAccessRequest(cfg(false), store, built.token, new MockChain(true, false))
    expect(again).toEqual({ ok: false, denied: 'NonceInvalid' })
  })

  it('denies a bad signature (nonce claim mismatched from the signed nonce)', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n4')
    const built = ed25519Token(7, 'OTHER') // signature is over OTHER
    const tampered = tokenB64({ address: built.address, nonce: 'n4', signature: built.signature })
    const res = await verifyAccessRequest(cfg(false), store, tampered, new MockChain(true, false))
    expect(res).toEqual({ ok: false, denied: 'BadSignature' })
  })

  it('denies malformed proof', async () => {
    const store = new FakeBackend()
    const res = await verifyAccessRequest(cfg(false), store, '!!!not-base64!!!', new MockChain(true, true))
    expect(res).toEqual({ ok: false, denied: 'BadProof' })
  })

  it('single-use requires a valid consume and returns the redemptionKey', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n5')
    const b5 = ed25519Token(7, 'n5', DIGEST)
    const denied = await verifyAccessRequest(cfg(true), store, b5.token, new MockChain(true, false))
    expect(denied).toEqual({ ok: false, denied: 'ConsumeMissing' })
    // The consume age bound is the configured one.

    store.issueSpecific('n6')
    const b6 = ed25519Token(7, 'n6', DIGEST)
    const chain = new MockChain(false, true)
    const ok = await verifyAccessRequest(cfg(true), store, b6.token, chain)
    // The digest is returned so the dispatcher can lease/commit it (single-use redemption).
    expect(ok).toEqual({ ok: true, address: b6.address, redemptionKey: DIGEST })
    // The chain is asked for the configured package's exact event type, never a suffix.
    expect(chain.lastMaxAgeSecs).toBe(432000)
    expect(chain.lastConsumedEventType).toBe(
      '0x0000000000000000000000000000000000000000000000000000000000000001::access_gate::AccessConsumedEvent',
    )
  })

  it('single-use denies a missing consumeDigest', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n7')
    const b7 = ed25519Token(7, 'n7') // no consumeDigest
    const res = await verifyAccessRequest(cfg(true), store, b7.token, new MockChain(true, true))
    expect(res).toEqual({ ok: false, denied: 'ConsumeMissing' })
  })

  it('denies an owner while the gate is paused with pause_blocks_access', async () => {
    const store = new FakeBackend()
    store.issueSpecific('p1')
    const b = ed25519Token(7, 'p1')
    const res = await verifyAccessRequest(cfg(false), store, b.token, new MockChain(true, false, true))
    expect(res).toEqual({ ok: false, denied: 'GatePaused' })
  })

  it('single-use: a paused gate denies before the consume is redeemed', async () => {
    const store = new FakeBackend()
    store.issueSpecific('p2')
    const b = ed25519Token(7, 'p2', DIGEST)
    const res = await verifyAccessRequest(cfg(true), store, b.token, new MockChain(true, true, true))
    // No redemptionKey is returned, so the dispatcher never leases the consume: it stays redeemable.
    expect(res).toEqual({ ok: false, denied: 'GatePaused' })
  })

  it('treats a failed gate read as a chain error (fail closed)', async () => {
    const store = new FakeBackend()
    store.issueSpecific('p3')
    const b = ed25519Token(7, 'p3')
    const chain = new MockChain(true, false)
    chain.gateAccessBlocked = async () => {
      throw new Error('rpc down')
    }
    const res = await verifyAccessRequest(cfg(false), store, b.token, chain)
    expect(res).toEqual({ ok: false, denied: 'ChainError' })
  })
})

describe('audience binding (protocol v2)', () => {
  async function decide(configure: (c: Config) => Config, tokenOf: () => string, singleUse = false) {
    const store = new FakeBackend()
    store.issueSpecific('aud-nonce')
    const chain = new MockChain(true, true)
    const res = await verifyAccessRequest(configure(cfg(singleUse)), store, tokenOf(), chain)
    return { res, chain }
  }

  it('accepts a proof signed for exactly this gateway, gate and network', async () => {
    const { res } = await decide((c) => c, () => ed25519Token(7, 'aud-nonce').token)
    expect(res.ok).toBe(true)
  })

  it.each([
    ['another gateway origin', (c: Config) => ({ ...c, gatewayOrigin: 'https://other.example.com' })],
    ['another gate', (c: Config) => ({ ...c, gateId: '0x3' })],
    ['another network', (c: Config) => ({ ...c, network: 'mainnet' as const })],
  ])('refuses a proof made for %s', async (_name, configure) => {
    const { res } = await decide(configure, () => ed25519Token(7, 'aud-nonce').token)
    expect(res).toEqual({ ok: false, denied: 'BadSignature' })
  })

  it('refuses the v1 message (no audience) outright', async () => {
    const v1 = new TextEncoder().encode('nft-gate:access:aud-nonce')
    const { res } = await decide((c) => c, () => ed25519Token(7, 'aud-nonce', undefined, v1).token)
    expect(res).toEqual({ ok: false, denied: 'BadSignature' })
  })

  it('an ownership gateway refuses a proof signed for single-use (consume line in the message)', async () => {
    const { res } = await decide((c) => c, () => ed25519Token(7, 'aud-nonce', DIGEST).token)
    expect(res).toEqual({ ok: false, denied: 'BadSignature' })
  })

  it('a single-use gateway refuses a swapped consume digest (it is signed)', async () => {
    const signedForOther = ed25519Token(7, 'aud-nonce', DIGEST)
    const swapped = JSON.parse(atob(signedForOther.token)) as Record<string, unknown>
    swapped.consumeDigest = '9' + DIGEST.slice(1)
    const { res, chain } = await decide((c) => c, () => tokenB64(swapped), true)
    expect(res).toEqual({ ok: false, denied: 'BadSignature' })
    expect(chain.consumeCalls).toBe(0)
  })

  it('a malformed digest never reaches the chain, and a missing one is not even verified', async () => {
    const { res, chain } = await decide((c) => c, () => tokenB64({ address: '0x1', nonce: 'aud-nonce', signature: 'AAAA', consumeDigest: 'DIGEST-1' }), true)
    expect(res).toEqual({ ok: false, denied: 'BadProof' })
    expect(chain.consumeCalls).toBe(0)
  })
})
