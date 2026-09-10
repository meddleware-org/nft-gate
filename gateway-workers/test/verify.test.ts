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
import { personalMessageForNonce } from '../src/wire.js'
import { bytesToBase64, concatBytes } from '../src/crypto.js'
import type { Config } from '../src/config.js'
import type { NonceBackend } from '../src/state/types.js'

// ── helpers to build real signed proof tokens (mirrors verify.rs test helpers) ──────────────
function tokenB64(obj: Record<string, unknown>): string {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(obj)))
}

function ed25519Token(seed: number, nonce: string, consumeDigest?: string) {
  const priv = new Uint8Array(32).fill(seed)
  const pub = ed25519.getPublicKey(priv)
  const address = deriveAddress(FLAG_ED25519, pub)
  const sig = ed25519.sign(signingDigest(personalMessageForNonce(nonce)), priv)
  const signature = bytesToBase64(concatBytes(Uint8Array.of(FLAG_ED25519), sig, pub))
  const obj: Record<string, unknown> = { address, nonce, signature }
  if (consumeDigest) obj.consumeDigest = consumeDigest
  return { token: tokenB64(obj), address, signature }
}

// ── FakeBackend + MockChain (mirror the Rust in-memory store + MockChain) ────────────────────
class FakeBackend implements NonceBackend {
  private nonces = new Map<string, { expiry: number; used: boolean }>()
  private redemptions = new Map<string, { state: 'leased' | 'committed'; expiry: number }>()
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
  async tryLeaseRedemption(key: string, leaseTtlSecs: number): Promise<'ok' | 'leased' | 'redeemed'> {
    const r = this.redemptions.get(key)
    const now = Date.now()
    if (r) {
      if (r.state === 'committed') return 'redeemed'
      if (r.state === 'leased' && r.expiry > now) return 'leased'
    }
    this.redemptions.set(key, { state: 'leased', expiry: now + leaseTtlSecs * 1000 })
    return 'ok'
  }
  async commitRedemption(key: string, retentionSecs: number) {
    this.redemptions.set(key, { state: 'committed', expiry: Date.now() + retentionSecs * 1000 })
  }
  async releaseRedemption(key: string) {
    if (this.redemptions.get(key)?.state === 'leased') this.redemptions.delete(key)
  }
}

class MockChain implements ChainQuery {
  constructor(
    private owns: boolean,
    private consumed: boolean,
  ) {}
  async ownsNft() {
    return this.owns
  }
  async consumeTxValid() {
    return this.consumed
  }
}

function cfg(singleUse: boolean): Config {
  return {
    upstreamUrl: 'http://upstream',
    suiRpcUrl: 'http://rpc',
    nftType: '0xpkg::access_gate::AccessNFT',
    challengeTtlSecs: 300,
    singleUse,
    publicPaths: ['/v1/tip-config'],
    rateLimitPerMin: 30,
    maxBodyBytes: 262144,
    ownershipCacheTtlMs: 0,
    redemptionLeaseTtlSecs: 120,
    redemptionRetentionSecs: 2592000,
    nonceBackend: 'durable-object',
    nonceShard: 'global',
    nonceMaxEntries: 10000,
    quotaGuardEnabled: false,
    upstreamAuthHeaders: [],
  }
}

describe('signature verification (all schemes)', () => {
  it('ed25519 verifies and recovers the address', () => {
    const { address, signature } = ed25519Token(7, 'nonce-1')
    const msg = personalMessageForNonce('nonce-1')
    expect(verifyPersonalMessageSignature(address, msg, signature)).toBe(true)
    expect(verifyPersonalMessageSignature('0xdead', msg, signature)).toBe(false) // wrong addr
    const other = personalMessageForNonce('nonce-2')
    expect(verifyPersonalMessageSignature(address, other, signature)).toBe(false) // tampered
  })

  it('secp256k1 verifies and recovers the address', () => {
    const priv = new Uint8Array(32).fill(9)
    const pub = secp256k1.getPublicKey(priv, true) // 33-byte compressed
    const address = deriveAddress(FLAG_SECP256K1, pub)
    const msg = personalMessageForNonce('k1-nonce')
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
    const msg = personalMessageForNonce('r1-nonce')
    // noble v2: sign() returns compact Uint8Array directly (no .toCompactRawBytes())
    const sig = p256.sign(signingDigest(msg), priv, { lowS: true })
    const signature = bytesToBase64(concatBytes(Uint8Array.of(FLAG_SECP256R1), sig, pub))
    expect(verifyPersonalMessageSignature(address, msg, signature)).toBe(true)
    expect(verifyPersonalMessageSignature('0xdead', msg, signature)).toBe(false)
  })

  it('multisig and zkLogin flags fail closed', () => {
    const msg = personalMessageForNonce('n')
    const ms = bytesToBase64(concatBytes(Uint8Array.of(FLAG_MULTISIG), new Uint8Array(96)))
    const zk = bytesToBase64(concatBytes(Uint8Array.of(FLAG_ZKLOGIN), new Uint8Array(96)))
    expect(verifyPersonalMessageSignature('0x1', msg, ms)).toBe(false)
    expect(verifyPersonalMessageSignature('0x1', msg, zk)).toBe(false)
  })

  it('golden personal-message bytes are stable', () => {
    expect(new TextDecoder().decode(personalMessageForNonce('GOLDEN-NONCE-123'))).toBe(
      'nft-gate:access:GOLDEN-NONCE-123',
    )
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
    const b5 = ed25519Token(7, 'n5', '0xdigest')
    const denied = await verifyAccessRequest(cfg(true), store, b5.token, new MockChain(true, false))
    expect(denied).toEqual({ ok: false, denied: 'ConsumeMissing' })

    store.issueSpecific('n6')
    const b6 = ed25519Token(7, 'n6', '0xdigest')
    const ok = await verifyAccessRequest(cfg(true), store, b6.token, new MockChain(false, true))
    // The digest is returned so the dispatcher can lease/commit it (single-use redemption).
    expect(ok).toEqual({ ok: true, address: b6.address, redemptionKey: '0xdigest' })
  })

  it('single-use denies a missing consumeDigest', async () => {
    const store = new FakeBackend()
    store.issueSpecific('n7')
    const b7 = ed25519Token(7, 'n7') // no consumeDigest
    const res = await verifyAccessRequest(cfg(true), store, b7.token, new MockChain(true, true))
    expect(res).toEqual({ ok: false, denied: 'ConsumeMissing' })
  })
})
