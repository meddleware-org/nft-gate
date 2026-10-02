import { describe, it, expect } from 'vitest'
import vectors from '../../conformance/vectors.json'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { verifyPersonalMessageSignature, normalizeAddress, signingDigest } from '../src/verify.js'
import { personalMessageForNonce, decodeAccessProof } from '../src/wire.js'
import { base64ToBytes } from '../src/crypto.js'

// The SAME golden fixtures the Rust gateway verifies (gateway/rust verify.rs
// `conformance_shared_vectors`). Drift on either side fails a test.
describe('conformance vectors (shared with the Rust gateway)', () => {
  it('personal-message derivation matches', () => {
    const pm = vectors.personalMessage
    const bytes = personalMessageForNonce(pm.nonce)
    expect(new TextDecoder().decode(bytes)).toBe(pm.messageUtf8)
    expect(Array.from(bytes)).toEqual(Array.from(base64ToBytes(pm.messageBytesBase64)))
  })

  it('proof token decode matches', () => {
    const p = decodeAccessProof(vectors.proofDecode.token)
    expect(p.address).toBe(vectors.proofDecode.expect.address)
    expect(p.nonce).toBe(vectors.proofDecode.expect.nonce)
    expect(p.signature).toBe(vectors.proofDecode.expect.signature)
  })

  for (const c of vectors.proofDecodeRejects.cases) {
    it(`rejects a proof token: ${c.name} (matches Rust gateway)`, () => {
      expect(() => decodeAccessProof(c.token)).toThrow()
    })
  }

  for (const c of vectors.addressNormalization.cases) {
    it(`normalizes address ${c.input} to canonical form (matches Rust gateway)`, () => {
      expect(normalizeAddress(c.input)).toBe(c.expected)
    })
  }

  for (const sig of vectors.signatures) {
    it(`verifies the ${sig.scheme} golden signature and recovers the address`, () => {
      const msg = personalMessageForNonce(sig.nonce)
      expect(verifyPersonalMessageSignature(sig.address, msg, sig.signature)).toBe(true)
      // wrong address rejected
      expect(verifyPersonalMessageSignature('0xdead', msg, sig.signature)).toBe(false)
      // tampered message rejected
      const other = personalMessageForNonce(sig.nonce + '-tampered')
      expect(verifyPersonalMessageSignature(sig.address, other, sig.signature)).toBe(false)
      // the embedded proof token decodes to the same address
      expect(decodeAccessProof(sig.proofToken).address).toBe(sig.address)
    })
  }

  for (const neg of vectors.negativeSignatures) {
    it(`rejects: ${neg.case}`, () => {
      expect(verifyPersonalMessageSignature(neg.address, personalMessageForNonce(neg.nonce), neg.signature)).toBe(false)
    })
  }

  it('the high-S vectors fail only because of the low-S rule (otherwise valid ECDSA)', () => {
    const digest = signingDigest(personalMessageForNonce(vectors.personalMessage.nonce))
    for (const [name, curve] of [
      ['secp256k1 high-S', secp256k1],
      ['secp256r1 high-S', p256],
    ] as const) {
      const raw = base64ToBytes(vectors.negativeSignatures.find((n) => n.case === name)!.signature)
      expect(curve.verify(raw.subarray(1, 65), digest, raw.subarray(65), { lowS: false })).toBe(true)
    }
  })

  it('accepts the ZIP-215 small-order vector (the rule Sui validators apply)', () => {
    const z = vectors.zip215
    expect(verifyPersonalMessageSignature(z.address, personalMessageForNonce(z.nonce), z.signature)).toBe(true)
    // …for any message, which is exactly why it pins the verification rule.
    expect(verifyPersonalMessageSignature(z.address, personalMessageForNonce('other'), z.signature)).toBe(true)
  })
})
