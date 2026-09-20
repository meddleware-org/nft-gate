import { describe, it, expect } from 'vitest'
import vectors from '../../conformance/vectors.json'
import { verifyPersonalMessageSignature, normalizeAddress } from '../src/verify.js'
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
})
