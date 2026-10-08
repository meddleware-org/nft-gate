import { describe, it, expect } from 'vitest'
import vectors from '../../conformance/vectors.json'
import published from '@meddleware/nft-gate-client/vectors.json'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { verifyPersonalMessageSignature, normalizeAddress, signingDigest } from '../src/verify.js'
import { personalMessage, decodeAccessProof } from '../src/wire.js'
import { base64ToBytes } from '../src/crypto.js'

// The SAME fixtures the Rust gateway verifies (gateway-rust `conformance_shared_vectors`), generated
// and published by @meddleware/nft-gate-client. Drift on either side fails a test.
type Ctx = Parameters<typeof personalMessage>[0]
const msg = (c: unknown) => personalMessage(c as Ctx)

describe('conformance vectors (shared with the Rust gateway)', () => {
  it('the repository copy is the published package file', () => {
    expect(published).toEqual(vectors)
  })

  for (const c of vectors.personalMessage.cases) {
    it(`personal message: ${c.name}`, () => {
      const bytes = msg(c.context)
      expect(new TextDecoder().decode(bytes)).toBe(c.messageUtf8)
      expect(Array.from(bytes)).toEqual(Array.from(base64ToBytes(c.messageBytesBase64)))
    })
  }

  for (const c of vectors.personalMessageRejects) {
    it(`refuses to build a message: ${c.name}`, () => {
      expect(() => msg(c.context)).toThrow()
    })
  }

  it('proof token decode matches', () => {
    expect(decodeAccessProof(vectors.proofDecode.token)).toEqual(vectors.proofDecode.expect)
  })

  for (const c of vectors.proofDecodeRejects.cases) {
    it(`rejects a proof token: ${c.name}`, () => {
      expect(() => decodeAccessProof(c.token)).toThrow()
    })
  }

  for (const c of vectors.addressNormalization.cases) {
    it(`normalizes address ${c.input} to canonical form`, () => {
      expect(normalizeAddress(c.input)).toBe(c.expected)
    })
  }

  for (const sig of vectors.signatures) {
    it(`verifies the ${sig.scheme} golden signature and recovers the address`, () => {
      const m = msg(sig.context)
      expect(verifyPersonalMessageSignature(sig.address, m, sig.signature)).toBe(true)
      expect(verifyPersonalMessageSignature('0xdead', m, sig.signature)).toBe(false) // wrong address
      expect(verifyPersonalMessageSignature(sig.address, msg({ ...sig.context, nonce: 'GOLDEN-NONCE-124' }), sig.signature)).toBe(false)
      expect(decodeAccessProof(sig.proofToken).address).toBe(sig.address)
    })
  }

  for (const v of vectors.audienceMismatch) {
    it(`refuses a valid signature presented for a different audience: ${v.case}`, () => {
      expect(verifyPersonalMessageSignature(v.address, msg(v.context), v.signature)).toBe(false)
    })
  }

  for (const neg of vectors.negativeSignatures) {
    it(`rejects: ${neg.case}`, () => {
      expect(verifyPersonalMessageSignature(neg.address, msg(neg.context), neg.signature)).toBe(false)
    })
  }

  it('the high-S vectors fail only because of the low-S rule (otherwise valid ECDSA)', () => {
    const digest = signingDigest(msg(vectors.signatures[0]!.context))
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
    expect(verifyPersonalMessageSignature(z.address, msg(z.context), z.signature)).toBe(true)
    // …for any message, which is exactly why it pins the verification rule.
    expect(verifyPersonalMessageSignature(z.address, msg({ ...z.context, nonce: 'other' }), z.signature)).toBe(true)
  })
})
