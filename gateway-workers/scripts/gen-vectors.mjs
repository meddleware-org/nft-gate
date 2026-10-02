// One-off generator for the shared conformance/vectors.json at the repo root.
// Run from a directory that resolves @mysten/sui (e.g. the nft-gate-client repo).
// Produces REAL Sui personal-message signatures for ed25519 / secp256k1 / secp256r1
// over a fixed nonce, so both the Workers and the Rust gateway verify byte-identical
// golden vectors.
//
//   node gateway-workers/scripts/gen-vectors.mjs > conformance/vectors.json
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1'
import { Secp256r1Keypair } from '@mysten/sui/keypairs/secp256r1'
import { blake2b } from '@noble/hashes/blake2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'

const NONCE = 'GOLDEN-NONCE-123'
const message = new TextEncoder().encode(`nft-gate:access:${NONCE}`)

function b64(bytes) {
  return Buffer.from(bytes).toString('base64')
}
/** base64 of the UTF-8 JSON — the client's encoding, which also covers non-ASCII fields. */
function utf8Token(obj) {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64')
}

function proofToken(address, nonce, signature) {
  return Buffer.from(JSON.stringify({ address, nonce, signature })).toString('base64')
}

async function vec(scheme, kp) {
  const address = kp.toSuiAddress()
  const { signature } = await kp.signPersonalMessage(message)
  return {
    scheme,
    address,
    nonce: NONCE,
    signature,
    proofToken: proofToken(address, NONCE, signature),
    expect: true,
  }
}

// ── negative + ZIP-215 vectors ────────────────────────────────────────────────────────────────
// Derived from the golden signatures above. Every verifier must REJECT the `negativeSignatures`
// and ACCEPT the `zip215` vector (Sui validates ed25519 under ZIP-215).

function fromB64(s) {
  return new Uint8Array(Buffer.from(s, 'base64'))
}
function suiAddress(flag, pk) {
  return '0x' + Buffer.from(blake2b(Uint8Array.from([flag, ...pk]), { dkLen: 32 })).toString('hex')
}
function bigToBytes32(n) {
  return Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex'))
}
function bytesToBig(b) {
  return BigInt('0x' + Buffer.from(b).toString('hex'))
}
/** Replace compact `s` with `n - s` (the high-S twin of a valid low-S ECDSA signature). */
function highS(sigB64, order) {
  const raw = fromB64(sigB64)
  const s = bytesToBig(raw.subarray(33, 65))
  raw.set(bigToBytes32(order - s), 33)
  return b64(raw)
}
/** ed25519 `s` is little-endian: add the group order L (non-canonical scalar, same value mod L). */
function ed25519NonCanonicalS(sigB64) {
  const raw = fromB64(sigB64)
  const L = 2n ** 252n + 27742317777372353535851937790883648493n
  const sLE = raw.subarray(33, 65)
  const s = bytesToBig(Uint8Array.from(sLE).reverse()) + L
  raw.set(bigToBytes32(s).reverse(), 33)
  return b64(raw)
}
function withFlag(sigB64, flag) {
  const raw = fromB64(sigB64)
  raw[0] = flag
  return b64(raw)
}
/** Sign the nonce message under the TransactionData intent [0,0,0] instead of PersonalMessage. */
async function wrongIntent(kp) {
  const bcsMsg = Uint8Array.from([message.length, ...message]) // uleb128 length (< 128) + bytes
  const digest = blake2b(Uint8Array.from([0, 0, 0, ...bcsMsg]), { dkLen: 32 })
  const sig = await kp.sign(digest)
  return b64(Uint8Array.from([0x00, ...sig, ...kp.getPublicKey().toRawBytes()]))
}

const edKp = Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(7))
const k1Kp = Secp256k1Keypair.fromSecretKey(new Uint8Array(32).fill(9))
const r1Kp = Secp256r1Keypair.fromSecretKey(new Uint8Array(32).fill(11))
const edSig = (await edKp.signPersonalMessage(message)).signature
const k1Sig = (await k1Kp.signPersonalMessage(message)).signature
const r1Sig = (await r1Kp.signPersonalMessage(message)).signature

const negative = (name, address, signature) => ({ case: name, address, nonce: NONCE, signature, expect: false })
const negativeSignatures = [
  negative('secp256k1 high-S', k1Kp.toSuiAddress(), highS(k1Sig, secp256k1.Point.CURVE().n)),
  negative('secp256r1 high-S', r1Kp.toSuiAddress(), highS(r1Sig, p256.Point.CURVE().n)),
  negative('ed25519 non-canonical s (s + L)', edKp.toSuiAddress(), ed25519NonCanonicalS(edSig)),
  negative('ed25519 wrong intent (TransactionData)', edKp.toSuiAddress(), await wrongIntent(edKp)),
  negative('ed25519 truncated', edKp.toSuiAddress(), b64(fromB64(edSig).subarray(0, 96))),
  negative('flag 0x03 multisig (fails closed)', edKp.toSuiAddress(), withFlag(edSig, 0x03)),
  negative('flag 0x05 zkLogin (fails closed)', edKp.toSuiAddress(), withFlag(edSig, 0x05)),
  negative('flag 0x06 passkey (fails closed)', edKp.toSuiAddress(), withFlag(edSig, 0x06)),
]

// ZIP-215 acceptance: the small-order identity point as public key, R = identity, s = 0. The
// cofactored equation [8]sB = [8]R + [8]kA holds for ANY message, so ZIP-215 accepts it while a
// strict RFC 8032 verifier rejects it. Sui accepts it, so both gateways must too.
const identity = new Uint8Array(32)
identity[0] = 1
const zipSig = Uint8Array.from([0x00, ...identity, ...new Uint8Array(32), ...identity])
const zip215 = {
  description:
    'ed25519 small-order public key (identity), R = identity, s = 0: valid under ZIP-215 (the rule Sui validators apply) for any message, invalid under strict RFC 8032.',
  address: suiAddress(0x00, identity),
  nonce: NONCE,
  signature: b64(zipSig),
  expect: true,
}

const out = {
  description:
    'Golden wire-format vectors shared by the Rust and Workers gateways. `signatures` are real Sui personal-message signatures over `nft-gate:access:<nonce>` that a verifier must accept for `address`; `negativeSignatures` must be rejected; `zip215` pins ed25519 verification to ZIP-215 (Sui\'s rule). Regenerate with: node gateway-workers/scripts/gen-vectors.mjs > conformance/vectors.json',
  personalMessage: {
    nonce: NONCE,
    messageUtf8: `nft-gate:access:${NONCE}`,
    messageBytesBase64: b64(message),
  },
  proofDecode: {
    token: proofToken('0x1', 'n', 's'),
    expect: { address: '0x1', nonce: 'n', signature: 's' },
  },
  proofDecodeRejects: {
    description:
      'Tokens every decoder must reject before verification: longer than 4096 characters (checked before base64/JSON parsing), or with a non-ASCII address, nonce or signature (the gateways issue ASCII-only nonces).',
    cases: [
      { name: 'oversized', token: 'A'.repeat(4097) },
      { name: 'non-ASCII nonce', token: utf8Token({ address: '0x1', nonce: 'n\u00f6nce', signature: 's' }) },
      { name: 'non-ASCII address', token: utf8Token({ address: '0x\u00e91', nonce: 'n', signature: 's' }) },
    ],
  },
  addressNormalization: {
    description:
      'Both gateways canonicalise the proof address (normalizeAddress / normalize_address) before comparing to on-chain owners: strip 0x, lower-case, zero-pad to 64 hex, re-prefix 0x. Static cases (no keypair).',
    cases: [
      { input: '0x1', expected: '0x0000000000000000000000000000000000000000000000000000000000000001' },
      { input: '0xABCDEF', expected: '0x0000000000000000000000000000000000000000000000000000000000abcdef' },
      {
        input: '0x0000000000000000000000000000000000000000000000000000000000000123',
        expected: '0x0000000000000000000000000000000000000000000000000000000000000123',
      },
    ],
  },
  signatures: [
    await vec('ed25519', edKp),
    await vec('secp256k1', k1Kp),
    await vec('secp256r1', r1Kp),
  ],
  negativeSignatures,
  zip215,
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n')
