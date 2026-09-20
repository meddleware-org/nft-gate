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

const NONCE = 'GOLDEN-NONCE-123'
const message = new TextEncoder().encode(`nft-gate:access:${NONCE}`)

function b64(bytes) {
  return Buffer.from(bytes).toString('base64')
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

const out = {
  description:
    'Golden wire-format vectors shared by the Rust and Workers gateways. Each entry is a real Sui personal-message signature over `nft-gate:access:<nonce>`; a verifier must recover `address` and accept it. Regenerate with: node gateway-workers/scripts/gen-vectors.mjs > conformance/vectors.json',
  personalMessage: {
    nonce: NONCE,
    messageUtf8: `nft-gate:access:${NONCE}`,
    messageBytesBase64: b64(message),
  },
  proofDecode: {
    token: proofToken('0x1', 'n', 's'),
    expect: { address: '0x1', nonce: 'n', signature: 's' },
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
    await vec('ed25519', Ed25519Keypair.fromSecretKey(new Uint8Array(32).fill(7))),
    await vec('secp256k1', Secp256k1Keypair.fromSecretKey(new Uint8Array(32).fill(9))),
    await vec('secp256r1', Secp256r1Keypair.fromSecretKey(new Uint8Array(32).fill(11))),
  ],
}

process.stdout.write(JSON.stringify(out, null, 2) + '\n')
