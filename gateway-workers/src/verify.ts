/**
 * Access verification — the security core. Direct Sui personal-message signature checking
 * plus the allow/deny decision. A 1:1 port of the Rust gateway's `verify.rs`; the on-chain
 * lookups are abstracted behind {@link ChainQuery} so the decision is unit-testable offline.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import type { Config } from './config.js'
import type { NonceBackend } from './state/types.js'
import { blake2b256, base64ToBytes, bytesToHex, concatBytes, uleb128 } from './crypto.js'
import { personalMessageForNonce, decodeAccessProof } from './wire.js'

// Sui signature-scheme flag bytes (first byte of a serialized signature).
const FLAG_ED25519 = 0x00
const FLAG_SECP256K1 = 0x01
const FLAG_SECP256R1 = 0x02
const FLAG_MULTISIG = 0x03
const FLAG_ZKLOGIN = 0x05

/** blake2b256( intent(PersonalMessage,V0,Sui) || bcs(Vec<u8> message) ) — what a Sui wallet signs. */
export function signingDigest(message: Uint8Array): Uint8Array {
  const intent = Uint8Array.from([3, 0, 0]) // IntentScope::PersonalMessage, V0, AppId::Sui
  return blake2b256(concatBytes(intent, uleb128(message.length), message))
}

/** Sui address for a scheme: `0x` + hex(blake2b256(flag || pubkey)). */
export function deriveAddress(flag: number, pk: Uint8Array): string {
  return '0x' + bytesToHex(blake2b256(concatBytes(Uint8Array.from([flag]), pk)))
}

/** Normalise a Sui address to lowercase, `0x`-prefixed, zero-padded to 64 hex digits. */
export function normalizeAddress(a: string): string {
  const s = a.trim().replace(/^0x/i, '').toLowerCase()
  return '0x' + s.padStart(64, '0')
}

/**
 * Verify a Sui personal-message signature recovers `address` over `message`, dispatching on
 * the scheme flag byte. Serialized layout: `flag(1) || signature || pubkey` (base64).
 *
 * Supported: ed25519 (0x00), secp256k1 (0x01), secp256r1 (0x02). multisig (0x03) and zkLogin
 * (0x05) are recognised but not yet verified (they need the official Sui verifier) and fail
 * **closed** — identical posture to the Rust gateway (audit F1).
 */
export function verifyPersonalMessageSignature(
  address: string,
  message: Uint8Array,
  signatureB64: string,
): boolean {
  let raw: Uint8Array
  try {
    raw = base64ToBytes(signatureB64)
  } catch {
    return false
  }
  if (raw.length === 0) return false
  const flag = raw[0]
  const body = raw.subarray(1)
  switch (flag) {
    case FLAG_ED25519:
      return verifyEd25519(address, message, body)
    case FLAG_SECP256K1:
      return verifyEcdsa(secp256k1, FLAG_SECP256K1, address, message, body)
    case FLAG_SECP256R1:
      return verifyEcdsa(p256, FLAG_SECP256R1, address, message, body)
    case FLAG_MULTISIG:
    case FLAG_ZKLOGIN:
      // Recognised but not yet supported by this verifier (fails closed); see gateway audit F1.
      return false
    default:
      return false
  }
}

/** ed25519 (flag 0x00): body = `sig(64) || pubkey(32)`. */
function verifyEd25519(address: string, message: Uint8Array, body: Uint8Array): boolean {
  if (body.length !== 96) return false
  const sig = body.subarray(0, 64)
  const pk = body.subarray(64, 96)
  const digest = signingDigest(message)
  let ok = false
  try {
    ok = ed25519.verify(sig, digest, pk)
  } catch {
    return false
  }
  if (!ok) return false
  return normalizeAddress(address) === deriveAddress(FLAG_ED25519, pk)
}

/**
 * secp256k1 (0x01) / secp256r1 (0x02): body = `sig(64, compact r||s) || pubkey(33, SEC1-
 * compressed)`. Sui signs `SHA256(blake2b256(intent||msg))` with ECDSA; noble's `verify` applies
 * the SHA256 step internally, so we pass the blake2b digest and let the curve do the rest.
 * `lowS: true` matches Sui's low-S normalisation.
 */
function verifyEcdsa(
  curve: typeof secp256k1 | typeof p256,
  flag: number,
  address: string,
  message: Uint8Array,
  body: Uint8Array,
): boolean {
  if (body.length !== 97) return false
  const sig = body.subarray(0, 64)
  const pk = body.subarray(64, 97)
  const msgHash = signingDigest(message)
  let ok = false
  try {
    ok = curve.verify(sig, msgHash, pk, { lowS: true })
  } catch {
    return false
  }
  if (!ok) return false
  return normalizeAddress(address) === deriveAddress(flag, pk)
}

/** On-chain lookups needed to authorise a request. Implemented by {@link ../chain.SuiGrpc}. */
export interface ChainQuery {
  ownsNft(address: string, nftType: string, gateId?: string): Promise<boolean>
  /**
   * True if `consumeDigest` names a successful `access_gate::consume` transaction that emitted an
   * `AccessConsumedEvent` for `address` (the sender) on `gateId`. Not bound to the challenge nonce
   * — single-use is enforced by the redemption store keying on the digest.
   */
  consumeTxValid(consumeDigest: string, address: string, gateId?: string): Promise<boolean>
}

/** The reason a request was rejected by {@link verifyAccessRequest}. Mirror of Rust `Denied`. */
export type Denied =
  | 'BadProof'
  | 'BadSignature'
  | 'NonceInvalid'
  | 'NotOwner'
  | 'ConsumeMissing'
  | 'RedeemConflict'
  | 'ChainError'

/** A short, client-visible description of why access was denied. */
export function deniedReason(d: Denied): string {
  switch (d) {
    case 'BadProof':
      return 'malformed access proof'
    case 'BadSignature':
      return 'signature does not recover address'
    case 'NonceInvalid':
      return 'challenge nonce invalid, expired, or already used'
    case 'NotOwner':
      return 'address does not hold the required access NFT'
    case 'ConsumeMissing':
      return 'no matching single-use consume for this address'
    case 'RedeemConflict':
      return 'this consume is already redeemed or an upload for it is in progress'
    case 'ChainError':
      return 'on-chain verification failed'
  }
}

/**
 * Result of {@link verifyAccessRequest}: the verified address on success, or a {@link Denied}
 * reason. In single-use mode a successful result also carries `redemptionKey` (the `consumeDigest`)
 * that the dispatcher leases/commits so the use is only spent on a successful upload.
 */
export type VerifyResult =
  | { ok: true; address: string; redemptionKey?: string }
  | { ok: false; denied: Denied }

/**
 * Authorise a request from its base64 proof token. The nonce is consumed (single-use at the
 * gateway) as part of a successful signature check, so a replay presents an already-used
 * nonce and is rejected. Mirror of Rust `verify_access_request`.
 */
export async function verifyAccessRequest(
  cfg: Config,
  store: NonceBackend,
  token: string,
  chain: ChainQuery,
): Promise<VerifyResult> {
  let proof
  try {
    proof = decodeAccessProof(token)
  } catch {
    return { ok: false, denied: 'BadProof' }
  }

  const message = personalMessageForNonce(proof.nonce)
  if (!verifyPersonalMessageSignature(proof.address, message, proof.signature)) {
    return { ok: false, denied: 'BadSignature' }
  }

  // Consume the nonce exactly once (fresh, unexpired, unused) — before the chain call.
  if (!(await store.takeIfValid(proof.nonce))) {
    return { ok: false, denied: 'NonceInvalid' }
  }

  if (cfg.singleUse) {
    if (proof.consumeDigest === undefined) {
      return { ok: false, denied: 'ConsumeMissing' }
    }
    let ok: boolean
    try {
      ok = await chain.consumeTxValid(proof.consumeDigest, proof.address, cfg.gateId)
    } catch {
      return { ok: false, denied: 'ChainError' }
    }
    if (!ok) return { ok: false, denied: 'ConsumeMissing' }
    // The consume is valid on-chain; the dispatcher leases/commits this digest so the use is
    // spent only on a successful upload (and a duplicate can't double-spend it).
    return { ok: true, address: proof.address, redemptionKey: proof.consumeDigest }
  }

  let ok: boolean
  try {
    ok = await chain.ownsNft(proof.address, cfg.nftType, cfg.gateId)
  } catch {
    return { ok: false, denied: 'ChainError' }
  }
  if (!ok) return { ok: false, denied: 'NotOwner' }

  return { ok: true, address: proof.address }
}

export { FLAG_ED25519, FLAG_SECP256K1, FLAG_SECP256R1, FLAG_MULTISIG, FLAG_ZKLOGIN }
