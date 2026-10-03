/**
 * Low-level hashing + encoding helpers, mirroring the Rust gateway's `verify.rs` primitives.
 * Uses the audited `@noble/*` primitives (the same family `@mysten/sui` builds on) so the
 * Worker needs no WebCrypto async quirks and stays consistent across ed25519/secp256k1/p256.
 */

import { blake2b } from '@noble/hashes/blake2.js'
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js'

/** Compute a 32-byte Blake2b-256 digest of `data`. */
export function blake2b256(data: Uint8Array): Uint8Array {
  return blake2b(data, { dkLen: 32 })
}

/** Compute a 32-byte SHA-256 digest of `data`. */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data)
}

const HEX = '0123456789abcdef'

/** Encode `bytes` as a lowercase hex string (no `0x` prefix). */
export function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) out += HEX.charAt(b >> 4) + HEX.charAt(b & 0x0f)
  return out
}

/**
 * Decode a hex string (with or without `0x` prefix) to bytes.
 *
 * @throws {Error} if `hex` has an odd number of characters.
 */
export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith('0x') ? hex.slice(2) : hex
  if (s.length % 2 !== 0) throw new Error('odd-length hex')
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/** base64 (standard) → bytes. Uses `atob` (present in the Workers runtime). */
export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim())
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Encode `bytes` as standard base64. Uses `btoa` (present in the Workers runtime). */
export function bytesToBase64(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** LEB128 unsigned encoding of `v` (matches Rust `write_uleb128`). */
export function uleb128(v: number): Uint8Array {
  const out: number[] = []
  let n = v >>> 0
  // Support lengths beyond 32 bits defensively, though messages are tiny.
  let big = v
  do {
    let byte = big & 0x7f
    big = Math.floor(big / 128)
    if (big !== 0) byte |= 0x80
    out.push(byte)
    n = big
  } while (n !== 0)
  return Uint8Array.from(out)
}

/** Concatenate multiple `Uint8Array` values into a single contiguous array. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0
  for (const p of parts) len += p.length
  const out = new Uint8Array(len)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}
