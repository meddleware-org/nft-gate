/**
 * Production {@link ChainQuery} over the Sui **gRPC** API (`@mysten/sui/grpc` `SuiGrpcClient`).
 *
 * Public Sui fullnodes have deprecated JSON-RPC (`suix_queryEvents`, `sui_getTransactionBlock`,
 * `suix_getOwnedObjects` now return `-32601 Method not found`), so the gateway queries the chain
 * over gRPC — the same transport `@meddleware/walrus-client` and `@meddleware/nft-gate-client`
 * already use. The pure match/parse helpers are exported for unit tests; the gRPC round-trips are
 * covered by the localnet/integration loop.
 *
 * Single-use verification is now **digest-first**: the access proof already carries the on-chain
 * `access_gate::consume` transaction digest, so the gateway fetches that exact transaction and
 * verifies it succeeded and emitted a matching `AccessConsumedEvent`. This is precise (bound to the
 * challenge nonce + sender + gate) and does not need the deprecated event-by-sender query.
 */

import { SuiGrpcClient } from '@mysten/sui/grpc'
import { fetchAccessNfts } from '@meddleware/nft-gate-client'
import type { ChainQuery } from './verify.js'
import { base64ToBytes } from './crypto.js'

type Json = unknown

/**
 * A cached result of a single ownership query.
 * `owns` — whether the address held the NFT at query time.
 * `expiry` — unix-ms timestamp after which this entry must be discarded.
 */
interface CacheEntry {
  owns: boolean
  expiry: number
}

/** Number of `getTransaction` attempts (absorbs fullnode indexing lag after the client's finality wait). */
const TX_FETCH_ATTEMPTS = 4
/** Delay between `getTransaction` retries, in ms. */
const TX_FETCH_RETRY_MS = 500

/** Production {@link ChainQuery} backed by the Sui gRPC API, with an optional ownership cache. */
export class SuiGrpc implements ChainQuery {
  private readonly cache = new Map<string, CacheEntry>()
  private readonly client: SuiGrpcClient

  /**
   * @param rpcUrl - Sui gRPC endpoint base URL (e.g. `https://fullnode.testnet.sui.io:443`).
   * @param cacheTtlMs - Ownership-cache TTL in ms. 0 disables the cache (live check every request).
   * @param authHeader - Optional header injected on every gRPC call (e.g. credentialed fullnode auth).
   */
  constructor(
    private readonly rpcUrl: string,
    /** Ownership-cache TTL (ms). 0 = disabled (every gated check is live on-chain). */
    private readonly cacheTtlMs: number = 0,
    authHeader?: { name: string; value: string },
  ) {
    // The `network` label is cosmetic when an explicit `baseUrl` is supplied (core RPC resolves via
    // the endpoint, not the label); infer it from the URL so a mainnet fullnode is labelled correctly.
    const network = /mainnet/i.test(rpcUrl) ? 'mainnet' : 'testnet'
    this.client = new SuiGrpcClient({
      network,
      baseUrl: rpcUrl,
      // gRPC-web metadata keys must be lower-case ASCII; a credentialed fullnode auth header
      // (e.g. `Authorization: Bearer …`) is threaded here on every call.
      ...(authHeader ? { meta: { [authHeader.name.toLowerCase()]: authHeader.value } } : {}),
    })
  }

  /**
   * Extract the package address from a `<pkg>::module::Type` string.
   *
   * @param nftType - Fully-qualified Move type string.
   * @returns The package address, or `undefined` if the string cannot be parsed.
   */
  static packageOf(nftType: string): string | undefined {
    const head = nftType.split('::')[0]
    return head && head.length > 0 ? head : undefined
  }

  /**
   * Build a stable cache key from the three ownership-query parameters.
   *
   * @param address - Sui address.
   * @param nftType - Fully-qualified NFT type string.
   * @param gateId - Optional gate object ID constraint.
   * @returns A pipe-delimited string suitable for use as a `Map` key.
   */
  static cacheKey(address: string, nftType: string, gateId?: string): string {
    return `${address}|${nftType}|${gateId ?? '-'}`
  }

  /**
   * Uncached, live ownership query over gRPC `listOwnedObjects`. Reuses `fetchAccessNfts` from
   * `@meddleware/nft-gate-client` (the same gRPC core-API parse the frontend uses), so the
   * gateway and client agree on what counts as a held access NFT.
   *
   * @param address - Sui address to query.
   * @param nftType - NFT struct type to filter by.
   * @param gateId - If given, only count objects whose `gate_id` field matches.
   * @returns `true` if at least one qualifying NFT is owned.
   */
  private async ownsNftLive(address: string, nftType: string, gateId?: string): Promise<boolean> {
    const nfts = await fetchAccessNfts(this.client, address, nftType, gateId)
    return nfts.length > 0
  }

  /**
   * Check whether `address` owns at least one NFT of `nftType`. Uses the in-process ownership
   * cache when `cacheTtlMs > 0`; otherwise every call is live on-chain.
   *
   * @param address - Sui address to check.
   * @param nftType - Fully-qualified NFT type string.
   * @param gateId - Optional gate object ID constraint.
   * @returns `true` if the address owns a qualifying NFT.
   */
  async ownsNft(address: string, nftType: string, gateId?: string): Promise<boolean> {
    // Cache is OFF by default (ttl 0) so a gated action is confirmed live on-chain.
    if (this.cacheTtlMs > 0) {
      const key = SuiGrpc.cacheKey(address, nftType, gateId)
      const hit = this.cache.get(key)
      const now = Date.now()
      if (hit && hit.expiry > now) return hit.owns
      const owns = await this.ownsNftLive(address, nftType, gateId)
      this.cache.set(key, { owns, expiry: now + this.cacheTtlMs })
      return owns
    }
    return this.ownsNftLive(address, nftType, gateId)
  }

  /**
   * Fetch a transaction by digest via gRPC, retrying briefly to absorb the window between the
   * client's finality wait and the gateway fullnode indexing the transaction.
   *
   * @param digest - Transaction digest to fetch.
   * @returns The gRPC `TransactionResult` (`$kind: 'Transaction' | 'FailedTransaction'`).
   * @throws If every attempt fails (surfaces as a {@link ChainQuery} ChainError → 502).
   */
  private async getTransaction(digest: string): Promise<Json> {
    let lastErr: unknown
    for (let attempt = 0; attempt < TX_FETCH_ATTEMPTS; attempt++) {
      try {
        return (await this.client.core.getTransaction({
          digest,
          include: { events: true },
        })) as Json
      } catch (e) {
        lastErr = e
        if (attempt < TX_FETCH_ATTEMPTS - 1) {
          await new Promise<void>((r) => setTimeout(r, TX_FETCH_RETRY_MS))
        }
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))
  }

  /**
   * Verify a single-use consume by fetching its `consumeDigest` transaction directly and confirming
   * it succeeded and emitted an `AccessConsumedEvent` for this sender + gate.
   *
   * The event is bound to the sender (which must equal the signature-verified proof address) and
   * the gate — NOT to the challenge nonce. Decoupling from the nonce is what lets an interrupted
   * upload resume with a fresh (free) challenge signature while reusing the same on-chain consume;
   * single-use is then enforced by the gateway's redemption store keying on this `consumeDigest`.
   * An attacker cannot present someone else's consume (the event `sender` would not match the
   * signed address) nor forge one without owning the soulbound NFT.
   *
   * @param consumeDigest - Transaction digest of the on-chain consume.
   * @param address - The signature-verified proof address; must equal the event sender.
   * @param gateId - Optional gate object ID constraint.
   * @returns `true` if the transaction confirms a matching consume.
   */
  async consumeTxValid(consumeDigest: string, address: string, gateId?: string): Promise<boolean> {
    const res = (await this.getTransaction(consumeDigest)) as Record<string, Json> | null
    // The gRPC result is a oneof: `{ $kind: 'Transaction', Transaction }` on success, or
    // `{ $kind: 'FailedTransaction', FailedTransaction }` when the transaction aborted.
    if (!res || res.$kind !== 'Transaction') return false
    const tx = res.Transaction as Record<string, Json> | undefined
    const status = tx?.status as { success?: boolean } | undefined
    if (!status?.success) return false
    const events = (Array.isArray(tx?.events) ? (tx?.events as Json[]) : []) as Json[]
    return events.some((ev) => isConsumedEvent(ev) && eventMatches(ev, address, gateId))
  }
}

// ── pure helpers (unit-tested; adapted to the gRPC event shape) ───────────────
// gRPC events expose `eventType`/`sender`/`json`; JSON-RPC used `type`/`sender`/`parsedJson`.
// The helpers read both keys so they stay tolerant to transport/shape variation (the SDK documents
// that the `json` shape may differ between transports).

/**
 * Traverse a nested JSON value by a sequence of object keys.
 *
 * @param v - The root JSON value.
 * @param path - Sequence of object keys to follow.
 * @returns The value at the path, or `undefined` if any step is missing or non-object.
 */
function pointer(v: Json, path: string[]): Json {
  let cur: Json = v
  for (const key of path) {
    if (cur && typeof cur === 'object' && !Array.isArray(cur) && key in (cur as Record<string, Json>)) {
      cur = (cur as Record<string, Json>)[key]
    } else {
      return undefined
    }
  }
  return cur
}

/**
 * Like {@link pointer} but returns `undefined` if the resolved value is not a string.
 *
 * @param v - The root JSON value.
 * @param path - Sequence of object keys to follow.
 * @returns The string value at the path, or `undefined`.
 */
function pointerStr(v: Json, path: string[]): string | undefined {
  const r = pointer(v, path)
  return typeof r === 'string' ? r : undefined
}

/** The event's Move type string, from the gRPC (`eventType`) or JSON-RPC (`type`) shape. */
function eventType(ev: Json): string | undefined {
  return pointerStr(ev, ['eventType']) ?? pointerStr(ev, ['type'])
}

/** The event's parsed Move struct fields, from the gRPC (`json`) or JSON-RPC (`parsedJson`) shape. */
function eventFields(ev: Json): Json {
  return pointer(ev, ['json']) ?? pointer(ev, ['parsedJson'])
}

/** True if the event's type ends with `::access_gate::AccessConsumedEvent`. */
export function isConsumedEvent(ev: Json): boolean {
  const t = eventType(ev)
  return t !== undefined && t.endsWith('::access_gate::AccessConsumedEvent')
}

/**
 * Match the on-chain `AccessConsumedEvent.nonce` (`vector<u8>`), rendered by the API as either an
 * array of byte numbers or a base64 string, against the challenge nonce's UTF-8 bytes.
 */
export function nonceMatches(eventNonce: Json, nonce: string): boolean {
  const want = new TextEncoder().encode(nonce)
  if (Array.isArray(eventNonce)) {
    if (eventNonce.length !== want.length) return false
    return eventNonce.every((b, i) => typeof b === 'number' && b === want[i])
  }
  if (typeof eventNonce === 'string') {
    try {
      const decoded = base64ToBytes(eventNonce)
      return decoded.length === want.length && decoded.every((b, i) => b === want[i])
    } catch {
      return false
    }
  }
  return false
}

/**
 * `sender == address` and (if given) `gate_id` matches. The consume event is bound to the
 * signature-verified sender + gate; single-use is enforced separately by redemption tracking on the
 * `consumeDigest`, so the event nonce is intentionally not checked here (see `consumeTxValid`).
 */
export function eventMatches(ev: Json, address: string, gateId?: string): boolean {
  const senderOk = pointerStr(ev, ['sender']) === address
  const fields = eventFields(ev)
  const gateOk = gateId === undefined ? true : pointerStr(fields, ['gate_id']) === gateId
  return senderOk && gateOk
}
