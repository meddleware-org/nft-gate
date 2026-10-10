/**
 * Production {@link ChainQuery} over the Sui **gRPC** API (`@mysten/sui/grpc` `SuiGrpcClient`).
 *
 * Public Sui fullnodes have deprecated JSON-RPC (`suix_queryEvents`, `sui_getTransactionBlock`,
 * `suix_getOwnedObjects` now return `-32601 Method not found`), so the gateway queries the chain
 * over gRPC — the same transport `@meddleware/walrus-client` and `@meddleware/access-gate-client`
 * already use. The pure match/parse helpers are exported for unit tests; the gRPC round-trips are
 * covered by the localnet/integration loop.
 *
 * Single-use verification is now **digest-first**: the access proof already carries the on-chain
 * `access_gate::consume` transaction digest, so the gateway fetches that exact transaction and
 * verifies it succeeded and emitted a matching `AccessConsumedEvent` for the proof's sender and the
 * gate. This is precise and does not need the deprecated event-by-sender query. The event is
 * deliberately not bound to the challenge nonce (the digest is the one-time token, redeemed once by
 * the redemption store; audit F23).
 */

import { SuiGrpcClient } from '@mysten/sui/grpc'
import { ownsAccessNft } from '@meddleware/access-gate-client'
import type { ChainQuery } from './verify.js'
import { normalizeAddress, normalizeMoveType } from './verify.js'
import type { SuiNetwork } from './config.js'

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

/** Number of `getTransaction` attempts while the node still reports the digest as unknown (indexing lag). */
const TX_FETCH_ATTEMPTS = 4
/** Delay between `getTransaction` retries, in ms. */
const TX_FETCH_RETRY_MS = 500
/** Entries kept by the ownership cache; the oldest is dropped past it. */
const MAX_CACHE_ENTRIES = 10_000
/** Clock skew tolerated between a consume event's timestamp and this isolate's clock. */
const CLOCK_SKEW_MS = 60_000

/** Reject if `p` has not settled within `ms`, so a hung fullnode cannot hold a request (and its lease). */
export async function withDeadline<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms)
  })
  try {
    return await Promise.race([p, timeout])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

/** True for the SDK's "transaction not found" error (the only failure worth retrying). */
function isNotFound(e: unknown): boolean {
  return typeof e === 'object' && e !== null && (e as { reason?: unknown }).reason === 'notFound'
}

/** Production {@link ChainQuery} backed by the Sui gRPC API, with an optional ownership cache. */
export class SuiGrpc implements ChainQuery {
  private readonly cache = new Map<string, CacheEntry>()
  private readonly client: SuiGrpcClient

  /**
   * @param rpcUrl - Sui gRPC endpoint base URL (e.g. `https://fullnode.testnet.sui.io:443`).
   * @param network - The Sui network the endpoint serves (from config, never inferred from the URL).
   * @param opts.cacheTtlMs - Ownership-cache TTL in ms. 0 disables the cache (live check every request).
   * @param opts.authHeader - Optional header injected on every gRPC call (e.g. credentialed fullnode auth).
   * @param opts.timeoutMs - Deadline for each chain read.
   */
  constructor(
    rpcUrl: string,
    network: SuiNetwork,
    private readonly opts: {
      cacheTtlMs: number
      timeoutMs: number
      authHeader?: { name: string; value: string }
    },
  ) {
    this.client = new SuiGrpcClient({
      network,
      baseUrl: rpcUrl,
      // Best effort: the server also gets the deadline. The authoritative bound is `withDeadline`.
      timeout: opts.timeoutMs,
      // gRPC-web metadata keys must be lower-case ASCII; a credentialed fullnode auth header
      // (e.g. `Authorization: Bearer …`) is threaded here on every call.
      ...(opts.authHeader ? { meta: { [opts.authHeader.name.toLowerCase()]: opts.authHeader.value } } : {}),
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
   * Uncached, live ownership query over gRPC `listOwnedObjects`. Reuses `ownsAccessNft` from
   * `@meddleware/access-gate-client` (the same exact-type parse the frontends use), so the
   * gateway and the clients agree on what counts as a held access NFT: only a USABLE pass (unlimited,
   * or single-use with uses left) counts. Every page is read until the first match; a list too long
   * to read throws, which denies (fail closed).
   *
   * @param address - Sui address to query.
   * @param nftType - NFT struct type to filter by.
   * @param gateId - If given, only count objects whose `gate_id` field matches.
   * @returns `true` if at least one usable, qualifying NFT is owned.
   */
  private async ownsNftLive(address: string, nftType: string, gateId?: string): Promise<boolean> {
    return withDeadline(ownsAccessNft(this.client, address, nftType, gateId), this.opts.timeoutMs, 'ownership query')
  }

  /**
   * Check whether `address` owns a usable NFT of `nftType`. Uses the in-process ownership cache
   * (bounded, expired entries dropped) when `cacheTtlMs > 0`; otherwise every call is live on-chain.
   *
   * @param address - Sui address to check.
   * @param nftType - Fully-qualified NFT type string.
   * @param gateId - Optional gate object ID constraint.
   * @returns `true` if the address owns a qualifying NFT.
   */
  async ownsNft(address: string, nftType: string, gateId?: string): Promise<boolean> {
    // Cache is OFF by default (ttl 0) so a gated action is confirmed live on-chain.
    if (this.opts.cacheTtlMs > 0) {
      const key = SuiGrpc.cacheKey(address, nftType, gateId)
      const now = Date.now()
      const hit = this.cache.get(key)
      if (hit && hit.expiry > now) return hit.owns
      this.cache.delete(key)
      const owns = await this.ownsNftLive(address, nftType, gateId)
      for (const [k, v] of this.cache) if (v.expiry <= now) this.cache.delete(k)
      while (this.cache.size >= MAX_CACHE_ENTRIES) this.cache.delete(this.cache.keys().next().value as string)
      this.cache.set(key, { owns, expiry: now + this.opts.cacheTtlMs })
      return owns
    }
    return this.ownsNftLive(address, nftType, gateId)
  }

  /**
   * Live read of the gate: blocked while paused if its policy has `pause_blocks_access`. Not
   * cached — pausing takes effect on the next request.
   *
   * @param gateId - The `Gate` shared object ID.
   * @throws If the gate cannot be read or its JSON is not the expected shape (surfaces as ChainError → 502; fail closed).
   */
  async gateAccessBlocked(gateId: string): Promise<boolean> {
    const { object } = await withDeadline(
      this.client.core.getObject({ objectId: gateId, include: { json: true } }),
      this.opts.timeoutMs,
      'gate read',
    )
    return gateBlocksAccess(object.json)
  }

  /**
   * Fetch a transaction by digest via gRPC. Only a "not found" answer is retried (a node can lag
   * behind the client's finality wait); the final not-found is `null`, which denies (403). Any other
   * failure (network, auth, server) throws at once and surfaces as ChainError → 502.
   *
   * @param digest - Transaction digest to fetch (shape already validated by the caller).
   * @returns The gRPC `TransactionResult` (`$kind: 'Transaction' | 'FailedTransaction'`), or `null`.
   */
  private async getTransaction(digest: string): Promise<Json | null> {
    for (let attempt = 0; attempt < TX_FETCH_ATTEMPTS; attempt++) {
      try {
        return (await withDeadline(
          this.client.core.getTransaction({ digest, include: { events: true } }),
          this.opts.timeoutMs,
          'transaction read',
        )) as Json
      } catch (e) {
        if (!isNotFound(e)) throw e
        if (attempt < TX_FETCH_ATTEMPTS - 1) await new Promise<void>((r) => setTimeout(r, TX_FETCH_RETRY_MS))
      }
    }
    return null
  }

  /**
   * Verify a single-use consume by fetching its `consumeDigest` transaction directly and confirming
   * it succeeded (effects status) and emitted an `AccessConsumedEvent` for this sender + gate that is
   * no older than `maxAgeSecs`.
   *
   * The event is bound to the sender (which must equal the signature-verified proof address) and
   * the gate — NOT to the challenge nonce. Decoupling from the nonce is what lets an interrupted
   * upload resume with a fresh (free) challenge signature while reusing the same on-chain consume;
   * single-use is then enforced by the gateway's redemption store keying on this `consumeDigest`.
   * The age bound keeps a consume from becoming redeemable again once the store has forgotten it.
   * An attacker cannot present someone else's consume (the event `sender` would not match the
   * signed address) nor forge one without owning the soulbound NFT.
   *
   * @param consumeDigest - Transaction digest of the on-chain consume.
   * @param address - The signature-verified proof address; must equal the event sender.
   * @param gateId - Optional gate object ID constraint.
   * @param maxAgeSecs - Oldest accepted consume event.
   * @returns `true` if the transaction confirms a matching, recent consume.
   */
  async consumeTxValid(
    consumeDigest: string,
    address: string,
    consumedEventType: string,
    gateId: string | undefined,
    maxAgeSecs: number,
  ): Promise<boolean> {
    const res = (await this.getTransaction(consumeDigest)) as Record<string, Json> | null
    // The gRPC result is a oneof: `{ $kind: 'Transaction', Transaction }` on success, or
    // `{ $kind: 'FailedTransaction', FailedTransaction }` when the transaction aborted.
    if (!res || res.$kind !== 'Transaction') return false
    const tx = res.Transaction as Record<string, Json> | undefined
    const status = tx?.status as { success?: boolean } | undefined
    if (!status?.success) return false
    const events = (Array.isArray(tx?.events) ? (tx?.events as Json[]) : []) as Json[]
    const now = Date.now()
    return events.some(
      (ev) => isConsumedEvent(ev, consumedEventType) && eventMatches(ev, address, gateId) && eventIsRecent(ev, now, maxAgeSecs),
    )
  }
}

// ── pure helpers (unit-tested; adapted to the gRPC event shape) ───────────────
// gRPC events expose `eventType`/`sender`/`json`. JSON-RPC is gone from public fullnodes, so only
// that shape is read.

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

/** The event's Move type string (gRPC `eventType`). */
function eventType(ev: Json): string | undefined {
  return pointerStr(ev, ['eventType'])
}

/** The event's parsed Move struct fields (gRPC `json`). */
function eventFields(ev: Json): Json {
  return pointer(ev, ['json'])
}

/**
 * True if a `Gate` object's JSON (gRPC core shape: fields flat) is paused and its policy has
 * `pause_blocks_access`. Fails closed: JSON without a boolean `paused` and an object `policy` with a
 * boolean `pause_blocks_access` is not understood, and throws (→ ChainError → deny) rather than
 * reading as "not paused".
 */
export function gateBlocksAccess(gateJson: Json): boolean {
  const g = gateJson as { paused?: unknown; policy?: { pause_blocks_access?: unknown } } | null
  const policy = g && typeof g === 'object' ? g.policy : undefined
  if (
    !g ||
    typeof g !== 'object' ||
    typeof g.paused !== 'boolean' ||
    !policy ||
    typeof policy !== 'object' ||
    typeof policy.pause_blocks_access !== 'boolean'
  ) {
    throw new Error('gate JSON has an unrecognised shape')
  }
  return g.paused && policy.pause_blocks_access
}

/**
 * True if the event's type is exactly `expectedType` (package address normalised). A suffix match
 * would accept an `AccessConsumedEvent` emitted by any package with an `access_gate` module.
 */
export function isConsumedEvent(ev: Json, expectedType: string): boolean {
  const t = eventType(ev)
  return t !== undefined && normalizeMoveType(t) === normalizeMoveType(expectedType)
}

/**
 * `sender == address` and (if given) `gate_id` matches. The consume event is bound to the
 * signature-verified sender + gate; single-use is enforced separately by redemption tracking on the
 * `consumeDigest`, so the event nonce is intentionally not checked here (see `consumeTxValid`).
 */
export function eventMatches(ev: Json, address: string, gateId?: string): boolean {
  const sender = pointerStr(ev, ['sender'])
  const senderOk = sender !== undefined && normalizeAddress(sender) === normalizeAddress(address)
  const gate = pointerStr(eventFields(ev), ['gate_id'])
  const gateOk = gateId === undefined ? true : gate !== undefined && normalizeAddress(gate) === normalizeAddress(gateId)
  return senderOk && gateOk
}

/**
 * True if the event's `timestamp_ms` is at most `maxAgeSecs` old and not in the future (beyond clock
 * skew). A missing or malformed timestamp is not recent: fail closed.
 */
export function eventIsRecent(ev: Json, nowMs: number, maxAgeSecs: number): boolean {
  const raw = pointer(eventFields(ev), ['timestamp_ms'])
  if (typeof raw !== 'string' && typeof raw !== 'number') return false
  if (typeof raw === 'string' && !/^\d{1,16}$/.test(raw)) return false
  const ts = Number(raw)
  if (!Number.isSafeInteger(ts)) return false
  return ts <= nowMs + CLOCK_SKEW_MS && nowMs - ts <= maxAgeSecs * 1000
}
