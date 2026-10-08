/**
 * Gateway configuration, loaded from Worker `env` bindings. Mirror of the Rust gateway's
 * `config.rs` — the SAME env-var names and defaults, so a deployment's settings map 1:1
 * between the two implementations (the interchangeability contract).
 *
 * Omitted vs. Rust (runtime-specific): `BIND_ADDR` (Workers has no listen socket);
 * `REDIS_URL` / `NONCE_MAX_ENTRIES` (the in-memory cap lives in the DO) /
 * `NONCE_PRUNE_INTERVAL_SECS` (the DO prunes on access) are superseded by the DO/KV backend.
 * Workers-specific: `NONCE_BACKEND`, `NONCE_SHARD`, `QUOTA_GUARD_ENABLED`. `SUI_RPC_AUTH_HEADER`
 * and `UPSTREAM_AUTH_HEADERS` are shared with the Rust gateway in the same formats.
 */

import { gatewayOrigin as gatewayOriginOf } from '@meddleware/nft-gate-client'

export interface Env {
  // ── config (parity with the Rust gateway) ─────────────────────────────────
  UPSTREAM_URL: string
  SUI_RPC_URL: string
  /**
   * The canonical public origin of THIS gateway (`https://host`, no path, lower-case). It is signed
   * into every access proof (protocol `nft-gate:access:v2`), so a proof made for another gateway is
   * useless here.
   */
  GATEWAY_ORIGIN: string
  /** `localnet` | `devnet` | `testnet` | `mainnet`: signed into every access proof. */
  NETWORK: string
  NFT_TYPE: string
  GATE_ID?: string
  SINGLE_USE?: string
  PUBLIC_PATHS?: string
  RATE_LIMIT_PER_MIN?: string
  /** Per-client-IP budget for `GET /v1/challenge` per minute (0 disables). */
  CHALLENGE_RATE_LIMIT_PER_MIN?: string
  PUBLIC_RATE_LIMIT_PER_MIN?: string
  PUBLIC_CACHE_TTL_SECS?: string
  MAX_BODY_BYTES?: string
  CHALLENGE_TTL_SECS?: string
  OWNERSHIP_CACHE_TTL_MS?: string
  /**
   * Total deadline (seconds) for one upstream exchange, request body and response included. The
   * redemption lease must outlive it, so a lease cannot lapse mid-forward (checked at startup).
   */
  UPSTREAM_TIMEOUT_SECS?: string
  /** Per-call deadline (seconds) for Sui RPC reads. */
  RPC_TIMEOUT_SECS?: string
  /** Per-client-IP budget per minute for gated requests, checked BEFORE signature verification. */
  GATED_PREAUTH_RATE_LIMIT_PER_MIN?: string
  /** Single-use: oldest consume (seconds since its event) the gateway accepts; ≤ the retention. */
  CONSUME_MAX_AGE_SECS?: string
  /** Single-use: seconds a consume-digest redemption lease is held during an in-flight upload. */
  REDEMPTION_LEASE_TTL_SECS?: string
  /** Single-use: seconds a committed (spent) consume-digest is remembered to block re-redemption. */
  REDEMPTION_RETENTION_SECS?: string
  // ── Workers-specific ──────────────────────────────────────────────────────
  /** `durable-object` (default) | `kv`. */
  NONCE_BACKEND?: string
  /** `region` (default) | `global` — DO shard granularity. */
  NONCE_SHARD?: string
  /** Hard cap on nonce rows per DO shard (evict soonest-to-expire beyond it). */
  NONCE_MAX_ENTRIES?: string
  /** Optional `Name: value` header line added to every Sui RPC call (secret). */
  SUI_RPC_AUTH_HEADER?: string
  /**
   * Headers injected into every upstream (relay) request, as a JSON array of `{name, value}`.
   * Use this to pass Cloudflare Access service-token headers when the relay origin is
   * Access-locked (your CF-Access-protected origin hostname).
   *
   * Format: `[{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]`
   * (JSON, so a value may contain commas or colons). Same format in the Rust gateway.
   *
   * Set via `wrangler secret put UPSTREAM_AUTH_HEADERS` — never in wrangler.toml.
   */
  UPSTREAM_AUTH_HEADERS?: string
  /** `true` enables the scheduled quota guard. */
  QUOTA_GUARD_ENABLED?: string
  /**
   * Comma-separated list of browser origins allowed to make cross-origin requests.
   * Only origins in this list receive an `Access-Control-Allow-Origin` header.
   * Defaults to NONE (no cross-origin access). Each entry must be a canonical origin.
   * Example: `"https://sui-walrus.meddleware.co.uk,https://dash.meddleware.co.uk,https://sui-token-deployer.meddleware.co.uk"`
   */
  ALLOWED_ORIGINS?: string
  // ── bindings ──────────────────────────────────────────────────────────────
  NONCE_STATE?: DurableObjectNamespace
  NONCE_KV?: KVNamespace
  // ── quota-guard secrets (optional) ────────────────────────────────────────
  CF_ANALYTICS_TOKEN?: string
  CF_ACCOUNT_ID?: string
}

/** Which nonce/rate-limit backend to use: strongly-consistent Durable Objects or Workers KV. */
export type NonceBackendKind = 'durable-object' | 'kv'
/** Nonce shard placement: one shard per region (near users) or a single global shard. */
export type NonceShardMode = 'region' | 'global'

/** Fully-resolved gateway configuration derived from {@link Env} by {@link loadConfig}. */
export interface Config {
  upstreamUrl: string
  suiRpcUrl: string
  /** Canonical origin signed into access proofs. */
  gatewayOrigin: string
  network: SuiNetwork
  suiRpcAuthHeader?: { name: string; value: string }
  /** Headers injected into every upstream relay request (e.g. CF Access service token). */
  upstreamAuthHeaders: Array<{ name: string; value: string }>
  nftType: string
  /** The access_gate `Gate` whose passes are accepted (required). */
  gateId: string
  challengeTtlSecs: number
  singleUse: boolean
  publicPaths: string[]
  rateLimitPerMin: number
  /** Per-client-IP cap on `GET /v1/challenge` per minute (0 disables). */
  challengeRateLimitPerMin: number
  /** Per-client-IP request cap for unauthenticated public paths (e.g. /v1/tip-config). */
  publicRateLimitPerMin: number
  /** Edge-cache TTL (s) for cacheable GET responses on public paths. 0 disables caching. */
  publicCacheTtlSecs: number
  maxBodyBytes: number
  /** Total deadline (ms) for one upstream exchange. */
  upstreamTimeoutMs: number
  /** Per-call deadline (ms) for Sui RPC reads. */
  rpcTimeoutMs: number
  /** Per-client-IP cap per minute on gated requests, before verification (0 disables). */
  gatedPreauthRateLimitPerMin: number
  /** Oldest accepted consume, in seconds since its event. */
  consumeMaxAgeSecs: number
  ownershipCacheTtlMs: number
  /** Single-use: lease TTL (s) for an in-flight consume-digest redemption. */
  redemptionLeaseTtlSecs: number
  /** Single-use: retention (s) of a committed (spent) consume-digest. */
  redemptionRetentionSecs: number
  nonceBackend: NonceBackendKind
  nonceShard: NonceShardMode
  nonceMaxEntries: number
  quotaGuardEnabled: boolean
  /** Allowed CORS origins — only these are reflected in Access-Control-Allow-Origin. */
  allowedOrigins: string[]
}

function req(env: Env, key: keyof Env): string {
  const v = env[key]
  if (typeof v !== 'string' || v.length === 0) {
    throw new Error(`${key} is required`)
  }
  return v
}

/** An integer env var in `[min, max]`; anything else (a typo, a negative, a fraction) fails startup. */
function int(env: Env, key: keyof Env, dflt: number, min: number, max: number): number {
  const raw = env[key]
  if (raw === undefined) return dflt
  if (typeof raw !== 'string' || !/^\d{1,15}$/.test(raw.trim())) {
    throw new Error(`${key} must be an integer in [${min}, ${max}]`)
  }
  const n = Number(raw.trim())
  if (n < min || n > max) throw new Error(`${key} must be an integer in [${min}, ${max}]`)
  return n
}

/** A boolean env var: exactly `true` or `false`; anything else fails startup rather than picking a mode. */
function bool(env: Env, key: keyof Env, dflt: boolean): boolean {
  const raw = env[key]
  if (raw === undefined) return dflt
  if (raw === 'true') return true
  if (raw === 'false') return false
  throw new Error(`${key} must be "true" or "false"`)
}

/** One of `allowed` (case-sensitive). */
function oneOf<T extends string>(env: Env, key: keyof Env, dflt: T, allowed: readonly T[]): T {
  const raw = env[key]
  if (raw === undefined) return dflt
  if (typeof raw === 'string' && (allowed as readonly string[]).includes(raw)) return raw as T
  throw new Error(`${key} must be one of ${allowed.join(', ')}`)
}

const NETWORKS = ['localnet', 'devnet', 'testnet', 'mainnet'] as const
export type SuiNetwork = (typeof NETWORKS)[number]

/** A URL that must be https (http only for a loopback host), without credentials. */
function httpsUrl(key: string, v: string): URL {
  let url: URL
  try {
    url = new URL(v)
  } catch {
    throw new Error(`${key} must be an https URL`)
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) throw new Error(`${key} must be an https URL`)
  if (url.username || url.password) throw new Error(`${key} must not carry credentials`)
  return url
}

/**
 * Parse `SUI_RPC_AUTH_HEADER`: `Name: value`. A bare value is refused (it used to be sent as
 * `Authorization`, a guess an operator could not see), as is a bad header name or a CR/LF.
 */
function parseAuthHeader(v: string | undefined): { name: string; value: string } | undefined {
  if (!v) return undefined
  const idx = v.indexOf(':')
  const name = idx > 0 ? v.slice(0, idx).trim() : ''
  const value = idx > 0 ? v.slice(idx + 1).trim() : ''
  if (!HEADER_NAME_RE.test(name) || value === '' || /[\r\n]/.test(value)) {
    throw new Error('SUI_RPC_AUTH_HEADER must be "Name: value"')
  }
  return { name, value }
}

/** `ALLOWED_ORIGINS`: comma-separated canonical origins; empty or unset allows no cross-origin access. */
function parseAllowedOrigins(v: string | undefined): string[] {
  if (!v || v.trim().length === 0) return []
  return v
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((o) => {
      let origin: string
      try {
        origin = httpsUrl('ALLOWED_ORIGINS', o).origin
      } catch {
        throw new Error(`ALLOWED_ORIGINS entry is not an https origin: ${o}`)
      }
      if (origin !== o) throw new Error(`ALLOWED_ORIGINS entry is not a canonical origin: ${o}`)
      return o
    })
}

/** `PUBLIC_PATHS`: exact paths, each starting with `/` and free of query, fragment and dot segments. */
function parsePublicPaths(v: string | undefined): string[] {
  return (v ?? '/v1/tip-config')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((p) => {
      if (!/^\/[A-Za-z0-9._~\-/]*$/.test(p) || p.split('/').some((seg) => seg === '..' || seg === '.')) {
        throw new Error(`PUBLIC_PATHS entry is not a plain absolute path: ${p}`)
      }
      return p
    })
}

/** An HTTP header field name (RFC 9110 token). */
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/

/**
 * Parse `UPSTREAM_AUTH_HEADERS`: a JSON array of `{ "name": …, "value": … }`. Anything else —
 * invalid JSON, a non-array, a bad header name, a non-string value — throws, so a mistyped
 * secret fails closed at startup instead of silently dropping the origin's credentials.
 */
export function parseUpstreamAuthHeaders(v: string | undefined): Array<{ name: string; value: string }> {
  if (!v || v.trim().length === 0) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(v)
  } catch {
    throw new Error('UPSTREAM_AUTH_HEADERS must be a JSON array of {"name","value"} objects')
  }
  if (!Array.isArray(parsed)) {
    throw new Error('UPSTREAM_AUTH_HEADERS must be a JSON array of {"name","value"} objects')
  }
  return parsed.map((h, i) => {
    const name = (h as { name?: unknown })?.name
    const value = (h as { value?: unknown })?.value
    if (typeof name !== 'string' || !HEADER_NAME_RE.test(name) || typeof value !== 'string' || /[\r\n]/.test(value)) {
      throw new Error(`UPSTREAM_AUTH_HEADERS[${i}] must be {"name": <header name>, "value": <string>}`)
    }
    return { name, value }
  })
}

/**
 * `NFT_TYPE` must be an access_gate pass type: `<pkg>::access_gate::AccessNFT` or
 * `…::SoulboundAccessNFT`. Anything else (a fungible `Coin<T>`, an arbitrary NFT) would gate on
 * mere ownership of an object that access_gate never sold, so it is rejected at startup.
 */
const NFT_TYPE_RE = /^0x[0-9a-fA-F]{1,64}::access_gate::(?:AccessNFT|SoulboundAccessNFT)$/
/** A Sui object ID. */
const OBJECT_ID_RE = /^0x[0-9a-fA-F]{1,64}$/

/** Build the typed config from `env`. Throws if a required var is missing or invalid (fail fast). */
export function loadConfig(env: Env): Config {
  const nftType = req(env, 'NFT_TYPE').trim()
  if (!NFT_TYPE_RE.test(nftType)) {
    throw new Error('NFT_TYPE must be <pkg>::access_gate::AccessNFT or <pkg>::access_gate::SoulboundAccessNFT')
  }
  const gateId = req(env, 'GATE_ID').trim()
  if (!OBJECT_ID_RE.test(gateId)) throw new Error('GATE_ID must be a 0x-prefixed object ID')

  let gatewayOrigin: string
  try {
    gatewayOrigin = gatewayOriginOf(req(env, 'GATEWAY_ORIGIN').trim())
  } catch {
    throw new Error('GATEWAY_ORIGIN must be a canonical https origin (https://host, no path)')
  }
  if (gatewayOrigin !== req(env, 'GATEWAY_ORIGIN').trim()) {
    throw new Error('GATEWAY_ORIGIN must be a canonical https origin (https://host, no path)')
  }
  const network = req(env, 'NETWORK').trim() as SuiNetwork
  if (!NETWORKS.includes(network)) throw new Error(`NETWORK must be one of ${NETWORKS.join(', ')}`)

  const upstream = httpsUrl('UPSTREAM_URL', req(env, 'UPSTREAM_URL'))
  if (upstream.origin === gatewayOrigin) throw new Error('UPSTREAM_URL must not be this gateway (request loop)')
  const rpc = httpsUrl('SUI_RPC_URL', req(env, 'SUI_RPC_URL'))

  const singleUse = bool(env, 'SINGLE_USE', false)
  const nonceBackend = oneOf<NonceBackendKind>(env, 'NONCE_BACKEND', 'durable-object', ['durable-object', 'kv'])
  if (singleUse && nonceBackend === 'kv') {
    // Workers KV is eventually consistent and its lease is read-then-write, so it cannot give the
    // "redeemed exactly once" guarantee the single-use paywall rests on.
    throw new Error('SINGLE_USE=true requires NONCE_BACKEND=durable-object')
  }

  const upstreamTimeoutSecs = int(env, 'UPSTREAM_TIMEOUT_SECS', 600, 1, 3600)
  const leaseTtlSecs = int(env, 'REDEMPTION_LEASE_TTL_SECS', 900, 30, 86400)
  if (leaseTtlSecs <= upstreamTimeoutSecs) {
    throw new Error('REDEMPTION_LEASE_TTL_SECS must exceed UPSTREAM_TIMEOUT_SECS (a lease must outlive its upload)')
  }
  const retentionSecs = int(env, 'REDEMPTION_RETENTION_SECS', 2592000, 3600, 31536000)
  const consumeMaxAgeSecs = int(env, 'CONSUME_MAX_AGE_SECS', 432000, 60, 31536000)
  if (consumeMaxAgeSecs > retentionSecs) {
    throw new Error('CONSUME_MAX_AGE_SECS must not exceed REDEMPTION_RETENTION_SECS (a spent consume must be remembered while it can be presented)')
  }

  return {
    upstreamUrl: req(env, 'UPSTREAM_URL').replace(/\/+$/, ''),
    suiRpcUrl: rpc.toString(),
    gatewayOrigin,
    network,
    suiRpcAuthHeader: parseAuthHeader(env.SUI_RPC_AUTH_HEADER),
    upstreamAuthHeaders: parseUpstreamAuthHeaders(env.UPSTREAM_AUTH_HEADERS),
    nftType,
    gateId,
    challengeTtlSecs: int(env, 'CHALLENGE_TTL_SECS', 300, 10, 3600),
    singleUse,
    publicPaths: parsePublicPaths(env.PUBLIC_PATHS),
    rateLimitPerMin: int(env, 'RATE_LIMIT_PER_MIN', 30, 0, 1_000_000),
    challengeRateLimitPerMin: int(env, 'CHALLENGE_RATE_LIMIT_PER_MIN', 30, 0, 1_000_000),
    publicRateLimitPerMin: int(env, 'PUBLIC_RATE_LIMIT_PER_MIN', 120, 0, 1_000_000),
    publicCacheTtlSecs: int(env, 'PUBLIC_CACHE_TTL_SECS', 60, 0, 86400),
    maxBodyBytes: int(env, 'MAX_BODY_BYTES', 262144, 1, 1_073_741_824),
    upstreamTimeoutMs: upstreamTimeoutSecs * 1000,
    rpcTimeoutMs: int(env, 'RPC_TIMEOUT_SECS', 15, 1, 120) * 1000,
    gatedPreauthRateLimitPerMin: int(env, 'GATED_PREAUTH_RATE_LIMIT_PER_MIN', 120, 0, 1_000_000),
    consumeMaxAgeSecs,
    ownershipCacheTtlMs: int(env, 'OWNERSHIP_CACHE_TTL_MS', 0, 0, 3_600_000),
    redemptionLeaseTtlSecs: leaseTtlSecs,
    redemptionRetentionSecs: retentionSecs,
    nonceBackend,
    nonceShard: oneOf<NonceShardMode>(env, 'NONCE_SHARD', 'region', ['region', 'global']),
    nonceMaxEntries: int(env, 'NONCE_MAX_ENTRIES', 1000000, 1, 100_000_000),
    quotaGuardEnabled: bool(env, 'QUOTA_GUARD_ENABLED', false),
    allowedOrigins: parseAllowedOrigins(env.ALLOWED_ORIGINS),
  }
}

/** Returns `true` if `path` is in the configured public-paths list (proxied without auth, GET/HEAD only). */
export function isPublicPath(cfg: Config, path: string): boolean {
  return cfg.publicPaths.some((p) => p === path)
}
