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

export interface Env {
  // ── config (parity with the Rust gateway) ─────────────────────────────────
  UPSTREAM_URL: string
  SUI_RPC_URL: string
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
   * Defaults to the two Meddleware app origins when absent (the same list as wrangler.toml).
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

function numOr(v: string | undefined, dflt: number): number {
  if (v === undefined) return dflt
  const n = Number(v)
  return Number.isFinite(n) ? n : dflt
}

function parseAuthHeader(v: string | undefined): { name: string; value: string } | undefined {
  if (!v) return undefined
  const idx = v.indexOf(':')
  // "Name: value" → {name, value}; a bare value defaults to an Authorization header.
  if (idx > 0) return { name: v.slice(0, idx).trim(), value: v.slice(idx + 1).trim() }
  return { name: 'Authorization', value: v.trim() }
}

const DEFAULT_ALLOWED_ORIGINS = [
  'https://sui-walrus.meddleware.co.uk',
  'https://dash.meddleware.co.uk',
  'https://sui-token-deployer.meddleware.co.uk',
]

function parseAllowedOrigins(v: string | undefined): string[] {
  if (!v || v.trim().length === 0) return DEFAULT_ALLOWED_ORIGINS
  return v
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
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

  const backendRaw = (env.NONCE_BACKEND ?? 'durable-object').toLowerCase()
  const nonceBackend: NonceBackendKind = backendRaw === 'kv' ? 'kv' : 'durable-object'
  const shardRaw = (env.NONCE_SHARD ?? 'region').toLowerCase()
  const nonceShard: NonceShardMode = shardRaw === 'global' ? 'global' : 'region'

  return {
    upstreamUrl: req(env, 'UPSTREAM_URL').replace(/\/+$/, ''),
    suiRpcUrl: req(env, 'SUI_RPC_URL'),
    suiRpcAuthHeader: parseAuthHeader(env.SUI_RPC_AUTH_HEADER),
    upstreamAuthHeaders: parseUpstreamAuthHeaders(env.UPSTREAM_AUTH_HEADERS),
    nftType,
    gateId,
    challengeTtlSecs: numOr(env.CHALLENGE_TTL_SECS, 300),
    singleUse: (env.SINGLE_USE ?? 'false').toLowerCase() === 'true',
    publicPaths: (env.PUBLIC_PATHS ?? '/v1/tip-config')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    rateLimitPerMin: numOr(env.RATE_LIMIT_PER_MIN, 30),
    challengeRateLimitPerMin: numOr(env.CHALLENGE_RATE_LIMIT_PER_MIN, 30),
    publicRateLimitPerMin: numOr(env.PUBLIC_RATE_LIMIT_PER_MIN, 120),
    publicCacheTtlSecs: numOr(env.PUBLIC_CACHE_TTL_SECS, 60),
    maxBodyBytes: numOr(env.MAX_BODY_BYTES, 262144),
    ownershipCacheTtlMs: numOr(env.OWNERSHIP_CACHE_TTL_MS, 0),
    redemptionLeaseTtlSecs: numOr(env.REDEMPTION_LEASE_TTL_SECS, 120),
    redemptionRetentionSecs: numOr(env.REDEMPTION_RETENTION_SECS, 2592000),
    nonceBackend,
    nonceShard,
    nonceMaxEntries: numOr(env.NONCE_MAX_ENTRIES, 1000000),
    quotaGuardEnabled: (env.QUOTA_GUARD_ENABLED ?? 'false').toLowerCase() === 'true',
    allowedOrigins: parseAllowedOrigins(env.ALLOWED_ORIGINS),
  }
}

/** Returns `true` if `path` is in the configured public-paths list (proxied without auth). */
export function isPublicPath(cfg: Config, path: string): boolean {
  return cfg.publicPaths.some((p) => p === path)
}
