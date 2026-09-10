/**
 * Gateway configuration, loaded from Worker `env` bindings. Mirror of the Rust gateway's
 * `config.rs` — the SAME env-var names and defaults, so a deployment's settings map 1:1
 * between the two implementations (the interchangeability contract).
 *
 * Omitted vs. Rust (runtime-specific): `BIND_ADDR` (Workers has no listen socket);
 * `REDIS_URL` / `NONCE_MAX_ENTRIES` (the in-memory cap lives in the DO) /
 * `NONCE_PRUNE_INTERVAL_SECS` (the DO prunes on access) are superseded by the DO/KV backend.
 * Added (Workers-specific): `NONCE_BACKEND`, `NONCE_SHARD`, `SUI_RPC_AUTH_HEADER`,
 * `UPSTREAM_AUTH_HEADERS`, `QUOTA_GUARD_ENABLED`.
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
   * Comma-separated `Name: value` header lines injected into every upstream (relay) request.
   * Use this to pass Cloudflare Access service-token headers when the relay origin is
   * Access-locked (your CF-Access-protected origin hostname).
   *
   * Format: `"CF-Access-Client-Id: <id>, CF-Access-Client-Secret: <secret>"`
   *
   * Set via `wrangler secret put UPSTREAM_AUTH_HEADERS` — never in wrangler.toml.
   */
  UPSTREAM_AUTH_HEADERS?: string
  /** `true` enables the scheduled quota guard. */
  QUOTA_GUARD_ENABLED?: string
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
  gateId?: string
  challengeTtlSecs: number
  singleUse: boolean
  publicPaths: string[]
  rateLimitPerMin: number
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

/**
 * Parse `UPSTREAM_AUTH_HEADERS`: comma-separated `Name: value` pairs.
 * Each entry follows the same `Name: value` format as `SUI_RPC_AUTH_HEADER`.
 * Entries that cannot be parsed (no colon) are silently skipped.
 */
function parseUpstreamAuthHeaders(v: string | undefined): Array<{ name: string; value: string }> {
  if (!v || v.trim().length === 0) return []
  return v
    .split(',')
    .map((entry) => parseAuthHeader(entry.trim()))
    .filter((h): h is { name: string; value: string } => h !== undefined)
}

/** Build the typed config from `env`. Throws if a required var is missing (fail fast). */
export function loadConfig(env: Env): Config {
  const backendRaw = (env.NONCE_BACKEND ?? 'durable-object').toLowerCase()
  const nonceBackend: NonceBackendKind = backendRaw === 'kv' ? 'kv' : 'durable-object'
  const shardRaw = (env.NONCE_SHARD ?? 'region').toLowerCase()
  const nonceShard: NonceShardMode = shardRaw === 'global' ? 'global' : 'region'

  return {
    upstreamUrl: req(env, 'UPSTREAM_URL').replace(/\/+$/, ''),
    suiRpcUrl: req(env, 'SUI_RPC_URL'),
    suiRpcAuthHeader: parseAuthHeader(env.SUI_RPC_AUTH_HEADER),
    upstreamAuthHeaders: parseUpstreamAuthHeaders(env.UPSTREAM_AUTH_HEADERS),
    nftType: req(env, 'NFT_TYPE'),
    gateId: env.GATE_ID && env.GATE_ID.length > 0 ? env.GATE_ID : undefined,
    challengeTtlSecs: numOr(env.CHALLENGE_TTL_SECS, 300),
    singleUse: (env.SINGLE_USE ?? 'false').toLowerCase() === 'true',
    publicPaths: (env.PUBLIC_PATHS ?? '/v1/tip-config')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    rateLimitPerMin: numOr(env.RATE_LIMIT_PER_MIN, 30),
    maxBodyBytes: numOr(env.MAX_BODY_BYTES, 262144),
    ownershipCacheTtlMs: numOr(env.OWNERSHIP_CACHE_TTL_MS, 0),
    redemptionLeaseTtlSecs: numOr(env.REDEMPTION_LEASE_TTL_SECS, 120),
    redemptionRetentionSecs: numOr(env.REDEMPTION_RETENTION_SECS, 2592000),
    nonceBackend,
    nonceShard,
    nonceMaxEntries: numOr(env.NONCE_MAX_ENTRIES, 1000000),
    quotaGuardEnabled: (env.QUOTA_GUARD_ENABLED ?? 'false').toLowerCase() === 'true',
  }
}

/** Returns `true` if `path` is in the configured public-paths list (proxied without auth). */
export function isPublicPath(cfg: Config, path: string): boolean {
  return cfg.publicPaths.some((p) => p === path)
}
