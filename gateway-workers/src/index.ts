/**
 * Generic NFT-gated reverse proxy — Cloudflare Workers implementation.
 *
 * A drop-in, wire-identical sibling of the Rust gateway (`../rust`): same routes, status
 * codes/messages, proof format, Sui RPC calls, and env-var config. Serves `GET /v1/challenge`,
 * proxies configured public paths unauthenticated, and requires a valid wallet-signed access
 * proof (verified against on-chain NFT ownership) for everything else. Mirror of `main.rs`.
 */

import type { Config, Env } from './config.js'
import { loadConfig, isPublicPath } from './config.js'
import type { NonceBackend, RedemptionStore } from './state/types.js'
import { NONCE_SHARDS } from './state/types.js'
import { makeBackends } from './state/select.js'
import { SuiGrpc } from './chain.js'
import { verifyAccessRequest, deniedReason } from './verify.js'
import { forward, FORWARDED_METHODS } from './proxy.js'
import { runQuotaGuard } from './quota.js'
import { redeemAndForward } from './redemption.js'
import { withCors, corsPreflightResponse, resolveAllowedOrigin } from './cors.js'

export { NonceRateState } from './state/durable_object.js'

/**
 * Per-isolate cached gateway state. Holds the fully resolved config, the chosen nonce
 * backend, and the Sui RPC client so they persist across requests within the same isolate.
 */
interface GatewayState {
  cfg: Config
  backend: NonceBackend
  /** Present exactly when `cfg.singleUse`. */
  redemptions?: RedemptionStore
  chain: SuiGrpc
}

/** Lazily initialised once per isolate; `null` before the first request. */
let cached: GatewayState | null = null

/**
 * Return (or lazily build) the per-isolate {@link GatewayState}. Checks a KV-based
 * quota-degrade flag once per isolate and may switch to the KV backend when set.
 *
 * @param env - The Worker environment bindings for this deployment.
 * @returns The resolved gateway state.
 * @throws If required config vars are missing or the chosen nonce-backend binding is absent.
 */
async function getState(env: Env): Promise<GatewayState> {
  if (cached) return cached
  const cfg = loadConfig(env)
  // Honour an operator/quota-guard "degrade" flag once per isolate: prefer KV before DO
  // free-tier limits bite (only when a KV binding is available). Never in single-use mode: the
  // redemption guarantee needs the Durable Object, and the flag must not change that silently.
  let effective = cfg
  if (!cfg.singleUse && cfg.nonceBackend === 'durable-object' && env.NONCE_KV) {
    try {
      if (await env.NONCE_KV.get('quota:degrade')) effective = { ...cfg, nonceBackend: 'kv' }
    } catch {
      /* ignore — stay on the configured backend */
    }
  }
  const { backend, redemptions } = makeBackends(effective, env)
  cached = {
    cfg,
    backend: guardBackend(backend),
    redemptions: redemptions && guardRedemptions(redemptions),
    chain: new SuiGrpc(cfg.suiRpcUrl, cfg.network, {
      cacheTtlMs: cfg.ownershipCacheTtlMs,
      timeoutMs: cfg.rpcTimeoutMs,
      authHeader: cfg.suiRpcAuthHeader,
    }),
  }
  return cached
}

/** A nonce/rate/redemption store call failed (Durable Object or KV unavailable). */
class StoreError extends Error {}

/** Run `fn`, mapping any storage failure to a {@link StoreError}. */
function wrapStore<A extends unknown[], R>(fn: (...args: A) => Promise<R>) {
  return async (...args: A): Promise<R> => {
    try {
      return await fn(...args)
    } catch (e) {
      throw new StoreError((e as Error).message)
    }
  }
}

/**
 * Wrap every backend call so a storage failure surfaces as a {@link StoreError} — answered with a
 * JSON 503 (fail closed, never a conflict) rather than an unhandled exception without CORS headers.
 */
function guardBackend(backend: NonceBackend): NonceBackend {
  return {
    issue: wrapStore(backend.issue.bind(backend)),
    takeIfValid: wrapStore(backend.takeIfValid.bind(backend)),
    rateCheck: wrapStore(backend.rateCheck.bind(backend)),
  }
}

function guardRedemptions(store: RedemptionStore): RedemptionStore {
  return {
    tryLeaseRedemption: wrapStore(store.tryLeaseRedemption.bind(store)),
    commitRedemption: wrapStore(store.commitRedemption.bind(store)),
    releaseRedemption: wrapStore(store.releaseRedemption.bind(store)),
  }
}

/**
 * Build a JSON response with the given status code.
 *
 * @param status - HTTP status code.
 * @param body - Value to serialize as the response body.
 * @returns A `Response` with `content-type: application/json`.
 */
function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Build a JSON `{"error": reason}` response with the given status code, optionally with a stable
 * machine-readable `code` (e.g. `"redeemed"` vs `"leased"`) so the client can react precisely.
 *
 * @param status - HTTP status code.
 * @param reason - Short, client-visible error description.
 * @param code - Optional stable code for programmatic handling.
 * @returns A JSON error response.
 */
function deny(status: number, reason: string, code?: string): Response {
  return json(status, code ? { error: reason, code } : { error: reason })
}

/** Prefer `Authorization: Bearer <token>`; fall back to an explicit `X-Access-Proof` header. */
function extractProofToken(request: Request): string | undefined {
  const auth = request.headers.get('authorization')
  if (auth) {
    const m = auth.match(/^Bearer\s+(.+)$/i)
    if (m?.[1]) return m[1].trim()
  }
  const x = request.headers.get('x-access-proof')
  return x ? x.trim() : undefined
}

/**
 * Derive the nonce-shard region tag for a request.
 *
 * @param cfg - The resolved gateway config.
 * @param request - The incoming Worker request (Cloudflare `cf` metadata is used when present).
 * @returns A short string identifying the region (continent code or `"g"` for global).
 */
function regionOf(cfg: Config, request: Request): string {
  if (cfg.nonceShard === 'global') return 'g'
  const cf = (request as { cf?: { continent?: string } }).cf
  const continent = cf?.continent?.toLowerCase()
  return continent && NONCE_SHARDS.has(continent) ? continent : 'g'
}

/**
 * The rate-limit key for the client Cloudflare observed (the only trustworthy source at the edge).
 * IPv6 clients are keyed by their /64, since one subscriber controls the whole prefix and could
 * otherwise rotate source addresses to dodge the limit and grow the store. A request that carries
 * no `CF-Connecting-IP` (it did not come through Cloudflare) shares one `unknown` bucket.
 */
export function clientIp(request: Request): string {
  const ip = request.headers.get('CF-Connecting-IP')
  if (!ip) return 'unknown'
  if (!ip.includes(':')) return ip
  // Expand `::` so the first four groups are the /64.
  const [head = '', tail = ''] = ip.split('::')
  const h = head === '' ? [] : head.split(':')
  const t = tail === '' || !ip.includes('::') ? [] : tail.split(':')
  const groups = ip.includes('::') ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t] : h
  return groups.slice(0, 4).map((g) => g.toLowerCase().replace(/^0+(?=.)/, '')).join(':') + '::/64'
}

/**
 * Forward an UNAUTHENTICATED public path (e.g. `/v1/tip-config`) to the upstream, hardened so it
 * can't be used to hammer the single relay origin:
 *   1. Per-client-IP rate limit (keyed on `CF-Connecting-IP`) — a higher ceiling than the gated
 *      per-address limit since these are cheap GETs, but bounded so a flood is rejected at the edge.
 *   2. Edge cache of successful GET responses (tip-config is near-static) via the Cache API, so
 *      repeat/flood reads are served from Cloudflare without reaching the origin at all.
 * Non-GET public requests are still rate-limited but not cached.
 */
async function forwardPublic(
  cfg: Config,
  backend: NonceBackend,
  request: Request,
  region: string,
  ctx: ExecutionContext,
): Promise<Response> {
  if (!(await backend.rateCheck(`ip:${clientIp(request)}`, cfg.publicRateLimitPerMin, region))) {
    return deny(429, 'rate limit exceeded')
  }

  if (request.method !== 'GET' || cfg.publicCacheTtlSecs <= 0) return forward(cfg, request)

  // Public GET paths take no parameters: drop the query string from both the cache key and the
  // forwarded request, so `?x=<random>` can neither bust the cache nor reach the origin with a
  // variant the cache would then serve to everyone.
  const bare = new URL(request.url)
  bare.search = ''
  const cache = (caches as unknown as { default: Cache }).default
  const cacheKey = new Request(bare.toString(), { method: 'GET' })
  const hit = await cache.match(cacheKey)
  if (hit) return hit

  const resp = await forward(cfg, new Request(bare.toString(), request))
  if (resp.ok) {
    const cached = new Response(resp.body, resp)
    cached.headers.set('Cache-Control', `public, max-age=${cfg.publicCacheTtlSecs}`)
    ctx.waitUntil(cache.put(cacheKey, cached.clone()))
    return cached
  }
  return resp
}

/**
 * Main request dispatcher. Handles `/healthz`, `/v1/challenge`, configured public paths,
 * and gated paths (signature + ownership verification before proxying to the upstream).
 *
 * @param request - The incoming HTTP request.
 * @param env - The Worker environment bindings.
 * @returns A `Response` to send to the client.
 */
async function handle(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url)
  const path = url.pathname

  if (path === '/healthz') return new Response('ok', { status: 200 })

  // Handle CORS preflight before any auth check. The browser sends OPTIONS before
  // non-simple cross-origin requests (e.g. PUT/POST with Authorization); responding
  // here avoids the auth path returning 401 and causing the browser to abort.
  if (request.method === 'OPTIONS') return corsPreflightResponse()

  let state: GatewayState
  try {
    state = await getState(env)
  } catch (e) {
    // Missing/invalid required config — fail closed (analogous to Rust's startup abort). The
    // detail goes to the Worker log only; clients learn nothing about the deployment.
    console.error('gateway misconfigured:', (e as Error).message)
    return deny(500, 'gateway misconfigured')
  }
  const { cfg, backend, redemptions, chain } = state

  if (request.method === 'GET' && path === '/v1/challenge') {
    const region = regionOf(cfg, request)
    // Per-IP budget (parity with the Rust gateway): issuing a nonce writes state, so an
    // unauthenticated flood must be bounded before it reaches the store.
    if (!(await backend.rateCheck(`chal:${clientIp(request)}`, cfg.challengeRateLimitPerMin, region))) {
      return deny(429, 'rate limit exceeded')
    }
    const { nonce, expiresAt } = await backend.issue(region, cfg.challengeTtlSecs)
    return json(200, { nonce, expiresAt })
  }

  // Public passthrough (e.g. /v1/tip-config): forward without auth, but protect the single relay
  // origin — these bypass the NFT gate. Per-client-IP rate limit + edge-cache of GET responses.
  if (isPublicPath(cfg, path)) {
    // Unauthenticated paths are read-only: a body-carrying method would reach the relay with no proof.
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const res = deny(405, 'method not allowed')
      res.headers.set('allow', 'GET, HEAD')
      return res
    }
    return forwardPublic(cfg, backend, request, regionOf(cfg, request), ctx)
  }

  if (!FORWARDED_METHODS.includes(request.method)) return deny(405, 'method not allowed')

  const token = extractProofToken(request)
  if (!token) return deny(401, 'missing access proof')

  // Verification costs CPU and a Durable Object call per request, so bound it per client first.
  if (!(await backend.rateCheck(`pre:${clientIp(request)}`, cfg.gatedPreauthRateLimitPerMin, regionOf(cfg, request)))) {
    return deny(429, 'rate limit exceeded')
  }

  const result = await verifyAccessRequest(cfg, backend, token, chain)
  if (!result.ok) {
    const status = result.denied === 'ChainError' ? 502 : 403
    return deny(status, deniedReason(result.denied))
  }

  if (!(await backend.rateCheck(result.address, cfg.rateLimitPerMin, regionOf(cfg, request)))) {
    return deny(429, 'rate limit exceeded')
  }

  // Single-use: the permanent on-chain `consumeDigest` is the one-time redemption token. Lease it,
  // proxy, then COMMIT on a successful upload or RELEASE on failure — so an interrupted upload
  // leaves the consume redeemable (the use is never lost) while a duplicate can't double-spend it.
  if (result.redemptionKey !== undefined) {
    if (!redemptions) throw new Error('single-use verified without a redemption store')
    return redeemAndForward(cfg, redemptions, result.redemptionKey, () => forward(cfg, request))
  }

  return forward(cfg, request)
}

/**
 * Cloudflare Worker entry point. The `fetch` handler routes all HTTP traffic through
 * {@link handle}; the `scheduled` handler runs the optional quota guard on a cron trigger.
 */
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = request.headers.get('origin')
    let res: Response
    try {
      res = await handle(request, env, ctx)
    } catch (e) {
      // Fail closed with a JSON body the browser can read (CORS is still applied below).
      if (e instanceof StoreError) {
        console.error('state backend error:', e.message)
        res = deny(503, 'gateway state unavailable')
      } else {
        console.error('unhandled gateway error:', (e as Error).message)
        res = deny(502, 'bad gateway')
      }
    }
    // State is cached after handle() completes; a second call is free.
    const state = await getState(env).catch(() => null)
    const allowedOrigin = resolveAllowedOrigin(origin, state?.cfg.allowedOrigins ?? [])
    return withCors(res, allowedOrigin)
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    if ((env.QUOTA_GUARD_ENABLED ?? 'false').toLowerCase() === 'true') {
      await runQuotaGuard(env)
    }
  },
}
