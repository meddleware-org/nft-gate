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
import type { NonceBackend } from './state/types.js'
import { makeBackend } from './state/select.js'
import { SuiRpc } from './chain.js'
import { verifyAccessRequest, deniedReason } from './verify.js'
import { forward } from './proxy.js'
import { runQuotaGuard } from './quota.js'
import { withCors, corsPreflightResponse } from './cors.js'

export { NonceRateState } from './state/durable_object.js'

/**
 * Per-isolate cached gateway state. Holds the fully resolved config, the chosen nonce
 * backend, and the Sui RPC client so they persist across requests within the same isolate.
 */
interface GatewayState {
  cfg: Config
  backend: NonceBackend
  chain: SuiRpc
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
  // free-tier limits bite (only when a KV binding is available).
  let effective = cfg
  if (cfg.nonceBackend === 'durable-object' && env.NONCE_KV) {
    try {
      if (await env.NONCE_KV.get('quota:degrade')) effective = { ...cfg, nonceBackend: 'kv' }
    } catch {
      /* ignore — stay on the configured backend */
    }
  }
  cached = {
    cfg,
    backend: makeBackend(effective, env),
    chain: new SuiRpc(cfg.suiRpcUrl, cfg.ownershipCacheTtlMs, cfg.suiRpcAuthHeader),
  }
  return cached
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
 * Build a JSON `{"error": reason}` response with the given status code.
 *
 * @param status - HTTP status code.
 * @param reason - Short, client-visible error description.
 * @returns A JSON error response.
 */
function deny(status: number, reason: string): Response {
  return json(status, { error: reason })
}

/** Prefer `Authorization: Bearer <token>`; fall back to an explicit `X-Access-Proof` header. */
function extractProofToken(request: Request): string | undefined {
  const auth = request.headers.get('authorization')
  if (auth) {
    const m = auth.match(/^Bearer\s+(.+)$/i)
    if (m) return m[1].trim()
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
  const continent = cf?.continent
  return continent ? continent.toLowerCase() : 'g'
}

/**
 * Main request dispatcher. Handles `/healthz`, `/v1/challenge`, configured public paths,
 * and gated paths (signature + ownership verification before proxying to the upstream).
 *
 * @param request - The incoming HTTP request.
 * @param env - The Worker environment bindings.
 * @returns A `Response` to send to the client.
 */
async function handle(request: Request, env: Env): Promise<Response> {
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
    // Missing/invalid required config — fail closed (analogous to Rust's startup abort).
    return deny(500, `gateway misconfigured: ${(e as Error).message}`)
  }
  const { cfg, backend, chain } = state

  if (request.method === 'GET' && path === '/v1/challenge') {
    const { nonce, expiresAt } = await backend.issue(regionOf(cfg, request), cfg.challengeTtlSecs)
    return json(200, { nonce, expiresAt })
  }

  // Public passthrough (e.g. /v1/tip-config): forward without auth.
  if (isPublicPath(cfg, path)) return forward(cfg, request)

  const token = extractProofToken(request)
  if (!token) return deny(401, 'missing access proof')

  const result = await verifyAccessRequest(cfg, backend, token, chain)
  if (!result.ok) {
    const status = result.denied === 'ChainError' ? 502 : 403
    return deny(status, deniedReason(result.denied))
  }

  if (!(await backend.rateCheck(result.address, cfg.rateLimitPerMin, regionOf(cfg, request)))) {
    return deny(429, 'rate limit exceeded')
  }

  return forward(cfg, request)
}

/**
 * Cloudflare Worker entry point. The `fetch` handler routes all HTTP traffic through
 * {@link handle}; the `scheduled` handler runs the optional quota guard on a cron trigger.
 */
export default {
  fetch(request: Request, env: Env): Promise<Response> {
    return handle(request, env).then(withCors)
  },
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    if ((env.QUOTA_GUARD_ENABLED ?? 'false').toLowerCase() === 'true') {
      await runQuotaGuard(env)
    }
  },
}
