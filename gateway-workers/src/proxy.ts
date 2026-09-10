/**
 * Reverse-proxy an authorised request to the configured upstream. Mirror of the Rust
 * gateway's `proxy.rs`: body capped at `maxBodyBytes` before forwarding; `Host` /
 * `Authorization` / `Content-Length` stripped from the request; hop-unsafe headers stripped
 * from the response.
 *
 * `cfg.upstreamAuthHeaders` are injected on the upstream fetch — use this to pass
 * Cloudflare Access service-token headers when the relay origin is Access-locked.
 */

import type { Config } from './config.js'

/**
 * Build a JSON `{"error": reason}` response with the given status code.
 *
 * @param status - HTTP status code.
 * @param reason - Short, client-visible error description.
 * @returns A JSON error response.
 */
function errorResponse(status: number, reason: string): Response {
  return new Response(JSON.stringify({ error: reason }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Forward an authorised request to the configured upstream origin.
 *
 * Strips `Host`, `Authorization`, `X-Access-Proof`, and `Content-Length` from the request;
 * strips `Content-Length`, `Transfer-Encoding`, and `Connection` from the response.
 * Injects `cfg.upstreamAuthHeaders` on the upstream fetch (e.g. CF Access service-token headers).
 * Returns 413 if the body exceeds `cfg.maxBodyBytes`.
 *
 * @param cfg - The resolved gateway config.
 * @param request - The original incoming Worker request.
 * @returns The upstream response, or an error response on failure.
 * @throws Never — upstream failures are caught and returned as 502.
 */
export async function forward(cfg: Config, request: Request): Promise<Response> {
  const url = new URL(request.url)
  const pathAndQuery = url.pathname + url.search
  const upstreamUrl = cfg.upstreamUrl + pathAndQuery

  // Size guard: check Content-Length first (cheap, avoids buffering). Not authoritative
  // (clients can lie) but protects against accidental oversized sends; the relay enforces
  // its own hard limit. Stream the body directly — buffering 60+ MB encoded blobs into an
  // ArrayBuffer would exhaust Worker memory for large Walrus uploads.
  const method = request.method.toUpperCase()
  if (method !== 'GET' && method !== 'HEAD') {
    const cl = parseInt(request.headers.get('content-length') ?? '', 10)
    if (Number.isFinite(cl) && cl > cfg.maxBodyBytes) {
      return errorResponse(413, 'request body too large')
    }
  }
  const body: ReadableStream | null | undefined =
    method !== 'GET' && method !== 'HEAD' ? request.body : undefined

  const headers = new Headers(request.headers)
  headers.delete('host')
  headers.delete('authorization')
  headers.delete('x-access-proof')
  headers.delete('content-length')

  // Inject upstream auth headers (e.g. CF Access service token for the locked relay origin).
  for (const { name, value } of cfg.upstreamAuthHeaders) {
    headers.set(name, value)
  }

  let upstream: Response
  try {
    upstream = await fetch(upstreamUrl, {
      method: request.method,
      headers,
      body: body ?? null,
      // @ts-expect-error — CF Workers supports streaming body via ReadableStream without 'duplex'
      duplex: 'half',
    })
  } catch {
    return errorResponse(502, 'upstream error')
  }

  // Strip hop-unsafe / recomputed headers from the response.
  const outHeaders = new Headers(upstream.headers)
  outHeaders.delete('content-length')
  outHeaders.delete('transfer-encoding')
  outHeaders.delete('connection')

  return new Response(upstream.body, { status: upstream.status, headers: outHeaders })
}
