/**
 * CORS utilities for the nft-gate Cloudflare Worker.
 *
 * The Worker is accessed from browser origins (e.g. sui-walrus.meddleware.co.uk,
 * sui.meddleware.co.uk) that differ from the Worker's own hostname. Without
 * Access-Control-Allow-Origin headers the browser blocks the response even when
 * the Worker returns 200, and OPTIONS preflights (required before non-simple requests
 * such as PUT uploads with an Authorization header) receive no preflight grant.
 *
 * Origin allowlist: rather than reflecting `*`, only origins present in the configured
 * ALLOWED_ORIGINS list receive the Access-Control-Allow-Origin header. An absent or
 * disallowed origin gets no CORS header — the browser blocks the cross-origin request,
 * which is the correct fail-closed behaviour.
 */

const CORS_STATIC_HEADERS: Record<string, string> = {
  'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, x-access-proof',
  'access-control-expose-headers': 'location, upload-offset',
  'access-control-max-age': '86400',
}

/**
 * Resolve the reflected `Access-Control-Allow-Origin` value for a request.
 * Returns the request origin if it appears in `allowedOrigins`, otherwise `null`.
 */
export function resolveAllowedOrigin(
  requestOrigin: string | null,
  allowedOrigins: string[],
): string | null {
  if (!requestOrigin || !allowedOrigins.includes(requestOrigin)) return null
  return requestOrigin
}

/**
 * Clone `res` and add CORS headers. If `allowedOrigin` is non-null, it is reflected
 * as `Access-Control-Allow-Origin`; otherwise that header is omitted (fail closed).
 */
export function withCors(res: Response, allowedOrigin: string | null): Response {
  const out = new Response(res.body, res)
  if (allowedOrigin) out.headers.set('access-control-allow-origin', allowedOrigin)
  for (const [k, v] of Object.entries(CORS_STATIC_HEADERS)) {
    out.headers.set(k, v)
  }
  return out
}

/**
 * Return a minimal 204 preflight response for OPTIONS requests.
 * The Access-Control-Allow-Origin header is added by the outer withCors wrapper.
 */
export function corsPreflightResponse(): Response {
  return new Response(null, { status: 204, headers: CORS_STATIC_HEADERS })
}
