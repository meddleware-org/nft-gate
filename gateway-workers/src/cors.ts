/**
 * CORS utilities for the nft-gate Cloudflare Worker.
 *
 * The Worker is accessed from browser origins (e.g. sui-walrus.meddleware.co.uk,
 * sui.meddleware.co.uk) that differ from the Worker's own hostname. Without
 * Access-Control-Allow-Origin headers the browser blocks the response even when
 * the Worker returns 200, and OPTIONS preflights (required before non-simple requests
 * such as PUT uploads with an Authorization header) receive no preflight grant.
 */

const CORS_HEADERS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, x-access-proof',
  'access-control-expose-headers': 'location, upload-offset',
  'access-control-max-age': '86400',
}

/**
 * Clone `res` and add CORS headers. Using `set()` so calling this on an upstream
 * response that already carries CORS headers just overwrites them consistently.
 */
export function withCors(res: Response): Response {
  const out = new Response(res.body, res)
  for (const [k, v] of Object.entries(CORS_HEADERS)) {
    out.headers.set(k, v)
  }
  return out
}

/**
 * Return a minimal 204 preflight response for OPTIONS requests.
 * The browser requires this before sending non-simple cross-origin requests
 * (e.g. PUT/POST with Authorization or Content-Type).
 */
export function corsPreflightResponse(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS })
}
