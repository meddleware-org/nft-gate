/**
 * Reverse-proxy an authorised request to the configured upstream. Mirror of the Rust
 * gateway's `proxy.rs`: body capped at `maxBodyBytes` (413 past it); `Host` /
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

/** Raised inside the body stream once more than `maxBodyBytes` have been read. */
class BodyTooLargeError extends Error {
  constructor() {
    super('request body too large')
  }
}

/**
 * Pass `body` through unchanged while counting bytes; once the running total exceeds `max`,
 * call `onExceeded` and error the stream so the upstream fetch fails instead of receiving the
 * excess. The body is never buffered — memory stays at one chunk regardless of size.
 *
 * @param body - The incoming request body.
 * @param max - Maximum number of bytes allowed through.
 * @param onExceeded - Called once, before the stream errors, when the limit is crossed.
 * @returns The counted stream to forward upstream.
 */
export function limitBody(
  body: ReadableStream<Uint8Array>,
  max: number,
  onExceeded: () => void,
): ReadableStream<Uint8Array> {
  let seen = 0
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      seen += chunk.byteLength
      if (seen > max) {
        onExceeded()
        controller.error(new BodyTooLargeError())
        return
      }
      controller.enqueue(chunk)
    },
  })
  // The pipe rejects when the counter errors the stream; the error reaches the consumer through
  // `readable`, so the pipe's own rejection is expected and deliberately swallowed.
  body.pipeTo(writable).catch(() => {})
  return readable
}

/**
 * Forward an authorised request to the configured upstream origin.
 *
 * Strips `Host`, `Authorization`, `X-Access-Proof`, and `Content-Length` from the request;
 * strips `Content-Length`, `Transfer-Encoding`, and `Connection` from the response.
 * Injects `cfg.upstreamAuthHeaders` on the upstream fetch (e.g. CF Access service-token headers).
 * Returns 413 if the body exceeds `cfg.maxBodyBytes`: up front when `Content-Length` says so,
 * otherwise as soon as the streamed byte count crosses the cap (the upstream fetch is aborted).
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

  // Size guard, two layers. Content-Length first: cheap, rejects a declared oversize body before
  // any upstream work. It is not sufficient on its own — a chunked body declares no length — so
  // the body is also streamed through a byte counter that aborts the upstream request past the
  // cap. Never buffer: 60+ MB encoded Walrus blobs would exhaust Worker memory.
  const method = request.method.toUpperCase()
  const hasBody = method !== 'GET' && method !== 'HEAD'
  const cl = hasBody ? parseInt(request.headers.get('content-length') ?? '', 10) : NaN
  if (Number.isFinite(cl) && cl > cfg.maxBodyBytes) {
    return errorResponse(413, 'request body too large')
  }
  const abort = new AbortController()
  let tooLarge = false
  let body: ReadableStream<Uint8Array> | null = null
  if (hasBody && request.body) {
    body = limitBody(request.body, cfg.maxBodyBytes, () => {
      tooLarge = true
      abort.abort()
    })
    // Re-attach the declared length (a transform stream has none) so the upstream still gets a
    // Content-Length-framed body rather than a chunked one.
    if (Number.isFinite(cl) && cl >= 0) body = body.pipeThrough(new FixedLengthStream(cl))
  }

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
      body,
      signal: abort.signal,
      // @ts-expect-error — CF Workers supports streaming body via ReadableStream without 'duplex'
      duplex: 'half',
    })
  } catch {
    return tooLarge ? errorResponse(413, 'request body too large') : errorResponse(502, 'upstream error')
  }
  if (tooLarge) {
    // The upstream answered before the counter tripped (e.g. an early error status); the body it
    // saw was cut short, so report the limit rather than a response to a truncated request.
    return errorResponse(413, 'request body too large')
  }

  // Strip hop-unsafe / recomputed headers from the response.
  const outHeaders = new Headers(upstream.headers)
  outHeaders.delete('content-length')
  outHeaders.delete('transfer-encoding')
  outHeaders.delete('connection')

  return new Response(upstream.body, { status: upstream.status, headers: outHeaders })
}
