import { afterEach, describe, expect, it, vi } from 'vitest'
import { forward } from '../src/proxy.js'
import type { Config } from '../src/config.js'

// Body-size enforcement in the real workerd runtime (streams, FixedLengthStream, abort).
const CAP = 1000
const cfg = {
  upstreamUrl: 'https://upstream.invalid',
  maxBodyBytes: CAP,
  upstreamTimeoutMs: 5000,
  upstreamAuthHeaders: [{ name: 'CF-Access-Client-Id', value: 'svc-id' }],
} as unknown as Config

interface Seen {
  bytes: Uint8Array
  signal: AbortSignal | null
}

/**
 * Read a forwarded body to the end, as the runtime does when sending it. A reader rather than
 * `new Response(body).arrayBuffer()`: in workerd the latter's internal pump reports an errored
 * stream as an unhandled rejection even though the returned promise rejects.
 */
async function drain(body: BodyInit | null | undefined): Promise<Uint8Array> {
  const reader = (body as ReadableStream<Uint8Array>).getReader()
  const parts: Uint8Array[] = []
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    parts.push(value)
  }
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0))
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.byteLength
  }
  return out
}

/** Stub the upstream: read the forwarded body in full, then answer 200 with the byte count. */
function stubUpstream(): Seen[] {
  const seen: Seen[] = []
  vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
    const bytes = await drain(init.body)
    seen.push({ bytes, signal: init.signal ?? null })
    return new Response(String(bytes.byteLength), { status: 200 })
  })
  return seen
}

function payload(n: number): Uint8Array {
  return Uint8Array.from({ length: n }, (_, i) => i % 251)
}

/** A body with no declared length (sent chunked), delivered in `chunk`-byte pieces. */
function chunked(data: Uint8Array, chunk: number): ReadableStream<Uint8Array> {
  let off = 0
  return new ReadableStream({
    pull(controller) {
      if (off >= data.byteLength) return controller.close()
      controller.enqueue(data.slice(off, off + chunk))
      off += chunk
    },
  })
}

function post(body: BodyInit, headers?: Record<string, string>): Request {
  return new Request('https://gw.example.com/v1/blob-upload-relay', { method: 'POST', body, headers })
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('forward body limit', () => {
  it('rejects an over-limit chunked body with 413 and aborts the upstream request', async () => {
    const seen = stubUpstream()
    const req = post(chunked(payload(CAP * 3), 400))
    expect(req.headers.get('content-length')).toBeNull()

    const res = await forward(cfg, req)

    expect(res.status).toBe(413)
    expect(await res.json()).toEqual({ error: 'request body too large' })
    expect(seen).toHaveLength(0) // the upstream never received a complete body
  })

  it('aborts the upstream signal when the cap is crossed', async () => {
    let signal: AbortSignal | undefined
    vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
      signal = init.signal ?? undefined
      await drain(init.body)
      return new Response('unreachable')
    })
    const res = await forward(cfg, post(chunked(payload(CAP + 1), 256)))
    expect(res.status).toBe(413)
    expect(signal?.aborted).toBe(true)
  })

  it('forwards an under-limit chunked body intact', async () => {
    const seen = stubUpstream()
    const data = payload(CAP)
    const res = await forward(cfg, post(chunked(data, 300)))
    expect(res.status).toBe(200)
    expect(seen[0]?.bytes).toEqual(data)
    expect(seen[0]?.signal?.aborted).toBe(false)
  })

  it('forwards an under-limit Content-Length body intact', async () => {
    const seen = stubUpstream()
    const data = payload(CAP - 1)
    const res = await forward(cfg, post(data, { 'content-length': String(data.byteLength) }))
    expect(res.status).toBe(200)
    expect(seen[0]?.bytes).toEqual(data)
  })

  it('rejects a declared over-limit Content-Length with 413 before contacting the upstream', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    const data = payload(CAP + 1)
    const res = await forward(cfg, post(data, { 'content-length': String(data.byteLength) }))
    expect(res.status).toBe(413)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('still answers 502 when the upstream itself fails', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('connection refused')
    })
    const res = await forward(cfg, post(payload(10), { 'content-length': '10' }))
    expect(res.status).toBe(502)
  })
})

describe('forward redirects', () => {
  it('never follows a redirect: the service-token headers must not reach the Location host', async () => {
    const calls: Array<{ url: string; redirect?: string }> = []
    vi.stubGlobal('fetch', async (url: string, init: RequestInit) => {
      calls.push({ url, redirect: init.redirect })
      return new Response(null, { status: 302, headers: { location: 'https://evil.example/steal' } })
    })
    const res = await forward(cfg, new Request('https://gw.example.com/v1/x', { method: 'GET' }))
    expect(calls).toEqual([{ url: 'https://upstream.invalid/v1/x', redirect: 'manual' }])
    expect(res.status).toBe(502)
    expect(res.headers.get('location')).toBeNull()
  })
})

describe('forward deadline', () => {
  it('ends a stalled upstream with 504 once the total deadline passes', async () => {
    vi.stubGlobal(
      'fetch',
      (_url: string, init: RequestInit) =>
        new Promise<Response>((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason))),
    )
    const started = Date.now()
    const res = await forward({ ...cfg, upstreamTimeoutMs: 50 } as Config, new Request('https://gw.example.com/v1/x'))
    expect(res.status).toBe(504)
    expect(Date.now() - started).toBeLessThan(2000)
  })
})

describe('forward header policy', () => {
  it('strips hop-by-hop (and Connection-named), credential and spoofable request fields', async () => {
    let sent: Headers | undefined
    vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
      sent = new Headers(init.headers)
      return new Response('ok')
    })
    await forward(
      cfg,
      new Request('https://gw.example.com/v1/x', {
        headers: {
          connection: 'x-secret-hop, close',
          'x-secret-hop': 'v',
          'keep-alive': 'timeout=5',
          te: 'trailers',
          upgrade: 'websocket',
          'proxy-authorization': 'Basic abc',
          authorization: 'Bearer proof',
          'x-access-proof': 'proof',
          cookie: 'session=1',
          forwarded: 'for=1.2.3.4',
          'x-forwarded-for': '1.2.3.4',
          via: '1.1 evil',
          'cf-access-client-secret': 'client-supplied',
          'x-keep-me': 'yes',
        },
      }),
    )
    for (const name of ['connection', 'x-secret-hop', 'keep-alive', 'te', 'upgrade', 'proxy-authorization', 'authorization', 'x-access-proof', 'cookie', 'forwarded', 'x-forwarded-for', 'via', 'cf-access-client-secret']) {
      expect(sent!.has(name), name).toBe(false)
    }
    expect(sent!.get('x-keep-me')).toBe('yes')
    expect(sent!.get('cf-access-client-id')).toBe('svc-id') // the gateway's own credential, set last
  })

  it('filters the response: no hop-by-hop, cookies or upstream CORS', async () => {
    vi.stubGlobal(
      'fetch',
      async () =>
        new Response('ok', {
          headers: {
            'keep-alive': 'timeout=5',
            'set-cookie': 'a=b',
            'access-control-allow-origin': '*',
            'access-control-allow-credentials': 'true',
            'x-relay': 'kept',
          },
        }),
    )
    const res = await forward(cfg, new Request('https://gw.example.com/v1/x'))
    for (const name of ['keep-alive', 'set-cookie', 'access-control-allow-origin', 'access-control-allow-credentials']) {
      expect(res.headers.has(name), name).toBe(false)
    }
    expect(res.headers.get('x-relay')).toBe('kept')
  })

  it('refuses a method outside the list and an unsafe path before contacting the upstream', async () => {
    const spy = vi.fn()
    vi.stubGlobal('fetch', spy)
    expect((await forward(cfg, new Request('https://gw.example.com/v1/x', { method: 'DELETE' }))).status).toBe(405)
    expect((await forward(cfg, new Request('https://gw.example.com/a%2fb'))).status).toBe(400)
    expect((await forward(cfg, new Request('https://gw.example.com/a//b'))).status).toBe(400)
    expect(spy).not.toHaveBeenCalled()
  })
})
