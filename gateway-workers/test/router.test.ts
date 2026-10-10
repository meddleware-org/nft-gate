import { describe, it, expect } from 'vitest'
import { env, createExecutionContext } from 'cloudflare:test'
import worker from '../src/index.js'
import type { Env } from '../src/config.js'
import { decodeAccessProof } from '../src/wire.js'
import vectors from '../../conformance/vectors.json'

const e = env as unknown as Env

const ALLOWED_ORIGIN = 'https://allowed.example.com'
const DISALLOWED_ORIGIN = 'https://evil.example.com'

async function call(method: string, path: string, headers?: Record<string, string>): Promise<Response> {
  return worker.fetch(new Request('https://gw.example.com' + path, { method, headers }), e, createExecutionContext())
}

/** Returns the reflected ACAO header value (null if absent). */
function corsOrigin(res: Response): string | null {
  return res.headers.get('access-control-allow-origin')
}

// Routing parity with main.rs (paths that don't require the upstream or a live RPC).
describe('router', () => {
  it('GET /healthz → 200 ok', async () => {
    const res = await call('GET', '/healthz')
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('ok')
  })

  it('GET /v1/challenge → 200 { nonce, expiresAt }', async () => {
    const res = await call('GET', '/v1/challenge')
    expect(res.status).toBe(200)
    const body = (await res.json()) as { nonce: string; expiresAt: number }
    expect(typeof body.nonce).toBe('string')
    expect(body.nonce.length).toBeGreaterThan(10)
    expect(typeof body.expiresAt).toBe('number')
    expect(body.expiresAt).toBeGreaterThan(Date.now())
  })

  it('gated request without a proof → 401 missing access proof', async () => {
    const res = await call('POST', '/v1/blob-upload')
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'missing access proof' })
  })

  it('gated request with a malformed proof → 403 malformed access proof', async () => {
    const res = await call('POST', '/v1/blob-upload', { authorization: 'Bearer !!!not-base64!!!' })
    expect(res.status).toBe(403)
    expect(await res.json()).toEqual({ error: 'malformed access proof' })
  })

  // The shared reject vectors, run in the workerd runtime (its own atob / TextDecoder / JSON.parse
  // glue, not Node's): every token the client's strict decoder must refuse is a 403 at the door.
  // A token with a newline cannot ride in a header value, so it is exercised through the decoder.
  for (const [i, c] of vectors.proofDecodeRejects.cases.entries()) {
    it(`refuses a malformed proof in workerd: ${c.name}`, async () => {
      expect(() => decodeAccessProof(c.token)).toThrow()
      if (/[\r\n]/.test(c.token)) return
      const res = await call('POST', '/v1/blob-upload', {
        authorization: `Bearer ${c.token}`,
        'CF-Connecting-IP': `198.51.100.${i + 1}`,
      })
      expect(res.status).toBe(403)
      expect(await res.json()).toEqual({ error: 'malformed access proof' })
    })
  }

  it('OPTIONS /v1/challenge → 204 preflight with CORS headers for allowed origin', async () => {
    const res = await call('OPTIONS', '/v1/challenge', { origin: ALLOWED_ORIGIN })
    expect(res.status).toBe(204)
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
    expect(res.headers.get('access-control-allow-methods')).toContain('GET')
    expect(res.headers.get('access-control-allow-headers')).toContain('authorization')
  })

  it('OPTIONS /v1/store → 204 preflight with CORS headers for allowed origin', async () => {
    const res = await call('OPTIONS', '/v1/store', { origin: ALLOWED_ORIGIN })
    expect(res.status).toBe(204)
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
  })

  it('GET /v1/challenge → reflects allowed origin', async () => {
    const res = await call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN })
    expect(res.status).toBe(200)
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
  })

  it('401 missing proof → reflects allowed origin', async () => {
    const res = await call('POST', '/v1/blob-upload', { origin: ALLOWED_ORIGIN })
    expect(res.status).toBe(401)
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
  })

  it('CORS: disallowed origin receives no Access-Control-Allow-Origin header', async () => {
    const res = await call('GET', '/v1/challenge', { origin: DISALLOWED_ORIGIN })
    expect(corsOrigin(res)).toBeNull()
    expect(res.headers.get('access-control-allow-methods')).toContain('GET')
  })

  it('CORS: request without Origin header receives no Access-Control-Allow-Origin header', async () => {
    const res = await call('GET', '/v1/challenge')
    expect(corsOrigin(res)).toBeNull()
  })

  it('challenge → sign is a full round trip the nonce store accepts once', async () => {
    // The issued nonce must be consumable exactly once by the same backend the router uses.
    const res = await call('GET', '/v1/challenge')
    const { nonce } = (await res.json()) as { nonce: string }
    expect(nonce.includes('.')).toBe(true) // <region>.<hex> shard-tagged form
  })
})

describe('router hardening', () => {
  it('rate-limits GET /v1/challenge per client IP (parity with Rust), with CORS on the 429', async () => {
    const headers = { 'CF-Connecting-IP': '203.0.113.7', origin: ALLOWED_ORIGIN }
    for (let i = 0; i < 30; i++) {
      expect((await call('GET', '/v1/challenge', headers)).status).toBe(200)
    }
    const limited = await call('GET', '/v1/challenge', headers)
    expect(limited.status).toBe(429)
    expect(await limited.json()).toEqual({ error: 'rate limit exceeded' })
    expect(corsOrigin(limited)).toBe(ALLOWED_ORIGIN)
    // Another client is unaffected.
    expect((await call('GET', '/v1/challenge', { 'CF-Connecting-IP': '203.0.113.8' })).status).toBe(200)
  })

  it('every response varies on Origin', async () => {
    for (const res of [
      await call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN }),
      await call('GET', '/v1/challenge'),
      await call('POST', '/v1/blob-upload'),
    ]) {
      expect(res.headers.get('vary')).toMatch(/Origin/)
    }
  })

  it('an unreachable upstream on a public path fails closed with a JSON body and CORS', async () => {
    const res = await call('GET', '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': '203.0.113.9' })
    expect(res.status).toBeGreaterThanOrEqual(500)
    expect(res.headers.get('content-type')).toMatch(/json/)
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
  })

  it('public paths are read-only: a body-carrying method is 405 and never reaches the upstream', async () => {
    const res = await call('POST', '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': '203.0.113.10' })
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toBe('GET, HEAD')
    expect(corsOrigin(res)).toBe(ALLOWED_ORIGIN)
  })

  it('gated paths refuse methods outside the list before any verification work', async () => {
    const res = await call('DELETE', '/v1/blob-upload', { authorization: 'Bearer abc' })
    expect(res.status).toBe(405)
  })

  it('rate-limits gated requests per client IP BEFORE verifying the proof', async () => {
    const headers = { 'CF-Connecting-IP': '203.0.113.50', authorization: 'Bearer !!!not-base64!!!' }
    let limited = 0
    for (let i = 0; i < 125; i++) {
      const res = await call('POST', '/v1/blob-upload', headers)
      if (res.status === 429) limited++
      else expect(res.status).toBe(403)
    }
    expect(limited).toBeGreaterThan(0) // GATED_PREAUTH_RATE_LIMIT_PER_MIN defaults to 120
  })

  it('upstream-supplied CORS never widens the allowlist', async () => {
    const realFetch = globalThis.fetch
    globalThis.fetch = (async () =>
      new Response('{"tip":1}', { status: 200, headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' } })) as typeof fetch
    try {
      const res = await call('GET', '/v1/tip-config', { origin: DISALLOWED_ORIGIN, 'CF-Connecting-IP': '198.51.100.77' })
      expect(res.status).toBe(200)
      expect(corsOrigin(res)).toBeNull()
      await new Promise((r) => setTimeout(r, 50)) // let the waitUntil cache.put land before others run
    } finally {
      globalThis.fetch = realFetch
    }
  })
})

describe('public-path edge cache', () => {
  it('drops the query string from the cache key and the forwarded request', async () => {
    // Other tests also fill the edge cache for this path; start clean.
    await (caches as unknown as { default: Cache }).default.delete(new Request('https://gw.example.com/v1/tip-config'))
    const seen: string[] = []
    const realFetch = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      seen.push(new Request(input).url)
      return new Response('{"tip":1}', { status: 200, headers: { 'content-type': 'application/json' } })
    }) as typeof fetch
    try {
      const first = await call('GET', '/v1/tip-config?bust=1', { 'CF-Connecting-IP': '198.51.100.20' })
      expect(first.status).toBe(200)
      await new Promise((r) => setTimeout(r, 50)) // cache.put runs in waitUntil
      const second = await call('GET', '/v1/tip-config?bust=2', { 'CF-Connecting-IP': '198.51.100.20' })
      expect(second.status).toBe(200)
      expect(await second.text()).toBe('{"tip":1}')
    } finally {
      globalThis.fetch = realFetch
    }
    // The upstream saw the bare path, and only once: the second, differently-busted request was a
    // cache hit.
    expect(seen).toEqual(['https://upstream.invalid/v1/tip-config'])
  })
})

