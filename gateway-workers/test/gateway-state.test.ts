import { afterEach, describe, expect, it, vi } from 'vitest'
import { env, createExecutionContext } from 'cloudflare:test'
import type { Env } from '../src/config.js'
import { forward } from '../src/proxy.js'
import type { Config } from '../src/config.js'
import worker, { clientIp } from '../src/index.js'

// Router-level behaviour that depends on per-isolate state or on a failing binding. The gateway
// caches its resolved state per isolate (module), so ORDER MATTERS in this file:
//   1. the static `worker` import serves the Durable Object tests; its state is built by the first
//      request, which is why the degrade-flag-ignored test comes first, with the flag already set;
//   2. the last two describes load a fresh copy of the module (`vi.resetModules`), which makes
//      workerd invalidate the Durable Object host, so nothing that needs the Durable Object may
//      follow them.
const base = env as unknown as Env
const ALLOWED_ORIGIN = 'https://allowed.example.com'

type Worker = { fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> }

async function freshWorker(): Promise<Worker> {
  vi.resetModules()
  return (await import('../src/index.js')).default as unknown as Worker
}

function req(path: string, headers?: Record<string, string>, method = 'GET'): Request {
  return new Request('https://gw.example.com' + path, { method, headers })
}

async function kvKeys(prefix: string): Promise<string[]> {
  return (await base.NONCE_KV!.list({ prefix })).keys.map((k) => k.name)
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('quota-degrade flag in single-use mode (F2, F30)', () => {
  it('is ignored: nonces stay on the Durable Object and nothing lands in KV', async () => {
    await base.NONCE_KV!.put('quota:degrade', '1')
    try {
      const before = (await kvKeys('nonce:')).length
      const res = await worker.fetch(req('/v1/challenge', { 'CF-Connecting-IP': '192.0.2.34' }), base, createExecutionContext())
      expect(res.status).toBe(200)
      expect((await kvKeys('nonce:')).length).toBe(before)
    } finally {
      await base.NONCE_KV!.delete('quota:degrade')
    }
  })
})

describe('rate limits (F9, F30)', () => {
  it('rate-limits public paths per client IP, before the cache and the upstream', async () => {
    vi.stubGlobal('fetch', async () => new Response('{"tip":1}', { status: 200 }))
    const call = (ip: string) =>
      worker.fetch(req('/v1/tip-config', { 'CF-Connecting-IP': ip, origin: ALLOWED_ORIGIN }), base, createExecutionContext())
    for (let i = 0; i < 120; i++) expect((await call('192.0.2.35')).status).toBe(200) // PUBLIC_RATE_LIMIT_PER_MIN = 120
    const limited = await call('192.0.2.35')
    expect(limited.status).toBe(429)
    expect(await limited.json()).toEqual({ error: 'rate limit exceeded' })
    expect(limited.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN)
    // Another client is unaffected.
    expect((await call('192.0.2.36')).status).toBe(200)
  })

  it('keys IPv6 clients by their /64', async () => {
    const ip = (value: string) => clientIp(req('/', { 'CF-Connecting-IP': value }))
    expect(ip('2001:db8:1:2:aaaa:bbbb:cccc:dddd')).toBe('2001:db8:1:2::/64')
    expect(ip('2001:DB8:1:2::1')).toBe('2001:db8:1:2::/64')
    expect(ip('2001:0db8:0001:0002:0:0:0:9')).toBe('2001:db8:1:2::/64')
    expect(ip('2001:db8::1')).toBe('2001:db8:0:0::/64')
    expect(ip('2001:db8:1:3::1')).not.toBe(ip('2001:db8:1:2::1'))
    expect(ip('203.0.113.9')).toBe('203.0.113.9')
    expect(clientIp(req('/'))).toBe('unknown')

    // Rotating the low 64 bits does not buy a fresh budget (CHALLENGE_RATE_LIMIT_PER_MIN = 30).
    const call = (addr: string) => worker.fetch(req('/v1/challenge', { 'CF-Connecting-IP': addr }), base, createExecutionContext())
    for (let i = 0; i < 30; i++) expect((await call(`2001:db8:a:b::${i + 1}`)).status).toBe(200)
    expect((await call('2001:db8:a:b:f::99')).status).toBe(429)
    expect((await call('2001:db8:a:c::1')).status).toBe(200)
  })
})

describe('gated responses are never cached (F30)', () => {
  it('forwarding a gated request neither reads nor writes the edge cache', async () => {
    const cache = (caches as unknown as { default: Cache }).default
    const put = vi.spyOn(cache, 'put')
    const match = vi.spyOn(cache, 'match')
    vi.stubGlobal('fetch', async () => new Response('stored', { status: 200, headers: { 'cache-control': 'public, max-age=3600' } }))
    const cfg = { upstreamUrl: 'https://upstream.invalid', maxBodyBytes: 1000, upstreamTimeoutMs: 5000, upstreamAuthHeaders: [] } as unknown as Config
    const request = new Request('https://gw.example.com/v1/blob-upload', { method: 'GET' })
    const res = await forward(cfg, request)
    expect(res.status).toBe(200)
    await new Promise((r) => setTimeout(r, 20))
    expect(put).not.toHaveBeenCalled()
    expect(match).not.toHaveBeenCalled()
    match.mockRestore()
    put.mockRestore()
    expect(await cache.match(request)).toBeUndefined()
  })
})

// From here on each test loads a fresh module copy; see the note at the top.
describe('quota-degrade flag in ownership mode (F2, F30)', () => {
  it('moves nonce issuing to KV when set', async () => {
    const fresh = await freshWorker()
    await base.NONCE_KV!.put('quota:degrade', '1')
    try {
      const before = (await kvKeys('nonce:')).length
      const res = await fresh.fetch(
        req('/v1/challenge', { 'CF-Connecting-IP': '192.0.2.32' }),
        { ...base, SINGLE_USE: 'false' },
        createExecutionContext(),
      )
      expect(res.status).toBe(200)
      const { nonce } = (await res.json()) as { nonce: string }
      const after = await kvKeys('nonce:')
      expect(after).toContain(`nonce:${nonce}`)
      expect(after.length).toBe(before + 1)
    } finally {
      await base.NONCE_KV!.delete('quota:degrade')
    }
  })
})

describe('store outage (F30)', () => {
  it('answers a JSON 503 with CORS when the Durable Object binding throws', async () => {
    const fresh = await freshWorker()
    const broken = {
      idFromName() {
        throw new Error('durable object unavailable')
      },
      get() {
        throw new Error('durable object unavailable')
      },
    } as unknown as DurableObjectNamespace
    const res = await fresh.fetch(
      req('/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': '192.0.2.31' }),
      { ...base, NONCE_STATE: broken },
      createExecutionContext(),
    )
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: 'gateway state unavailable' })
    expect(res.headers.get('access-control-allow-origin')).toBe(ALLOWED_ORIGIN)
  })
})
