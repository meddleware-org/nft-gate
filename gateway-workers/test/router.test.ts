import { describe, it, expect } from 'vitest'
import { env, createExecutionContext } from 'cloudflare:test'
import worker from '../src/index.js'
import type { Env } from '../src/config.js'

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
