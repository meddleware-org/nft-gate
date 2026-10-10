import { describe, expect, it } from 'vitest'
// @ts-expect-error — this package carries no @types/node; the unit project runs on Node and has the module
import { spawnSync } from 'node:child_process'
import { classifyOriginResponse } from '../scripts/origin-lock.ts'

// The scheduled negative origin check (audit F32): what counts as "refused by Cloudflare Access".
const h = (o: Record<string, string>) => new Headers(o)

describe('classifyOriginResponse', () => {
  it('401 or 403 from Cloudflare Access is locked', () => {
    expect(classifyOriginResponse(401, h({ 'cf-access-domain': 'walrus-relay-origin.example.com' })).state).toBe('locked')
    expect(classifyOriginResponse(403, h({ 'cf-access-domain': 'walrus-relay-origin.example.com' })).state).toBe('locked')
  })

  it('a redirect to the Access login is locked', () => {
    expect(classifyOriginResponse(302, h({ location: 'https://team.cloudflareaccess.com/cdn-cgi/access/login/x?kid=1' })).state).toBe('locked')
    expect(classifyOriginResponse(302, h({ location: '/cdn-cgi/access/login/x' })).state).toBe('locked')
  })

  it('a refusal that is not Access is open (the lock is not what the audit records)', () => {
    expect(classifyOriginResponse(401, h({})).state).toBe('open')
    expect(classifyOriginResponse(403, h({ server: 'cloudflare' })).state).toBe('open')
  })

  it('a redirect elsewhere, any 2xx, 404 and 5xx are open', () => {
    expect(classifyOriginResponse(302, h({ location: 'https://elsewhere.example.com/' })).state).toBe('open')
    expect(classifyOriginResponse(301, h({})).state).toBe('open')
    expect(classifyOriginResponse(200, h({})).state).toBe('open')
    expect(classifyOriginResponse(200, h({ 'cf-access-domain': 'x' })).state).toBe('open')
    expect(classifyOriginResponse(404, h({})).state).toBe('open')
    expect(classifyOriginResponse(502, h({})).state).toBe('open')
  })

  it('a zone challenge proves nothing', () => {
    expect(classifyOriginResponse(403, h({ 'cf-mitigated': 'challenge' })).state).toBe('inconclusive')
  })
})

describe('check-origin-locked.mjs', () => {
  const proc = (globalThis as unknown as { process: { execPath: string } }).process
  const run = (env: Record<string, string>): { status: number; stdout: string } =>
    spawnSync(proc.execPath, ['scripts/check-origin-locked.mjs'], { env, encoding: 'utf8' })

  it('fails closed when the origin URL is not configured', () => {
    const r = run({})
    expect(r.status).toBe(1)
    expect(r.stdout).toContain('UPSTREAM_CHECK_URL is not set')
  })

  it('refuses a non-https origin URL without sending anything', () => {
    const r = run({ UPSTREAM_CHECK_URL: 'http://origin.invalid/v1/tip-config' })
    expect(r.status).toBe(1)
    expect(r.stdout).toContain('must be an https URL')
  })
})
