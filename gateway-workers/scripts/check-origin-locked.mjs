// Scheduled negative origin check (audit F32 / CF-M2; .github/workflows/origin-lock.yml).
//
// The relay origin must be reachable ONLY with the gateway's Cloudflare Access service token. The
// deploy check (check-upstream-auth.mjs) proves the positive case; this proves the negative: direct
// requests WITHOUT the token, and with a made-up token, must be refused by Access. Read-only, GET
// only, sends no secret (the origin URL is the public repository variable UPSTREAM_CHECK_URL).
//
//   UPSTREAM_CHECK_URL=https://<origin>/v1/tip-config node scripts/check-origin-locked.mjs
//
// Exit 0: every probe was refused by Access (a challenged probe only warns). Exit 1: a probe reached
// the origin, was refused by something other than Access, or could not be completed.
// Run from gateway-workers/ (Node 24 strips the .ts types).
import { classifyOriginResponse } from './origin-lock.ts'

const raw = process.argv[2] ?? process.env.UPSTREAM_CHECK_URL
if (!raw) {
  console.log('::error::UPSTREAM_CHECK_URL is not set (repository variable); the origin lock cannot be checked.')
  process.exit(1)
}
const checkUrl = new URL(raw)
if (checkUrl.protocol !== 'https:') {
  console.log('::error::UPSTREAM_CHECK_URL must be an https URL.')
  process.exit(1)
}

const bogusToken = { 'CF-Access-Client-Id': `${'0'.repeat(32)}.access`, 'CF-Access-Client-Secret': '0'.repeat(64) }
const probes = [
  { label: 'no token, check path', url: checkUrl, headers: {} },
  { label: 'no token, root', url: new URL('/', checkUrl), headers: {} },
  { label: 'unknown token, check path', url: checkUrl, headers: bogusToken },
]

async function probe({ url, headers }) {
  let lastError
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { method: 'GET', headers, redirect: 'manual', signal: AbortSignal.timeout(15_000) })
      await res.body?.cancel()
      return classifyOriginResponse(res.status, res.headers)
    } catch (e) {
      lastError = e
      await new Promise((r) => setTimeout(r, attempt * 3000))
    }
  }
  return { state: 'error', detail: `request failed after 3 attempts: ${lastError?.message ?? lastError}` }
}

let failures = 0
let inconclusive = 0
for (const p of probes) {
  const v = await probe(p)
  console.log(`${v.state.padEnd(12)} ${p.label} (${p.url.host}${p.url.pathname}): ${v.detail}`)
  if (v.state === 'inconclusive') inconclusive++
  else if (v.state !== 'locked') failures++
}
if (failures > 0) {
  console.log(`::error::Origin lock check failed (${failures} of ${probes.length} probes): the relay origin is not refusing direct requests as Cloudflare Access should (docs/networking/CLOUDFLARE.md section 2.4).`)
  process.exit(1)
}
if (inconclusive > 0) {
  console.log(`::warning::${inconclusive} of ${probes.length} probes were challenged by the zone (Bot Fight Mode) and prove nothing; the others were refused by Access.`)
}
console.log('Origin lock holds: direct requests without the service token are refused by Access.')
