// Pre-deploy check for a GitHub-held UPSTREAM_AUTH_HEADERS (used by deploy-workers.yml).
//
// 1. Parses the value with the Worker's own parser (a malformed value fails the deploy).
// 2. Prints non-revealing diagnostics: header names, value lengths, whether a Cloudflare Access
//    service-token pair has the expected shape (client id `<32 hex>.access`, secret `<64 hex>`).
// 3. When UPSTREAM_CHECK_URL is set, sends the headers to that origin URL and fails unless it
//    answers 2xx — so credentials the origin rejects never reach production traffic.
//
// Never prints a value. Run from gateway-workers/ (Node 24 strips the .ts types).
import { parseUpstreamAuthHeaders } from '../src/config.ts'

const headers = parseUpstreamAuthHeaders(process.env.UPSTREAM_AUTH_HEADERS)
if (headers.length === 0) throw new Error('UPSTREAM_AUTH_HEADERS has no headers')

const SHAPES = {
  'cf-access-client-id': [/^[0-9a-f]{32}\.access$/, '<32 hex>.access (39 chars)'],
  'cf-access-client-secret': [/^[0-9a-f]{64}$/, '<64 hex> (64 chars)'],
}
let shapeProblems = 0
for (const { name, value } of headers) {
  const shape = SHAPES[name.toLowerCase()]
  const notes = [`length ${value.length}`]
  if (value !== value.trim()) notes.push('leading/trailing whitespace')
  if (/:\s/.test(value)) notes.push('contains ": " (a whole header line pasted as the value?)')
  if (shape) {
    const ok = shape[0].test(value)
    notes.push(ok ? 'shape ok' : `unexpected shape, want ${shape[1]}`)
    if (!ok) shapeProblems++
  }
  console.log(`  ${name}: ${notes.join(', ')}`)
}
console.log(`UPSTREAM_AUTH_HEADERS: ${headers.length} header(s)`)
if (shapeProblems > 0) {
  console.log(`::warning::${shapeProblems} Cloudflare Access header value(s) do not have the expected shape`)
}

const url = process.env.UPSTREAM_CHECK_URL
if (!url) {
  console.log('UPSTREAM_CHECK_URL not set: skipping the origin check')
} else {
  const res = await fetch(url, {
    headers: Object.fromEntries(headers.map((h) => [h.name, h.value])),
    redirect: 'manual',
    signal: AbortSignal.timeout(15_000),
  })
  const via = res.headers.get('cf-access-domain') ? ' (rejected by Cloudflare Access)' : ''
  console.log(`Origin check ${new URL(url).host}: HTTP ${res.status}${via}`)
  if (!res.ok) {
    // Say who rejected it (Access, a WAF/bot rule, or the origin) without echoing any request data.
    const title = ((await res.text()).match(/<title>([^<]{0,120})<\/title>/i) ?? [])[1]
    for (const h of ['server', 'cf-mitigated', 'cf-access-domain', 'www-authenticate']) {
      if (res.headers.get(h)) console.log(`  ${h}: ${res.headers.get(h)}`)
    }
    if (title) console.log(`  page title: ${title.trim()}`)
    console.log('::error::The origin rejected UPSTREAM_AUTH_HEADERS; not deploying.')
    process.exit(1)
  }
}
