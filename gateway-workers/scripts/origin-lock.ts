// Pure verdict logic for scripts/check-origin-locked.mjs (the scheduled negative origin check, audit
// F32). No imports: Node strips the types when the script loads it, and the unit tests import it too.
//
// The upstream origin is locked by a Cloudflare Access application whose policy admits only the
// Worker's service token. A request WITHOUT that token must be refused by Access itself:
//   - 401/403 carrying `cf-access-domain` (a service-auth policy answers like this), or
//   - a redirect to the Access login (`<team>.cloudflareaccess.com` or `/cdn-cgi/access/…`).
// Anything else that reaches the origin or is refused by something other than Access means the lock
// is not what the audit records.

export type OriginLockState = 'locked' | 'open' | 'inconclusive'

export interface OriginLockVerdict {
  state: OriginLockState
  detail: string
}

type HeaderReader = { get(name: string): string | null }

export function classifyOriginResponse(status: number, headers: HeaderReader): OriginLockVerdict {
  // Bot Fight Mode can challenge a CI runner before Access sees it. That proves nothing either way.
  if (headers.get('cf-mitigated') === 'challenge') {
    return { state: 'inconclusive', detail: `HTTP ${status}, the zone challenged this client (cf-mitigated: challenge)` }
  }
  if (status === 401 || status === 403) {
    return headers.get('cf-access-domain')
      ? { state: 'locked', detail: `HTTP ${status} from Cloudflare Access` }
      : { state: 'open', detail: `HTTP ${status} but not from Cloudflare Access (no cf-access-domain header)` }
  }
  if (status >= 300 && status < 400) {
    const location = headers.get('location') ?? ''
    let toAccess = false
    try {
      const u = new URL(location, 'https://origin.invalid')
      toAccess = u.hostname.endsWith('.cloudflareaccess.com') || u.pathname.startsWith('/cdn-cgi/access/')
    } catch {
      toAccess = false
    }
    return toAccess
      ? { state: 'locked', detail: `HTTP ${status} redirect to the Access login` }
      : { state: 'open', detail: `HTTP ${status} redirect that does not go to the Access login` }
  }
  if (status >= 200 && status < 300) return { state: 'open', detail: `HTTP ${status}: the origin answered a request without the service token` }
  return { state: 'open', detail: `HTTP ${status}: not an Access refusal` }
}
