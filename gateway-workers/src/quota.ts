/**
 * OPTIONAL free-tier quota guard (off by default; `QUOTA_GUARD_ENABLED=true`). Cloudflare
 * exposes account **usage** via the GraphQL Analytics API but **not** per-account *limit*
 * values, so this compares current usage against the published Workers-Free thresholds
 * (constants below — verify against the current pricing docs at deploy time).
 *
 * It (a) logs a warning as usage approaches a threshold and (b) can set a KV "degrade" flag
 * that {@link ../config} consumers may honour to prefer the KV backend before DO limits bite.
 * It never pre-pays or maintains a balance; it needs only a read-only Analytics API token.
 */

import type { Env } from './config.js'

/** Published Workers Free plan monthly request limit. Verify against current pricing docs at deploy time. */
const FREE_REQUESTS_PER_MONTH = 3_000_000
/** Published Workers Free plan monthly Durable Object GB-second limit. Verify against current pricing docs. */
const FREE_DO_GB_S_PER_MONTH = 390_000
/** Log a warning when usage reaches this fraction of any free-tier limit. */
const WARN_AT = 0.8
/** Set the KV degrade flag when usage reaches this fraction of any free-tier limit. */
const DEGRADE_AT = 0.95

/** Cloudflare GraphQL Analytics API endpoint. */
const GRAPHQL_URL = 'https://api.cloudflare.com/client/v4/graphql'

/**
 * Aggregated monthly usage snapshot for this Cloudflare account.
 * `requests` — total Workers + DO invocations this calendar month.
 * `doGbSeconds` — Durable Object GB-seconds of active time this calendar month.
 */
interface Usage {
  requests: number
  doGbSeconds: number
}

/**
 * Run the optional free-tier quota guard. Reads monthly usage via the Cloudflare GraphQL
 * Analytics API, logs a warning near a limit, and sets (or clears) a KV `quota:degrade` flag
 * that the isolate-state bootstrap may honour to prefer the KV nonce backend.
 *
 * @param env - Worker environment bindings. Requires `CF_ANALYTICS_TOKEN` and `CF_ACCOUNT_ID`;
 *   optionally uses `NONCE_KV` to set the degrade flag.
 * @returns Resolves when the check completes (never rejects — errors are logged and suppressed).
 */
export async function runQuotaGuard(env: Env): Promise<void> {
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) {
    console.warn('quota-guard: CF_ANALYTICS_TOKEN / CF_ACCOUNT_ID not set; skipping')
    return
  }
  let usage: Usage
  try {
    usage = await fetchMonthlyUsage(env.CF_ANALYTICS_TOKEN, env.CF_ACCOUNT_ID)
  } catch (e) {
    console.warn('quota-guard: usage query failed:', (e as Error).message)
    return
  }

  const reqPct = usage.requests / FREE_REQUESTS_PER_MONTH
  const doPct = usage.doGbSeconds / FREE_DO_GB_S_PER_MONTH
  const worst = Math.max(reqPct, doPct)

  if (worst >= WARN_AT) {
    console.warn(
      `quota-guard: usage at ${(worst * 100).toFixed(0)}% of a Workers-Free limit ` +
        `(requests ${(reqPct * 100).toFixed(0)}%, DO ${(doPct * 100).toFixed(0)}%)`,
    )
  }
  // Dormant unless a NONCE_KV binding exists (wrangler.toml ships it commented out).
  if (env.NONCE_KV) {
    try {
      if (worst >= DEGRADE_AT) {
        await env.NONCE_KV.put('quota:degrade', '1', { expirationTtl: 3600 })
        console.warn('quota-guard: set KV degrade flag (prefer KV backend)')
      } else {
        await env.NONCE_KV.delete('quota:degrade')
      }
    } catch (e) {
      console.warn('quota-guard: KV degrade-flag update failed:', (e as Error).message)
    }
  }
}

/**
 * Fetch aggregated Workers + DO usage for the current UTC calendar month.
 *
 * @param token - Read-only Cloudflare Analytics API token.
 * @param accountId - Cloudflare account ID (`CF_ACCOUNT_ID`).
 * @returns A {@link Usage} snapshot for the month so far.
 * @throws If the GraphQL HTTP response is not OK.
 */
async function fetchMonthlyUsage(token: string, accountId: string): Promise<Usage> {
  const since = new Date()
  since.setUTCDate(1)
  since.setUTCHours(0, 0, 0, 0)
  const query = `query($accountTag: String!, $since: Time!) {
    viewer { accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: $since }) { sum { requests } }
      durableObjectsInvocationsAdaptiveGroups(limit: 10000, filter: { datetime_geq: $since }) { sum { requests } }
      durableObjectsPeriodicGroups(limit: 10000, filter: { datetime_geq: $since }) { sum { activeTime } }
    } }
  }`
  const resp = await fetch(GRAPHQL_URL, {
    signal: AbortSignal.timeout(15_000),
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ query, variables: { accountTag: accountId, since: since.toISOString() } }),
  })
  if (!resp.ok) throw new Error(`graphql http ${resp.status}`)
  const json = (await resp.json()) as {
    data?: { viewer?: { accounts?: Array<Record<string, Array<{ sum?: { requests?: number; activeTime?: number } }>>> } }
  }
  const acct = json.data?.viewer?.accounts?.[0]
  const sumField = (rows: Array<{ sum?: { requests?: number; activeTime?: number } }> | undefined, key: 'requests' | 'activeTime'): number =>
    (rows ?? []).reduce((n, r) => n + (r.sum?.[key] ?? 0), 0)
  const requests =
    sumField(acct?.workersInvocationsAdaptive, 'requests') +
    sumField(acct?.durableObjectsInvocationsAdaptiveGroups, 'requests')
  // activeTime is reported in microseconds → GB-seconds requires the memory tier; approximate
  // with seconds of active time as a conservative signal (documented; refine per pricing docs).
  const doGbSeconds = sumField(acct?.durableObjectsPeriodicGroups, 'activeTime') / 1_000_000
  return { requests, doGbSeconds }
}
