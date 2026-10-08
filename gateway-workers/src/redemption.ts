/**
 * Single-use redemption flow, kept out of the Worker entry module so it can be tested directly
 * (the entry module may only export the fetch/scheduled handlers and Durable Object classes).
 */

import type { Config } from './config.js'
import type { RedemptionStore } from './state/types.js'

/** JSON `{"error": reason, code?}` response. */
function deny(status: number, reason: string, code?: string): Response {
  return new Response(JSON.stringify(code ? { error: reason, code } : { error: reason }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Single-use: the permanent on-chain `consumeDigest` is the one-time redemption token. Lease it
 * (the lease returns an owner token), proxy, then COMMIT on a successful upload or RELEASE on
 * failure, both presenting the token — so an interrupted upload leaves the consume redeemable (the
 * use is never lost), a duplicate can't double-spend it, and a request whose lease lapsed can never
 * clear or overwrite a newer holder's. The lease outlives the upload deadline (checked at startup).
 *
 * A commit that fails after a successful upload, or finds its lease lost, is reported as `502`,
 * never as success. Store errors propagate to the caller (answered `503`, never as a conflict).
 */
export async function redeemAndForward(
  cfg: Config,
  store: RedemptionStore,
  redemptionKey: string,
  send: () => Promise<Response>,
): Promise<Response> {
  const lease = await store.tryLeaseRedemption(redemptionKey, cfg.redemptionLeaseTtlSecs)
  if (lease.status === 'redeemed') {
    return deny(409, 'this consume has already been redeemed for an upload', 'redeemed')
  }
  if (lease.status === 'leased') {
    return deny(409, 'an upload for this consume is already in progress', 'leased')
  }
  const { token } = lease
  let resp: Response
  try {
    resp = await send()
  } catch (e) {
    // Exception before a definitive upstream result — release so the user can retry.
    await store.releaseRedemption(redemptionKey, token).catch(() => {})
    throw e
  }
  if (!resp.ok) {
    await store.releaseRedemption(redemptionKey, token).catch(() => {})
    return resp
  }
  try {
    if ((await store.commitRedemption(redemptionKey, token, cfg.redemptionRetentionSecs)) === 'lost') {
      // The lease lapsed or moved: the upload happened but is not recorded by us. Never report
      // success for a redemption we do not hold (and leave the new holder's lease alone).
      console.error('redemption lease lost before commit')
      return deny(502, 'redemption lease lost')
    }
  } catch (e) {
    // Never report success for a redemption we could not record. Release the lease (best effort)
    // so the user's consume stays usable.
    console.error('commitRedemption failed:', (e as Error).message)
    await store.releaseRedemption(redemptionKey, token).catch(() => {})
    return deny(502, 'redemption commit failed')
  }
  return resp
}
