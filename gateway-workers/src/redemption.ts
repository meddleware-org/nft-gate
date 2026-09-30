/**
 * Single-use redemption flow, kept out of the Worker entry module so it can be tested directly
 * (the entry module may only export the fetch/scheduled handlers and Durable Object classes).
 */

import type { Config } from './config.js'
import type { NonceBackend } from './state/types.js'

/** JSON `{"error": reason, code?}` response. */
function deny(status: number, reason: string, code?: string): Response {
  return new Response(JSON.stringify(code ? { error: reason, code } : { error: reason }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/**
 * Single-use: the permanent on-chain `consumeDigest` is the one-time redemption token. Lease it,
 * proxy, then COMMIT on a successful upload or RELEASE on failure — so an interrupted upload leaves
 * the consume redeemable (the use is never lost) while a duplicate can't double-spend it. A commit
 * that fails after a successful upload is reported as `502` (Rust parity), never as success.
 */
export async function redeemAndForward(
  cfg: Config,
  backend: NonceBackend,
  redemptionKey: string,
  send: () => Promise<Response>,
): Promise<Response> {
  const lease = await backend.tryLeaseRedemption(redemptionKey, cfg.redemptionLeaseTtlSecs)
  if (lease === 'redeemed') {
    return deny(409, 'this consume has already been redeemed for an upload', 'redeemed')
  }
  if (lease === 'leased') {
    return deny(409, 'an upload for this consume is already in progress', 'leased')
  }
  let resp: Response
  try {
    resp = await send()
  } catch (e) {
    // Network/exception before a definitive upstream result — release so the user can retry.
    await backend.releaseRedemption(redemptionKey)
    throw e
  }
  if (!resp.ok) {
    await backend.releaseRedemption(redemptionKey)
    return resp
  }
  try {
    await backend.commitRedemption(redemptionKey, cfg.redemptionRetentionSecs)
  } catch (e) {
    // Never report success for a redemption we could not record. Release the lease (best effort)
    // so the user's consume stays usable.
    console.error('commitRedemption failed:', (e as Error).message)
    await backend.releaseRedemption(redemptionKey).catch(() => {})
    return deny(502, 'redemption commit failed')
  }
  return resp
}
