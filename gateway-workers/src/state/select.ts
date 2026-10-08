/**
 * Backend selection — the Workers analog of the Rust gateway's `main.rs` store bootstrap.
 * Chooses the Durable Object or KV nonce backend from config + available bindings, failing fast if
 * the chosen backend's binding is missing.
 */

import type { Config, Env } from '../config.js'
import type { NonceBackend, RedemptionStore } from './types.js'
import type { NonceRateState } from './durable_object.js'
import { DurableObjectBackend } from './durable_object.js'
import { KvBackend } from './kv.js'

/** The state a gateway needs: nonces and rate limits, plus redemptions when `SINGLE_USE=true`. */
export interface GatewayBackends {
  backend: NonceBackend
  /** Present exactly when `cfg.singleUse`; always Durable Object backed. */
  redemptions?: RedemptionStore
}

/**
 * Instantiate the backends from config and available bindings. Redemptions always live in the
 * Durable Object (the config refuses `SINGLE_USE=true` with the KV nonce backend), whatever backend
 * the nonces use.
 *
 * @param cfg - The resolved gateway config, potentially modified by the quota-degrade flag.
 * @param env - Worker environment bindings.
 * @throws If the required binding for the chosen backend is absent.
 */
export function makeBackends(cfg: Config, env: Env): GatewayBackends {
  const durable = () => {
    if (!env.NONCE_STATE) throw new Error('the NONCE_STATE Durable Object binding is missing')
    return new DurableObjectBackend(
      env.NONCE_STATE as DurableObjectNamespace<NonceRateState>,
      cfg.nonceShard,
      cfg.nonceMaxEntries,
    )
  }
  if (cfg.nonceBackend === 'kv') {
    if (!env.NONCE_KV) throw new Error('NONCE_BACKEND=kv but the NONCE_KV binding is missing')
    return { backend: new KvBackend(env.NONCE_KV) }
  }
  const d = durable()
  return { backend: d, redemptions: cfg.singleUse ? d : undefined }
}
