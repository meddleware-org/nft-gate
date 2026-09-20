/// <reference types="@cloudflare/vitest-pool-workers/types" />

// Augment Cloudflare.Env with the bindings for this Worker.
// This types the `env` export from 'cloudflare:test' and 'cloudflare:workers'.
declare namespace Cloudflare {
  interface Env {
    NONCE_STATE: DurableObjectNamespace
    NONCE_KV: KVNamespace
    UPSTREAM_URL: string
    SUI_RPC_URL: string
    NFT_TYPE: string
    PUBLIC_PATHS: string
    NONCE_BACKEND: string
    NONCE_SHARD: string
    RATE_LIMIT_PER_MIN: string
    PUBLIC_RATE_LIMIT_PER_MIN: string
    PUBLIC_CACHE_TTL_SECS: string
    CHALLENGE_TTL_SECS: string
  }
}
