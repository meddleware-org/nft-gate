import { cloudflareTest } from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

/**
 * Two test projects with different runtime environments.
 *
 * unit (default / CI):
 *   Runs verify, config, conformance, and chain tests in the standard Node.js
 *   pool. No Cloudflare runtime dependency; always safe in CI (`npm test`).
 *
 * cloudflare-integration (local dev):
 *   Runs router, state and proxy (body-limit) tests inside the real `workerd` runtime via
 *   @cloudflare/vitest-pool-workers. Requires Durable Objects + KV bindings.
 *   Run with: npm run test:integration
 *
 *   Requires wrangler 4.x + miniflare 5.x. If `cloudflare:test` is unavailable
 *   in your workerd version, try upgrading wrangler: npm update wrangler
 */
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: [
            'test/verify.test.ts',
            'test/config.test.ts',
            'test/conformance.test.ts',
            'test/chain.test.ts',
            'test/redemption.test.ts',
            'test/integration/grpc-chain.integration.test.ts',
          ],
        },
      },
      {
        // The plugin (not a bare `pool`) also registers the `cloudflare:test` module resolution.
        plugins: [
          cloudflareTest({
            wrangler: { configPath: './wrangler.toml' },
            miniflare: {
              // NONCE_KV: wrangler.toml keeps this commented out for prod (DO is the primary
              // backend); state.test.ts exercises KvBackend, so provision it for tests only.
              kvNamespaces: ['NONCE_KV'],
              // Override URL bindings with test doubles so the suite stays fully offline.
              bindings: {
                UPSTREAM_URL: 'https://upstream.invalid',
                GATEWAY_ORIGIN: 'https://gw.example.com',
                NETWORK: 'testnet',
                SUI_RPC_URL: 'https://rpc.invalid',
                // A plain var in production (wrangler.toml); required by the config loader.
                NFT_TYPE:
                  '0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9::access_gate::SoulboundAccessNFT',
                ALLOWED_ORIGINS: 'https://allowed.example.com,https://sui-walrus.meddleware.co.uk',
              },
            },
          }),
        ],
        test: {
          name: 'cloudflare-integration',
          include: ['test/router.test.ts', 'test/state.test.ts', 'test/proxy.test.ts'],
        },
      },
    ],
  },
})
