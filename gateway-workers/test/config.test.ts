import { describe, it, expect } from 'vitest'
import { loadConfig } from '../src/config.js'
import type { Env } from '../src/config.js'

const baseEnv: Env = {
  UPSTREAM_URL: 'https://relay-origin.example.com',
  SUI_RPC_URL: 'https://fullnode.testnet.sui.io:443',
  GATEWAY_ORIGIN: 'https://gateway.example.com',
  NETWORK: 'testnet',
  NFT_TYPE: '0x1::access_gate::AccessNFT',
  GATE_ID: '0x2',
}

describe('loadConfig — UPSTREAM_AUTH_HEADERS', () => {
  it('defaults to empty array when env var is absent', () => {
    const cfg = loadConfig(baseEnv)
    expect(cfg.upstreamAuthHeaders).toEqual([])
  })

  it('defaults to empty array when env var is empty string', () => {
    const cfg = loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: '' })
    expect(cfg.upstreamAuthHeaders).toEqual([])
  })

  it('parses the JSON array format (CF Access service token)', () => {
    const cfg = loadConfig({
      ...baseEnv,
      UPSTREAM_AUTH_HEADERS: JSON.stringify([
        { name: 'CF-Access-Client-Id', value: 'abc123' },
        { name: 'CF-Access-Client-Secret', value: 'super,secret:with,commas' },
      ]),
    })
    expect(cfg.upstreamAuthHeaders).toEqual([
      { name: 'CF-Access-Client-Id', value: 'abc123' },
      { name: 'CF-Access-Client-Secret', value: 'super,secret:with,commas' },
    ])
  })

  it('fails closed on the retired "Name: value" format', () => {
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: 'CF-Access-Client-Id: abc123' })).toThrow(
      /JSON array/,
    )
  })

  it('rejects a non-array, a bad header name and a header-injection value', () => {
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: '{"name":"a","value":"b"}' })).toThrow(/JSON array/)
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: '[{"name":"Bad Name","value":"b"}]' })).toThrow(
      /UPSTREAM_AUTH_HEADERS\[0\]/,
    )
    expect(() =>
      loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: JSON.stringify([{ name: 'X', value: 'a\r\nInjected: 1' }]) }),
    ).toThrow(/UPSTREAM_AUTH_HEADERS\[0\]/)
  })
})

describe('loadConfig — ALLOWED_ORIGINS', () => {
  it('defaults to no cross-origin access (fail closed, like the Rust gateway)', () => {
    expect(loadConfig(baseEnv).allowedOrigins).toEqual([])
    expect(loadConfig({ ...baseEnv, ALLOWED_ORIGINS: '' }).allowedOrigins).toEqual([])
  })

  it('parses a comma-separated list of canonical origins, trimming whitespace', () => {
    const cfg = loadConfig({ ...baseEnv, ALLOWED_ORIGINS: '  https://app.example.com , https://admin.example.com  ' })
    expect(cfg.allowedOrigins).toEqual(['https://app.example.com', 'https://admin.example.com'])
  })

  it('rejects an entry that is not a canonical https origin', () => {
    for (const bad of ['*', 'http://app.example.com', 'https://app.example.com/', 'https://App.example.com', 'app.example.com', 'https://a.example.com:443']) {
      expect(() => loadConfig({ ...baseEnv, ALLOWED_ORIGINS: bad })).toThrow(/ALLOWED_ORIGINS/)
    }
  })
})

describe('loadConfig — audience binding (GATEWAY_ORIGIN, NETWORK)', () => {
  it('requires a canonical https origin and a known network', () => {
    expect(loadConfig(baseEnv)).toMatchObject({ gatewayOrigin: 'https://gateway.example.com', network: 'testnet' })
    for (const bad of ['', 'gateway.example.com', 'http://gateway.example.com', 'https://gateway.example.com/', 'https://Gateway.example.com']) {
      expect(() => loadConfig({ ...baseEnv, GATEWAY_ORIGIN: bad })).toThrow(/GATEWAY_ORIGIN/)
    }
    expect(() => loadConfig({ ...baseEnv, NETWORK: 'testnet2' })).toThrow(/NETWORK/)
    expect(() => loadConfig({ ...baseEnv, NETWORK: undefined as never })).toThrow(/NETWORK/)
  })

  it('refuses an upstream that is the gateway itself (request loop)', () => {
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_URL: 'https://gateway.example.com/relay' })).toThrow(/loop/)
  })
})

describe('loadConfig — strict values (a typo must not select a weaker mode)', () => {
  it('SINGLE_USE and QUOTA_GUARD_ENABLED are exactly true or false', () => {
    expect(loadConfig({ ...baseEnv, SINGLE_USE: 'true' }).singleUse).toBe(true)
    expect(loadConfig({ ...baseEnv, SINGLE_USE: 'false' }).singleUse).toBe(false)
    for (const bad of ['TRUE', '1', 'yes', 'true ', '']) {
      expect(() => loadConfig({ ...baseEnv, SINGLE_USE: bad })).toThrow(/SINGLE_USE/)
    }
    expect(() => loadConfig({ ...baseEnv, QUOTA_GUARD_ENABLED: 'on' })).toThrow(/QUOTA_GUARD_ENABLED/)
  })

  it('numbers are integers within bounds', () => {
    for (const [key, bad] of [
      ['MAX_BODY_BYTES', '0'],
      ['MAX_BODY_BYTES', '-1'],
      ['MAX_BODY_BYTES', '1.5'],
      ['MAX_BODY_BYTES', 'lots'],
      ['RATE_LIMIT_PER_MIN', '-5'],
      ['NONCE_MAX_ENTRIES', '0'],
      ['CHALLENGE_TTL_SECS', '1'],
      ['UPSTREAM_TIMEOUT_SECS', '0'],
      ['REDEMPTION_LEASE_TTL_SECS', '5'],
    ] as const) {
      expect(() => loadConfig({ ...baseEnv, [key]: bad } as Env)).toThrow(new RegExp(key))
    }
    expect(loadConfig({ ...baseEnv, RATE_LIMIT_PER_MIN: '0' }).rateLimitPerMin).toBe(0) // 0 = off, documented
  })

  it('enumerations reject unknown values', () => {
    expect(() => loadConfig({ ...baseEnv, NONCE_BACKEND: 'redis' })).toThrow(/NONCE_BACKEND/)
    expect(() => loadConfig({ ...baseEnv, NONCE_SHARD: 'planet' })).toThrow(/NONCE_SHARD/)
  })

  it('upstream and RPC URLs must be https', () => {
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_URL: 'http://relay.example.com' })).toThrow(/UPSTREAM_URL/)
    expect(() => loadConfig({ ...baseEnv, SUI_RPC_URL: 'ftp://rpc.example.com' })).toThrow(/SUI_RPC_URL/)
    expect(() => loadConfig({ ...baseEnv, SUI_RPC_URL: 'https://u:p@rpc.example.com' })).toThrow(/SUI_RPC_URL/)
    expect(loadConfig({ ...baseEnv, UPSTREAM_URL: 'http://127.0.0.1:8080' }).upstreamUrl).toBe('http://127.0.0.1:8080')
  })

  it('PUBLIC_PATHS are plain absolute paths', () => {
    expect(loadConfig({ ...baseEnv, PUBLIC_PATHS: '/v1/tip-config, /health' }).publicPaths).toEqual(['/v1/tip-config', '/health'])
    for (const bad of ['v1/tip-config', '/a/../b', '/a?x=1', '/a#f', '/a b']) {
      expect(() => loadConfig({ ...baseEnv, PUBLIC_PATHS: bad })).toThrow(/PUBLIC_PATHS/)
    }
  })
})

describe('loadConfig — single-use invariants', () => {
  it('refuses the KV backend, whose lease cannot be atomic', () => {
    expect(() => loadConfig({ ...baseEnv, SINGLE_USE: 'true', NONCE_BACKEND: 'kv' })).toThrow(/durable-object/)
    expect(loadConfig({ ...baseEnv, SINGLE_USE: 'false', NONCE_BACKEND: 'kv' }).nonceBackend).toBe('kv')
  })

  it('the lease must outlive the upload deadline, and a consume must not outlive its retention', () => {
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_TIMEOUT_SECS: '600', REDEMPTION_LEASE_TTL_SECS: '600' })).toThrow(/exceed UPSTREAM_TIMEOUT_SECS/)
    expect(() => loadConfig({ ...baseEnv, UPSTREAM_TIMEOUT_SECS: '600', REDEMPTION_LEASE_TTL_SECS: '300' })).toThrow(/exceed/)
    expect(() => loadConfig({ ...baseEnv, CONSUME_MAX_AGE_SECS: '864000', REDEMPTION_RETENTION_SECS: '432000' })).toThrow(/CONSUME_MAX_AGE_SECS/)
    const ok = loadConfig(baseEnv)
    expect(ok.redemptionLeaseTtlSecs * 1000).toBeGreaterThan(ok.upstreamTimeoutMs)
    expect(ok.consumeMaxAgeSecs).toBeLessThanOrEqual(ok.redemptionRetentionSecs)
  })
})

describe('loadConfig — SUI_RPC_AUTH_HEADER', () => {
  it('parses "Name: value" and refuses anything else', () => {
    expect(loadConfig({ ...baseEnv, SUI_RPC_AUTH_HEADER: 'Authorization: Bearer tok' }).suiRpcAuthHeader).toEqual({
      name: 'Authorization',
      value: 'Bearer tok',
    })
    for (const bad of ['Bearer tok', 'Bad Name: v', 'X-Key: ', 'X-Key: a\r\nInjected: 1']) {
      expect(() => loadConfig({ ...baseEnv, SUI_RPC_AUTH_HEADER: bad })).toThrow(/SUI_RPC_AUTH_HEADER/)
    }
  })
})

describe('loadConfig — NFT_TYPE and GATE_ID validation', () => {
  it('accepts both access_gate pass types', () => {
    expect(loadConfig(baseEnv).nftType).toBe('0x1::access_gate::AccessNFT')
    expect(loadConfig({ ...baseEnv, NFT_TYPE: '0xab::access_gate::SoulboundAccessNFT' }).nftType).toBe(
      '0xab::access_gate::SoulboundAccessNFT',
    )
  })

  it('rejects a fungible coin or any non-access_gate type', () => {
    for (const t of ['0x2::coin::Coin<0x2::sui::SUI>', '0x1::other::AccessNFT', '0x1::access_gate::Gate', 'AccessNFT']) {
      expect(() => loadConfig({ ...baseEnv, NFT_TYPE: t })).toThrow(/NFT_TYPE/)
    }
  })

  it('requires a GATE_ID object id', () => {
    expect(() => loadConfig({ ...baseEnv, GATE_ID: '' })).toThrow(/GATE_ID/)
    expect(() => loadConfig({ ...baseEnv, GATE_ID: 'gate' })).toThrow(/GATE_ID/)
  })
})

describe('loadConfig — CHALLENGE_RATE_LIMIT_PER_MIN', () => {
  it('defaults to 30 per IP per minute (parity with the Rust gateway)', () => {
    expect(loadConfig(baseEnv).challengeRateLimitPerMin).toBe(30)
    expect(loadConfig({ ...baseEnv, CHALLENGE_RATE_LIMIT_PER_MIN: '0' }).challengeRateLimitPerMin).toBe(0)
  })
})
