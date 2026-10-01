import { describe, it, expect } from 'vitest'
import { loadConfig } from '../src/config.js'
import type { Env } from '../src/config.js'

const baseEnv: Env = {
  UPSTREAM_URL: 'https://relay-origin.example.com',
  SUI_RPC_URL: 'https://fullnode.testnet.sui.io:443',
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
  it('defaults to the three Meddleware app origins when env var is absent', () => {
    const cfg = loadConfig(baseEnv)
    expect(cfg.allowedOrigins).toEqual([
      'https://sui-walrus.meddleware.co.uk',
      'https://dash.meddleware.co.uk',
      'https://sui-token-deployer.meddleware.co.uk',
    ])
  })

  it('defaults to the three Meddleware app origins when env var is empty string', () => {
    const cfg = loadConfig({ ...baseEnv, ALLOWED_ORIGINS: '' })
    expect(cfg.allowedOrigins).toHaveLength(3)
  })

  it('parses a comma-separated list of origins', () => {
    const cfg = loadConfig({
      ...baseEnv,
      ALLOWED_ORIGINS: 'https://app.example.com,https://admin.example.com',
    })
    expect(cfg.allowedOrigins).toEqual(['https://app.example.com', 'https://admin.example.com'])
  })

  it('trims whitespace around each origin', () => {
    const cfg = loadConfig({
      ...baseEnv,
      ALLOWED_ORIGINS: '  https://app.example.com , https://admin.example.com  ',
    })
    expect(cfg.allowedOrigins).toEqual(['https://app.example.com', 'https://admin.example.com'])
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
