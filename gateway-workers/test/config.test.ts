import { describe, it, expect } from 'vitest'
import { loadConfig } from '../src/config.js'
import type { Env } from '../src/config.js'

const baseEnv: Env = {
  UPSTREAM_URL: 'https://relay-origin.example.com',
  SUI_RPC_URL: 'https://fullnode.testnet.sui.io:443',
  NFT_TYPE: '0x1::access_gate::AccessNFT',
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

  it('parses a single "Name: value" entry', () => {
    const cfg = loadConfig({ ...baseEnv, UPSTREAM_AUTH_HEADERS: 'CF-Access-Client-Id: abc123' })
    expect(cfg.upstreamAuthHeaders).toEqual([{ name: 'CF-Access-Client-Id', value: 'abc123' }])
  })

  it('parses two comma-separated entries (CF Access service token format)', () => {
    const cfg = loadConfig({
      ...baseEnv,
      UPSTREAM_AUTH_HEADERS:
        'CF-Access-Client-Id: abc123, CF-Access-Client-Secret: super-secret',
    })
    expect(cfg.upstreamAuthHeaders).toEqual([
      { name: 'CF-Access-Client-Id', value: 'abc123' },
      { name: 'CF-Access-Client-Secret', value: 'super-secret' },
    ])
  })

  it('trims extra whitespace around entries', () => {
    const cfg = loadConfig({
      ...baseEnv,
      UPSTREAM_AUTH_HEADERS: '  X-Custom-Header:  trimmed  ,  X-Other: val  ',
    })
    expect(cfg.upstreamAuthHeaders).toEqual([
      { name: 'X-Custom-Header', value: 'trimmed' },
      { name: 'X-Other', value: 'val' },
    ])
  })

  it('preserves colons inside the header value', () => {
    const cfg = loadConfig({
      ...baseEnv,
      UPSTREAM_AUTH_HEADERS: 'Authorization: Bearer tok:en:with:colons',
    })
    expect(cfg.upstreamAuthHeaders).toEqual([
      { name: 'Authorization', value: 'Bearer tok:en:with:colons' },
    ])
  })
})

describe('loadConfig — ALLOWED_ORIGINS', () => {
  it('defaults to the two Meddleware app origins when env var is absent', () => {
    const cfg = loadConfig(baseEnv)
    expect(cfg.allowedOrigins).toContain('https://sui-walrus.meddleware.co.uk')
    expect(cfg.allowedOrigins).toContain('https://sui.meddleware.co.uk')
  })

  it('defaults to the two Meddleware app origins when env var is empty string', () => {
    const cfg = loadConfig({ ...baseEnv, ALLOWED_ORIGINS: '' })
    expect(cfg.allowedOrigins).toHaveLength(2)
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
