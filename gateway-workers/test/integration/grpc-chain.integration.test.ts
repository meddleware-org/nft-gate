/**
 * Live gRPC integration test for the chain module.
 *
 * Validates that the `SuiGrpc` class can reach the Sui testnet over gRPC and that
 * the ownership-query path returns the expected shape. These tests are skipped in
 * normal CI — run them explicitly with:
 *
 *   npm run test:grpc
 *
 * They require a live Sui testnet fullnode and are deliberately NOT included in the
 * standard `npm test` run.
 *
 * Environment variables (all optional — default to public testnet values):
 *   GRPC_TESTNET_RPC_URL   — gRPC endpoint (default: https://fullnode.testnet.sui.io:443)
 *   GRPC_TESTNET_NFT_TYPE  — fully-qualified NFT type, e.g. `<pkg>::access_gate::SoulboundAccessNFT`
 *   GRPC_TESTNET_ADDRESS   — Sui address to check ownership for
 *   GRPC_TESTNET_GATE_ID   — Gate shared object ID (optional; omit to skip gate filtering)
 */

import { describe, it, expect, beforeAll } from 'vitest'
import { SuiGrpc } from '../../src/chain.js'

const ENABLED = process.env.GRPC_TESTNET === '1'
const RPC_URL = process.env.GRPC_TESTNET_RPC_URL ?? 'https://fullnode.testnet.sui.io:443'

describe.skipIf(!ENABLED)('SuiGrpc live gRPC integration (GRPC_TESTNET=1)', () => {
  let chain: SuiGrpc

  beforeAll(() => {
    chain = new SuiGrpc(RPC_URL, 0)
  })

  it('ownsNft resolves without throwing for a known address + NFT type', async () => {
    const nftType = process.env.GRPC_TESTNET_NFT_TYPE
    const address = process.env.GRPC_TESTNET_ADDRESS
    const gateId = process.env.GRPC_TESTNET_GATE_ID

    if (!nftType || !address) {
      console.log(
        'Skipping ownership check: set GRPC_TESTNET_NFT_TYPE + GRPC_TESTNET_ADDRESS to enable.',
      )
      return
    }

    const owns = await chain.ownsNft(address, nftType, gateId)
    // The call must resolve to a boolean — true or false, depending on whether the
    // configured address holds the NFT. We don't assert a specific value here because
    // the test address may or may not hold the NFT on any given testnet state.
    expect(typeof owns).toBe('boolean')
  }, 15_000)

  it('ownsNft returns false (not throws) for a zero address with any NFT type', async () => {
    const nftType = process.env.GRPC_TESTNET_NFT_TYPE
    if (!nftType) {
      console.log('Skipping: set GRPC_TESTNET_NFT_TYPE to enable.')
      return
    }
    const zeroAddress = '0x' + '0'.repeat(64)
    const owns = await chain.ownsNft(zeroAddress, nftType, undefined)
    expect(owns).toBe(false)
  }, 15_000)

  it('packageOf extracts the 0x-prefixed package address from the configured NFT type', () => {
    const nftType = process.env.GRPC_TESTNET_NFT_TYPE
    if (!nftType) {
      console.log('Skipping: set GRPC_TESTNET_NFT_TYPE to enable.')
      return
    }
    const pkg = SuiGrpc.packageOf(nftType)
    expect(pkg).toBeDefined()
    expect(pkg!.startsWith('0x')).toBe(true)
  })
})
