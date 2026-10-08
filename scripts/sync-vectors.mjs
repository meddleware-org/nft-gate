#!/usr/bin/env node
// The conformance vectors are generated and published by @meddleware/nft-gate-client (the protocol's
// home). This repository keeps a copy at conformance/vectors.json so the Rust gateway, which cannot
// import an npm package, tests against the same bytes.
//
//   node scripts/sync-vectors.mjs          copy the installed package's vectors here
//   node scripts/sync-vectors.mjs --check  fail if the copy differs (run in CI)
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const source = join(root, 'gateway-workers', 'node_modules', '@meddleware', 'nft-gate-client', 'vectors.json')
const copy = join(root, 'conformance', 'vectors.json')
const want = readFileSync(source, 'utf8')
if (process.argv.includes('--check')) {
  if (readFileSync(copy, 'utf8') !== want) {
    console.error('conformance/vectors.json differs from @meddleware/nft-gate-client/vectors.json; run: node scripts/sync-vectors.mjs')
    process.exit(1)
  }
  console.log('conformance/vectors.json matches the installed @meddleware/nft-gate-client')
} else {
  writeFileSync(copy, want)
  console.log('conformance/vectors.json updated')
}
