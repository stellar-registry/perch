#!/usr/bin/env node
// perch-derive-id content <registry-C-id> <wasm-hash-hex> <network-passphrase>
//
// deployer(registry, salt = wasm_hash): a `deploy_stateless` address, as
// crates/perch-derive-id's `content` mode prints it.
import { contentAddress } from '../derive.js';

const [mode, registry, hash, passphrase, ...rest] = process.argv.slice(2);
if (mode !== 'content' || !registry || !hash || passphrase === undefined || rest.length) {
  const usage = 'usage: perch-derive-id content <registry> <wasm-hash-hex> <passphrase>';
  if (mode === '--help' || mode === '-h') {
    console.log(usage);
    process.exit(0);
  }
  console.error(usage);
  process.exit(2);
}
console.log(contentAddress(registry, hash, passphrase));
