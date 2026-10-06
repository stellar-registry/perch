#!/usr/bin/env node
// A single-process relay over an in-memory store:
//
//   perch-relay --controller C... --network-passphrase "Test SDF Network ; September 2015" \
//       --rpc-url https://soroban-testnet.stellar.org [--host 127.0.0.1] [--port 8787]
//
// With --rpc-url every entry is admitted by enforcing simulation; without it
// only G guardians' own signatures are accepted. Prints the URL it serves as
// its first line of output. Approvals do not survive a restart.

import { parseArgs } from 'node:util';
import { MemoryKv } from './kv.js';
import { listen } from './node.js';
import { handleRelay } from './relay.js';
import { rpcSimulator } from './simulate.js';

const { values } = parseArgs({
  options: {
    controller: { type: 'string' },
    'network-passphrase': { type: 'string' },
    'rpc-url': { type: 'string' },
    host: { type: 'string', default: '127.0.0.1' },
    port: { type: 'string', default: '8787' },
    help: { type: 'boolean', short: 'h' },
  },
});
const usage =
  'usage: perch-relay --controller C... --network-passphrase <passphrase> [--rpc-url <url>] [--host h] [--port p]';
if (values.help) {
  console.log(usage);
  process.exit(0);
}
const controller = values.controller;
const networkPassphrase = values['network-passphrase'];
if (!controller || !networkPassphrase) {
  console.error(usage);
  process.exit(2);
}
const rpcUrl = values['rpc-url'];
const simulate = rpcUrl
  ? rpcSimulator(rpcUrl, networkPassphrase, { allowHttp: rpcUrl.startsWith('http://') })
  : undefined;
const kv = new MemoryKv();
const { url } = await listen(
  (request) => handleRelay(request, kv, { controller, networkPassphrase, simulate }),
  Number(values.port),
  values.host,
);
console.log(url);
