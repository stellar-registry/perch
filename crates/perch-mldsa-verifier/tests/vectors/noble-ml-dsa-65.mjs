// Generates noble-ml-dsa-65.json: ML-DSA-65 keys and signatures made by
// @noble/post-quantum, the signer Nido's SDK uses, for the verifier to check.
//
//   npm install @noble/post-quantum@0.6.1
//   node noble-ml-dsa-65.mjs > noble-ml-dsa-65.json
//
// The deterministic signature reproduces exactly; the hedged ones draw fresh
// randomness on every run, so a rerun changes only those.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const hex = (b) => Buffer.from(b).toString('hex');
const sha256 = (s) => createHash('sha256').update(s).digest();
const context = 'nido-mldsa-v1';
const ctx = new TextEncoder().encode(context);
const pkg = JSON.parse(readFileSync(new URL('package.json', import.meta.resolve('@noble/post-quantum/ml-dsa.js'))));

const cases = [
  { name: 'deterministic signature', seed: Buffer.alloc(32, 0x07), message: Buffer.alloc(32, 0x42), deterministic: true },
  { name: 'hedged signature', seed: Buffer.alloc(32, 0x07), message: sha256('perch-mldsa-verifier') },
  { name: 'hedged signature, second key', seed: sha256('perch-mldsa-verifier second key'), message: sha256('a rule-bound auth digest') },
];

const vectors = cases.map((c) => {
  const { publicKey, secretKey } = ml_dsa65.keygen(c.seed);
  const signature = ml_dsa65.sign(c.message, secretKey, c.deterministic ? { context: ctx, extraEntropy: false } : { context: ctx });
  if (!ml_dsa65.verify(signature, c.message, publicKey, { context: ctx })) throw new Error(`${c.name}: does not verify`);
  return {
    name: c.name,
    seed: hex(c.seed),
    public_key: hex(publicKey),
    key_commitment: hex(sha256(publicKey)),
    message: hex(c.message),
    signature: hex(signature),
  };
});

console.log(JSON.stringify({
  source: `@noble/post-quantum ${pkg.version}: ml_dsa65.keygen(seed), then ml_dsa65.sign(message, secretKey, { context }), with extraEntropy: false for the deterministic case (tests/vectors/noble-ml-dsa-65.mjs)`,
  context,
  vectors,
}, null, 1));
