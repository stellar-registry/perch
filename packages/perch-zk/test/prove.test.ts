import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { init, leaf } from '../src/hash.js';
import { Tree } from '../src/tree.js';
import { prove } from '../src/prove.js';
import type { CompiledCircuit } from '../src/prove.js';
import { publicInputBytes } from '../src/inputs.js';
import { b, fixture, repo } from './helpers.js';

// A real proof generated in-process with bb.js (the browser prover's code
// path, here under Node's WASM) for the lost_key fixture's witness. bb.js and
// the bb CLI share one version and the non-ZK keccak flavor, so the proof is
// byte-identical to the committed CLI proof the adapter's tests verify
// on-chain.
describe('bb.js proving', () => {
  beforeAll(init);

  it('reproduces the committed CLI proof byte for byte', async () => {
    const { f, proof, publicInputs } = fixture('lost_key');
    const circuit = JSON.parse(
      readFileSync(repo('packages/perch-zk/artifacts/perch_zk_recovery.json'), 'utf8'),
    ) as CompiledCircuit;
    const leaves = f.enrollments.map((x) =>
      leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment)),
    );
    const out = await prove(circuit, {
      secret: b(f.secret),
      accountId: b(f.account_id),
      enrollmentId: b(f.enrollment_id),
      digest: b(f.digest),
      leafIndex: BigInt(f.leaf_index),
      siblings: new Tree(leaves).path(f.leaf_index),
    });
    expect(publicInputBytes(out.publicInputs)).toEqual(publicInputs);
    expect(out.proof).toEqual(proof);
  }, 120_000);
});
