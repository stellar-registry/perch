import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { UltraHonkBackend } from '@aztec/bb.js';
import { init, leaf } from '../src/hash.js';
import { PROOF_BYTES, prove, verify } from '../src/prove.js';
import type { CompiledCircuit, Proof } from '../src/prove.js';
import { publicInputBytes } from '../src/inputs.js';
import { b, fixture, pathFor, repo } from './helpers.js';

// Real zero-knowledge proofs generated in-process with bb.js (the browser
// prover's code path, here under Node's WASM) for the lost_key fixture's
// witness. ZK proofs are randomized, so instead of matching the CLI's bytes, a
// bb.js proof is committed (testdata/zk/lost_key/proof.bbjs) and checked on
// the other side: the adapter's tests verify it on-chain, and
// `perch-zk-fixtures check` verifies it with `bb verify --zk`. Rewrite it with
// PERCH_ZK_WRITE_VECTORS=1 after the fixtures change.
const BBJS_PROOF = repo('testdata/zk/lost_key/proof.bbjs');

describe('bb.js proving', () => {
  beforeAll(init);

  const circuit = JSON.parse(
    readFileSync(repo('packages/perch-zk/artifacts/perch_zk_recovery.json'), 'utf8'),
  ) as CompiledCircuit;

  async function proveLostKey(): Promise<Proof> {
    const { f } = fixture('lost_key');
    const leaves = f.enrollments.map((x) =>
      leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment)),
    );
    return prove(circuit, {
      secret: b(f.secret),
      accountId: b(f.account_id),
      enrollmentId: b(f.enrollment_id),
      digest: b(f.digest),
      leafIndex: BigInt(f.leaf_index),
      siblings: await pathFor(leaves, f.leaf_index),
    });
  }

  it('proves the committed statement with a fresh, verifying ZK proof', async () => {
    const { publicInputs, proof: cli } = fixture('lost_key');
    const one = await proveLostKey();
    const two = await proveLostKey();
    for (const p of [one, two]) {
      expect(publicInputBytes(p.publicInputs)).toEqual(publicInputs);
      expect(p.proof.length).toBe(PROOF_BYTES);
      expect(await verify(circuit, p)).toBe(true);
    }
    // Randomized: two proofs of one witness differ, and neither is the CLI's.
    expect(one.proof).not.toEqual(two.proof);
    expect(one.proof).not.toEqual(cli);
    // And bb.js accepts the CLI's proof of the same statement.
    expect(await verify(circuit, { proof: cli, publicInputs: one.publicInputs })).toBe(true);

    if (process.env.PERCH_ZK_WRITE_VECTORS) writeFileSync(BBJS_PROOF, one.proof);
  }, 120_000);

  it('refuses a proof for other public inputs, and a non-ZK proof', async () => {
    const p = await proveLostKey();
    const other = { ...p.publicInputs, nullifier: p.publicInputs.root };
    expect(await verify(circuit, { proof: p.proof, publicInputs: other })).toBe(false);
    const nonZk = new Uint8Array(readFileSync(repo('testdata/zk/lost_key/proof.non-zk')));
    expect(nonZk.length).toBe(456 * 32);
    expect(await verify(circuit, { proof: nonZk, publicInputs: p.publicInputs })).toBe(false);
  }, 120_000);

  it('verifies the committed bb.js proof', async () => {
    const { publicInputs } = fixture('lost_key');
    const proof = new Uint8Array(readFileSync(BBJS_PROOF));
    expect(proof.length).toBe(PROOF_BYTES);
    const words = [0, 32, 64].map((o) => publicInputs.slice(o, o + 32));
    expect(
      await verify(circuit, {
        proof,
        publicInputs: { root: words[0]!, nullifier: words[1]!, statementHash: words[2]! },
      }),
    ).toBe(true);
  }, 120_000);

  it('uses the verification key the adapter compiles in', async () => {
    const backend = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
    try {
      const vk = await backend.getVerificationKey({ keccakZK: true });
      expect(vk).toEqual(
        new Uint8Array(readFileSync(repo('crates/perch-zk-adapter/vk/perch_zk_recovery.vk'))),
      );
    } finally {
      await backend.destroy();
    }
  }, 120_000);
});
