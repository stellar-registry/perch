import { beforeAll, describe, expect, it } from 'vitest';
import { init, leaf } from '../src/hash.js';
import { zeroHashes } from '../src/tree.js';
import { publicInputBytes, publicInputs } from '../src/inputs.js';
import { hex } from '../src/field.js';
import { FIXTURES, b, fixture, pathFor } from './helpers.js';

// Every committed real-proof fixture was produced by the Rust tooling; the TS
// SDK must rebuild the same tree from the same enrollments and derive the same
// public inputs, or a wallet's proofs would not match what the pool and
// adapter compute on-chain.
describe('rebuilds every fixture from its enrollment history', () => {
  beforeAll(init);

  for (const name of FIXTURES) {
    it(name, async () => {
      const { f, publicInputs: committed } = fixture(name);
      const leaves = f.enrollments.map((x) =>
        leaf(b(x.account_id), b(x.enrollment_id), b(x.commitment)),
      );
      const siblings =
        f.synthetic_prefix === 0
          ? await pathFor(leaves, f.leaf_index)
          : zeroHashes(32).slice(0, 32);
      const p = publicInputs({
        secret: b(f.secret),
        accountId: b(f.account_id),
        enrollmentId: b(f.enrollment_id),
        digest: b(f.digest),
        leafIndex: BigInt(f.leaf_index),
        siblings,
      });
      expect(hex(p.root)).toBe(f.root);
      expect(hex(p.nullifier)).toBe(f.nullifier);
      expect(hex(p.statementHash)).toBe(f.statement_hash);
      expect(publicInputBytes(p)).toEqual(committed);
    });
  }
});

