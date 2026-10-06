import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromHex } from '../src/field.js';
import type { Bytes32 } from '../src/field.js';
import { IncrementalTree, LeafChunks } from '../src/tree.js';

const here = dirname(fileURLToPath(import.meta.url));
export const repo = (...p: string[]) => resolve(here, '../../..', ...p);

export interface FixtureEnrollment {
  account_id: string;
  enrollment_id: string;
  commitment: string;
}

/** `crates/perch-zk-prover/src/fixture.rs::Fixture`, the fields used here. */
export interface Fixture {
  pool_id: string;
  account_id: string;
  enrollment_id: string;
  digest: string;
  tree_id: number;
  synthetic_prefix: number;
  enrollments: FixtureEnrollment[];
  leaf_index: number;
  secret: string;
  root: string;
  nullifier: string;
  statement_hash: string;
}

export function fixture(name: string): { f: Fixture; proof: Uint8Array; publicInputs: Uint8Array } {
  const dir = repo('testdata/zk', name);
  return {
    f: JSON.parse(readFileSync(resolve(dir, 'fixture.json'), 'utf8')) as Fixture,
    proof: new Uint8Array(readFileSync(resolve(dir, 'proof'))),
    publicInputs: new Uint8Array(readFileSync(resolve(dir, 'public_inputs'))),
  };
}

export const b = (s: string) => fromHex(s);

export const FIXTURES = [
  'lost_key',
  'compromise',
  'cancel',
  'reconfigure',
  'reconfigure_remove',
  'upgrade',
  'earlier_tree',
  'later_root',
];


/** The witness for `leaves[index]` in a depth-`depth` tree of `leaves`, built
 * the way an indexer builds it: appended in order over chunked storage. */
export async function pathFor(leaves: Bytes32[], index: number, depth = 32): Promise<Bytes32[]> {
  const store = new LeafChunks();
  const tree = new IncrementalTree({ depth });
  for (const l of leaves) {
    store.push(l);
    tree.append(l);
  }
  return (await tree.witness(BigInt(index), store.read)).siblings;
}
