import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fromHex } from '../src/field.js';

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
