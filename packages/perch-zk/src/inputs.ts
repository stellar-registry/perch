// The full input set of one recovery proof, and its Noir input map.

import { commitment, leaf, nullifier, statementHash } from './hash.js';
import { rootFromPath } from './tree.js';
import { hex, isCanonical, splitHiLo } from './field.js';
import type { Bytes32 } from './field.js';

export interface Witness {
  /** The enrolled secret (a canonical field element). */
  secret: Bytes32;
  /** The recovering account's 32-byte contract id. */
  accountId: Bytes32;
  /** The enrollment id the account's recovery configuration names. */
  enrollmentId: Bytes32;
  /** The recovery statement's 32-byte digest (`RecoveryStatement::digest`). */
  digest: Bytes32;
  /** The leaf's index in its tree. */
  leafIndex: bigint;
  /** The leaf's sibling path, leaf level first. */
  siblings: Bytes32[];
}

/** The circuit's public inputs, in order. */
export interface PublicInputs {
  root: Bytes32;
  nullifier: Bytes32;
  statementHash: Bytes32;
}

export function publicInputs(w: Witness): PublicInputs {
  if (!isCanonical(w.secret)) throw new Error('secret is not a canonical field element');
  const stored = leaf(w.accountId, w.enrollmentId, commitment(w.secret));
  return {
    root: rootFromPath(stored, w.leafIndex, w.siblings),
    nullifier: nullifier(w.accountId, w.enrollmentId, w.secret),
    statementHash: statementHash(w.accountId, w.enrollmentId, w.digest),
  };
}

/** `root || nullifier || statement_hash`, as the verifier takes them. */
export function publicInputBytes(p: PublicInputs): Uint8Array {
  const out = new Uint8Array(96);
  out.set(p.root, 0);
  out.set(p.nullifier, 32);
  out.set(p.statementHash, 64);
  return out;
}

const field = (v: bigint | Bytes32): string =>
  typeof v === 'bigint' ? '0x' + v.toString(16) : hex(v);

/** The Noir input map for `circuits/perch_zk_recovery`. */
export function noirInputs(w: Witness): Record<string, string | string[]> {
  const p = publicInputs(w);
  const [acctHi, acctLo] = splitHiLo(w.accountId);
  const [enrHi, enrLo] = splitHiLo(w.enrollmentId);
  const [digestHi, digestLo] = splitHiLo(w.digest);
  return {
    root: field(p.root),
    nullifier: field(p.nullifier),
    statement_hash: field(p.statementHash),
    secret: field(w.secret),
    acct_hi: field(acctHi),
    acct_lo: field(acctLo),
    enr_hi: field(enrHi),
    enr_lo: field(enrLo),
    digest_hi: field(digestHi),
    digest_lo: field(digestLo),
    leaf_index: field(w.leafIndex),
    siblings: w.siblings.map((s) => field(s)),
  };
}
