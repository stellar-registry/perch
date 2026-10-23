// The relation's Poseidon2 hashes, computed with Barretenberg's own
// Poseidon2 (bb.js), which Noir's `Poseidon2::hash` and the Soroban host's
// `poseidon2_permutation` both match. test/parity.test.ts pins the outputs
// the Noir circuit and crates/perch-zk-primitives assert.

import { BarretenbergSync, Fr } from '@aztec/bb.js';
import { DOM_AUTH, DOM_BIND, DOM_LEAF, DOM_NULLIFIER, splitHiLo, toBigInt, toBytes32 } from './field.js';
import type { Bytes32 } from './field.js';

let api: BarretenbergSync | undefined;

/** Load Barretenberg's WASM once. Every other function here needs it. */
export async function init(): Promise<void> {
  api ??= await BarretenbergSync.initSingleton();
}

function bb(): BarretenbergSync {
  if (!api) throw new Error('perch-zk: call init() first');
  return api;
}

/** `Poseidon2::hash(inputs, inputs.length)`. */
export function poseidon2(inputs: bigint[]): bigint {
  return toBigInt(bb().poseidon2Hash(inputs.map((x) => new Fr(x))).toBuffer());
}

/** Interior Merkle node `H(left, right)`. */
export function node(left: Bytes32, right: Bytes32): Bytes32 {
  return toBytes32(poseidon2([toBigInt(left), toBigInt(right)]));
}

/** `inner = H(DOM_LEAF, secret)`: what an account enrolls in the pool. */
export function commitment(secret: Bytes32): Bytes32 {
  return toBytes32(poseidon2([DOM_LEAF, toBigInt(secret)]));
}

/** `H(DOM_BIND, account, enrollmentId, inner)`: the leaf the pool stores. */
export function leaf(accountId: Bytes32, enrollmentId: Bytes32, inner: Bytes32): Bytes32 {
  return toBytes32(poseidon2([DOM_BIND, ...splitHiLo(accountId), ...splitHiLo(enrollmentId), toBigInt(inner)]));
}

/** `H(DOM_NULLIFIER, account, enrollmentId, secret)`: one per enrolled credential. */
export function nullifier(accountId: Bytes32, enrollmentId: Bytes32, secret: Bytes32): Bytes32 {
  return toBytes32(
    poseidon2([DOM_NULLIFIER, ...splitHiLo(accountId), ...splitHiLo(enrollmentId), toBigInt(secret)]),
  );
}

/** `H(DOM_AUTH, account, enrollmentId, digest)`: the third public input. */
export function statementHash(accountId: Bytes32, enrollmentId: Bytes32, digest: Bytes32): Bytes32 {
  return toBytes32(
    poseidon2([DOM_AUTH, ...splitHiLo(accountId), ...splitHiLo(enrollmentId), ...splitHiLo(digest)]),
  );
}
