// UltraHonk proving with the pinned toolchain: noir_js 1.0.0-beta.9 solves the
// witness, and bb.js 0.87.0 proves with the keccak transcript in its
// zero-knowledge flavor (UltraKeccakZKFlavor, `bb prove --zk`), the flavor the
// on-chain verifier implements. A proof reveals nothing about the witness
// (the secret, the leaf's position, its Merkle path) beyond the public
// inputs. Proofs are randomized: two proofs of one witness differ, and both
// verify.

import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';
import { fromHex, hex, toBytes32 } from './field.js';
import { noirInputs, publicInputBytes, publicInputs } from './inputs.js';
import type { PublicInputs, Witness } from './inputs.js';
import type { Bytes32 } from './field.js';

/** A compiled circuit artifact (`circuits/artifacts/*.json`). */
export interface CompiledCircuit {
  noir_version: string;
  hash: string | number;
  abi: unknown;
  bytecode: string;
}

/** Bytes of a zero-knowledge UltraHonk proof for this verifier (507 field
 * elements). */
export const PROOF_BYTES = 507 * 32;

export interface Proof {
  proof: Uint8Array;
  publicInputs: PublicInputs;
}

export interface ProveOptions {
  /** Barretenberg worker threads (needs cross-origin isolation in browsers). */
  threads?: number;
}

/** Prove `witness` against `circuit`. */
export async function prove(
  circuit: CompiledCircuit,
  witness: Witness,
  options: ProveOptions = {},
): Promise<Proof> {
  const expected = publicInputs(witness);
  // The committed artifacts drop nargo's machine-specific debug info (absolute
  // source paths), which execution does not need.
  const noir = new Noir({
    ...circuit,
    debug_symbols: '',
    file_map: {},
  } as unknown as ConstructorParameters<typeof Noir>[0]);
  const { witness: solved } = await noir.execute(noirInputs(witness));
  const backend = new UltraHonkBackend(circuit.bytecode, { threads: options.threads ?? 1 });
  try {
    const out = await backend.generateProof(solved, { keccakZK: true });
    const got = out.publicInputs.map((v) => toBytes32(BigInt(v)));
    const want = [expected.root, expected.nullifier, expected.statementHash];
    if (got.length !== 3 || got.some((g, i) => !equal(g, want[i]!))) {
      throw new Error('prover public inputs differ from the host computation');
    }
    if (out.proof.length !== PROOF_BYTES) {
      throw new Error(`unexpected proof length ${out.proof.length}`);
    }
    return { proof: out.proof, publicInputs: expected };
  } finally {
    await backend.destroy();
  }
}

/** Check `p` against `circuit` with bb.js's own verifier, as the adapter
 * would check it (same flavor, same verification key). For a client's
 * self-check before submitting; the chain does not depend on it. */
export async function verify(
  circuit: CompiledCircuit,
  p: Proof,
  options: ProveOptions = {},
): Promise<boolean> {
  const backend = new UltraHonkBackend(circuit.bytecode, { threads: options.threads ?? 1 });
  try {
    const { root, nullifier, statementHash } = p.publicInputs;
    return await backend.verifyProof(
      { proof: p.proof, publicInputs: [root, nullifier, statementHash].map(hex) },
      { keccakZK: true },
    );
  } finally {
    await backend.destroy();
  }
}

/** The contract's `ZkEvidence` fields, ready for a contract client. */
export interface ZkEvidence {
  treeId: number;
  root: Bytes32;
  nullifier: Bytes32;
  proof: Uint8Array;
}

export function evidence(treeId: number, p: Proof): ZkEvidence {
  return { treeId, root: p.publicInputs.root, nullifier: p.publicInputs.nullifier, proof: p.proof };
}

export { publicInputBytes };

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Parse a hex string into exactly 32 bytes. */
export function bytes32(s: string): Bytes32 {
  const b = fromHex(s);
  if (b.length !== 32) throw new Error(`expected 32 bytes: ${s}`);
  return b;
}
