import { beforeAll, describe, expect, it } from 'vitest';
import { commitment, init, leaf, node, nullifier, statementHash } from '../src/hash.js';
import { zeroHashes } from '../src/tree.js';
import { hex, toBytes32 } from '../src/field.js';

/** 32 bytes whose big-endian halves are the field elements `hi` and `lo`. */
const halves = (hi: number, lo: number) => toBytes32((BigInt(hi) << 128n) | BigInt(lo));
const small = (v: number) => toBytes32(BigInt(v));

// The same inputs and outputs `circuits/perch_zk/src/tests.nr::parity_vectors`
// (Noir) and `crates/perch-zk-primitives/src/test.rs::parity` (Soroban host)
// assert: the three Poseidon2 implementations agree.
describe('Poseidon2 parity with the circuit and the Soroban host', () => {
  beforeAll(init);

  it('every relation hash', () => {
    expect(hex(node(small(1), small(2)))).toBe(
      '0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383',
    );
    expect(hex(commitment(small(3)))).toBe(
      '0x301d7a7973f3ec9c92ebc8afa9855b49aef4ba8c7c67fb64fae99fac8992dfa0',
    );
    expect(hex(leaf(halves(4, 5), halves(6, 7), small(8)))).toBe(
      '0x241225f632b43077765a98b79d36e32782272c95b46b8a2c9275bfd0ac551d1c',
    );
    expect(hex(nullifier(halves(9, 10), halves(11, 12), small(13)))).toBe(
      '0x1ffa05820357fd280b04acdf157da0a4481feefec252476b44fc702b77902b8c',
    );
    expect(hex(statementHash(halves(14, 15), halves(16, 17), halves(18, 19)))).toBe(
      '0x17d4bf97cdbb6037d073d98b2e87f37039e7db0927c2be8b2f46c668b15f3cf7',
    );
    expect(hex(zeroHashes(32)[32]!)).toBe(
      '0x0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d',
    );
  });
});
