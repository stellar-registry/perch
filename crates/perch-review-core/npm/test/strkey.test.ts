// Strkeys against SEP-23's own vectors, and the `SCAddress` XDR the core
// writes.

import { describe, expect, it } from 'vitest';
import { decodeStrkey, scAddressOfStrkey, strkeyOfScAddress } from '../src/strkey.js';

const KEY = '3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a';
const G = 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ';
const C = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
const CID = '363eaa3867841fbad0f4ed88c779e4fe66e56a2470dc98c0ec9c073d05c7b103';
const M = 'MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

describe('strkeys', () => {
  it('match SEP-23', () => {
    expect(strkeyOfScAddress(`0000000000000000${KEY}`)).toBe(G);
    expect(strkeyOfScAddress(`00000001${CID}`)).toBe(C);
    expect(strkeyOfScAddress(`00000002${'00'.repeat(8)}${KEY}`)).toBe(M);
  });

  it('round-trip through the SCAddress XDR', () => {
    for (const s of [G, C, M]) expect(strkeyOfScAddress(scAddressOfStrkey(s))).toBe(s);
    expect(hex(scAddressOfStrkey(C))).toBe(`00000001${CID}`);
  });

  it('refuse a bad checksum', () => {
    expect(() => decodeStrkey(`${C.slice(0, -1)}A`)).toThrow();
  });
});
