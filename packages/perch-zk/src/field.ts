// BN254 scalar-field values as they cross the contract boundary: 32-byte
// big-endian, canonical (< r). Mirrors perch-recovery-interface::zk.

/** The BN254 scalar field order `r`. */
export const FIELD_MODULUS =
  0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

/** `sha256("perch/recovery/zk/v2/<name>") mod r` — perch-recovery-interface::zk. */
export const DOM_LEAF = 0x1981de3e07709613862272edb5ff4fab545737382d1405fe8d0970dc7d4d7ed6n;
export const DOM_BIND = 0x20ae6172af8bed19c921e91e21641198661035616a6a4d733346853501fd07c5n;
export const DOM_NULLIFIER = 0x0280c3170f4abb8389838a5c280dbdac8bfd7c75fcb780a9485d93af553ab840n;
export const DOM_AUTH = 0x04e4c99c7477379c7e47c9380170e3fb1e7c565afe67dd56216df99861f1fb3cn;

export type Bytes32 = Uint8Array;

export function toBigInt(b: Bytes32): bigint {
  if (b.length !== 32) throw new Error(`expected 32 bytes, got ${b.length}`);
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function toBytes32(v: bigint): Bytes32 {
  if (v < 0n || v >= 1n << 256n) throw new Error('value does not fit in 32 bytes');
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function hex(b: Uint8Array): string {
  return '0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

export function fromHex(s: string): Uint8Array {
  const h = s.startsWith('0x') ? s.slice(2) : s;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error(`bad hex: ${s}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Whether `b`, read big-endian, is a canonical field element (`< r`). */
export function isCanonical(b: Bytes32): boolean {
  return toBigInt(b) < FIELD_MODULUS;
}

/** Big-endian 16/16 split of 32 bytes into two field elements, each `< 2^128`. */
export function splitHiLo(b: Bytes32): [bigint, bigint] {
  const v = toBigInt(b);
  return [v >> 128n, v & ((1n << 128n) - 1n)];
}

/** A uniformly random canonical secret (`< 2^253 < r`). */
export function randomSecret(): Bytes32 {
  const b = crypto.getRandomValues(new Uint8Array(32));
  b[0] = b[0]! & 0x1f;
  return b;
}
