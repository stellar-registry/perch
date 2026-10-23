// The few Soroban `ScVal` XDR encodings authorization needs, written out by
// hand so perch-js carries no Stellar SDK: a `Vec<u32>` (what OZ appends to
// the signature payload) and OZ's `AuthPayload` (what an account's auth entry
// carries as its signature). Byte-identical to `soroban_sdk`'s `to_xdr`,
// pinned against testdata/auth/auth-vectors.json, which the Rust suite writes
// with the account's own types.

import { addressPayload } from './statement.js';

// `ScValType` discriminants (Stellar-contract.x).
const SCV_U32 = 3;
const SCV_BYTES = 13;
const SCV_SYMBOL = 15;
const SCV_VEC = 16;
const SCV_MAP = 17;
const SCV_ADDRESS = 18;

/** An OZ `Signer`: a delegated address, or a key checked by a verifier. */
export type SignerKey =
  | { kind: 'delegated'; address: string }
  | { kind: 'external'; verifier: string; key: Uint8Array };

class XdrWriter {
  private readonly parts: Uint8Array[] = [];

  u32(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error(`not a u32: ${v}`);
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v);
    this.parts.push(b);
    return this;
  }

  /** Variable-length opaque: length, bytes, zero padding to 4. */
  opaque(b: Uint8Array): this {
    this.u32(b.length);
    this.parts.push(b);
    const pad = (4 - (b.length % 4)) % 4;
    if (pad) this.parts.push(new Uint8Array(pad));
    return this;
  }

  fixed(b: Uint8Array): this {
    this.parts.push(b);
    return this;
  }

  done(): Uint8Array {
    const out = new Uint8Array(this.parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of this.parts) {
      out.set(p, at);
      at += p.length;
    }
    return out;
  }
}

function scU32(w: XdrWriter, v: number) {
  w.u32(SCV_U32).u32(v);
}

function scSymbol(w: XdrWriter, s: string) {
  w.u32(SCV_SYMBOL).opaque(new TextEncoder().encode(s));
}

function scBytes(w: XdrWriter, b: Uint8Array) {
  w.u32(SCV_BYTES).opaque(b);
}

function scAddress(w: XdrWriter, strkey: string) {
  const { tag, payload } = addressPayload(strkey);
  w.u32(SCV_ADDRESS).u32(tag);
  // An account address is a `PublicKey`, whose only arm is ed25519 (0).
  if (tag === 0) w.u32(0);
  w.fixed(payload);
}

function scSigner(w: XdrWriter, s: SignerKey) {
  if (s.kind === 'delegated') {
    w.u32(SCV_VEC).u32(1).u32(2);
    scSymbol(w, 'Delegated');
    scAddress(w, s.address);
  } else {
    w.u32(SCV_VEC).u32(1).u32(3);
    scSymbol(w, 'External');
    scAddress(w, s.verifier);
    scBytes(w, s.key);
  }
}

function checkRuleIds(ruleIds: readonly number[]) {
  for (const id of ruleIds) {
    if (!Number.isInteger(id) || id < 0 || id > 0xffffffff) throw new Error(`not a rule id: ${id}`);
  }
}

/** `ScVal::Vec` of `ScVal::U32`: what `context_rule_ids.to_xdr()` produces. */
export function ruleIdsXdr(ruleIds: readonly number[]): Uint8Array {
  checkRuleIds(ruleIds);
  const w = new XdrWriter().u32(SCV_VEC).u32(1).u32(ruleIds.length);
  for (const id of ruleIds) scU32(w, id);
  return w.done();
}

const compareBytes = (a: Uint8Array, b: Uint8Array): number => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
};

const compareAddress = (a: string, b: string): number => {
  const x = addressPayload(a);
  const y = addressPayload(b);
  return x.tag - y.tag || compareBytes(x.payload, y.payload);
};

/** The host's ordering of two `Signer` values, which an `ScMap`'s keys must
 *  follow: by variant name (`Delegated` before `External`), then field by
 *  field. */
export function compareSigners(a: SignerKey, b: SignerKey): number {
  if (a.kind !== b.kind) return a.kind === 'delegated' ? -1 : 1;
  if (a.kind === 'delegated' && b.kind === 'delegated') return compareAddress(a.address, b.address);
  const x = a as Extract<SignerKey, { kind: 'external' }>;
  const y = b as Extract<SignerKey, { kind: 'external' }>;
  return compareAddress(x.verifier, y.verifier) || compareBytes(x.key, y.key);
}

/** OZ's `AuthPayload { signers: Map<Signer, Bytes>, context_rule_ids: Vec<u32> }`. */
export interface AuthPayload {
  contextRuleIds: number[];
  signers: { signer: SignerKey; signature: Uint8Array }[];
}

/** The `AuthPayload` as an `ScVal` (a struct is a map keyed by field name, in
 *  name order), the bytes an auth entry's `signature` carries. Signers are
 *  sorted into the host's key order; a repeated signer is refused. */
export function authPayloadXdr(payload: AuthPayload): Uint8Array {
  checkRuleIds(payload.contextRuleIds);
  const signers = [...payload.signers].sort((a, b) => compareSigners(a.signer, b.signer));
  for (let i = 1; i < signers.length; i++) {
    if (compareSigners(signers[i - 1]!.signer, signers[i]!.signer) === 0) throw new Error('repeated signer');
  }
  const w = new XdrWriter().u32(SCV_MAP).u32(1).u32(2);
  scSymbol(w, 'context_rule_ids');
  w.fixed(ruleIdsXdr(payload.contextRuleIds));
  scSymbol(w, 'signers');
  w.u32(SCV_MAP).u32(1).u32(signers.length);
  for (const { signer, signature } of signers) {
    scSigner(w, signer);
    scBytes(w, signature);
  }
  return w.done();
}
