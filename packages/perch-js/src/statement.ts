// The recovery statement and its companions, byte for byte as
// docs/recovery/statement.md lays them out: what a guardian's wallet
// recomputes before signing a digest, rather than trusting the digest an RPC
// hands it. Pinned against testdata/recovery/statement-v2.json, which an
// independent Python implementation writes and the Rust interface crate
// asserts too.

import { sha256 } from '@noble/hashes/sha2.js';

const enc = new TextEncoder();

const STATEMENT_DOMAIN = 'perch/recovery/statement';
const STATEMENT_VERSION = 0x02;
const CREDENTIAL_DOMAIN = 'perch/recovery/credential';
const REPLACEMENTS_DOMAIN = 'perch/recovery/replacements';

export type RecoveryAction = 'lost-key' | 'compromise' | 'cancel' | 'reconfigure' | 'upgrade';

const ACTION: Record<RecoveryAction, number> = {
  'lost-key': 1,
  compromise: 2,
  cancel: 3,
  reconfigure: 4,
  upgrade: 5,
};

export type StatementSubject =
  | {
      action: 'lost-key' | 'compromise';
      attemptId: bigint;
      sourceDocHash: Uint8Array;
      targetDocHash: Uint8Array;
      replacementsHash: Uint8Array;
    }
  | { action: 'cancel'; attemptId: bigint; attemptStatement: Uint8Array }
  | { action: 'reconfigure'; change: { set: Uint8Array } | 'remove' }
  | { action: 'upgrade'; requestId: bigint; wasmHash: Uint8Array };

/** `perch_recovery_interface::RecoveryStatement`. */
export interface RecoveryStatement {
  /** `sha256` of the network passphrase. */
  networkId: Uint8Array;
  /** The account (`C...`). */
  account: string;
  /** The controller (`C...`). */
  controller: string;
  epoch: bigint;
  configHash: Uint8Array;
  delayLedgers: number;
  expiryLedgers: number;
  validUntilLedger: number;
  subject: StatementSubject;
}

export type Credential =
  | { kind: 'delegated'; address: string }
  | { kind: 'external'; verifier: string; key: Uint8Array };

export interface Replacement {
  signerId: string;
  credential: Credential;
}

export interface ReplacementSet {
  signers: Replacement[];
  zkEnrollment?: { id: Uint8Array; commitment: Uint8Array };
}

// --- strkeys --------------------------------------------------------------

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function crc16xmodem(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

/** Decode a `G...` or `C...` strkey to its kind tag and 32-byte payload. */
export function addressPayload(strkey: string): { tag: 0 | 1; payload: Uint8Array } {
  if (!/^[GC][A-Z2-7]{55}$/.test(strkey)) throw new Error(`not a G... or C... address: ${strkey}`);
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of strkey) {
    value = (value << 5) | BASE32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  const raw = Uint8Array.from(out);
  const version = raw[0]!;
  const payload = raw.slice(1, 33);
  const checksum = raw[33]! | (raw[34]! << 8);
  if (crc16xmodem(raw.slice(0, 33)) !== checksum) throw new Error(`bad strkey checksum: ${strkey}`);
  if (version === 6 << 3) return { tag: 0, payload }; // account
  if (version === 2 << 3) return { tag: 1, payload }; // contract
  throw new Error(`unsupported strkey version: ${strkey}`);
}

function contractId(strkey: string): Uint8Array {
  const { tag, payload } = addressPayload(strkey);
  if (tag !== 1) throw new Error(`expected a contract address: ${strkey}`);
  return payload;
}

// --- encodings ------------------------------------------------------------

class Writer {
  private readonly parts: Uint8Array[] = [];
  bytes(b: Uint8Array, len?: number): this {
    if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
    this.parts.push(b);
    return this;
  }
  u8(v: number): this {
    return this.bytes(Uint8Array.of(v));
  }
  u32(v: number): this {
    if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) throw new Error(`not a u32: ${v}`);
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v);
    return this.bytes(b);
  }
  u64(v: bigint): this {
    if (v < 0n || v >= 1n << 64n) throw new Error(`not a u64: ${v}`);
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, v);
    return this.bytes(b);
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

/** The statement's fixed-width encoding (`statement.md`, "Statement"). */
export function encodeStatement(s: RecoveryStatement): Uint8Array {
  const w = new Writer()
    .bytes(enc.encode(STATEMENT_DOMAIN))
    .u8(STATEMENT_VERSION)
    .u8(ACTION[s.subject.action])
    .bytes(s.networkId, 32)
    .bytes(contractId(s.account), 32)
    .bytes(contractId(s.controller), 32)
    .u64(s.epoch)
    .bytes(s.configHash, 32)
    .u32(s.delayLedgers)
    .u32(s.expiryLedgers)
    .u32(s.validUntilLedger);
  const sub = s.subject;
  switch (sub.action) {
    case 'lost-key':
    case 'compromise':
      w.u64(sub.attemptId).bytes(sub.sourceDocHash, 32).bytes(sub.targetDocHash, 32).bytes(sub.replacementsHash, 32);
      break;
    case 'cancel':
      w.u64(sub.attemptId).bytes(sub.attemptStatement, 32);
      break;
    case 'reconfigure':
      if (sub.change === 'remove') w.u8(0).bytes(new Uint8Array(32));
      else w.u8(1).bytes(sub.change.set, 32);
      break;
    case 'upgrade':
      w.u64(sub.requestId).bytes(sub.wasmHash, 32);
      break;
  }
  return w.done();
}

/** What a guardian signs and the circuit binds: `sha256(encoding)`. */
export function statementDigest(s: RecoveryStatement): Uint8Array {
  return sha256(encodeStatement(s));
}

/** `statement.md`, "Credential". For an external key, pass the verifier's
 * canonical key (the WebAuthn verifier strips the credential id). */
export function encodeCredential(c: Credential): Uint8Array {
  if (c.kind === 'delegated') {
    const { tag, payload } = addressPayload(c.address);
    return new Writer().u8(1).u8(tag).bytes(payload).done();
  }
  const { tag, payload } = addressPayload(c.verifier);
  return new Writer().u8(2).u8(tag).bytes(payload).u32(c.key.length).bytes(c.key).done();
}

/** The fingerprint the account's revoked set holds. */
export function credentialFingerprint(c: Credential): Uint8Array {
  return sha256(new Writer().bytes(enc.encode(CREDENTIAL_DOMAIN)).bytes(encodeCredential(c)).done());
}

const lessThan = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i]! < b[i]!;
  return a.length < b.length;
};

/** `statement.md`, "Replacement set". Ids must be strictly ascending by
 * bytes; an unsorted or duplicated list is refused, not normalised. */
export function encodeReplacementSet(r: ReplacementSet): Uint8Array {
  const w = new Writer().u32(r.signers.length);
  let previous: Uint8Array | undefined;
  for (const { signerId, credential } of r.signers) {
    const id = enc.encode(signerId);
    if (previous && !lessThan(previous, id)) throw new Error('replacement ids must be strictly ascending');
    previous = id;
    w.u32(id.length).bytes(id).bytes(encodeCredential(credential));
  }
  if (r.zkEnrollment) w.u8(1).bytes(r.zkEnrollment.id, 32).bytes(r.zkEnrollment.commitment, 32);
  else w.u8(0);
  return w.done();
}

/** The `replacements_hash` an attempt's statement binds. */
export function replacementsHash(r: ReplacementSet): Uint8Array {
  return sha256(new Writer().bytes(enc.encode(REPLACEMENTS_DOMAIN)).bytes(encodeReplacementSet(r)).done());
}

/** `statement.md`, "ZK projection": `hi = 0^16 || x[0..16]`,
 * `lo = 0^16 || x[16..32]`, for the account, enrollment, and digest. */
export function zkStatementFields(s: RecoveryStatement, enrollmentId: Uint8Array) {
  const split = (x: Uint8Array) => {
    if (x.length !== 32) throw new Error('expected 32 bytes');
    const hi = new Uint8Array(32);
    const lo = new Uint8Array(32);
    hi.set(x.slice(0, 16), 16);
    lo.set(x.slice(16), 16);
    return [hi, lo] as const;
  };
  const [accountHi, accountLo] = split(contractId(s.account));
  const [enrollmentHi, enrollmentLo] = split(enrollmentId);
  const [digestHi, digestLo] = split(statementDigest(s));
  return { accountHi, accountLo, enrollmentHi, enrollmentLo, digestHi, digestLo };
}
