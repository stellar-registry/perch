// The bytes the core reads, and the ledger keys a wallet fetches for it.
//
// The core's input is a small binary envelope (the crate's `envelope.rs`):
// big-endian u32s and length-prefixed byte strings around the account's
// `SorobanAuthorizationEntry` XDR and its `LedgerEntryData` XDRs, exactly
// as wallets and `getLedgerEntries` carry them. The keys are the
// `LedgerKey` XDRs of the account's entries `__check_auth` reads
// (`Snapshot::keys` in the crate).

import { scAddressOfStrkey } from './strkey.js';

/** XDR as bytes or standard base64. */
export type Xdr = Uint8Array | string;

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toBase64(b: Uint8Array): string {
  let bin = '';
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin);
}

export function bytesOf(x: Xdr): Uint8Array {
  return typeof x === 'string' ? fromBase64(x) : x;
}

/** A growable byte buffer of XDR pieces. */
class Out {
  private parts: number[] = [];
  u32(n: number): this {
    this.parts.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
    return this;
  }
  raw(b: Uint8Array): this {
    for (const x of b) this.parts.push(x);
    return this;
  }
  /** A length-prefixed byte string, unpadded (the envelope's form). */
  bytes(b: Uint8Array): this {
    return this.u32(b.length).raw(b);
  }
  /** An XDR opaque or string: length-prefixed and zero-padded. */
  opaque(b: Uint8Array): this {
    this.u32(b.length).raw(b);
    for (let i = b.length % 4; i % 4 !== 0; i++) this.parts.push(0);
    return this;
  }
  done(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

/** Whether a signer's signature verifies, as far as the caller knows. */
export type Verified = 'yes' | 'no' | 'assumed';

export interface ReviewInput {
  /** The account's `SorobanAuthorizationEntry`. */
  entry: Xdr;
  /** The account's ledger entries, as `getLedgerEntries` returns them (`LedgerEntryData`). */
  ledgerEntries: Iterable<Xdr>;
  /** The ledger sequence the transaction is expected to execute at. */
  ledger: number;
  /** One flag per payload signer, in the payload's order; omitted: every one assumed. */
  verified?: Verified[];
}

/** The core's `review` envelope. */
export function reviewEnvelope(input: ReviewInput): Uint8Array {
  const entries = Array.from(input.ledgerEntries, bytesOf);
  const out = new Out().u32(1).u32(input.ledger).bytes(bytesOf(input.entry)).u32(entries.length);
  for (const e of entries) out.bytes(e);
  const verified = input.verified ?? [];
  out.u32(verified.length);
  out.raw(Uint8Array.from(verified, (v) => (v === 'no' ? 0 : v === 'yes' ? 1 : 2)));
  return out.done();
}

/** The core's `chosen` envelope. */
export function chosenEnvelope(entry: Xdr): Uint8Array {
  return new Out().u32(1).bytes(bytesOf(entry)).done();
}

/** The core's `budget` envelope: a `StoredRecord` and a `StoredCap` (`ScVal` XDR), and a ledger. */
export function budgetEnvelope(record: Xdr, cap: Xdr, ledger: number): Uint8Array {
  return new Out().u32(1).bytes(bytesOf(record)).bytes(bytesOf(cap)).u32(ledger).done();
}

/** The core's `witness` envelope: parent rules, steps and child rules (`ScVal` XDR). */
export function witnessEnvelope(parent: Xdr, steps: Xdr, child: Xdr): Uint8Array {
  return new Out().u32(1).bytes(bytesOf(parent)).bytes(bytesOf(steps)).bytes(bytesOf(child)).done();
}

const SCV_U32 = 3;
const SCV_SYMBOL = 15;
const SCV_VEC = 16;
const PERSISTENT = 1;

/** `Symbol(name)`, the key of a `PerchStorage` item. */
function itemKey(name: string): Uint8Array {
  return new Out().u32(SCV_SYMBOL).opaque(new TextEncoder().encode(name)).done();
}

/** `[Symbol(name), U32(id)]`, the key of a `PerchStorage` map entry. */
function mapKey(name: string, id: number): Uint8Array {
  return new Out()
    .u32(SCV_VEC)
    .u32(1)
    .u32(2)
    .raw(itemKey(name))
    .u32(SCV_U32)
    .u32(id)
    .done();
}

/** The `LedgerKey` XDR of a persistent contract-data entry. */
function dataKey(account: Uint8Array, key: Uint8Array): Uint8Array {
  return new Out().u32(6).raw(account).raw(key).u32(PERSISTENT).done();
}

/** The `LedgerKey` XDR of the account's instance entry. */
function instanceKey(account: Uint8Array): Uint8Array {
  return new Out().u32(6).raw(account).u32(20).u32(PERSISTENT).done();
}

function dedupe(keys: Uint8Array[]): string[] {
  return [...new Set(keys.map(toBase64))];
}

/**
 * The ledger keys (base64 `LedgerKey` XDR) `__check_auth` reads for an
 * entry choosing `ruleIds`: the account's instance entry, `RuleSet`, and each
 * id's `GrantTags` and `SpendRecords`. A tagged id's grant record is read
 * once its tag is: see {@link grantKeys}.
 */
export function ledgerKeys(account: string, ruleIds: Iterable<number>): string[] {
  const a = scAddressOfStrkey(account);
  const keys = [instanceKey(a), dataKey(a, itemKey('RuleSet'))];
  for (const id of ruleIds) {
    keys.push(dataKey(a, mapKey('GrantTags', id)), dataKey(a, mapKey('SpendRecords', id)));
  }
  return dedupe(keys);
}

/**
 * The `Grants` keys the fetched `GrantTags` entries among `ledgerEntries`
 * name for `ruleIds`: the second fetch, after {@link ledgerKeys}.
 */
export function grantKeys(
  account: string,
  ruleIds: Iterable<number>,
  ledgerEntries: Iterable<Xdr>,
): string[] {
  const a = scAddressOfStrkey(account);
  const entries = Array.from(ledgerEntries, bytesOf);
  const keys: Uint8Array[] = [];
  for (const id of ruleIds) {
    // `LedgerEntryData`: contract data, no extension, the address, the key,
    // the durability, then the value, here a `U32` grant id.
    const prefix = new Out()
      .u32(6)
      .u32(0)
      .raw(a)
      .raw(mapKey('GrantTags', id))
      .u32(PERSISTENT)
      .u32(SCV_U32)
      .done();
    for (const e of entries) {
      if (e.length === prefix.length + 4 && prefix.every((b, i) => e[i] === b)) {
        const grant = new DataView(e.buffer, e.byteOffset + prefix.length, 4).getUint32(0);
        keys.push(dataKey(a, mapKey('Grants', grant)));
      }
    }
  }
  return dedupe(keys);
}
