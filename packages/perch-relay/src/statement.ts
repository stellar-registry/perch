// The recovery statement a guardian signs, byte for byte as
// docs/recovery/statement.md lays it out, and the controller call it
// commits to. A guardian's entry authorizes only `controller.<fn>(digest)`:
// the call's other arguments (account, attempt id or subject, evidence
// domain or expiry) are not signed. Only `sha256(encoding)` is. A relay
// without the chain can therefore trust a call's arguments only when they
// follow from a statement that hashes to the signed digest. This module
// checks that. It is pinned against testdata/recovery/statement-v2.json, the
// vectors perch-js and the Rust interface crate assert too.

import { Address, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { ApprovalError } from './approval.js';
import type { ApprovalFunction, ParsedApproval } from './approval.js';

const enc = new TextEncoder();

const STATEMENT_DOMAIN = 'perch/recovery/statement';
const STATEMENT_VERSION = 0x02;

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

/** A statement on the wire, in the schema of
 * testdata/recovery/statement-v2.json: hashes as lowercase hex, `u64`s as
 * decimal strings (numbers are accepted too). */
export interface StatementJson {
  network_id: string;
  account: string;
  controller: string;
  config_epoch: string | number;
  config_hash: string;
  delay_ledgers: number;
  expiry_ledgers: number;
  valid_until_ledger: number;
  action: RecoveryAction;
  subject: Record<string, string | number>;
}

const HEX32 = /^[0-9a-f]{64}$/;

function bytes32(v: unknown, field: string): Uint8Array {
  if (typeof v !== 'string' || !HEX32.test(v)) throw new ApprovalError(`statement ${field} must be 64 hex characters`);
  return Uint8Array.from(Buffer.from(v, 'hex'));
}

function u32(v: unknown, field: string): number {
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 0xffffffff) {
    throw new ApprovalError(`statement ${field} must be a u32`);
  }
  return v;
}

function u64(v: unknown, field: string): bigint {
  const ok = (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0) || (typeof v === 'string' && /^[0-9]+$/.test(v));
  if (!ok) throw new ApprovalError(`statement ${field} must be a u64 (a number or a decimal string)`);
  const n = BigInt(v as number | string);
  if (n > 0xffffffffffffffffn) throw new ApprovalError(`statement ${field} must be a u64`);
  return n;
}

function contract(v: unknown, field: string): string {
  if (typeof v !== 'string' || !StrKey.isValidContract(v)) throw new ApprovalError(`statement ${field} must be a C... address`);
  return v;
}

const hexOf = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** `s` as {@link StatementJson}. Takes perch-js's `RecoveryStatement` as is. */
export function statementJson(s: RecoveryStatement): StatementJson {
  const sub = s.subject;
  let subject: StatementJson['subject'];
  switch (sub.action) {
    case 'lost-key':
    case 'compromise':
      subject = {
        attempt_id: sub.attemptId.toString(),
        source_doc_hash: hexOf(sub.sourceDocHash),
        target_doc_hash: hexOf(sub.targetDocHash),
        replacements_hash: hexOf(sub.replacementsHash),
      };
      break;
    case 'cancel':
      subject = { attempt_id: sub.attemptId.toString(), attempt_statement: hexOf(sub.attemptStatement) };
      break;
    case 'reconfigure':
      subject = sub.change === 'remove' ? { change: 'remove' } : { change: 'set', new_config_hash: hexOf(sub.change.set) };
      break;
    case 'upgrade':
      subject = { request_id: sub.requestId.toString(), wasm_hash: hexOf(sub.wasmHash) };
      break;
  }
  return {
    network_id: hexOf(s.networkId),
    account: s.account,
    controller: s.controller,
    config_epoch: s.epoch.toString(),
    config_hash: hexOf(s.configHash),
    delay_ledgers: s.delayLedgers,
    expiry_ledgers: s.expiryLedgers,
    valid_until_ledger: s.validUntilLedger,
    action: sub.action,
    subject,
  };
}

/** Read a {@link StatementJson}. Other fields (a vector's `name`,
 * `encoding`, `digest`) are ignored. */
export function parseStatement(json: unknown): RecoveryStatement {
  if (typeof json !== 'object' || json === null) throw new ApprovalError('statement must be an object');
  const v = json as Record<string, unknown>;
  if (typeof v.subject !== 'object' || v.subject === null) throw new ApprovalError('statement subject must be an object');
  const s = v.subject as Record<string, unknown>;
  let subject: StatementSubject;
  switch (v.action) {
    case 'lost-key':
    case 'compromise':
      subject = {
        action: v.action,
        attemptId: u64(s.attempt_id, 'subject.attempt_id'),
        sourceDocHash: bytes32(s.source_doc_hash, 'subject.source_doc_hash'),
        targetDocHash: bytes32(s.target_doc_hash, 'subject.target_doc_hash'),
        replacementsHash: bytes32(s.replacements_hash, 'subject.replacements_hash'),
      };
      break;
    case 'cancel':
      subject = {
        action: 'cancel',
        attemptId: u64(s.attempt_id, 'subject.attempt_id'),
        attemptStatement: bytes32(s.attempt_statement, 'subject.attempt_statement'),
      };
      break;
    case 'reconfigure':
      if (s.change !== 'set' && s.change !== 'remove') throw new ApprovalError('statement subject.change must be set or remove');
      subject = {
        action: 'reconfigure',
        change: s.change === 'remove' ? 'remove' : { set: bytes32(s.new_config_hash, 'subject.new_config_hash') },
      };
      break;
    case 'upgrade':
      subject = {
        action: 'upgrade',
        requestId: u64(s.request_id, 'subject.request_id'),
        wasmHash: bytes32(s.wasm_hash, 'subject.wasm_hash'),
      };
      break;
    default:
      throw new ApprovalError('statement action must be lost-key, compromise, cancel, reconfigure, or upgrade');
  }
  return {
    networkId: bytes32(v.network_id, 'network_id'),
    account: contract(v.account, 'account'),
    controller: contract(v.controller, 'controller'),
    epoch: u64(v.config_epoch, 'config_epoch'),
    configHash: bytes32(v.config_hash, 'config_hash'),
    delayLedgers: u32(v.delay_ledgers, 'delay_ledgers'),
    expiryLedgers: u32(v.expiry_ledgers, 'expiry_ledgers'),
    validUntilLedger: u32(v.valid_until_ledger, 'valid_until_ledger'),
    subject,
  };
}

class Writer {
  private parts: Uint8Array[] = [];
  bytes(b: Uint8Array, len?: number): this {
    if (len !== undefined && b.length !== len) throw new ApprovalError(`expected ${len} bytes`);
    this.parts.push(b);
    return this;
  }
  u8(n: number): this {
    return this.bytes(Uint8Array.of(n));
  }
  u32(n: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n);
    return this.bytes(b);
  }
  u64(n: bigint): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n);
    return this.bytes(b);
  }
  done(): Uint8Array {
    return Uint8Array.from(Buffer.concat(this.parts));
  }
}

const contractId = (strkey: string) => Uint8Array.from(StrKey.decodeContract(strkey));

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

/** What a guardian signs: `sha256(encoding)`, lowercase hex. */
export function statementDigest(s: RecoveryStatement): string {
  return Buffer.from(hash(Buffer.from(encodeStatement(s)))).toString('hex');
}

const sym = (s: string) => xdr.ScVal.scvSymbol(s);
const bytes = (b: Uint8Array) => xdr.ScVal.scvBytes(Buffer.from(b));

/** The controller call `statement` commits to, for the approval `fn` by
 * `guardian`, as base64 `ScVal`s:
 * - `submit_guardian(account, attempt_id, domain, guardian)` for an
 *   attempt's statement: `domain` is `EvidenceDomain::Initiate` (`0`) for
 *   `lost-key` and `compromise`, `Cancel` (`1`) for `cancel`;
 * - `approve_change(account, subject, valid_until, guardian)` for a
 *   `reconfigure` or `upgrade` statement.
 * Any other pairing is refused: the controller would build another
 * statement from it, whose digest the guardian did not sign. */
export function callArgsFor(s: RecoveryStatement, fn: ApprovalFunction, guardian: string): string[] {
  const account = Address.fromString(s.account).toScVal();
  const who = Address.fromString(guardian).toScVal();
  const sub = s.subject;
  let vals: xdr.ScVal[];
  if (fn === 'submit_guardian') {
    if (sub.action === 'reconfigure' || sub.action === 'upgrade') {
      throw new ApprovalError(`a ${sub.action} statement is approved through approve_change, not submit_guardian`);
    }
    // `EvidenceDomain` is an integer `#[contracttype]` enum: a `u32`.
    const domain = sub.action === 'cancel' ? 1 : 0;
    vals = [account, xdr.ScVal.scvU64(sub.attemptId), xdr.ScVal.scvU32(domain), who];
  } else {
    let subject: xdr.ScVal;
    if (sub.action === 'reconfigure') {
      const change = sub.change === 'remove' ? xdr.ScVal.scvVec([sym('Remove')]) : xdr.ScVal.scvVec([sym('Set'), bytes(sub.change.set)]);
      subject = xdr.ScVal.scvVec([sym('Reconfigure'), change]);
    } else if (sub.action === 'upgrade') {
      subject = xdr.ScVal.scvVec([
        sym('Upgrade'),
        xdr.ScVal.scvMap([
          new xdr.ScMapEntry({ key: sym('request_id'), val: xdr.ScVal.scvU64(sub.requestId) }),
          new xdr.ScMapEntry({ key: sym('wasm_hash'), val: bytes(sub.wasmHash) }),
        ]),
      ]);
    } else {
      throw new ApprovalError(`a ${sub.action} statement is approved through submit_guardian, not approve_change`);
    }
    vals = [account, subject, xdr.ScVal.scvU32(s.validUntilLedger), who];
  }
  return vals.map((v) => v.toXDR('base64'));
}

/** The call `approval` is for, rebuilt from the statement it signs: checks
 * that `json` is a statement for `controller` on `networkPassphrase` that
 * hashes to the approval's digest, and returns {@link callArgsFor} it. */
export function statementCall(
  json: unknown,
  approval: ParsedApproval,
  controller: string,
  networkPassphrase: string,
): string[] {
  const s = parseStatement(json);
  if (s.controller !== controller) throw new ApprovalError('the statement is for another controller');
  if (!Buffer.from(s.networkId).equals(hash(Buffer.from(networkPassphrase)))) {
    throw new ApprovalError('the statement is for another network');
  }
  if (statementDigest(s) !== approval.digest) throw new ApprovalError('the statement does not hash to the approved digest');
  return callArgsFor(s, approval.function, approval.guardian);
}
