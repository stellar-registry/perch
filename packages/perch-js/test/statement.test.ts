import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  addressPayload,
  credentialFingerprint,
  encodeCredential,
  encodeReplacementSet,
  encodeStatement,
  replacementsHash,
  statementDigest,
  zkStatementFields,
  type Credential,
  type RecoveryStatement,
  type ReplacementSet,
  type StatementSubject,
} from '../src/statement.js';

// The vectors an independent Python implementation writes
// (scripts/recovery-statement-vectors.py) and the Rust interface crate
// asserts (crates/perch-recovery-interface/tests/vectors.rs).
const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(here, '../../../testdata/recovery/statement-v2.json'), 'utf8'),
);

type Json = Record<string, any>;
const h = (s: string) => hexToBytes(s);

function credential(c: Json): Credential {
  return c.kind === 'delegated'
    ? { kind: 'delegated', address: c.address }
    : { kind: 'external', verifier: c.verifier, key: h(c.key) };
}

function subject(v: Json): StatementSubject {
  const s = v.subject;
  switch (v.action) {
    case 'lost-key':
    case 'compromise':
      return {
        action: v.action,
        attemptId: BigInt(s.attempt_id),
        sourceDocHash: h(s.source_doc_hash),
        targetDocHash: h(s.target_doc_hash),
        replacementsHash: h(s.replacements_hash),
      };
    case 'cancel':
      return { action: 'cancel', attemptId: BigInt(s.attempt_id), attemptStatement: h(s.attempt_statement) };
    case 'reconfigure':
      return { action: 'reconfigure', change: s.change === 'remove' ? 'remove' : { set: h(s.new_config_hash) } };
    case 'upgrade':
      return { action: 'upgrade', requestId: BigInt(s.request_id), wasmHash: h(s.wasm_hash) };
  }
  throw new Error(`unknown action ${v.action}`);
}

function statement(v: Json): RecoveryStatement {
  return {
    networkId: h(v.network_id),
    account: v.account,
    controller: v.controller,
    epoch: BigInt(v.config_epoch),
    configHash: h(v.config_hash),
    delayLedgers: v.delay_ledgers,
    expiryLedgers: v.expiry_ledgers,
    validUntilLedger: v.valid_until_ledger,
    subject: subject(v),
  };
}

describe('recovery statement parity with statement-v2.json', () => {
  for (const v of vectors.statements as Json[]) {
    it(`${v.name}: encoding, digest, and ZK fields`, () => {
      const s = statement(v);
      expect(bytesToHex(encodeStatement(s))).toBe(v.encoding);
      expect(bytesToHex(statementDigest(s))).toBe(v.digest);
      const f = zkStatementFields(s, h(v.zk_fields.enrollment_id));
      expect(bytesToHex(f.accountHi)).toBe(v.zk_fields.account_hi);
      expect(bytesToHex(f.accountLo)).toBe(v.zk_fields.account_lo);
      expect(bytesToHex(f.enrollmentHi)).toBe(v.zk_fields.enrollment_hi);
      expect(bytesToHex(f.enrollmentLo)).toBe(v.zk_fields.enrollment_lo);
      expect(bytesToHex(f.digestHi)).toBe(v.zk_fields.digest_hi);
      expect(bytesToHex(f.digestLo)).toBe(v.zk_fields.digest_lo);
    });
  }

  for (const c of vectors.credentials as Json[]) {
    it(`${c.kind} credential: encoding and fingerprint`, () => {
      expect(bytesToHex(encodeCredential(credential(c)))).toBe(c.encoding);
      expect(bytesToHex(credentialFingerprint(credential(c)))).toBe(c.fingerprint);
    });
  }

  it('replacement set: encoding and hash', () => {
    const r = vectors.replacements as Json;
    const set: ReplacementSet = {
      signers: r.signers.map((s: Json) => ({ signerId: s.signer_id, credential: credential(s.credential) })),
      zkEnrollment: r.zk_enrollment && { id: h(r.zk_enrollment.id), commitment: h(r.zk_enrollment.commitment) },
    };
    expect(bytesToHex(encodeReplacementSet(set))).toBe(r.encoding);
    expect(bytesToHex(replacementsHash(set))).toBe(r.hash);
    expect(() => encodeReplacementSet({ ...set, signers: [...set.signers].reverse() })).toThrow(/ascending/);
  });

  it('refuses malformed addresses and the wrong address kind', () => {
    const v = vectors.statements[0] as Json;
    expect(() => addressPayload('CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXA')).toThrow(/checksum/);
    expect(() => encodeStatement({ ...statement(v), account: 'GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ' })).toThrow(
      /contract/,
    );
  });
});
