import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { authPayloadXdr, buildAuthPayload, ERROR_CODES, ruleIdsXdr, signingDigest, type SignerKey } from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
// Written by crates/integration-tests/tests/auth_vectors.rs from the
// account's own types; that suite also checks the digest against the one OZ
// hands a verifier.
const vectors = JSON.parse(readFileSync(resolve(here, '../../../testdata/auth/auth-vectors.json'), 'utf8'));

type JsonSigner = { kind: 'delegated'; address: string } | { kind: 'external'; verifier: string; key: string };
const signer = (s: JsonSigner): SignerKey =>
  s.kind === 'delegated' ? s : { kind: 'external', verifier: s.verifier, key: hexToBytes(s.key) };

describe('Rust parity: the signing digest', () => {
  for (const v of vectors.signing_digest) {
    it(`rule ids [${v.rule_ids.join(', ')}]`, () => {
      expect(bytesToHex(ruleIdsXdr(v.rule_ids))).toBe(v.rule_ids_xdr);
      expect(bytesToHex(signingDigest(hexToBytes(v.signature_payload), v.rule_ids))).toBe(v.digest);
    });
  }

  it('refuses a payload that is not 32 bytes', () => {
    expect(() => signingDigest(new Uint8Array(31), [0])).toThrow();
  });
});

describe('Rust parity: the AuthPayload', () => {
  for (const v of vectors.auth_payload) {
    it(`${v.signers.length} signers, rule ids [${v.rule_ids.join(', ')}]`, () => {
      const signatures = v.signers.map((s: { signer: JsonSigner; signature: string }) => ({
        signer: signer(s.signer),
        signature: hexToBytes(s.signature),
      }));
      // Given out of the host's order: the encoder sorts.
      const selection = { account: '', revision: 0n, ruleIds: v.rule_ids };
      expect(bytesToHex(buildAuthPayload(selection, signatures))).toBe(v.xdr);
      expect(bytesToHex(authPayloadXdr({ contextRuleIds: v.rule_ids, signers: [...signatures].reverse() }))).toBe(v.xdr);
    });
  }

  it('refuses a signer named twice', () => {
    const s: SignerKey = { kind: 'delegated', address: 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA' };
    expect(() =>
      authPayloadXdr({
        contextRuleIds: [0],
        signers: [
          { signer: s, signature: new Uint8Array() },
          { signer: s, signature: new Uint8Array() },
        ],
      }),
    ).toThrow(/repeated/);
  });
});

describe('Rust parity: contract error codes', () => {
  it('match the account and OZ', () => {
    expect(ERROR_CODES.accountStaleRevision).toBe(vectors.error_codes.account_stale_revision);
    expect(ERROR_CODES.accountFrozen).toBe(vectors.error_codes.account_frozen);
    expect(ERROR_CODES.contextRuleNotFound).toBe(vectors.error_codes.context_rule_not_found);
  });
});
