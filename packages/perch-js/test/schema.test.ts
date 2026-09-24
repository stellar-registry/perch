import { describe, it, expect } from 'vitest';
import { parsePolicyDoc } from '../src/schema.js';

const valid = {
  version: 1,
  signers: [{ id: 'a', verifier: 'C', key: 'ab' }],
  rules: [{ name: 'r', scope: { type: 'self-admin' }, principals: { type: 'all', signers: ['a'] } }],
};

describe('fail-closed schema', () => {
  it('accepts a minimal valid doc', () => {
    expect(() => parsePolicyDoc(valid)).not.toThrow();
  });

  it('rejects version != 1', () => {
    expect(() => parsePolicyDoc({ ...valid, version: 2 })).toThrow();
  });

  it('rejects an unknown top-level field', () => {
    expect(() => parsePolicyDoc({ ...valid, bogus: true })).toThrow();
  });

  it('rejects an unknown field inside a rule', () => {
    expect(() => parsePolicyDoc({ ...valid, rules: [{ ...valid.rules[0], bogus: 1 }] })).toThrow();
  });

  it('rejects an unknown scope tag', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        rules: [{ name: 'r', scope: { type: 'nope' }, principals: { type: 'all', signers: ['a'] } }],
      }),
    ).toThrow();
  });

  it('accepts threshold principals (M-of-N quorum)', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        rules: [
          {
            name: 'r',
            scope: { type: 'self-admin' },
            principals: { type: 'threshold', signers: ['a'], m: 1 },
          },
        ],
      }),
    ).not.toThrow();
  });

  it('rejects threshold principals missing m, with an unknown field, or a non-u32 m', () => {
    const rule = (principals: unknown) => ({
      ...valid,
      rules: [{ name: 'r', scope: { type: 'self-admin' }, principals }],
    });
    expect(() => parsePolicyDoc(rule({ type: 'threshold', signers: ['a'] }))).toThrow();
    expect(() =>
      parsePolicyDoc(rule({ type: 'threshold', signers: ['a'], m: 1, bogus: 1 })),
    ).toThrow();
    expect(() => parsePolicyDoc(rule({ type: 'threshold', signers: ['a'], m: 1.5 }))).toThrow();
  });

  it('rejects a non-integer / out-of-range u32 (not-after-ledger)', () => {
    expect(() =>
      parsePolicyDoc({ ...valid, rules: [{ ...valid.rules[0], 'not-after-ledger': 1.5 }] }),
    ).toThrow();
    expect(() =>
      parsePolicyDoc({ ...valid, rules: [{ ...valid.rules[0], 'not-after-ledger': 2 ** 33 }] }),
    ).toThrow();
  });
});

describe('recovery configuration', () => {
  const guardianOnlyRecovery = {
    profile: 'loss' as const,
    mode: {
      type: 'guardian-only' as const,
      guardians: ['GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH'],
      quorum: 1,
    },
    controller: 'CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF',
    replaceable: ['a'],
    'delay-ledgers': 100,
    'expiry-ledgers': 1000,
    'max-cancels': 3,
    'pending-activity': 'continue' as const,
  };

  it('accepts a document with no `recovery` field at all (the common case)', () => {
    expect(() => parsePolicyDoc(valid)).not.toThrow();
  });

  it('accepts a valid guardian-only recovery config', () => {
    expect(() => parsePolicyDoc({ ...valid, recovery: guardianOnlyRecovery })).not.toThrow();
  });

  it('rejects an unknown field on the recovery object', () => {
    expect(() =>
      parsePolicyDoc({ ...valid, recovery: { ...guardianOnlyRecovery, bogus: 1 } }),
    ).toThrow();
  });

  it('rejects guardian-only mode carrying a ZK field (strict per-variant shape)', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: {
          ...guardianOnlyRecovery,
          mode: { ...guardianOnlyRecovery.mode, verifier: 'C...' },
        },
      }),
    ).toThrow();
  });

  it('rejects an unknown recovery mode type', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: { ...guardianOnlyRecovery, mode: { type: 'nope' } },
      }),
    ).toThrow();
  });

  it('requires `pending-activity` explicitly (no default)', () => {
    const { 'pending-activity': _omit, ...withoutPendingActivity } = guardianOnlyRecovery;
    expect(() => parsePolicyDoc({ ...valid, recovery: withoutPendingActivity })).toThrow();
  });

  it('rejects an invalid `pending-activity` value', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: { ...guardianOnlyRecovery, 'pending-activity': 'restrict' },
      }),
    ).toThrow();
  });

  it('accepts a combined-mode recovery config with baseline', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: {
          ...guardianOnlyRecovery,
          profile: 'protected',
          mode: {
            type: 'combined',
            guardians: guardianOnlyRecovery.mode.guardians,
            quorum: 1,
            verifier: 'CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ',
            'circuit-id': '21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb',
          },
          baseline: { 'doc-hash': '27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98' },
        },
      }),
    ).not.toThrow();
  });
});
