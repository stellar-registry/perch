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
  };
  const zkFactor = {
    adapter: 'CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ',
    'circuit-id': '21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb',
    pool: 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5',
    'enrollment-id': '6f0d1c2b3a49586776859483a2b1c0dfeefdfcfbfaf9f8f7f6f5f4f3f2f1f0e1',
    commitment: '0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff0',
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
          mode: { ...guardianOnlyRecovery.mode, adapter: zkFactor.adapter },
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

  it('rejects the removed `pending-activity` field as unknown', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: { ...guardianOnlyRecovery, 'pending-activity': 'continue' },
      }),
    ).toThrow();
  });

  it('accepts a valid zk-only recovery config', () => {
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: { ...guardianOnlyRecovery, mode: { type: 'zk-only', ...zkFactor } },
      }),
    ).not.toThrow();
  });

  it.each(['adapter', 'circuit-id', 'pool', 'enrollment-id', 'commitment'] as const)(
    'rejects a zk-only mode missing `%s`',
    (field) => {
      const { [field]: _omit, ...partial } = zkFactor;
      expect(() =>
        parsePolicyDoc({
          ...valid,
          recovery: { ...guardianOnlyRecovery, mode: { type: 'zk-only', ...partial } },
        }),
      ).toThrow();
    },
  );

  it('rejects a zk-only mode spelling the adapter as the old `verifier` field', () => {
    const { adapter, ...rest } = zkFactor;
    expect(() =>
      parsePolicyDoc({
        ...valid,
        recovery: {
          ...guardianOnlyRecovery,
          mode: { type: 'zk-only', verifier: adapter, ...rest },
        },
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
            ...zkFactor,
          },
          baseline: { 'doc-hash': '27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98' },
        },
      }),
    ).not.toThrow();
  });
});
