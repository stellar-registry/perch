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

  it('rejects a non-integer / out-of-range u32 (not-after-ledger)', () => {
    expect(() =>
      parsePolicyDoc({ ...valid, rules: [{ ...valid.rules[0], 'not-after-ledger': 1.5 }] }),
    ).toThrow();
    expect(() =>
      parsePolicyDoc({ ...valid, rules: [{ ...valid.rules[0], 'not-after-ledger': 2 ** 33 }] }),
    ).toThrow();
  });
});
