import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  decodeStoredScope,
  docHash,
  parsePolicyDocJson,
  rebuildScopeDoc,
  ScopeNotRebuilt,
  type SignerKey,
  type StoredCond,
  type StoredRule,
  type StoredScope,
  type StoredVal,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
// Written by crates/integration-tests/tests/scope_rebuild.rs from scopes the
// account applied, each with the canonical text it was applied as.
const vectors = JSON.parse(readFileSync(resolve(here, '../../../testdata/scope-rebuild/vectors.json'), 'utf8'));

/* eslint-disable @typescript-eslint/no-explicit-any */
const signer = (s: any): SignerKey =>
  s.kind === 'delegated' ? { kind: 'delegated', address: s.address } : { kind: 'external', verifier: s.verifier, key: hexToBytes(s.key) };

const val = (v: any): StoredVal => {
  switch (v.kind) {
    case 'bytes':
      return { kind: 'bytes', value: hexToBytes(v.value) };
    case 'other':
      return { kind: 'other', xdr: hexToBytes(v.xdr) };
    case 'i128':
    case 'u64':
      return { kind: v.kind, value: BigInt(v.value) };
    default:
      return v;
  }
};

const cond = (c: any): StoredCond => {
  switch (c.kind) {
    case 'argEq':
      return { ...c, value: val(c.value) };
    case 'argIn':
      return { ...c, values: c.values.map(val) };
    case 'argI128AtMost':
      return { ...c, bound: BigInt(c.bound) };
    default:
      return c;
  }
};

const rule = (r: any): StoredRule => ({
  contract: r.contract,
  functions: r.functions,
  conds: r.conds.map(cond),
  signers: r.signers.map(signer),
  threshold: r.threshold,
  cap: r.cap === null ? null : { limit: BigInt(r.cap.limit), period: r.cap.period, amountArg: r.cap.amountArg },
  validUntil: r.validUntil,
  generation: r.generation === null ? null : BigInt(r.generation),
});

const scope = (v: any): StoredScope => ({
  account: v.account,
  network: v.network,
  docHash: hexToBytes(v.docHash),
  signerIds: v.signerIds,
  rules: v.rules.map((r: any) => ({ name: r.name, rule: rule(r.rule) })),
});

/** A vector's views as the generated bindings return them. */
const native = (v: any) => {
  const tagged = (tag: string, ...values: unknown[]) => ({ tag, values });
  const nVal = (x: any) => {
    const tag = x.kind === 'other' ? 'Other' : x.kind[0].toUpperCase() + x.kind.slice(1);
    const inner = x.kind === 'address' ? x.address : x.kind === 'other' ? hexToBytes(x.xdr) : x.kind === 'i128' || x.kind === 'u64' ? BigInt(x.value) : x.value;
    return tagged(tag, inner);
  };
  const nCond = (c: any) =>
    c.kind === 'argEq'
      ? tagged('ArgEq', c.index, nVal(c.value))
      : c.kind === 'argIn'
        ? tagged('ArgIn', c.index, c.values.map(nVal))
        : c.kind === 'argI128AtMost'
          ? tagged('ArgI128AtMost', c.index, BigInt(c.bound))
          : tagged('ArgStrPrefix', c.index, c.prefix);
  const nSigner = (s: any) =>
    s.kind === 'delegated' ? tagged('Delegated', s.address) : tagged('External', s.verifier, Buffer.from(hexToBytes(s.key)));
  const ruleSet = v.rules.map(({ rule: r }: any) => ({
    contract: r.contract,
    functions: tagged(r.functions.kind === 'anyExcept' ? 'AnyExcept' : 'Only', r.functions.names),
    conds: r.conds.map(nCond),
    signers: r.signers.map(nSigner),
    threshold: r.threshold,
    cap: r.cap === null ? [] : [{ limit: BigInt(r.cap.limit), period: r.cap.period, amount_arg: r.cap.amountArg }],
    valid_until: r.validUntil ?? undefined,
    generation: r.generation === null ? undefined : BigInt(r.generation),
  }));
  const record = {
    gen: 0n,
    doc_hash: Buffer.from(hexToBytes(v.docHash)),
    rules: v.rules.map(({ name }: any, id: number) => ({ id, name })),
  };
  return { record, ruleSet, signerIds: v.signerIds };
};
/* eslint-enable @typescript-eslint/no-explicit-any */

describe('Rust parity: rebuildScopeDoc gives back every scoped document the account applied', () => {
  it('has vectors', () => expect(vectors.vectors.length).toBeGreaterThan(50));
  for (const v of vectors.vectors) {
    it(v.name, () => {
      const rebuilt = rebuildScopeDoc(scope(v));
      expect(rebuilt.canonical).toBe(v.canonical);
      expect(rebuilt.docHash).toBe(v.docHash);
      expect(docHash(rebuilt.doc)).toBe(v.docHash);
      // The rebuilt document is a valid document, the one applied.
      expect(parsePolicyDocJson(v.canonical)).toEqual(parsePolicyDocJson(rebuilt.canonical));
    });
  }
});

describe('rebuildScopeDoc trusts only what hashes to doc_hash', () => {
  const shared = vectors.vectors.find((v: { name: string }) => v.name === 'a signer shared across rules');

  it('refuses other signer ids', () => {
    const s = scope(shared);
    expect(() => rebuildScopeDoc({ ...s, signerIds: [...s.signerIds].reverse() })).toThrow(ScopeNotRebuilt);
    expect(() => rebuildScopeDoc({ ...s, signerIds: s.signerIds.slice(1) })).toThrow(ScopeNotRebuilt);
  });

  it('refuses another network', () => {
    expect(() => rebuildScopeDoc({ ...scope(shared), network: 'Public Global Stellar Network ; September 2015' })).toThrow(
      ScopeNotRebuilt,
    );
  });

  it('refuses rules in another order', () => {
    const s = scope(shared);
    expect(() => rebuildScopeDoc({ ...s, rules: [...s.rules].reverse() })).toThrow(ScopeNotRebuilt);
  });

  it('refuses a cap on anything but a transfer amount', () => {
    const v = vectors.vectors.find((x: { name: string }) => x.name === 'caps at their extremes');
    const s = scope(v);
    const [first, ...rest] = s.rules;
    const capped = { ...first!, rule: { ...first!.rule, conds: [] } };
    expect(() => rebuildScopeDoc({ ...s, rules: [capped, ...rest] })).toThrow(ScopeNotRebuilt);
  });
});

describe('decodeStoredScope', () => {
  it('reads the views as the generated bindings return them', () => {
    for (const v of vectors.vectors) {
      const n = native(v);
      expect(decodeStoredScope(v.account, v.network, n.record, n.ruleSet, n.signerIds)).toEqual(scope(v));
    }
  });

  it('is null for a scope the account does not have', () => {
    expect(decodeStoredScope('C', 'n', undefined, [], undefined)).toBeNull();
  });
});
