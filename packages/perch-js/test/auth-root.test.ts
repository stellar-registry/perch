import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { canonicalJson, docHash, ruleHash } from '../src/canonical.js';
import { parsePolicyDoc } from '../src/schema.js';
import { policy, delegated } from '../src/builder.js';
import { requestToPolicyDoc } from '../src/request.js';
import { checkDocumentCapabilities, readSnapshot, type Snapshot } from '../src/snapshot.js';
import { AuthRootMismatch, selectRules } from '../src/selection.js';
import { decodeStoredRule } from '../src/bindings.js';
import { SimAccount } from './support/sim.js';

const read = (file: string) => readFileSync(new URL(`../../../testdata/${file}`, import.meta.url), 'utf8').trimEnd();
const fixture = parsePolicyDoc(JSON.parse(read('auth-root.json')));
const restricted = fixture.rules.find((r) => r['auth-root'])!;
const root = restricted['auth-root']!;
const token = restricted.scope.type === 'contract' ? restricted.scope.address : '';

describe('exact authorization root', () => {
  it('shares the Rust canonical/hash vector and commits each root field', () => {
    expect(canonicalJson(fixture)).toBe(read('auth-root.canonical.json'));
    expect(docHash(fixture)).toBe(read('auth-root.doc-hash'));
    for (const changed of [{ ...root, function: 'other' }, { ...root, contract: token }]) {
      expect(ruleHash({ ...restricted, 'auth-root': changed })).not.toBe(ruleHash(restricted));
    }
    const { 'auth-root': _, ...legacy } = restricted;
    expect(canonicalJson({ ...legacy, 'auth-root': undefined })).toBe(canonicalJson(legacy));
  });

  it('preserves the constraint through builders and requests', () => {
    const doc = policy().signer('key', delegated(root.contract))
      .rule('transfer', (r) => r.callContract(token).signedBy('key').func('transfer').authRoot(root.contract, root.function)).build();
    const request = requestToPolicyDoc({ signers: doc.signers, permissions: [{
      name: 'transfer', on: { contract: token }, by: ['key'], functions: ['transfer'], authRoot: root,
    }] });
    expect(request).toEqual(doc);
    expect(doc.rules[0]!['auth-root']).toEqual(root);
  });

  it('refuses malformed or administrative restrictions', () => {
    for (const value of [null, {}, { ...root, depth: 0 }, { ...root, function: '*' }, { ...root, contract: 'bad' }]) {
      expect(() => parsePolicyDoc({ ...fixture, rules: [{ ...restricted, 'auth-root': value }] })).toThrow();
    }
    expect(() => parsePolicyDoc({ ...fixture, rules: [{ ...restricted, scope: { type: 'self-admin' } }] })).toThrow();
  });

  it('requires a new account capability only when the document uses roots', () => {
    const legacy = { interfaceVersion: 2, snapshotVersion: 1, docIdentity: 'canon_v1', authDigest: 'addr_oz_v1', applyModes: ['one_tx'] };
    expect(() => checkDocumentCapabilities(fixture, legacy)).toThrow();
    expect(() => checkDocumentCapabilities(fixture, { ...legacy, interfaceVersion: 3, snapshotVersion: 2 })).not.toThrow();
    const old = { ...fixture, rules: fixture.rules.map(({ 'auth-root': _, ...r }) => r) };
    expect(() => checkDocumentCapabilities(old, legacy)).not.toThrow();
  });

  it('refuses snapshot 2 metadata loss before rule selection', async () => {
    const sim = new SimAccount();
    const reader = sim.reader();
    const capabilities = reader.capabilities.bind(reader);
    reader.capabilities = async () => {
      const answer = await capabilities();
      return { ...answer, value: { ...answer.value, interfaceVersion: 3, snapshotVersion: 2 } };
    };
    await expect(readSnapshot(reader)).rejects.toThrow('omits auth-root metadata');
    sim.rules = sim.rules.map((r) => ({ ...r, authRoot: null }));
    expect((await readSnapshot(reader)).configuration.rules[0]!.authRoot).toBeNull();
  });

  it('screens the supplied preorder as one entry and keeps a rule per context', () => {
    const snapshot = { account: token, configuration: { revision: 2n, rules: [
      { id: 1, recovery: false, name: 'game', contract: root.contract, authRoot: null },
      { id: 2, recovery: false, name: 'transfer', contract: token, authRoot: root },
    ] } } as unknown as Snapshot;
    const game = { name: 'game', scope: { type: 'contract' as const, address: root.contract } };
    const transfer = { name: 'transfer', scope: { type: 'contract' as const, address: token } };
    expect(selectRules(snapshot, [game, transfer], [root, { contract: token, function: 'transfer' }]).ruleIds).toEqual([1, 2]);
    expect(selectRules(snapshot, game, [root]).ruleIds).toEqual([1]);
    expect(() => selectRules(snapshot, transfer)).toThrow(AuthRootMismatch);
    expect(() => selectRules(snapshot, transfer, [{ contract: token, function: 'transfer' }])).toThrow(AuthRootMismatch);
    expect(() => selectRules(snapshot, [game, transfer], [root])).toThrow();
    expect(() => selectRules(snapshot, [game, transfer], [{ ...root, function: 'wrong' }, root])).toThrow(AuthRootMismatch);
  });

  it('recognizes legacy stored rules and never defaults malformed new layouts', () => {
    const old = { cap: [], conds: [], contract: token, functions: { tag: 'Only', values: [['transfer']] }, generation: 1n, signers: [], threshold: 1, valid_until: undefined };
    expect(decodeStoredRule(old).authRoot).toBeUndefined();
    expect(decodeStoredRule({ ...old, auth_root: [root] }).authRoot).toEqual(root);
    for (const value of [[], ['bad'], [{ ...root, function: '*' }], {}, [root, root]]) {
      expect(() => decodeStoredRule({ ...old, auth_root: value })).toThrow();
    }
    expect(() => decodeStoredRule({ ...old, auth_rooot: [root.contract, root.function] })).toThrow();
  });
});
