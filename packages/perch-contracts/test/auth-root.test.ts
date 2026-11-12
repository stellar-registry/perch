import { describe, expect, it } from 'vitest';
import { xdr } from '@stellar/stellar-sdk';
import { account, legacyAccount, legacyDocCompiler } from '../src/index.js';

const address = 'CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF';
const opts = { contractId: address, networkPassphrase: 'Test SDF Network ; September 2015', rpcUrl: 'https://example.invalid' };
const current = new account.Client(opts).spec;
const legacy = new legacyAccount.Client(opts).spec;
const udt = (name: string) => xdr.ScSpecTypeDef.scSpecTypeUdt(new xdr.ScSpecTypeUdt({ name }));

const oldRule = {
  context_type: { tag: 'CallContract', values: [address] }, id: 1, name: 'pay',
  policies: [], recovery: false, signers: [], valid_until: null,
};

describe('root-aware and legacy contract ABI boundaries', () => {
  it('retains a usable snapshot-1 spec and compiler', () => {
    const value = legacy.nativeToScVal(oldRule, udt('InstalledRule'));
    expect(legacy.scValToNative(value, udt('InstalledRule'))).toEqual(oldRule);
    // The SDK decodes by index: supplying the new spec cannot be a fallback.
    expect(() => current.scValToNative(value, udt('InstalledRule'))).toThrow();
    expect(new legacyDocCompiler.Client(opts).spec.funcs().map((f) => f.name.toString())).toContain('compile_doc');
  });

  it('round-trips optional singleton roots in the generated new spec', () => {
    for (const auth_root of [null, [{ contract: address, function: 'guess' }]]) {
      const rule = { ...oldRule, auth_root };
      const value = current.nativeToScVal(rule, udt('InstalledRule'));
      expect(current.scValToNative(value, udt('InstalledRule'))).toEqual(rule);
      expect(() => legacy.scValToNative(value, udt('InstalledRule'))).toThrow();
    }
  });

  it('decodes the snapshot-3 stored rule as a tuple and refuses the old map', () => {
    // contract, functions, conds, signer positions, threshold, cap, valid_until, generation, auth_root
    const stored = [address, { tag: 'Only', values: [['transfer']] }, [{ tag: 'ArgIn', values: [1, ['a', 'b']] }], [0, 1], 2, [[10n, 100, 2]], 999, 7n, [{ contract: address, function: 'guess' }]];
    const value = current.nativeToScVal(stored, udt('StoredRule'));
    expect((value as unknown as { type: string }).type).toBe('scvVec');
    expect(current.scValToNative(value, udt('StoredRule'))).toEqual(stored);
    // A struct with named fields is a map: one where the tuple belongs is refused.
    const map = current.nativeToScVal({ contract: address, function: 'guess' }, udt('StoredAuthRoot'));
    expect((map as unknown as { type: string }).type).toBe('scvMap');
    expect(() => current.scValToNative(map, udt('StoredRule'))).toThrow();
  });

  it('keeps the capabilities view decodable before selecting a spec', () => {
    // Snapshot 2's build and this one (snapshot 3).
    for (const [interface_version, snapshot_version] of [[3, 2], [4, 3]]) {
      const capabilities = { interface_version, snapshot_version, doc_identity: 'canon_v1', auth_digest: 'addr_oz_v1', apply_modes: ['one_tx', 'grant_v1'] };
      const value = current.nativeToScVal(capabilities, udt('AccountCapabilities'));
      expect(legacy.scValToNative(value, udt('AccountCapabilities'))).toEqual(capabilities);
    }
  });
});
