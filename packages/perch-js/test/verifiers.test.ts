import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalJson,
  checkVerifiers,
  docHash,
  isAdminDocument,
  named,
  parsePolicyDoc,
  parseVerifierName,
  policy,
  resolveVerifierName,
  unverifiedReuse,
  unverifiedVerifiers,
  unverifiedWarnings,
  UnverifiedVerifier,
  UnverifiedVerifierReused,
  external,
  verifierAddress,
  verifierRegistryId,
  VERIFIERS_PATH,
  type PolicyDoc,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const TESTNET = 'Test SDF Network ; September 2015';
const MAINNET = 'Public Global Stellar Network ; September 2015';
const V = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';
const W = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';
const APP = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const NAME = 'perch-webauthn-verifier@0.1.2';

describe('parseVerifierName', () => {
  it('reads a registry name and an exact version, as perch-ir does', () => {
    expect(parseVerifierName(NAME)).toEqual({ name: 'perch-webauthn-verifier', version: '0.1.2' });
    expect(parseVerifierName('a@0.0.0')).toEqual({ name: 'a', version: '0.0.0' });
    expect(parseVerifierName(`${'a'.repeat(64)}@1.0.0`)).not.toBeNull();
    for (const bad of [
      'perch',
      '@0.1.0',
      'Perch@0.1.0',
      'perch_x@0.1.0',
      '1perch@0.1.0',
      `${'a'.repeat(65)}@1.0.0`,
      'perch@0.1',
      'perch@0.1.0.0',
      'perch@01.0.0',
      'perch@0.1.0-rc.1',
      'perch@0.1.0@1.0.0',
      'perch@12345678901.0.0',
    ]) {
      expect(parseVerifierName(bad), bad).toBeNull();
    }
  });
});

describe('perch/verifiers', () => {
  it('is the path the account, the compiler and the factory compile in', () => {
    for (const krate of ['perch-doc-compiler', 'perch-smart-account', 'perch-account-factory']) {
      const text = readFileSync(resolve(here, `../../../crates/${krate}/wasm/verifiers.path`), 'utf8');
      const line = (key: string) =>
        text
          .split('\n')
          .find((l) => l.startsWith(`${key} `))!
          .slice(key.length + 1)
          .trim();
      expect(line('root-deployer'), krate).toBe(VERIFIERS_PATH.rootDeployer);
      expect(line('root-salt'), krate).toBe(VERIFIERS_PATH.rootSalt);
      expect(line('path').split('/'), krate).toEqual([...VERIFIERS_PATH.path]);
    }
  });

  it('derives what the Rust account and scripts/derive-id.py derive', () => {
    // crates/integration-tests/tests/registry_path.rs pins the same ids.
    expect(verifierRegistryId(TESTNET)).toBe('CCHJ7RWPMO33JB5PS74B64N4LVTWCGLEMH5IAKYCV32X56MXGYLHN5HW');
    expect(verifierRegistryId(MAINNET)).toBe('CCDCKRUV4W4DQYBWFWT4FNQ2QXQPGUQ7EXOZHIHSSLB6YJHMLHPMGDPH');
    // scripts/derive-id.py content <testnet perch/verifiers> <webauthn hash>.
    const hash = readFileSync(resolve(here, '../../../crates/perch-account-factory/wasm/perch-webauthn-verifier.sha256'), 'utf8').trim();
    expect(hash).toBe('f2e1dfce8c496be6d318045bc5a24ac5eb799ada837f92e8032ec953f1994230');
    expect(verifierAddress(TESTNET, hash)).toBe('CDMTSU5TO2EGN4Q76N376L3DX4MXGEDI6PVNXIWBDEUIFX74Y6PO2JMQ');
  });

  it('resolves a name through the registry the caller reads', async () => {
    const hash = 'f2e1dfce8c496be6d318045bc5a24ac5eb799ada837f92e8032ec953f1994230';
    const asked: string[][] = [];
    const resolved = await resolveVerifierName(NAME, TESTNET, async (registry, name, version) => {
      asked.push([registry, name, version]);
      return hash;
    });
    expect(asked).toEqual([[verifierRegistryId(TESTNET), 'perch-webauthn-verifier', '0.1.2']]);
    expect(resolved).toEqual({ verifierName: NAME, verifier: verifierAddress(TESTNET, hash), wasmHash: hash });
    await expect(resolveVerifierName('perch', TESTNET, async () => hash)).rejects.toMatchObject({ code: 'INVALID_VERIFIER_NAME' });
  });
});

const doc = (signers: PolicyDoc['signers'], rules: PolicyDoc['rules'], extra: Partial<PolicyDoc> = {}): PolicyDoc =>
  parsePolicyDoc({ version: 1, network: TESTNET, signers, rules, ...extra });

const admin = { name: 'admin', scope: { type: 'self-admin' as const }, principals: { type: 'all' as const, signers: ['a'] } };
const app = (signers: string[], m?: number) => ({
  name: `app-${signers.join('-')}`,
  scope: { type: 'contract' as const, address: APP },
  principals: m === undefined ? { type: 'all' as const, signers } : { type: 'threshold' as const, signers, m },
});

describe('a named verifier in a document', () => {
  it('is written beside its address and bound by the hash', () => {
    const d = policy()
      .network(TESTNET)
      .signer('a', named(NAME, W, '04' + '11'.repeat(64)))
      .rule('admin', (r) => r.selfAdmin().signedBy('a'))
      .build();
    expect(d.signers[0]).toEqual({ id: 'a', verifier: W, 'verifier-name': NAME, key: '04' + '11'.repeat(64) });
    expect(canonicalJson(d)).toContain(`"verifier":"${W}","verifier-name":"${NAME}"`);
    const unnamed = { ...d, signers: [{ id: 'a', verifier: W, key: '04' + '11'.repeat(64) }] };
    expect(docHash(d)).not.toBe(docHash(unnamed));
    expect(() => checkVerifiers(d)).not.toThrow();
  });

  it('may not be null', () => {
    expect(() => parsePolicyDoc({ version: 1, signers: [{ id: 'a', verifier: W, 'verifier-name': null, key: 'aa' }], rules: [] })).toThrow();
    expect(() => parsePolicyDoc({ version: 1, signers: [{ id: 'a', address: W, 'verifier-name': NAME }], rules: [] })).toThrow();
  });
});

describe('unverified verifiers', () => {
  const raw = (id: string, verifier = V, key = 'aa') => ({ id, verifier, key });
  const namedSigner = (id: string, key = 'bb') => ({ id, verifier: W, 'verifier-name': NAME, key });

  it('an admin document is one with a self-admin rule or a recovery member', () => {
    expect(isAdminDocument(doc([namedSigner('a')], [admin]))).toBe(true);
    expect(isAdminDocument(doc([raw('a')], [app(['a'])]))).toBe(false);
  });

  it('are listed once each, in declaration order, as the compile result lists them', () => {
    const d = doc([raw('a'), namedSigner('b'), raw('c', W, 'cc'), raw('d', V, 'dd')], [app(['a', 'b', 'c', 'd'], 1)]);
    expect(unverifiedVerifiers(d)).toEqual([V, W]);
  });

  it('are refused in an admin document', () => {
    const d = doc([namedSigner('a'), raw('x')], [admin, app(['x'])]);
    expect(() => checkVerifiers(d)).toThrow(UnverifiedVerifier);
    // Even the named verifier's own address, written without its name.
    expect(() => checkVerifiers(doc([raw('a', W)], [admin]))).toThrow(UnverifiedVerifier);
  });

  it('are allowed in a scoped document, one signer per rule, and warned about', () => {
    const d = doc([raw('a'), namedSigner('b'), raw('c', V, 'cc')], [app(['a', 'b'], 1), app(['c'])]);
    expect(() => checkVerifiers(d)).not.toThrow();
    expect(unverifiedWarnings(d)).toEqual([
      { rule: 'app-a-b', verifier: V, message: `Unverified verifier ${V}: it can approve anything this rule allows` },
      { rule: 'app-c', verifier: V, message: `Unverified verifier ${V}: it can approve anything this rule allows` },
    ]);
    const reused = doc([raw('a'), raw('c', V, 'cc')], [app(['a', 'c'], 2)]);
    expect(unverifiedReuse(reused)).toEqual({ rule: 'app-a-c', verifier: V });
    expect(() => checkVerifiers(reused)).toThrow(UnverifiedVerifierReused);
  });

  it('come from the plain external() builder', () => {
    const d = policy()
      .network(TESTNET)
      .signer('a', external(V, 'aa'))
      .rule('app', (r) => r.callContract(APP).signedBy('a'))
      .build();
    expect(unverifiedVerifiers(d)).toEqual([V]);
  });
});
