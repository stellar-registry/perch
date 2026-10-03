import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as contracts from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const repo = (...p: string[]) => resolve(here, '../../..', ...p);
const manifest = JSON.parse(readFileSync(repo('deployments/testnet.json'), 'utf8'));

const MODULES = {
  account: { module: contracts.account, contract: 'perch-account' },
  factory: { module: contracts.factory, contract: 'perch-account-factory' },
  recovery: { module: contracts.recovery, contract: 'perch-recovery' },
  pool: { module: contracts.pool, contract: 'perch-zk-pool' },
  adapter: { module: contracts.adapter, contract: 'perch-zk-adapter' },
  webauthnVerifier: { module: contracts.webauthnVerifier, contract: 'perch-webauthn-verifier' },
  docCompiler: { module: contracts.docCompiler, contract: 'perch-doc-compiler' },
};

describe('generated from the deployment', () => {
  it('ships the manifest unchanged', () => {
    expect(contracts.testnet).toEqual(manifest);
  });

  for (const [name, { module, contract }] of Object.entries(MODULES)) {
    it(`${name} bindings come from the deployed ${contract}`, () => {
      expect(module.WASM_SHA256).toBe(manifest.contracts[contract].sha256);
    });
  }

  it('exposes the entry points wallets call', () => {
    const fns = (m: { Client: new (...a: never[]) => unknown }) => {
      const client = new (m.Client as unknown as new (o: object) => { spec: { funcs(): { name: { toString(): string } }[] } })({
        contractId: manifest.contracts['perch-account-factory'].address,
        networkPassphrase: manifest.network_passphrase,
        rpcUrl: manifest.rpc_url,
      });
      return client.spec.funcs().map((f) => f.name.toString());
    };
    expect(fns(contracts.factory)).toEqual(
      expect.arrayContaining(['create', 'create_passkey', 'passkey_address', 'account_wasm_hash', 'webauthn_verifier']),
    );
    expect(fns(contracts.account)).toEqual(
      expect.arrayContaining(['apply_doc', 'execute', 'applied_doc', 'infra', 'schedule_upgrade', 'cancel_recovery']),
    );
    expect(fns(contracts.recovery)).toEqual(
      expect.arrayContaining(['begin_lost_key', 'submit_guardian', 'submit_zk', 'approve_change', 'submit_zk_change', 'statement']),
    );
    expect(fns(contracts.pool)).toEqual(expect.arrayContaining(['leaves', 'is_known_root', 'enrollment', 'tree']));
  });

  it('addresses come from the manifest', () => {
    expect(contracts.addressOf(contracts.testnet, 'perch-account-factory')).toBe(
      manifest.contracts['perch-account-factory'].address,
    );
    expect(() => contracts.addressOf(contracts.testnet, 'perch-account')).toThrow(/no address/);
  });
});

// Against testnet: PERCH_LIVE=1 npm test.
describe.runIf(process.env.PERCH_LIVE)('the deployed testnet stack, through the bindings', () => {
  const opts = (contractId: string) => ({
    contractId,
    networkPassphrase: manifest.network_passphrase,
    rpcUrl: manifest.rpc_url,
  });

  it('the factory pins the manifest account and verifier', async () => {
    const f = new contracts.factory.Client(opts(contracts.addressOf(contracts.testnet, 'perch-account-factory')));
    expect(Buffer.from((await f.account_wasm_hash()).result).toString('hex')).toBe(
      manifest.contracts['perch-account'].sha256,
    );
    expect((await f.webauthn_verifier()).result).toBe(manifest.contracts['perch-webauthn-verifier'].address);
  });

  it('an exercised account resolves the manifest infra', async () => {
    const exercise = JSON.parse(readFileSync(repo('deployments/testnet-exercise.json'), 'utf8'));
    const a = new contracts.account.Client(opts(exercise.accounts[0].address));
    const infra = (await a.infra()).result;
    expect(infra.doc_compiler).toBe(manifest.contracts['perch-doc-compiler'].address);
    expect(infra.interpreter).toBe(manifest.contracts['perch-interpreter'].address);
    expect(infra.spending_limit).toBe(manifest.contracts['perch-spending-limit'].address);
  });

  it('the adapter verifies the manifest circuit', async () => {
    const ad = new contracts.adapter.Client(opts(contracts.addressOf(contracts.testnet, 'perch-zk-adapter')));
    expect(Buffer.from((await ad.circuit_id()).result).toString('hex')).toBe(manifest.zk.circuit_id);
  });
});
