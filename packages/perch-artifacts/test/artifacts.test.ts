import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  circuitManifest,
  constants,
  contentAddress,
  decodeContract,
  deployment,
  deploymentPath,
  paths,
  root,
  vectorPath,
  type VectorName,
} from '../src/index.js';

const pkg = fileURLToPath(new URL('..', import.meta.url));
const sources = JSON.parse(readFileSync(join(pkg, 'sources.json'), 'utf8')) as Record<string, string>;
const node = (...args: string[]) => spawnSync('node', args, { cwd: pkg, encoding: 'utf8' });

describe('content addresses (perch-derive-id)', () => {
  const testnet = deployment('testnet');
  const deployed = Object.entries(testnet.contracts).filter(([, c]) => c.address);

  it("match every address the manifest records, which crates/perch-derive-id derived", () => {
    expect(deployed.length).toBeGreaterThan(5);
    for (const [name, c] of deployed) {
      expect(contentAddress(testnet.registry.id, c.sha256, testnet.network_passphrase), name).toBe(c.address);
    }
  });

  it('come out of the bin the packaged fetch-infra-wasm.sh calls', () => {
    const [, c] = deployed[0]!;
    const run = node('dist/cli/derive-id.js', 'content', testnet.registry.id, c.sha256, testnet.network_passphrase);
    expect(run.status).toBe(0);
    expect(run.stdout.trim()).toBe(c.address);
  });

  it('refuse a malformed contract strkey', () => {
    const id = testnet.registry.id;
    expect(decodeContract(id)).toHaveLength(32);
    expect(() => decodeContract(id.slice(0, -1) + (id.endsWith('A') ? 'B' : 'A'))).toThrow(/not a contract/);
    expect(() => decodeContract(testnet.registry.admin)).toThrow(/not a contract/);
  });
});

describe('the index', () => {
  it('parses the manifests and constants', () => {
    expect(deployment().network).toBe('testnet');
    expect(circuitManifest.circuits.perch_zk_recovery?.depth).toBe(deployment().zk.tree_depth);
    expect(constants.doc_compiler.MAX_DOC_SIGNERS).toBeGreaterThan(0);
    expect(constants.program.MAX_PROGRAM_LEN).toBeGreaterThan(0);
  });

  it('points at files that exist', () => {
    for (const p of Object.values(paths)) expect(existsSync(p), p).toBe(true);
    expect(existsSync(deploymentPath('testnet'))).toBe(true);
    const vectors: VectorName[] = ['auth-vectors.json', 'diagnostic-events.json', 'statement-v2.json', 'rule-hashes.json', 'eval-vectors.json'];
    for (const v of vectors) expect(existsSync(vectorPath(v)), v).toBe(true);
    for (const c of Object.values(circuitManifest.circuits)) expect(existsSync(join(root, c.artifact)), c.artifact).toBe(true);
  });
});

describe('the packed artifacts', () => {
  it('are byte-identical copies of their sources', () => {
    const check = node('tools/stage.mjs', '--check', '.');
    expect(check.stderr).toMatch(/artifacts match their sources/);
    expect(check.status).toBe(0);
  });

  it('are all in the tarball, beside the built index and nothing else', () => {
    const [packed] = JSON.parse(
      execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: pkg, encoding: 'utf8' }),
    ) as { files: { path: string }[] }[];
    const files = packed!.files.map((f) => f.path);
    for (const to of Object.keys(sources)) expect(files.some((f) => f === to || f.startsWith(`${to}/`)), to).toBe(true);
    expect(files).toContain('constants.json');
    expect(files).toContain('dist/index.js');
    expect(files.filter((f) => /^(src|test|tools)\/|^sources\.json$/.test(f))).toEqual([]);
  });
});

describe('the packaged scripts', () => {
  it('fetch-infra-wasm.sh needs --stack outside a perch checkout', () => {
    expect(node('dist/cli/fetch-infra-wasm.js', '--help').status).toBe(0);
    const run = node('dist/cli/fetch-infra-wasm.js');
    expect(run.status).toBe(1);
    expect(run.stderr).toMatch(/pass --stack/);
  });

  it('zk-toolchain.sh prints its usage without installing anything', () => {
    const run = node('dist/cli/zk-toolchain.js', '--help');
    expect(run.status).toBe(0);
    expect(run.stdout).toMatch(/PERCH_ZK_TOOLCHAIN_DIR/);
  });
});
