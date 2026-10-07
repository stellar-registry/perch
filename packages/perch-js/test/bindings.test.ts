// `accountReader` over values shaped exactly as the generated bindings
// (`packages/perch-contracts/src/{account,doc-compiler}.ts`) return them.

import { describe, expect, it } from 'vitest';
import { accountReader, readSnapshot, selectRules, UnsupportedCapability } from '../src/index.js';

const ACCOUNT = 'CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF';
const TOKEN = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
const VERIFIER = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';
const OWNER = 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA';

const sim = <T>(result: T, latestLedger = 500) => Promise.resolve({ result, simulation: { latestLedger } });

const configuration = {
  revision: 7n,
  doc_hash: Buffer.alloc(32, 9),
  rules: [
    {
      id: 0,
      recovery: false,
      name: 'admin',
      context_type: { tag: 'CallContract', values: [ACCOUNT] },
      valid_until: undefined,
      signers: [{ tag: 'Delegated', values: [OWNER] }],
      policies: [],
    },
    {
      id: 12,
      recovery: false,
      name: 'pay',
      context_type: { tag: 'CallContract', values: [TOKEN] },
      valid_until: 9_000,
      signers: [{ tag: 'External', values: [VERIFIER, Buffer.alloc(65, 4)] }],
      policies: [{ policy: VERIFIER, params: Buffer.alloc(32, 1) }],
    },
    {
      id: 13,
      recovery: true,
      name: 'recovery',
      context_type: { tag: 'CallContract', values: [ACCOUNT] },
      valid_until: undefined,
      signers: [],
      policies: [],
    },
  ],
  recovery_controller: TOKEN,
  recovery_rule: 13,
  gate: [{ attempt_id: 3n, until: 800 }],
  recovery_generation: 2n,
  infra: { doc_compiler: VERIFIER, interpreter: VERIFIER, spending_limit: VERIFIER },
};
const capabilities = {
  apply_modes: ['one_tx'],
  auth_digest: 'oz_rule_ids',
  doc_identity: 'canon_v1',
  interface_version: 1,
  snapshot_version: 1,
};
const limits = {
  tag: 'V1',
  values: [{ max_canonical_bytes: 8192, max_rule_name_bytes: 20, max_rules: 11, max_signers: 8 }],
};

const client = {
  configuration: () => sim(configuration),
  revision: () => sim(7n),
  document: () => sim([7n, Buffer.from('{}')] as const),
  capabilities: () => sim(capabilities),
};

describe('accountReader over the generated bindings', () => {
  it('decodes every view', async () => {
    const reader = accountReader(ACCOUNT, client, { limits: () => sim(limits) });
    const s = await readSnapshot(reader, { document: true });
    expect(s.configuration.revision).toBe(7n);
    expect(s.configuration.gate).toEqual({ attemptId: 3n, until: 800 });
    expect(s.configuration.recoveryRule).toBe(13);
    expect(s.configuration.rules[1]).toEqual({
      id: 12,
      recovery: false,
      name: 'pay',
      contract: TOKEN,
      validUntil: 9_000,
      signers: [{ kind: 'external', verifier: VERIFIER, key: new Uint8Array(65).fill(4) }],
      policies: [{ policy: VERIFIER, params: new Uint8Array(32).fill(1) }],
    });
    expect(s.document).toEqual(new TextEncoder().encode('{}'));
    expect(s.limits).toEqual({ maxSigners: 8, maxRules: 11, maxCanonicalBytes: 8192, maxRuleNameBytes: 20 });
    expect(selectRules(s, { name: 'pay', scope: { type: 'contract', address: TOKEN } }).ruleIds).toEqual([12]);
  });

  it('refuses a limits format it does not know', async () => {
    const reader = accountReader(ACCOUNT, client, { limits: () => sim({ tag: 'V2', values: [{}] }) });
    await expect(readSnapshot(reader)).rejects.toBeInstanceOf(UnsupportedCapability);
  });

  it('refuses another authorization digest', async () => {
    const other = { ...client, capabilities: () => sim({ ...capabilities, auth_digest: 'perch_v2' }) };
    const reader = accountReader(ACCOUNT, other, { limits: () => sim(limits) });
    await expect(readSnapshot(reader)).rejects.toBeInstanceOf(UnsupportedCapability);
  });
});
