import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalJson, docHash } from '../src/canonical.js';
import { requestToPolicyDoc, type PolicyRequest } from '../src/request.js';

const here = dirname(fileURLToPath(import.meta.url));
const td = (n: string) => resolve(here, '../../../testdata', n);

// The 7715-shaped request that reproduces the ci-publish policy exactly.
const CI_PUBLISH: PolicyRequest = {
  network: 'Test SDF Network ; September 2015',
  signers: [
    {
      id: 'admin',
      verifier: 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN',
      key: '045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e',
    },
    {
      id: 'ci',
      verifier: 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG',
      key: '1ce6040b0d03232ac6c911b0c375f1a52ebdefff56fd361d13680e23ca578a17',
    },
  ],
  permissions: [
    { name: 'admin', on: 'self-admin', by: ['admin'] },
    {
      name: 'ci-publish',
      on: { contract: 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL' },
      by: ['ci'],
      functions: ['publish', 'publish_hash'],
      args: [{ index: 1, pred: { type: 'is-self' } }],
      until: 55_000_000,
    },
  ],
};

describe('request → PolicyDoc', () => {
  it('a request reproducing ci-publish lowers to the identical canonical bytes', () => {
    const doc = requestToPolicyDoc(CI_PUBLISH);
    const committed = readFileSync(td('ci-publish.canonical.json'), 'utf8').replace(/\n+$/, '');
    expect(canonicalJson(doc)).toBe(committed);
  });

  it('and therefore the identical doc_hash — perch is the backend for a 7715 request', () => {
    const doc = requestToPolicyDoc(CI_PUBLISH);
    expect(docHash(doc)).toBe(readFileSync(td('ci-publish.doc-hash'), 'utf8').trim());
  });

  it('carries a cumulative cap through to the document', () => {
    const withCap: PolicyRequest = {
      signers: [{ id: 'ci', verifier: 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG', key: 'ab' }],
      permissions: [
        {
          name: 'spend',
          on: { contract: 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL' },
          by: ['ci'],
          functions: ['transfer'],
          cap: { limit: '10', 'period-ledgers': 1000 },
        },
      ],
    };
    const doc = requestToPolicyDoc(withCap);
    expect(doc.rules[0]!.cap).toEqual({ limit: '10', 'period-ledgers': 1000 });
    // A cap changes the hash; a cap-free version of the same request does not.
    const noCap = requestToPolicyDoc({
      ...withCap,
      permissions: [{ ...withCap.permissions[0]!, cap: undefined }],
    });
    expect(docHash(doc)).not.toBe(docHash(noCap));
  });

  it('omits optional fields when a permission has none', () => {
    // A bare permission carries no functions/args/until/cap; the mapping must
    // omit those keys entirely (not emit nulls), so the canonical form matches
    // a directly-authored minimal document.
    const doc = requestToPolicyDoc({
      signers: [{ id: 'admin', verifier: 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN', key: 'ab' }],
      permissions: [{ name: 'root', on: 'self-admin', by: ['admin'] }],
    });
    const r = doc.rules[0]!;
    expect(r.functions).toBeUndefined();
    expect(r.args).toBeUndefined();
    expect(r['not-after-ledger']).toBeUndefined();
    expect(r.cap).toBeUndefined();
    expect(canonicalJson(doc)).toContain('"name":"root"');
  });
});
