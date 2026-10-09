import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  canonicalJson,
  configHash,
  docHash,
  ruleHash,
  CONFIG_HASH_DOMAIN,
  RULE_HASH_DOMAIN,
} from '../src/index.js';
import { parsePolicyDoc } from '../src/schema.js';

const here = dirname(fileURLToPath(import.meta.url));
const td = (n: string) => resolve(here, '../../../testdata', n);
const fixture = (n: string) => parsePolicyDoc(JSON.parse(readFileSync(td(n), 'utf8')));

interface RuleVector {
  name: string;
  canonical: string;
  rule_hash: string;
}
interface Vectors {
  domain: string;
  fixtures: { fixture: string; doc_hash: string; rules: RuleVector[] }[];
}

// testdata/rule-hashes.json is written by an independent script that cuts
// each rule's bytes out of the committed canonical fixtures
// (CANONICAL.md, "Fragment hashes").
describe('ruleHash', () => {
  const vectors: Vectors = JSON.parse(readFileSync(td('rule-hashes.json'), 'utf8'));

  it('uses the specified domain tag', () => {
    expect(vectors.domain).toBe(RULE_HASH_DOMAIN);
  });

  for (const f of vectors.fixtures) {
    it(`matches every rule of ${f.fixture}`, () => {
      const doc = fixture(f.fixture.replace(/^testdata\//, '').replace('.canonical.json', '.json'));
      expect(docHash(doc)).toBe(f.doc_hash);
      expect(doc.rules.map((r) => r.name)).toEqual(f.rules.map((r) => r.name));
      doc.rules.forEach((rule, i) => {
        expect(canonicalJson(rule)).toBe(f.rules[i]!.canonical);
        expect(ruleHash(rule)).toBe(f.rules[i]!.rule_hash);
      });
    });
  }

  it('is not the plain hash of the same bytes', () => {
    const rule = fixture('ci-publish.json').rules[1]!;
    const plain = bytesToHex(sha256(new TextEncoder().encode(canonicalJson(rule))));
    expect(ruleHash(rule)).not.toBe(plain);
  });
});

// Pinned from an independent cut of each fixture's canonical `recovery`
// member (sha256("perch/recovery/config" || bytes)); the Rust doc compiler's
// `config_hash` is pinned to the same values in
// crates/integration-tests/tests/fragment_hashes.rs.
describe('configHash', () => {
  it('matches the pinned recovery fixtures', () => {
    expect(configHash(fixture('ci-publish-recovery.json'))).toBe(
      '82157c6fc97d9dbf5216417cae232e2301a78e3c373580c70013586b4c342d14',
    );
    expect(configHash(fixture('ci-publish-recovery-combined.json'))).toBe(
      '6f44a3313c66ff6bab1719f684e4f58b04b10ec930624f8a6432ba761cd1ae78',
    );
  });

  it('is the tagged hash of the canonical recovery member', () => {
    const doc = fixture('ci-publish-recovery.json');
    const bytes = new TextEncoder().encode(CONFIG_HASH_DOMAIN + canonicalJson(doc.recovery));
    expect(configHash(doc)).toBe(bytesToHex(sha256(bytes)));
  });

  it('refuses a document without recovery', () => {
    expect(() => configHash(fixture('ci-publish.json'))).toThrow();
  });
});
