import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalJson, docHash } from '../src/canonical.js';
import { parsePolicyDoc } from '../src/schema.js';

const here = dirname(fileURLToPath(import.meta.url));
const td = (n: string) => resolve(here, '../../../testdata', n);

// The ci-publish fixture is the shared oracle: perch-ir writes it, the TS
// surface must reproduce its canonical form and doc_hash exactly.
describe('perch-ir parity: ci-publish fixture', () => {
  const doc = parsePolicyDoc(JSON.parse(readFileSync(td('ci-publish.json'), 'utf8')));

  it('canonical JSON is byte-identical to the Rust canonical form', () => {
    const committed = readFileSync(td('ci-publish.canonical.json'), 'utf8').replace(/\n+$/, '');
    expect(canonicalJson(doc)).toBe(committed);
  });

  it('doc_hash matches the committed and pinned Rust hash', () => {
    expect(docHash(doc)).toBe(readFileSync(td('ci-publish.doc-hash'), 'utf8').trim());
    expect(docHash(doc)).toBe('27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98');
  });
});

// The delegated variant: the ci signer as a CAP-0071 delegated address. Pins
// the delegated signer shape's canonical form against the Rust vector.
describe('perch-ir parity: ci-publish-delegated fixture', () => {
  const doc = parsePolicyDoc(JSON.parse(readFileSync(td('ci-publish-delegated.json'), 'utf8')));

  it('canonical JSON is byte-identical to the Rust canonical form', () => {
    const committed = readFileSync(td('ci-publish-delegated.canonical.json'), 'utf8').replace(
      /\n+$/,
      '',
    );
    expect(canonicalJson(doc)).toBe(committed);
  });

  it('doc_hash matches the committed and pinned Rust hash', () => {
    expect(docHash(doc)).toBe(readFileSync(td('ci-publish-delegated.doc-hash'), 'utf8').trim());
    expect(docHash(doc)).toBe('0e2f8e7c826d8252ce0bec1528a079e21ba6b628649762a7cae3fb823e6155ea');
  });
});
