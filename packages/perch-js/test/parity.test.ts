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
    expect(docHash(doc)).toBe('38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d');
  });
});
