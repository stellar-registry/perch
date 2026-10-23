import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex } from '../src/field.js';
import { repo } from './helpers.js';

const pkg = (n: string) => resolve(repo('packages/perch-zk/artifacts'), n);

// The package ships copies of the circuit artifacts; they must be the exact
// bytes circuits/manifest.json pins.
describe('shipped artifacts are the pinned ones', () => {
  const manifest = JSON.parse(readFileSync(repo('circuits/manifest.json'), 'utf8'));

  it('manifest copy is current', () => {
    expect(readFileSync(pkg('manifest.json'))).toEqual(readFileSync(repo('circuits/manifest.json')));
  });

  for (const name of ['perch_zk_recovery', 'perch_zk_recovery_d24']) {
    it(name, () => {
      const bytes = readFileSync(pkg(`${name}.json`));
      expect(bytes).toEqual(readFileSync(repo('circuits/artifacts', `${name}.json`)));
      expect(hex(sha256(bytes))).toBe(manifest.circuits[name].artifact_sha256);
    });
  }
});
