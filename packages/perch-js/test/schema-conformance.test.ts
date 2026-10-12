import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { ACK_SENTINEL, parsePolicyDoc } from '../src/schema.js';

// Criterion 2 + 3, node side: the schema shipped in this package validates the
// shared conformance cases with a real draft 2020-12 validator (ajv), and its
// accept/reject agrees with the zod surface at the structural boundary. The
// authoritative comparison against perch-ir's parser + validator lives in the
// Rust suite (crates/perch-schema/tests/conformance.rs); here we prove the
// SAME committed schema and cases hold against the JS surface offline editors
// and clients consume.

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = resolve(here, '../schemas/policy.schema.json');
const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
const casesPath = resolve(here, '../../../testdata/schema/cases.json');
const cases: Array<{
  name: string;
  expect: 'accept' | 'reject-structural' | 'reject-constraint' | 'accept-semantic-invalid';
  doc?: unknown;
  file?: string;
}> = JSON.parse(readFileSync(casesPath, 'utf8')).cases;

const ajv = new Ajv2020({ strict: false, allErrors: true });
const validate = ajv.compile(schema);

function caseDoc(c: { doc?: unknown; file?: string }): unknown {
  if (c.doc !== undefined) return c.doc;
  return JSON.parse(readFileSync(resolve(here, '../../../testdata', c.file!), 'utf8'));
}

function zodAccepts(doc: unknown): boolean {
  try {
    parsePolicyDoc(doc);
    return true;
  } catch {
    return false;
  }
}

describe('policy.schema.json: shipped artifact and dialect', () => {
  it('declares draft 2020-12 and the stable $id', () => {
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');
    expect(schema.$id).toBe('https://unpkg.com/@stellar-registry/perch/schemas/policy.schema.json');
    expect(schema.properties.version.const).toBe(1);
  });

  it('pins the ack sentinel to the one the TS surface uses', () => {
    // The self-authenticating ack `const` is the third principals variant.
    const ack = schema.$defs.principals.oneOf[2].properties.ack.const;
    expect(ack).toBe(ACK_SENTINEL);
  });
});

describe('policy.schema.json: conformance cases', () => {
  it('has a broad case set', () => {
    expect(cases.length).toBeGreaterThanOrEqual(30);
  });

  it.each(cases.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const doc = caseDoc(c);
    const schemaOk = validate(doc) as boolean;
    const zodOk = zodAccepts(doc);

    switch (c.expect) {
      case 'accept':
        expect(schemaOk).toBe(true);
        // The zod surface (shape-only) also accepts a canonical document.
        expect(zodOk).toBe(true);
        break;
      case 'reject-structural':
        expect(schemaOk).toBe(false);
        // A structural defect is one zod (strict shape) also rejects.
        expect(zodOk).toBe(false);
        break;
      case 'reject-constraint':
        // A representable format/range/collection rule the schema enforces.
        // The zod surface is shape-only and may accept it, so it is not
        // compared here (the Rust suite compares against perch-ir's validator).
        expect(schemaOk).toBe(false);
        break;
      case 'accept-semantic-invalid':
        // Outside the schema (cross-reference / semantic range). The schema and
        // the shape-only zod surface both accept; only perch-ir's validator
        // rejects (asserted Rust-side).
        expect(schemaOk).toBe(true);
        expect(zodOk).toBe(true);
        break;
    }
  });
});
