import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { checkLimits, type FlatDocLimits } from '../src/limits.js';
import { OverLimits } from '../src/errors.js';
import type { PolicyDoc } from '../src/schema.js';

// The same source-of-truth parity the Rust `limits_parity` suite runs, node
// side: perch-js mirrors the compiler's per-document caps at runtime in
// `checkLimits`, and the shipped schema now encodes the representable ones
// (maxItems / maxLength). This proves the schema's encoded caps and
// `checkLimits` REJECT THE SAME over-cap documents when fed the same caps — so
// the schema an offline editor reads and the client-side limit check cannot
// disagree about what is over the limit. The caps themselves come from the
// schema (generated from the Rust constants), so there is one declared source.

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(
  readFileSync(resolve(here, '../schemas/policy.schema.json'), 'utf8'),
);

const ajv = new Ajv2020({ strict: false, allErrors: true });
const validate = ajv.compile(schema);

const maxSigners: number = schema.properties.signers.maxItems;
const maxRules: number = schema.properties.rules.maxItems;
const maxRuleNameBytes: number = schema.$defs.rule.properties.name.maxLength;

// The schema cannot express the canonical-byte budget; keep it out of the way
// so only the three representable caps are exercised here.
const limits: FlatDocLimits = {
  maxSigners,
  maxRules,
  maxCanonicalBytes: Number.MAX_SAFE_INTEGER,
  maxRuleNameBytes,
};

const VALID_C = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';

function docWithSigners(n: number): PolicyDoc {
  const signers = Array.from({ length: n }, (_, i) => ({
    id: `s${i}`,
    verifier: VALID_C,
    key: i.toString(16).padStart(2, '0'),
  }));
  return {
    version: 1,
    signers,
    rules: [{ name: 'r', scope: { type: 'self-admin' }, principals: { type: 'all', signers: ['s0'] } }],
  } as unknown as PolicyDoc;
}

function docWithRules(m: number): PolicyDoc {
  const rules = Array.from({ length: m }, (_, i) => ({
    name: `r${i}`,
    scope: { type: 'self-admin' },
    principals: { type: 'all', signers: ['a'] },
  }));
  return {
    version: 1,
    signers: [{ id: 'a', verifier: VALID_C, key: 'ab' }],
    rules,
  } as unknown as PolicyDoc;
}

function docWithRuleName(len: number): PolicyDoc {
  return {
    version: 1,
    signers: [{ id: 'a', verifier: VALID_C, key: 'ab' }],
    rules: [{ name: 'n'.repeat(len), scope: { type: 'self-admin' }, principals: { type: 'all', signers: ['a'] } }],
  } as unknown as PolicyDoc;
}

function limitsThrows(doc: PolicyDoc): boolean {
  try {
    checkLimits(doc, limits);
    return false;
  } catch (e) {
    return e instanceof OverLimits;
  }
}

describe('policy.schema.json caps agree with checkLimits', () => {
  it('declares the caps the Rust constants produced', () => {
    // Not hard-coded here: these come from the generated schema. The exact
    // numbers are pinned Rust-side against the compiler constants.
    expect(Number.isInteger(maxSigners)).toBe(true);
    expect(Number.isInteger(maxRules)).toBe(true);
    expect(Number.isInteger(maxRuleNameBytes)).toBe(true);
  });

  it('signer count: schema and checkLimits flip together at the cap', () => {
    const at = docWithSigners(maxSigners);
    expect(validate(at)).toBe(true);
    expect(limitsThrows(at)).toBe(false);

    const over = docWithSigners(maxSigners + 1);
    expect(validate(over)).toBe(false);
    expect(limitsThrows(over)).toBe(true);
  });

  it('rule count: schema and checkLimits flip together at the cap', () => {
    const at = docWithRules(maxRules);
    expect(validate(at)).toBe(true);
    expect(limitsThrows(at)).toBe(false);

    const over = docWithRules(maxRules + 1);
    expect(validate(over)).toBe(false);
    expect(limitsThrows(over)).toBe(true);
  });

  it('rule name bytes: schema maxLength and checkLimits byte count agree (ASCII)', () => {
    const at = docWithRuleName(maxRuleNameBytes);
    expect(validate(at)).toBe(true);
    expect(limitsThrows(at)).toBe(false);

    const over = docWithRuleName(maxRuleNameBytes + 1);
    expect(validate(over)).toBe(false);
    expect(limitsThrows(over)).toBe(true);
  });
});
