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
// `checkLimits`, and the shipped schema encodes the representable ones
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

const maxRuleNameBytes: number = schema.$defs.rule.properties.name.maxLength;

// The caps of each kind of document: an account document's (one with a
// self-admin rule or a recovery member: the schema's `then`, the compiler's
// `limits()`) and a grant document's (`else`, `grant_limits()`). The schema
// cannot express the canonical-byte budget; keep it out of the way so only the
// three representable caps are exercised here.
type Kind = 'account' | 'grant';
const capsOf = (branch: { properties: { signers: { maxItems: number }; rules: { maxItems: number } } }): FlatDocLimits => ({
  maxSigners: branch.properties.signers.maxItems,
  maxRules: branch.properties.rules.maxItems,
  maxCanonicalBytes: Number.MAX_SAFE_INTEGER,
  maxRuleNameBytes,
});
const limitsOf: Record<Kind, FlatDocLimits> = { account: capsOf(schema.then), grant: capsOf(schema.else) };

const VALID_C = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';

/** A rule of `kind`'s document: self-admin makes it an account document. */
function rule(kind: Kind, name: string, signer: string) {
  const scope = kind === 'account' ? { type: 'self-admin' } : { type: 'contract', address: VALID_C };
  return { name, scope, principals: { type: 'all', signers: [signer] } };
}

function docWithSigners(kind: Kind, n: number): PolicyDoc {
  const signers = Array.from({ length: n }, (_, i) => ({
    id: `s${i}`,
    verifier: VALID_C,
    key: i.toString(16).padStart(2, '0'),
  }));
  return { version: 1, signers, rules: [rule(kind, 'r', 's0')] } as unknown as PolicyDoc;
}

function docWithRules(kind: Kind, m: number): PolicyDoc {
  const rules = Array.from({ length: m }, (_, i) => rule(kind, `r${i}`, 'a'));
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

function limitsThrows(doc: PolicyDoc, limits: FlatDocLimits = limitsOf.account): boolean {
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
    for (const limits of Object.values(limitsOf)) {
      expect(Number.isInteger(limits.maxSigners)).toBe(true);
      expect(Number.isInteger(limits.maxRules)).toBe(true);
    }
    expect(Number.isInteger(maxRuleNameBytes)).toBe(true);
    // The document-wide bound is the larger of the two kinds' caps.
    expect(schema.properties.signers.maxItems).toBe(Math.max(limitsOf.account.maxSigners, limitsOf.grant.maxSigners));
    expect(schema.properties.rules.maxItems).toBe(Math.max(limitsOf.account.maxRules, limitsOf.grant.maxRules));
  });

  for (const kind of ['account', 'grant'] as const) {
    const limits = limitsOf[kind];

    it(`signer count: schema and checkLimits flip together at the ${kind} cap`, () => {
      const at = docWithSigners(kind, limits.maxSigners);
      expect(validate(at)).toBe(true);
      expect(limitsThrows(at, limits)).toBe(false);

      const over = docWithSigners(kind, limits.maxSigners + 1);
      expect(validate(over)).toBe(false);
      expect(limitsThrows(over, limits)).toBe(true);
    });

    it(`rule count: schema and checkLimits flip together at the ${kind} cap`, () => {
      const at = docWithRules(kind, limits.maxRules);
      expect(validate(at)).toBe(true);
      expect(limitsThrows(at, limits)).toBe(false);

      const over = docWithRules(kind, limits.maxRules + 1);
      expect(validate(over)).toBe(false);
      expect(limitsThrows(over, limits)).toBe(true);
    });
  }

  it('an account document past its caps is refused within the grant caps', () => {
    const over = docWithRules('account', limitsOf.account.maxRules + 1);
    expect(limitsOf.account.maxRules + 1).toBeLessThanOrEqual(limitsOf.grant.maxRules);
    expect(validate(over)).toBe(false);
    expect(limitsThrows(over, limitsOf.grant)).toBe(false);
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
