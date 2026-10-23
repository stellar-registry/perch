import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  canonicalJson, checkLimits, compiledRuleCount, docHash, external,
  OverLimits, parsePolicyDocJson, policy, ruleHash,
} from '../src/index.js';

const read = (name: string) => readFileSync(new URL(`../../../testdata/${name}`, import.meta.url), 'utf8').trim();
const fixture = () => parsePolicyDocJson(read('cross-token-cap.json'));

describe('cross-token caps', () => {
  it('matches the independent canonical/hash vector shared with Rust', () => {
    const doc = fixture();
    expect(canonicalJson(doc)).toBe(read('cross-token-cap.canonical.json'));
    expect(docHash(doc)).toBe(read('cross-token-cap.doc-hash'));
    const hash = ruleHash(doc.rules[1]!);
    doc.rules[1]!.cap!.recipient = { type: 'any' };
    expect(ruleHash(doc.rules[1]!)).not.toBe(hash);
  });

  it.each([undefined, { type: 'any' as const }, { type: 'address-eq' as const, address: 'treasury' }])('builds recipient %j without adding absent fields', (recipient) => {
    const doc = policy().signer('owner', external('verifier', 'ab'))
      .rule('game', r => r.callContract('game').signedBy('owner').func('guess')
        .cap({ token: 'token', limit: 2n, periodLedgers: 1000, recipient })).build();
    expect(doc.rules[0]!.cap).toEqual({ token: 'token', limit: '2', 'period-ledgers': 1000, ...(recipient ? { recipient } : {}) });
    expect(Object.hasOwn(doc.rules[0]!.cap!, 'recipient')).toBe(recipient !== undefined);
  });

  it('counts the pair against v1 limits and leaves same-token/uncapped counts unchanged', () => {
    const doc = fixture();
    const limits = { maxSigners: 10, maxRules: 3, maxCanonicalBytes: 8192, maxRuleNameBytes: 50 };
    expect(compiledRuleCount(doc)).toBe(3);
    expect(() => checkLimits(doc, limits)).not.toThrow();
    expect(() => checkLimits(doc, { ...limits, maxRules: 2 })).toThrow(OverLimits);
    const rule = doc.rules[1]!;
    if (rule.scope.type !== 'contract') throw new Error('fixture');
    delete rule.cap!.recipient;
    rule.cap!.token = rule.scope.address;
    expect(compiledRuleCount(doc)).toBe(2);
    delete rule.cap!.token;
    expect(compiledRuleCount(doc)).toBe(2);
    delete rule.cap;
    expect(compiledRuleCount(doc)).toBe(2);
  });
});
