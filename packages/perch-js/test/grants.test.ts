import { describe, expect, it } from 'vitest';
import { OWNER_FNS, parsePolicyDoc, selfPinWarnings } from '../src/index.js';

const TESTNET = 'Test SDF Network ; September 2015';
const TOKEN = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const GAME = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';
const KEY = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';

type RuleExtra = { functions?: string[]; args?: unknown[]; cap?: unknown };

function rule(name: string, contract: string, extra: RuleExtra = {}) {
  return {
    name,
    scope: { type: 'contract', address: contract },
    principals: { type: 'all', signers: ['app'] },
    ...extra,
  };
}

function grant(...rules: unknown[]) {
  return parsePolicyDoc({
    version: 1,
    network: TESTNET,
    signers: [{ id: 'app', address: KEY }],
    rules,
  });
}

const isSelf = (index: number) => ({ index, pred: { type: 'is-self' } });

describe('selfPinWarnings', () => {
  it('warns about a grant rule that pins no argument to the account', () => {
    expect(selfPinWarnings(grant(rule('play', GAME)))).toEqual([
      {
        rule: 'play',
        message:
          'Rule play pins no argument to the account (is-self): it matches every call its target, functions and argument predicates allow',
      },
    ]);
    expect(selfPinWarnings(grant(rule('send', GAME, { functions: ['send'] })))).toHaveLength(1);
  });

  it('does not warn about a rule with an is-self pin on any argument', () => {
    expect(selfPinWarnings(grant(rule('play', GAME, { functions: ['guess'], args: [isSelf(1)] })))).toEqual([]);
  });

  it('does not warn about a rule listing only token owner functions, which the account pins itself', () => {
    expect(OWNER_FNS).toEqual(['transfer', 'transfer_from', 'approve', 'burn', 'burn_from']);
    const capped = rule('spend', TOKEN, { functions: ['transfer'], cap: { limit: '100000000', 'period-ledgers': 100 } });
    const owner = rule('owner', TOKEN, { functions: ['approve', 'burn', 'transfer_from'] });
    expect(selfPinWarnings(grant(capped, owner))).toEqual([]);
    // A rule mixing an owner function with another, or listing none, is warned about.
    const mixed = rule('mixed', TOKEN, { functions: ['transfer', 'swap'] });
    const any = rule('any', TOKEN);
    expect(selfPinWarnings(grant(mixed, any)).map((w) => w.rule)).toEqual(['mixed', 'any']);
  });

  it('gives an account document no warnings', () => {
    const admin = parsePolicyDoc({
      version: 1,
      network: TESTNET,
      signers: [{ id: 'app', address: KEY }],
      rules: [{ name: 'admin', scope: { type: 'self-admin' }, principals: { type: 'all', signers: ['app'] } }, rule('play', GAME)],
    });
    expect(selfPinWarnings(admin)).toEqual([]);
  });
});
