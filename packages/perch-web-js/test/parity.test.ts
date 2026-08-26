import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  canonicalJson,
  checkBrowserCall,
  checkServerCall,
  compilePolicy,
  parsePolicyDoc,
  parsePolicyDocJson,
  policyHash,
  verifyPlans,
  type CallContext,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const web = (name: string) => resolve(here, '../../../testdata/web', name);
const source = readFileSync(web('site-rescue.policy.json'), 'utf8');
const doc = parsePolicyDocJson(source);

describe('Rust and TypeScript golden parity', () => {
  it('matches canonical bytes and SHA-256 identity', () => {
    expect(`${canonicalJson(doc)}\n`).toBe(readFileSync(web('site-rescue.canonical.json'), 'utf8'));
    expect(`${policyHash(doc)}\n`).toBe(readFileSync(web('site-rescue.policy-hash'), 'utf8'));
  });

  it('matches both data-only plans', () => {
    const plans = compilePolicy(doc);
    expect(plans.browser).toEqual(JSON.parse(readFileSync(web('site-rescue.browser-plan.json'), 'utf8')));
    expect(plans.server).toEqual(JSON.parse(readFileSync(web('site-rescue.server-plan.json'), 'utf8')));
    expect(plans.browser['policy-hash']).toBe(plans.server['policy-hash']);
    expect(verifyPlans(doc, plans)).toBe(true);
    expect(plans.browser['policy-hash']).toBe(
      '874cf21112f5067d939b951570f6d7554db8b3f32e0d1e4c8c491bac1532f138',
    );
  });
});

describe('strict parsing', () => {
  it('rejects unknown fields, unsupported predicates, and duplicate keys', () => {
    expect(() => parsePolicyDocJson(source.replace('"origin":', '"unknown":true,"origin":'))).toThrow();
    expect(() =>
      parsePolicyDocJson(
        source.replace(
          '"type": "string-eq"',
          '"type": "unsupported"',
        ),
      ),
    ).toThrow();
    expect(() => parsePolicyDocJson(source.replace('"dom-read"', '"unsupported"'))).toThrow();
    for (const invalid of ['a:b/c#d/e', 'a/b#c']) {
      expect(() =>
        parsePolicyDocJson(source.replace('site-rescue:tools/rescue#inspect-site', invalid)),
      ).toThrow();
    }
    expect(() =>
      parsePolicyDocJson(source.replace('2027-08-26T12:00:00Z', '2027-08-26T12:00:00.5Z')),
    ).toThrow();
    expect(() => parsePolicyDoc({ ...doc, principal: 'user:\ud800' })).toThrow();
    expect(() => parsePolicyDocJson(source.replace('{', '{"profile":"perch-web/v1",'))).toThrow(
      /duplicate JSON key/,
    );
  });

  it('rejects ambiguous grants and missing effects', () => {
    const value = JSON.parse(source);
    value.grants.push({
      ...value.grants[0],
      id: 'other',
      'revocation-id': 'other',
    });
    expect(() => compilePolicy(value)).toThrow(/duplicate tool export/);
    value.grants.pop();
    value.grants[0].effects = [];
    expect(() => compilePolicy(value)).toThrow();
  });
});

describe('matched call checks', () => {
  const plans = compilePolicy(doc);
  const base: CallContext = {
    origin: doc.origin,
    target: doc.target,
    'manifest-sha256': doc['manifest-sha256'],
    principal: doc.principal,
    now: '2027-01-01T00:00:00Z',
    'tool-export': 'site-rescue:tools/rescue#inspect-site',
    arguments: {
      url: 'https://damaged.example/',
      'include-assets': true,
      mode: 'safe',
      'max-bytes': '1048576',
    },
    effects: ['dom-read', 'network-request'],
    approved: false,
    revoked: new Set(),
  };

  it('allows the bound call in both plans', () => {
    expect(checkBrowserCall(plans.browser, base)).toEqual({ allowed: true });
    expect(checkServerCall(plans.server, base)).toEqual({ allowed: true });
  });

  it('denies changed bindings and exact argument failures', () => {
    expect(checkBrowserCall(plans.browser, { ...base, origin: 'https://evil.example' })).toEqual({
      allowed: false,
      denial: 'origin',
    });
    expect(
      checkBrowserCall(plans.browser, { ...base, target: { type: 'component', id: 'other' } }),
    ).toEqual({ allowed: false, denial: 'target' });
    expect(
      checkServerCall(plans.server, { ...base, 'manifest-sha256': '0'.repeat(64) }),
    ).toEqual({ allowed: false, denial: 'manifest' });
    expect(checkBrowserCall(plans.browser, { ...base, principal: 'user:other' })).toEqual({
      allowed: false,
      denial: 'principal',
    });
    expect(checkServerCall(plans.server, { ...base, arguments: { ...base.arguments, extra: true } })).toEqual({
      allowed: false,
      denial: 'arguments',
    });
    expect(checkServerCall(plans.server, { ...base, arguments: { url: 'https://damaged.example/' } })).toEqual({
      allowed: false,
      denial: 'arguments',
    });
    expect(
      checkServerCall(plans.server, {
        ...base,
        arguments: { ...base.arguments, url: 'https://other.example/' },
      }),
    ).toEqual({ allowed: false, denial: 'arguments' });
    expect(checkBrowserCall(plans.browser, { ...base, now: doc['expires-at'] })).toEqual({
      allowed: false,
      denial: 'expired',
    });
    expect(checkBrowserCall(plans.browser, { ...base, now: '2027-01-01T00:00:00+00:00' })).toEqual({
      allowed: false,
      denial: 'invalid-plan',
    });
    expect(
      checkServerCall(plans.server, {
        ...base,
        revoked: new Set(['site-rescue/inspection/2027-01']),
      }),
    ).toEqual({ allowed: false, denial: 'revoked' });
    expect(checkBrowserCall({ ...plans.browser, 'policy-hash': '0'.repeat(64) }, base)).toEqual({
      allowed: false,
      denial: 'invalid-plan',
    });
  });

  it('denies missing approval and unsupported effects', () => {
    const download: CallContext = {
      ...base,
      'tool-export': 'site-rescue:tools/rescue#download-archive',
      arguments: { 'archive-name': 'site-rescue.zip' },
      effects: ['user-download'],
    };
    expect(checkBrowserCall(plans.browser, download)).toEqual({ allowed: false, denial: 'approval' });
    expect(checkBrowserCall(plans.browser, { ...download, approved: true })).toEqual({ allowed: true });
    expect(
      checkServerCall(plans.server, { ...download, approved: true, effects: ['dom-write'] }),
    ).toEqual({ allowed: false, denial: 'effects' });
  });
});
