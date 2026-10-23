// Failed submissions typed from the host's own diagnostic events
// (testdata/auth/diagnostic-events.json, written by the Rust suite from real
// failures under enforcing authorization), not from rendered error text.

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AccountFrozen,
  addressPayload,
  decodeDiagnosticEvent,
  mapSubmissionError,
  StaleRevision,
  StaleSelection,
  strkey,
} from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, '../../../testdata/auth/diagnostic-events.json'), 'utf8')) as {
  cases: { name: string; account: string; events: string[] }[];
};
const byName = (name: string) => vectors.cases.find((c) => c.name === name)!;
const OTHER = 'CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5';

describe('the host diagnostic events decode', () => {
  for (const c of vectors.cases) {
    it(`${c.name}: every event`, () => {
      expect(c.events.length).toBeGreaterThan(0);
      for (const e of c.events) {
        const d = decodeDiagnosticEvent(e);
        expect(d).toBeDefined();
        expect(d!.topics[0]).toEqual({ type: 'symbol', value: 'error' });
      }
    });
  }

  it('an event it cannot read whole is skipped, not guessed', () => {
    expect(decodeDiagnosticEvent(new Uint8Array([0, 0, 0]))).toBeUndefined();
    const first = Buffer.from(byName('stale_selection').events[0]!, 'base64');
    expect(decodeDiagnosticEvent(first.subarray(0, first.length - 4))).toBeUndefined();
  });

  it('strkey inverts addressPayload', () => {
    const { payload } = addressPayload(OTHER);
    expect(strkey('contract', payload)).toBe(OTHER);
    const g = 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA';
    expect(strkey('account', addressPayload(g).payload)).toBe(g);
  });
});

describe('mapSubmissionError from diagnostic events', () => {
  const ctx = (account: string, diagnosticEvents: string[]) => ({ account, ruleIds: [4], revision: 1n, diagnosticEvents });
  const opaque = new Error('submission failed'); // no rendered log at all

  it('a selection whose rule is gone is StaleSelection', () => {
    const c = byName('stale_selection');
    expect(mapSubmissionError(opaque, ctx(c.account, c.events))).toEqual(new StaleSelection([4]));
  });

  it('an apply_doc at a left revision is StaleRevision', () => {
    const c = byName('stale_revision');
    expect(mapSubmissionError(opaque, ctx(c.account, c.events))).toEqual(new StaleRevision(1n, undefined));
  });

  it('activity on a frozen account is AccountFrozen', () => {
    const c = byName('account_frozen');
    expect(mapSubmissionError(opaque, ctx(c.account, c.events))).toEqual(new AccountFrozen(undefined, undefined));
  });

  it('the same events for another account are not mapped', () => {
    for (const c of vectors.cases) expect(mapSubmissionError(opaque, ctx(OTHER, c.events))).toBe(opaque);
  });

  it("events the transport attaches to its error are read, ahead of the error's text", () => {
    const c = byName('stale_revision');
    const misleading = Object.assign(
      new Error(`[Diagnostic Event] contract:${c.account}, topics:[error, Error(Contract, #3000)]`),
      { diagnosticEvents: c.events },
    );
    expect(mapSubmissionError(misleading, { account: c.account, ruleIds: [4], revision: 1n })).toEqual(
      new StaleRevision(1n, undefined),
    );
  });
});
