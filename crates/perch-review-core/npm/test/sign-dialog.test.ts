// The sign dialog's Perch verdict and budgets, from the core, against the
// account's own verdicts on the committed gate cases.

import { beforeAll, describe, expect, it } from 'vitest';
import { ReviewCore, type Verified } from '../src/index.js';
import { perchBudgets, perchPreview, perchVerdict } from '../src/sign-dialog.js';
import { fixtures, parseReviewEnvelope } from './fixtures.js';

let core: ReviewCore;

beforeAll(async () => {
  core = await ReviewCore.load();
});

/** The account's verdict on a fixture: `true`, `false`, and its error code. */
function account(f: { account: string }): { allowed: boolean; code: number | null } {
  if (f.account === 'Accepted') return { allowed: true, code: null };
  const m = /^Refused\((?:Some\((\d+)\)|None)\)$/.exec(f.account);
  if (!m) throw new Error(f.account);
  return { allowed: false, code: m[1] ? Number(m[1]) : null };
}

/** The gate case charging 60 to a capped rule with 100 left. */
function capped60() {
  const f = fixtures.review.find((x) => {
    const b = (x.output.budgets as { requested: string; before: { remaining: string } }[] | undefined)?.[0];
    return x.account === 'Accepted' && b?.requested === '60' && b.before.remaining === '100';
  });
  if (!f) throw new Error('no gate case charges 60 of 100');
  return f;
}

describe('perchPreview', () => {
  it("gives the account's own verdict on every gate case", () => {
    const seen = new Set<string>();
    for (const f of fixtures.review) {
      const p = parseReviewEnvelope(f.input);
      const verified = p.verified.map((x) => (x === 0 ? 'no' : x === 1 ? 'yes' : 'assumed') as Verified);
      const { verdicts } = perchPreview(core, {
        authEntries: [p.entry],
        ledgerEntries: p.entries,
        ledger: p.ledger,
        verified: verified.length ? [verified] : undefined,
      });
      expect(verdicts.length, f.name).toBe(1);
      const v = verdicts[0]!;
      const want = account(f);
      expect(v.kind).toBe('perch');
      expect(v.address.startsWith('C')).toBe(true);
      if (v.reasonCode === 'controller') {
        // The controller decides a completion; the account's verdict is its.
        expect(v.allowed).toBeNull();
      } else {
        expect(v.allowed, f.name).toBe(want.allowed);
        if (!want.allowed && v.code != null) expect(v.code, f.name).toBe(want.code);
      }
      expect(v.reason.length).toBeGreaterThan(0);
      seen.add(v.reasonCode);
    }
    expect([...seen].sort()).toEqual(expect.arrayContaining(['accepted', 'refused']));
  });

  it('names the ledger and the assumed signatures in an accepted verdict', () => {
    const f = fixtures.review.find((x) => x.account === 'Accepted')!;
    const p = parseReviewEnvelope(f.input);
    const review = core.review({ entry: p.entry, ledgerEntries: p.entries, ledger: p.ledger });
    const v = perchVerdict('C', review);
    expect(v.allowed).toBe(true);
    expect(v.reason).toContain(`at ledger ${p.ledger}`);
    if (review.status !== 'unreadable' && review.assumed.length) {
      expect(v.reason).toContain('assuming');
    }
  });

  it('marks a refusal over the cap', () => {
    const f = fixtures.review.find(
      (x) => (x.output.refusal as { detail?: string } | null)?.detail === 'Cap.LimitExceeded',
    );
    expect(f).toBeDefined();
    const p = parseReviewEnvelope(f!.input);
    const review = core.review({ entry: p.entry, ledgerEntries: p.entries, ledger: p.ledger });
    expect(perchVerdict('C', review).reasonCode).toBe('refused-over-cap');
  });

  it('skips entries of other accounts', () => {
    const f = fixtures.review[0]!;
    const p = parseReviewEnvelope(f.input);
    const other = 'CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE';
    const out = perchPreview(core, { authEntries: [p.entry], ledgerEntries: p.entries, ledger: p.ledger, account: other });
    expect(out.verdicts).toEqual([]);
  });

  it('does not accept a second entry charging a cap the first one charges', () => {
    const p = parseReviewEnvelope(capped60().input);
    const { verdicts, budgets } = perchPreview(core, {
      authEntries: [p.entry, p.entry],
      ledgerEntries: p.entries,
      ledger: p.ledger,
    });
    expect(verdicts.map((v) => v.allowed)).toEqual([true, null]);
    expect(verdicts.map((v) => v.reasonCode)).toEqual(['accepted', 'uncomposed']);
    expect(verdicts[1]!.reason).toContain('earlier entry');
    expect(budgets.map((b) => b.amount)).toEqual(['60', '60']);
    expect(budgets.map((b) => b.remaining)).toEqual(['100', null]);
    expect(budgets.map((b) => b.remainingAfter)).toEqual(['40', null]);
    expect(budgets[0]!.uncomposed).toBeNull();
    expect(budgets[1]!.uncomposed).toContain('earlier entry');
  });

  it('keeps a refusal of an entry whose cap an earlier one charges, without what is left', () => {
    const named = (name: string) => {
      const f = fixtures.review.find((x) => x.name === name);
      if (!f) throw new Error(name);
      return parseReviewEnvelope(f.input);
    };
    const first = named('the 40 left');
    const second = named('two transfers of 30 on 40 left');
    const { verdicts, budgets } = perchPreview(core, {
      authEntries: [first.entry, second.entry],
      ledgerEntries: first.entries,
      ledger: first.ledger,
    });
    expect(verdicts.map((v) => v.reasonCode)).toEqual(['accepted', 'refused-over-cap']);
    expect(budgets.map((b) => b.remaining)).toEqual(['40', null]);
    expect(budgets[1]!.uncomposed).toContain('earlier entry');
  });

  it('counts no charge from a refused entry', () => {
    const over = parseReviewEnvelope(
      fixtures.review.find((x) => x.name === 'two transfers of 30 on 40 left')!.input,
    );
    const { verdicts, budgets } = perchPreview(core, {
      authEntries: [over.entry, over.entry],
      ledgerEntries: over.entries,
      ledger: over.ledger,
    });
    expect(verdicts.map((v) => v.allowed)).toEqual([false, false]);
    expect(budgets.map((b) => b.uncomposed)).toEqual([null, null]);
  });
});

describe('perchBudgets', () => {
  it('counts every context charging a rule together, and gives what is left exactly', () => {
    let checked = 0;
    for (const f of fixtures.review) {
      const p = parseReviewEnvelope(f.input);
      const review = core.review({ entry: p.entry, ledgerEntries: p.entries, ledger: p.ledger });
      if (review.status === 'unreadable') continue;
      const budgets = perchBudgets('C', review, {});
      expect(budgets.length).toBe(review.budgets.length);
      for (const [b, r] of budgets.map((b, i) => [b, review.budgets[i]!] as const)) {
        checked++;
        expect(b.limit).toBe(r.limit.toString());
        expect(b.amount).toBe(r.requested === null ? null : r.requested.toString());
        expect(b.remaining).toBe(r.before.remaining.toString());
        expect(b.uncomposed).toBeNull();
        expect(b.token.code).toBe('units');
        if (review.status === 'accepted') {
          expect(BigInt(b.remainingAfter!)).toBe(r.before.remaining - r.requested!);
        }
      }
    }
    expect(checked).toBeGreaterThan(0);
  });

  it('gives no amount when the core reads none', () => {
    const p = parseReviewEnvelope(capped60().input);
    const review = core.review({ entry: p.entry, ledgerEntries: p.entries, ledger: p.ledger });
    if (review.status === 'unreadable') throw new Error('unreadable');
    const unread = { ...review, budgets: review.budgets.map((b) => ({ ...b, requested: null, after: null })) };
    expect(perchBudgets('C', unread, {}).map((b) => b.amount)).toEqual([null]);
  });
});
