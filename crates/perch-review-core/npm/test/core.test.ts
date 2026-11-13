// The built wasm modules (`npm run build:wasm`): they import nothing, they
// are about the size the crate's README states, and they give the native
// core's answer to every committed input, byte for byte once parsed.

import { readFileSync } from 'node:fs';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  ReviewCore,
  WitnessCore,
  fromBase64,
  grantKeys,
  ledgerKeys,
  reviewEnvelope,
  strkeyOfScAddress,
  type Verified,
} from '../src/index.js';
import { fixtures, parseReviewEnvelope } from './fixtures.js';

const wasm = (name: string) => new URL(`../wasm/${name}`, import.meta.url);

let core: ReviewCore;
let witness: WitnessCore;

beforeAll(async () => {
  core = await ReviewCore.load();
  witness = await WitnessCore.load();
});

describe('the wasm modules', () => {
  for (const [name, exports, brotliBudget] of [
    ['perch_review_core.wasm', ['alloc', 'budget', 'chosen', 'memory', 'review'], 18_000],
    ['perch_review_witness.wasm', ['alloc', 'memory', 'witness'], 10_500],
  ] as const) {
    it(`${name} imports nothing, exports only its interface, and stays small`, () => {
      const bytes = readFileSync(wasm(name));
      const module = new WebAssembly.Module(bytes);
      expect(WebAssembly.Module.imports(module)).toEqual([]);
      expect(WebAssembly.Module.exports(module).map((e) => e.name).sort()).toEqual([...exports]);
      const brotli = brotliCompressSync(bytes, {
        params: { [constants.BROTLI_PARAM_QUALITY]: 11 },
      }).length;
      const gzip = gzipSync(bytes, { level: 9 }).length;
      console.log(`${name}: raw ${bytes.length}, gzip -9 ${gzip}, brotli -q 11 ${brotli}`);
      expect(brotli).toBeLessThanOrEqual(brotliBudget);
    });
  }
});

describe('the wasm answers as the native core', () => {
  it('on every committed review input', () => {
    expect(fixtures.review.length).toBeGreaterThan(0);
    for (const f of fixtures.review) {
      expect(core.raw('review', fromBase64(f.input)), f.name).toEqual(f.output);
    }
  });

  it('on every committed witness input', () => {
    expect(fixtures.witness.length).toBeGreaterThan(0);
    for (const f of fixtures.witness) {
      expect(witness.raw('witness', fromBase64(f.input)), f.name).toEqual(f.output);
    }
  });

  it('on every committed budget input', () => {
    expect(fixtures.budget.length).toBeGreaterThan(0);
    for (const f of fixtures.budget) {
      expect(core.raw('budget', fromBase64(f.input)), f.name).toEqual(f.output);
    }
  });

  it('across many calls, the arena reset at each', () => {
    const f = fixtures.review[0]!;
    const input = fromBase64(f.input);
    const before = core.raw('review', input);
    for (let i = 0; i < 2000; i++) core.raw('review', input);
    expect(core.raw('review', input)).toEqual(before);
  });
});

describe('the wrapper', () => {
  it('writes the envelope the core reads', () => {
    for (const f of fixtures.review) {
      const p = parseReviewEnvelope(f.input);
      const verified: Verified[] = p.verified.map((v) => (v === 0 ? 'no' : v === 1 ? 'yes' : 'assumed'));
      const env = reviewEnvelope({
        entry: p.entry,
        ledgerEntries: p.entries,
        ledger: p.ledger,
        verified: verified.length ? verified : undefined,
      });
      expect(Array.from(env), f.name).toEqual(Array.from(fromBase64(f.input)));
    }
  });

  it("reads an entry's account and rule ids, and names the keys the account reads", () => {
    for (const f of fixtures.review) {
      const p = parseReviewEnvelope(f.input);
      const chosen = core.chosen(p.entry);
      if ('unreadable' in chosen) throw new Error(f.name);
      expect(chosen.account).toBe(strkeyOfScAddress(f.output.account as string));
      expect(chosen.ruleIds, f.name).toEqual(f.rule_ids);
      expect(ledgerKeys(chosen.account, chosen.ruleIds), f.name).toEqual(f.keys);
    }
  });

  it('names the grant records the fetched tags point to', () => {
    let tagged = 0;
    for (const f of fixtures.review) {
      const p = parseReviewEnvelope(f.input);
      const chosen = core.chosen(p.entry);
      if ('unreadable' in chosen) throw new Error(f.name);
      const keys = grantKeys(chosen.account, chosen.ruleIds, p.entries).map(fromBase64);
      const granted = ((f.output.rules as { grant: number | null }[]) ?? []).some((r) => r.grant != null);
      if (granted) {
        tagged++;
        expect(keys.length, f.name).toBeGreaterThan(0);
      }
      // Each names an entry the account holds: `LedgerEntryData` is the
      // key's type, an empty extension, then the key's address, key and
      // durability.
      for (const k of keys) {
        const held = p.entries.some(
          (e) =>
            e.length > k.length + 4 &&
            k.subarray(0, 4).every((b, i) => e[i] === b) &&
            e.subarray(4, 8).every((b) => b === 0) &&
            k.subarray(4).every((b, i) => e[i + 8] === b),
        );
        expect(held, f.name).toBe(true);
      }
    }
    expect(tagged).toBeGreaterThan(0);
  });

  it('types the answer', () => {
    const f = fixtures.review.find((x) => x.account === 'Accepted' && (x.output.budgets as unknown[]).length)!;
    const p = parseReviewEnvelope(f.input);
    const r = core.review({ entry: p.entry, ledgerEntries: p.entries, ledger: p.ledger });
    expect(r.status).toBe('accepted');
    if (r.status === 'unreadable') throw new Error('unreadable');
    expect(r.account.startsWith('C')).toBe(true);
    const b = r.budgets[0]!;
    expect(typeof b.limit).toBe('bigint');
    expect(b.after?.remaining).toBe(b.before.remaining - (b.requested ?? 0n));
  });

  it('reports what it cannot read', () => {
    const r = core.review({ entry: new Uint8Array([0, 0, 0, 9]), ledgerEntries: [], ledger: 1 });
    expect(r).toEqual({ status: 'unreadable', unreadable: 'entry' });
  });
});
