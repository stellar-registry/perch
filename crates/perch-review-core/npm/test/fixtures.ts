// The committed fixtures (`fixtures.json`): gate cases the account itself
// decided, with the native core's answers (perch-integration-tests,
// `review_core_differential.rs`, `write_npm_fixtures`; the crate's
// `tests/fixtures.rs` checks them against the native core).

import { readFileSync } from 'node:fs';
import { fromBase64 } from '../src/xdr.js';

export interface ReviewFixture {
  name: string;
  input: string;
  output: Record<string, unknown>;
  /** The account's own verdict: `Accepted`, `Refused(Some(n))` or `Refused(None)`. */
  account: string;
  rule_ids: number[];
  keys: string[];
}

export interface Fixture {
  name: string;
  input: string;
  output: Record<string, unknown>;
}

export const fixtures = JSON.parse(
  readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'),
) as { review: ReviewFixture[]; witness: Fixture[]; budget: Fixture[] };

/** A review envelope's parts, read back (the envelope's layout, `xdr.ts`). */
export function parseReviewEnvelope(b64: string): {
  ledger: number;
  entry: Uint8Array;
  entries: Uint8Array[];
  verified: number[];
} {
  const b = fromBase64(b64);
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let at = 0;
  const u32 = () => {
    const n = v.getUint32(at);
    at += 4;
    return n;
  };
  const bytes = () => {
    const n = u32();
    const out = b.slice(at, at + n);
    at += n;
    return out;
  };
  if (u32() !== 1) throw new Error('version');
  const ledger = u32();
  const entry = bytes();
  const entries = Array.from({ length: u32() }, bytes);
  const verified = Array.from(b.slice(at + 4, at + 4 + v.getUint32(at)));
  return { ledger, entry, entries, verified };
}
