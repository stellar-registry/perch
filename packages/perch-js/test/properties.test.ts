// Property tests for the canonicalization + schema surface (PLAN.md phase 0).
//
// Fixed seed so failures reproduce exactly (mirror of the Rust suites'
// splitmix64 discipline). What these pin, beyond the frozen parity vectors:
//
// - canonical form is insertion-order independent (the JCS member-sort
//   actually bites on every generated document, not just the fixtures);
// - the canonical form round-trips through the schema byte-identically
//   (canonicalJson is idempotent across parse);
// - doc_hash is injective on the generated sample (distinct canonical bytes
//   never collide — a hash collision here would be publishable news);
// - every builder output passes the schema (the builder can't construct an
//   invalid document).

import { describe, expect, it } from 'vitest';
import fc from 'fast-check';

import {
  canonicalJson,
  docHash,
  parsePolicyDoc,
  parsePolicyDocJson,
  policy,
  external,
  delegated,
  isSelf,
  addressEq,
  stringIn,
  stringPrefix,
  u32Eq,
  type ArgPred,
} from '../src/index.js';

const SEED = 0x5eed_0001;
const RUNS = 300;

// Checksum-valid strkeys shared with the Rust suites / testdata fixtures.
const CONTRACT_C = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const VERIFIER_A = 'CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN';
const VERIFIER_B = 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG';
const DELEGATE_G = 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA';

// --- generators ---------------------------------------------------------------

const hexByte = fc.integer({ min: 0, max: 255 }).map((n) => n.toString(16).padStart(2, '0'));
const keyHex = fc.array(hexByte, { minLength: 1, maxLength: 8 }).map((bs) => bs.join(''));

const fnName = fc.constantFrom('publish', 'publish_hash', 'transfer', 'set_admin');
const shortString = fc.constantFrom('alpha', 'beta', 'release', 'r');

const argPredArb: fc.Arbitrary<ArgPred> = fc.oneof(
  fc.constant(isSelf()),
  fc.constantFrom(VERIFIER_A, VERIFIER_B).map(addressEq),
  fc.integer({ min: 0, max: 2 }).map(u32Eq),
  fc
    .uniqueArray(shortString, { minLength: 1, maxLength: 3 })
    .map((values) => stringIn(values)),
  shortString.map(stringPrefix),
);

interface GenSigner {
  id: string;
  kind: 'external' | 'delegated';
  verifier: string;
  key: string;
}

const signerArb: fc.Arbitrary<Omit<GenSigner, 'id'>> = fc.oneof(
  fc
    .record({ verifier: fc.constantFrom(VERIFIER_A, VERIFIER_B), key: keyHex })
    .map(({ verifier, key }) => ({ kind: 'external' as const, verifier, key })),
  fc.constant({ kind: 'delegated' as const, verifier: '', key: '' }),
);

interface GenRule {
  name: string;
  selfAdmin: boolean;
  signerIdx: number[];
  functions: string[] | undefined;
  args: { index: number; pred: ArgPred }[] | undefined;
  notAfter: number | undefined;
}

const docArb = fc
  .record({
    network: fc.option(fc.constantFrom('testnet', 'mainnet'), { nil: undefined }),
    signers: fc.array(signerArb, { minLength: 1, maxLength: 3 }),
    rules: fc.array(
      fc.record({
        selfAdmin: fc.boolean(),
        signerIdx: fc.uniqueArray(fc.integer({ min: 0, max: 2 }), {
          minLength: 1,
          maxLength: 3,
        }),
        functions: fc.option(fc.uniqueArray(fnName, { minLength: 1, maxLength: 3 }), {
          nil: undefined,
        }),
        args: fc.option(
          fc
            .uniqueArray(fc.integer({ min: 0, max: 5 }), { minLength: 1, maxLength: 3 })
            .chain((indexes) =>
              fc
                .array(argPredArb, { minLength: indexes.length, maxLength: indexes.length })
                .map((preds) => indexes.map((index, i) => ({ index, pred: preds[i]! }))),
            ),
          { nil: undefined },
        ),
        notAfter: fc.option(fc.integer({ min: 1, max: 1_000_000 }), { nil: undefined }),
      }),
      { minLength: 1, maxLength: 3 },
    ),
  })
  .map(({ network, signers, rules }) => {
    const signerDecls: GenSigner[] = signers.map((s, i) => ({ id: `signer-${i}`, ...s }));
    const genRules: GenRule[] = rules.map((r, i) => ({
      name: `rule-${i}`,
      selfAdmin: r.selfAdmin,
      signerIdx: r.signerIdx.filter((idx) => idx < signerDecls.length),
      functions: r.functions,
      args: r.args,
      notAfter: r.notAfter,
    }));
    for (const r of genRules) {
      if (r.signerIdx.length === 0) r.signerIdx = [0];
    }
    return { network, signers: signerDecls, rules: genRules };
  });

/** Assemble the plain-object wire form, with object keys in a caller-chosen
 * order — canonicalization must erase the difference. */
function wireDoc(
  g: { network?: string; signers: GenSigner[]; rules: GenRule[] },
  reversedKeys: boolean,
): unknown {
  const obj = (entries: [string, unknown][]): Record<string, unknown> =>
    Object.fromEntries(reversedKeys ? [...entries].reverse() : entries);

  const signers = g.signers.map((s) =>
    s.kind === 'external'
      ? obj([
          ['id', s.id],
          ['verifier', s.verifier],
          ['key', s.key],
        ])
      : obj([
          ['id', s.id],
          ['address', DELEGATE_G],
        ]),
  );
  const rules = g.rules.map((r) => {
    const entries: [string, unknown][] = [
      ['name', r.name],
      [
        'scope',
        r.selfAdmin
          ? obj([['type', 'self-admin']])
          : obj([
              ['type', 'contract'],
              ['address', CONTRACT_C],
            ]),
      ],
      [
        'principals',
        obj([
          ['type', 'all'],
          ['signers', r.signerIdx.map((i) => g.signers[i]!.id)],
        ]),
      ],
    ];
    if (r.functions !== undefined) entries.push(['functions', r.functions]);
    if (r.args !== undefined)
      entries.push([
        'args',
        r.args.map((a) =>
          obj([
            ['index', a.index],
            ['pred', a.pred],
          ]),
        ),
      ]);
    if (r.notAfter !== undefined) entries.push(['not-after-ledger', r.notAfter]);
    return obj(entries);
  });

  const docEntries: [string, unknown][] = [['version', 1]];
  if (g.network !== undefined) docEntries.push(['network', g.network]);
  docEntries.push(['signers', signers], ['rules', rules]);
  return obj(docEntries);
}

// --- properties ---------------------------------------------------------------

describe('canonicalization properties', () => {
  it('canonical form is object-key-insertion-order independent', () => {
    fc.assert(
      fc.property(docArb, (g) => {
        // Deliberately NOT parsed first: zod's .parse() rebuilds objects in
        // schema-definition key order, which would erase the reversed
        // insertion order before canonicalJson ever saw it (and make this
        // property vacuous). canonicalJson takes the raw wire object.
        const a = wireDoc(g, false);
        const b = wireDoc(g, true);
        parsePolicyDoc(a); // both orders are schema-valid …
        parsePolicyDoc(b);
        expect(canonicalJson(b)).toBe(canonicalJson(a)); // … and hash identically
        expect(docHash(b)).toBe(docHash(a));
      }),
      { seed: SEED, numRuns: RUNS },
    );
  });

  it('canonical form round-trips through the schema byte-identically', () => {
    fc.assert(
      fc.property(docArb, (g) => {
        const doc = parsePolicyDoc(wireDoc(g, false));
        const canonical = canonicalJson(doc);
        const reparsed = parsePolicyDocJson(canonical);
        expect(canonicalJson(reparsed)).toBe(canonical);
        expect(docHash(reparsed)).toBe(docHash(doc));
      }),
      { seed: SEED, numRuns: RUNS },
    );
  });

  it('doc_hash is injective on the generated sample', () => {
    fc.assert(
      fc.property(docArb, docArb, (ga, gb) => {
        const a = parsePolicyDoc(wireDoc(ga, false));
        const b = parsePolicyDoc(wireDoc(gb, false));
        if (canonicalJson(a) !== canonicalJson(b)) {
          expect(docHash(a)).not.toBe(docHash(b));
        } else {
          expect(docHash(a)).toBe(docHash(b));
        }
      }),
      { seed: SEED, numRuns: RUNS },
    );
  });

  it('every builder output passes the schema and hashes like its wire form', () => {
    fc.assert(
      fc.property(docArb, (g) => {
        let b = policy();
        if (g.network !== undefined) b = b.network(g.network);
        for (const s of g.signers) {
          b = b.signer(
            s.id,
            s.kind === 'external' ? external(s.verifier, s.key) : delegated(DELEGATE_G),
          );
        }
        for (const r of g.rules) {
          b = b.rule(r.name, (rb) => {
            if (r.selfAdmin) rb.selfAdmin();
            else rb.callContract(CONTRACT_C);
            rb.signedBy(...r.signerIdx.map((i) => g.signers[i]!.id));
            if (r.functions !== undefined) rb.func(...r.functions);
            for (const a of r.args ?? []) rb.arg(a.index, a.pred);
            if (r.notAfter !== undefined) rb.notAfter(r.notAfter);
          });
        }
        const built = b.build();
        const wire = parsePolicyDoc(wireDoc(g, false));
        expect(canonicalJson(built)).toBe(canonicalJson(wire));
        expect(docHash(built)).toBe(docHash(wire));
      }),
      { seed: SEED, numRuns: RUNS },
    );
  });
});
