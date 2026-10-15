# PolicyDoc JSON Schema

A machine-readable description of the perch policy-document JSON surface, for
policy editors, documentation, recursive tree viewers, and interactive
debuggers: hover help, completion, and path-specific structural errors without
each consumer reconstructing the contract from `perch-ir`.

- **Artifact:** [`packages/perch-js/schemas/policy.schema.json`](../packages/perch-js/schemas/policy.schema.json)
- **Dialect:** JSON Schema draft 2020-12
- **`$id`:** `https://unpkg.com/@stellar-registry/perch/schemas/policy.schema.json`
- **Generator:** `crates/perch-schema` (host-side; `just schema` regenerates)

## Generation and drift

The schema is **generated, never hand-edited**. One command produces it:

```sh
just schema      # cargo run -q -p perch-schema --bin perch-schema-gen -- --write
```

The committed artifact must equal the generator's current output. CI enforces
this in `crates/perch-schema/tests/drift.rs` under `cargo test --workspace` (the
existing `rust` job) — no workflow change. If a perch-ir constant moves or the
generator changes and the file is not regenerated, that test fails with
`run \`just schema\``.

## Release / packaging path

The schema ships inside the already-published npm package
**`@stellar-registry/perch`** (`packages/perch-js`): it is listed in the
package's `files`, so `npm publish` includes it, and the normal release
pipeline publishes the package when its version is bumped (no hand version
bumps here). Clients and offline editors consume it at:

- the installed package: `@stellar-registry/perch/schemas/policy.schema.json`
- the CDN mirror (the `$id`): `https://unpkg.com/@stellar-registry/perch/schemas/policy.schema.json`

## Versioning policy

The schema describes policy-document format **`version: 1`** (the `version`
field is `{ "const": 1 }`). perch-ir rejects any other document version before
reading the rest of the document, and a future wire format is a new document
`version`, not a mutation of this one (`perch-ir`'s types carry no serde
framework; the wire format is hand-written in `parse.rs`/`canon.rs`).

- **Backward-compatible additions** to the `version: 1` surface (a new optional
  field, a new enum variant) are a new generation of *this* file at the same
  `$id`; consumers re-fetch.
- A **breaking** wire change introduces document `version: 2` and a sibling
  `policy.v2.schema.json` with its own `$id`; `policy.schema.json` continues to
  describe `version: 1`.

## Single source of truth for the representable limits

The schema is a host-side projection of the authoritative contracts. Each limit
it encodes is taken from the one place that declares it:

- **`perch-ir`** — `parse.rs` for shape and `validate.rs` for the representable
  format/range rules. `MAX_SIGNER_KEY_LEN` and `ACK_SENTINEL` directly; the
  strkey/hex shapes, the `m <= N` / guardian `quorum <= count` ranges, and the
  `limit` positivity/overflow shape behaviourally.
- **`perch-doc-compiler`** — the per-document caps `MAX_DOC_SIGNERS`,
  `MAX_DOC_RULES`, and `MAX_RULE_NAME_BYTES`, which the generator reads directly
  (they are plain `pub const`s; the generator depends on the crate with
  `default-features = false`, so no on-chain parser/compiler code is pulled in,
  and perch-schema is in no contract's build graph — nothing reaches a wasm
  build).

Two guards keep schema and source from silently diverging (the reason this work
started — a tightened string-length rule that broke a fixture a single declared
source would have caught):

- `crates/perch-schema/tests/drift.rs` — the committed file equals the
  generator output (so tightening a constant without regenerating fails CI);
- `crates/perch-schema/tests/limits_parity.rs` — each limit is checked against
  its source in both directions: behaviourally against perch-ir's own
  `from_json` + `validate` where perch-ir owns the rule, and by constant
  equality against the `perch-doc-compiler` caps where the compiler owns it (the
  sanctioned alternative to generating the numbers straight from the constants:
  a test that fails when the source and the schema disagree). The perch-js suite
  (`test/schema-limits-parity.test.ts`) runs the same cap parity against
  `checkLimits`, so the client-side check and the schema cannot disagree either.

## What the schema enforces

Structural shape and the representable data constraints:

- the kebab-case field names and `type` tags verbatim; **unknown fields are
  rejected** everywhere (`additionalProperties: false`), including beside a
  tag;
- shape-discriminated signer methods (`verifier`+`key` external, `address`
  delegated), required/optional fields, recursive `$ref` definitions;
- `version` is exactly `1`; an explicit JSON `null` for an optional field is
  rejected (leave the key out);
- **formats:** C-/G-address strkey shapes, 64-lowercase-hex digests, the signer
  `key` hex window (1..=`MAX_SIGNER_KEY_LEN` bytes), the `ack` sentinel, and the
  `cap.limit` positive-integer decimal string (rejects `0`, all-zero spellings,
  a sign-minus, and any value wider than an `i128` — see the CANON v2 note
  below for what it deliberately still accepts);
- **ranges:** `u32` bounds, and the non-zero minimums perch-ir refuses at `0`
  (`not-after-ledger`, `m`, `period-ledgers`, `quorum`, the recovery
  `*-ledgers` and `max-cancels`); the referenced-count bounds `m <= N`
  (threshold) and guardian `quorum <= guardian count`, encoded as an `allOf`
  `if`/`then` chain enumerated up to `MAX_DOC_SIGNERS`;
- **collections:** non-empty and no-duplicate lists where perch-ir requires
  them (`functions`, `string-in` values, principal/guardian/replaceable lists);
- **per-document caps the compiler enforces (`perch-doc-compiler`):** at most
  `MAX_DOC_SIGNERS` signers and `MAX_DOC_RULES` rules (`maxItems`), and a rule
  `name` at most `MAX_RULE_NAME_BYTES` bytes. Because JSON Schema's `maxLength`
  counts code points, not bytes, the rule name is also constrained to ASCII so
  one character is one byte — the single place the schema is intentionally
  *stricter* than the compiler (a non-ASCII name within the byte cap is
  schema-rejected; it fails closed, the safe direction for an editing schema).

## What stays outside the schema

Schema-valid is **not** the same as authorized or canonically encoded. These
checks are enforced elsewhere; a consumer must not treat schema validation as a
substitute:

- **Duplicate raw JSON keys.** A JSON Schema validator runs on already-parsed
  JSON, where a duplicate key is collapsed; perch-ir's raw-text parser rejects
  it (`crates/perch-schema/tests/conformance.rs` proves this boundary).
- **Lexical / canonical (RFC 8785) encoding.** A schema-valid document is not
  necessarily in canonical form; only canonical bytes feed `doc_hash`. See
  `CANONICAL.md`.
- **Cross-reference and semantic invariants.** Principal/replaceable references
  resolving to a declared signer; cap `token` matching the contract scope;
  unique signer ids and rule names; `commitment` being a canonical BN254 field
  element (below the scalar modulus); and the **exact** `i128` upper bound on
  `cap.limit` (the schema caps the *digit width* but not the precise maximum
  value). These are perch-ir's `validate` (and the compiler's lowering). The
  `m <= N` and guardian `quorum <= count` ranges are now *mostly* encoded (see
  above); they stay with the validator only for guardian sets larger than
  `MAX_DOC_SIGNERS`, which the `if`/`then` chain does not enumerate (guardians
  have no dedicated cap constant — a guardian-count cap would let the schema
  cover them fully; recorded as CANON v2 follow-up).
- **Value checks the schema does not encode.** The CRC16 checksum of every
  address strkey (the schema pins only the shape); each `functions` entry
  being a Soroban `Symbol` (1–32 characters from `[a-zA-Z0-9_]`); and a
  `string-prefix` prefix of at most `MAX_STRING_PRED_LEN` (256) bytes.
  perch-ir's `validate` refuses each.
- **Aggregate byte budget.** The compiler's `max_canonical_bytes` — the size of
  the *canonically-encoded* document, not a property of the parsed JSON tree —
  is not expressible as a schema keyword. It lives in
  `perch-doc-compiler::doc_limits()` and is mirrored client-side by perch-js's
  `checkLimits`. (The other per-document caps — `max_signers`, `max_rules`,
  `max_rule_name_bytes` — are now encoded by the schema; see above.)
- **Canonical spelling (CANON v2).** The schema accepts everything today's
  parser accepts, including non-canonical spellings of a valid value: a
  `cap.limit` with leading zeros or a leading `+` (`007`, `+5`), and uppercase
  hex in a signer `key` (perch-ir's `hex::decode` is case-insensitive there,
  unlike the 64-lowercase-hex digest fields, which *are* pinned because the
  parser requires that form). Rejecting these non-canonical spellings is a
  stricter *canonical* profile deferred to CANON v2 — it becomes correct only
  once the parser itself enforces one spelling, so that schema and parser stay
  in agreement. See the Perch `DEFERRED.md` CANON v2 entry.
- **Signatures and authorization.** Whether an invocation is actually
  authorized is `__check_auth` / OZ policy enforcement on-chain, nothing a
  document schema can state.

## Conformance

`crates/perch-schema/tests/conformance.rs` validates the committed canonical
fixtures and a set of negative examples (unknown fields, missing fields, wrong
tags/variant shape, bad ranges/formats, empty/duplicate collections) against the
schema with a real draft 2020-12 validator and compares the result with
perch-ir's real parser + validator **at the applicable boundary**:

| case kind | schema | perch-ir / compiler |
| --- | --- | --- |
| canonical fixture | accepts | parses + validates |
| structural defect | rejects | parser rejects |
| representable constraint (incl. `m <= N`, `quorum <= count`, `limit` positivity) | rejects | validator rejects (document still parses) |
| per-document cap (signer/rule count, rule-name bytes) | rejects | **validator accepts** — the cap is the *compiler's*, so the schema is the earlier gate; the constant is pinned in `limits_parity.rs` |
| non-ASCII rule name within the byte cap | **rejects** | validator accepts — the one place the schema is deliberately stricter (byte cap via ASCII) |
| cross-reference / semantic | **accepts** | validator rejects (documented gap) |

The `m <= N` / `quorum <= count` and `limit`-positivity cases, previously in the
last (documented-gap) row, now land in the "representable constraint" row —
schema and validator reject together. The negative examples (unknown fields,
missing fields, wrong tags/variant shape, bad ranges, over-cap collections) live
in `testdata/schema/cases.json` plus the generated boundary cases in the Rust
suite.

The shared cases live in [`testdata/schema/cases.json`](../testdata/schema/cases.json)
and are also run by the perch-js suite (`packages/perch-js/test/schema-conformance.test.ts`)
against the shipped artifact with `ajv`, so the JS surface offline editors
consume is held to the same contract.

## No contract-Wasm footprint

Generation adds nothing to any contract build (criterion 5). `perch-schema` is
host-only: it is a dependency of no deployable contract, uses `serde_json` only
to assemble JSON off-chain, and the `jsonschema` validator is a test-only
dependency. It reads the compiler caps from `perch-doc-compiler` with
`default-features = false`, so only that crate's plain `const`s and wire-type
module are pulled in (its on-chain parser/compiler sit behind the `contract`
feature) — and since nothing on any contract's build graph depends on
`perch-schema`, none of this reaches a `wasm32` build regardless. perch-ir stays
serde-free and float-free — nothing here changes what compiles to `wasm32`.

## Invocation tooling schema (deferred, with reasons)

Issue #114 also asks for an invocation schema **only for a defined JSON-facing
representation**, and to name the owning type first rather than imply a
production JSON ABI. There is **no stable JSON-facing invocation contract** to
schematize today:

- The authorization/invocation surface — `AuthPayload` and the selected rule
  ids a signer binds (#108, `packages/perch-js/src/{auth,xdr,selection}.ts`),
  and the Soroban `Context` an invocation is checked against — has its stable
  wire form in **XDR**, not JSON. A JSON Schema would misrepresent it.
- The one JSON-facing tooling type is the **ERC-7715-shaped permission request**
  (`packages/perch-js/src/request.ts`), which lowers *losslessly to a
  `PolicyDoc`* (`requestToPolicyDoc`). It is therefore already governed by this
  policy schema once lowered, and is itself a TS-side surface still settling
  (#8/#63/#108), not a versioned cross-language contract.

So this PR ships the policy schema and defers the invocation schema rather than
inventing one. If a stable JSON invocation representation is defined later, it
should be versioned here as its own file (e.g. `invocation.v1.schema.json`)
with the same generation/drift/conformance treatment.
