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

The schema is generated, never hand-edited:

```sh
just schema      # cargo run -q -p perch-schema --bin perch-schema-gen -- --write
```

The committed artifact must equal the generator's current output.
`crates/perch-schema/tests/drift.rs` checks this under `cargo test --workspace`.
If a perch-ir constant moves or the generator changes and the file is not
regenerated, that test fails with `run \`just schema\``.

## Release / packaging path

The schema ships in the npm package `@stellar-registry/perch`
(`packages/perch-js`). It is listed in the package's `files`, so `npm publish`
includes it, and the release pipeline publishes the package when its version
is bumped. Clients and offline editors read it from:

- the installed package: `@stellar-registry/perch/schemas/policy.schema.json`
- the CDN mirror (the `$id`): `https://unpkg.com/@stellar-registry/perch/schemas/policy.schema.json`

## Versioning policy

The schema describes policy-document format `version: 1` (the `version`
field is `{ "const": 1 }`). perch-ir rejects any other document version before
reading the rest of the document, and a future wire format is a new document
`version`, not a mutation of this one (`perch-ir`'s types carry no serde
framework; the wire format is hand-written in `parse.rs`/`canon.rs`).

- Backward-compatible additions to `version: 1` (a new optional
  field, a new enum variant) are a new generation of *this* file at the same
  `$id`; consumers re-fetch.
- A breaking wire change introduces document `version: 2` and a sibling
  `policy.v2.schema.json` with its own `$id`; `policy.schema.json` still
  describes `version: 1`.

## Single source of truth for the representable limits

Each limit the schema encodes is taken from the one place that declares it:

- `perch-ir`: `parse.rs` for shape and `validate.rs` for the representable
  format/range rules. `MAX_SIGNER_KEY_LEN` and `ACK_SENTINEL` directly; the
  strkey/hex shapes, the `m <= N` / guardian `quorum <= count` ranges, and the
  `limit` positivity/overflow shape behaviourally.
- `perch-doc-compiler`: the per-document caps `MAX_DOC_SIGNERS` and
  `MAX_DOC_RULES` (an account document's), `MAX_GRANT_SIGNERS` and
  `MAX_GRANT_RULES` (a grant document's), and `MAX_RULE_NAME_BYTES`, which the
  generator reads directly
  (plain `pub const`s; see "No contract-Wasm footprint").

Two tests keep schema and source in agreement:

- `crates/perch-schema/tests/drift.rs`: the committed file equals the
  generator output, so tightening a constant without regenerating fails CI.
- `crates/perch-schema/tests/limits_parity.rs`: each limit is checked against
  its source in both directions, behaviourally against perch-ir's own
  `from_json` + `validate` where perch-ir owns the rule, and by constant
  equality against the `perch-doc-compiler` caps where the compiler owns it.
  The perch-js suite (`test/schema-limits-parity.test.ts`) runs the same cap
  parity against `checkLimits`.

## What the schema enforces

Structural shape and the representable data constraints:

- the kebab-case field names and `type` tags verbatim; unknown fields are
  rejected everywhere (`additionalProperties: false`), including beside a
  tag;
- shape-discriminated signer methods (`verifier`+`key` external, with an
  optional `verifier-name`; `address` delegated), required/optional fields,
  recursive `$ref` definitions;
- `version` is exactly `1`; an explicit JSON `null` for an optional field is
  rejected (leave the key out);
- formats: C-/G-address strkey shapes, 64-lowercase-hex digests, the signer
  `key` hex window (1..=`MAX_SIGNER_KEY_LEN` bytes), a `verifier-name`'s
  `<name>@<MAJOR>.<MINOR>.<PATCH>` spelling (`perch_ir::parse_verifier_name`,
  the name at most `MAX_VERIFIER_NAME_LEN` bytes), the `ack` sentinel, and the
  `cap.limit` positive-integer decimal string (rejects `0`, all-zero spellings,
  a sign-minus, and any value wider than an `i128`; "Canonical spelling"
  below lists what it still accepts);
- ranges: `u32` bounds, and the non-zero minimums perch-ir refuses at `0`
  (`not-after-ledger`, `m`, `period-ledgers`, `quorum`, the recovery
  `*-ledgers` and `max-cancels`); the referenced-count bounds `m <= N`
  (threshold) and guardian `quorum <= guardian count`, encoded as an `allOf`
  `if`/`then` chain enumerated up to the larger signer cap (`m`) and
  `MAX_DOC_SIGNERS` (`quorum`);
- collections: non-empty and no-duplicate lists where perch-ir requires
  them (`functions`, `string-in` values, principal/guardian/replaceable lists);
- per-document caps the compiler enforces (`perch-doc-compiler`): at most
  `MAX_DOC_SIGNERS` signers and `MAX_DOC_RULES` rules in an account document
  (one with a `recovery` member or a self-admin rule) and `MAX_GRANT_SIGNERS`
  and `MAX_GRANT_RULES` in a grant document (`maxItems`, the larger of each
  pair at the top level and the document's own under a top-level
  `if`/`then`/`else` on its kind), and a rule `name` at most
  `MAX_RULE_NAME_BYTES` bytes. Because JSON Schema's `maxLength`
  counts code points, not bytes, the rule name is also constrained to ASCII so
  one character is one byte. This is the one place the schema is stricter
  than the compiler: it rejects a non-ASCII name within the byte cap, which
  fails closed.

The optional rule member `auth-root` is a strict object with a contract
C-address and a 1–32 character function symbol. Null, extra members and
self-admin use are refused. Omission preserves legacy identity. See
[Exact authorization-entry roots](auth-root.md) for capability and rollout
requirements; schema acceptance alone does not establish account support.

## What stays outside the schema

Schema-valid is not the same as authorized or canonically encoded. Other
components enforce these checks, and a consumer must not treat schema
validation as a substitute for them:

- **Duplicate raw JSON keys.** A JSON Schema validator runs on already-parsed
  JSON, where a duplicate key is collapsed; perch-ir's raw-text parser rejects
  it (`crates/perch-schema/tests/conformance.rs` proves this boundary).
- **Lexical / canonical (RFC 8785) encoding.** A schema-valid document is not
  necessarily in canonical form; only canonical bytes feed `doc_hash`. See
  `CANONICAL.md`.
- **Cross-reference and semantic invariants.** Principal/replaceable references
  resolving to a declared signer; cap `token` matching the contract scope;
  unique signer ids and rule names; `commitment` being a canonical BN254 field
  element (below the scalar modulus); and the exact `i128` upper bound on
  `cap.limit` (the schema caps the *digit width* but not the precise maximum
  value). These are perch-ir's `validate` (and the compiler's lowering). The
  schema encodes the `m <= N` and guardian `quorum <= count` ranges (above)
  except for guardian sets larger than `MAX_DOC_SIGNERS`, which the
  `if`/`then` chain does not enumerate. Guardians have no dedicated cap
  constant; a guardian-count cap would let the schema cover them fully
  (`docs/DEFERRED.md`, "PolicyDoc JSON Schema: strict profile and
  out-of-schema checks").
- **Value checks the schema does not encode.** The CRC16 checksum of every
  address strkey (the schema pins only the shape); each `functions` entry
  being a Soroban `Symbol` (1–32 characters from `[a-zA-Z0-9_]`); and a
  `string-prefix` prefix of at most `MAX_STRING_PRED_LEN` (256) bytes.
  perch-ir's `validate` refuses each.
- **Aggregate byte budget.** The compiler's `max_canonical_bytes` is the size of
  the canonically encoded document, not a property of the parsed JSON tree,
  so no schema keyword can express it. It lives in
  `perch-doc-compiler::doc_limits()` (an account document's) and
  `grant_limits()` (a grant document's) and is mirrored client-side by
  perch-js's `checkLimits`. The schema encodes the other per-document caps
  (`max_signers`, `max_rules`, `max_rule_name_bytes`). Likewise the size of
  the ledger entry a grant document makes its account store
  (`MAX_GRANT_STORED_BYTES`), which the compiler computes from the document.
- **Canonical spelling (CANON v2).** The schema accepts everything today's
  parser accepts, including non-canonical spellings of a valid value: a
  `cap.limit` with leading zeros or a leading `+` (`007`, `+5`), and uppercase
  hex in a signer `key` (perch-ir's `hex::decode` is case-insensitive there,
  unlike the 64-lowercase-hex digest fields, which the schema pins because the
  parser requires that form). Rejecting these spellings is a strict canonical
  profile deferred to CANON v2. It is correct only once the parser enforces
  one spelling, so that schema and parser still agree. See `docs/DEFERRED.md`,
  "Canonical value spellings".
- **Verifier names and unverified verifiers.** Whether a `verifier-name`
  resolves to its `verifier` in `perch/verifiers` is read from the chain;
  that an account document names no verifier by contract id alone, and that a
  rule holds one signer per such verifier, are the doc compiler's checks
  (`docs/account-interface.md`, "Verifiers").
- **Signatures and authorization.** Whether an invocation is actually
  authorized is decided on-chain by the account's `__check_auth`, nothing a
  document schema can state. See [the account interface](account-interface.md).

## Conformance

`crates/perch-schema/tests/conformance.rs` validates the committed canonical
fixtures and a set of negative examples (unknown fields, missing fields, wrong
tags/variant shape, bad ranges/formats, empty/duplicate collections) against the
schema with a real draft 2020-12 validator and compares the result with
perch-ir's parser and validator at the applicable boundary:

| case kind | schema | perch-ir / compiler |
| --- | --- | --- |
| canonical fixture | accepts | parses + validates |
| structural defect | rejects | parser rejects |
| representable constraint (incl. `m <= N`, `quorum <= count`, `limit` positivity) | rejects | validator rejects (document still parses) |
| per-document cap (signer/rule count, rule-name bytes) | rejects | validator accepts; the cap is the compiler's, so the schema is the earlier gate. `limits_parity.rs` pins the constant |
| non-ASCII rule name within the byte cap | rejects | validator accepts; the one place the schema is stricter (byte cap via ASCII) |
| cross-reference / semantic | accepts | validator rejects (documented gap) |

The negative examples (unknown fields, missing fields, wrong tags/variant
shape, bad ranges, over-cap collections) live in
[`testdata/schema/cases.json`](../testdata/schema/cases.json), plus the
generated boundary cases in the Rust suite. The perch-js suite
(`packages/perch-js/test/schema-conformance.test.ts`) runs the same shared
cases against the shipped artifact with `ajv`.

## No contract-Wasm footprint

Generation adds nothing to any contract build. `perch-schema` is
host-only: it is a dependency of no deployable contract, uses `serde_json` only
to assemble JSON off-chain, and the `jsonschema` validator is a test-only
dependency. It reads the compiler caps from `perch-doc-compiler` with
`default-features = false`, so only that crate's plain `const`s and wire-type
module are pulled in (its on-chain parser/compiler sit behind the `contract`
feature). Nothing on any contract's build graph depends on `perch-schema`, so
none of this reaches a `wasm32` build. perch-ir stays serde-free and
float-free.

## Invocation tooling schema (deferred, with reasons)

An invocation schema needs a defined JSON-facing representation with a named
owning type (issue #114), and there is no stable JSON-facing invocation
contract to describe:

- `AuthPayload`, the selected rule ids a signer binds (#108,
  `packages/perch-js/src/{auth,xdr,selection}.ts`), and the Soroban `Context`
  an invocation is checked against have their stable wire form in XDR, not
  JSON. A JSON Schema would misrepresent it.
- The one JSON-facing tooling type is the ERC-7715-shaped permission request
  (`packages/perch-js/src/request.ts`), which lowers losslessly to a
  `PolicyDoc` (`requestToPolicyDoc`). Once lowered, the policy schema covers
  it. The request type itself is TypeScript-only and unversioned
  (#8/#63/#108).

A stable JSON invocation representation, once defined, gets its own versioned
file here (e.g. `invocation.v1.schema.json`) with the same generation, drift
and conformance tests.
