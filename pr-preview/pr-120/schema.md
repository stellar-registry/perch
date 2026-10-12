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

The schema is a host-side projection of the authoritative contract in
`perch-ir` — `parse.rs` for shape and `validate.rs` for the representable
format/range rules. Every limit the schema can express is taken from perch-ir:
`MAX_SIGNER_KEY_LEN` and `ACK_SENTINEL` directly, the strkey/hex shapes
behaviourally. Two guards keep them from silently diverging (the reason this
work started — a tightened string-length rule that broke a fixture a single
declared source would have caught):

- `crates/perch-schema/tests/drift.rs` — the committed file equals the
  generator output (so tightening a constant without regenerating fails CI);
- `crates/perch-schema/tests/limits_parity.rs` — each limit is checked against
  perch-ir's own `from_json` + `validate` at its boundary, in both directions
  (the sanctioned alternative to generating the numbers straight from the
  constants: a test that fails when the validator and the schema disagree).

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
  `key` hex window (1..=`MAX_SIGNER_KEY_LEN` bytes), the `ack` sentinel;
- **ranges:** `u32` bounds, and the non-zero minimums perch-ir refuses at `0`
  (`not-after-ledger`, `m`, `period-ledgers`, `quorum`, the recovery
  `*-ledgers` and `max-cancels`);
- **collections:** non-empty and no-duplicate lists where perch-ir requires
  them (`functions`, `string-in` values, principal/guardian/replaceable lists).

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
- **Cross-reference and semantic invariants.** `m <= N` and guardian
  `quorum <= guardian count`; principal/replaceable references resolving to a
  declared signer; cap token matching the contract scope; `commitment` being a
  canonical BN254 field element (below the scalar modulus); `limit` parsing as a
  positive `i128`; unique signer ids and rule names. These are perch-ir's
  `validate` (and the compiler's lowering).
- **Aggregate resource bounds.** The compiler's per-document caps —
  `max_signers`, `max_rules`, `max_rule_name_bytes`, and the
  `max_canonical_bytes` byte budget (not expressible as a schema keyword) — live
  in `perch-doc-compiler::doc_limits()` and are mirrored client-side by
  perch-js's `checkLimits`.
- **Signatures and authorization.** Whether an invocation is actually
  authorized is `__check_auth` / OZ policy enforcement on-chain, nothing a
  document schema can state.

## Conformance

`crates/perch-schema/tests/conformance.rs` validates the committed canonical
fixtures and a set of negative examples (unknown fields, missing fields, wrong
tags/variant shape, bad ranges/formats, empty/duplicate collections) against the
schema with a real draft 2020-12 validator and compares the result with
perch-ir's real parser + validator **at the applicable boundary**:

| case kind | schema | perch-ir |
| --- | --- | --- |
| canonical fixture | accepts | parses + validates |
| structural defect | rejects | parser rejects |
| representable constraint | rejects | validator rejects (document still parses) |
| cross-reference / semantic | **accepts** | validator rejects (documented gap) |

The shared cases live in [`testdata/schema/cases.json`](../testdata/schema/cases.json)
and are also run by the perch-js suite (`packages/perch-js/test/schema-conformance.test.ts`)
against the shipped artifact with `ajv`, so the JS surface offline editors
consume is held to the same contract.

## No contract-Wasm footprint

Generation adds nothing to any contract build (criterion 5). `perch-schema` is
host-only: it is a dependency of no deployable contract, uses `serde_json` only
to assemble JSON off-chain, and the `jsonschema` validator is a test-only
dependency. perch-ir stays serde-free and float-free — nothing here changes
what compiles to `wasm32`.

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
