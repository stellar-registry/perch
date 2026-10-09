# The perch formal model

An executable Lean 4 twin of the perch-program v1 semantics, the core of the
verification-guided-development plan in
[`docs/verification/PLAN.md`](../docs/verification/PLAN.md), in the style of
[AWS Cedar's `cedar-spec`](https://github.com/cedar-policy/cedar-spec). No
dependencies beyond Lean core; the toolchain is pinned by `lean-toolchain`.

| File | Contents |
|---|---|
| `PerchFormal/Verdict.lean` | the Kleene verdict lattice + T1/T2 |
| `PerchFormal/Semantics.lean` | the op alphabet, leaf semantics (every fail-closed decode path), the guarded RPN machine (`rpn::eval` twin, every defensive guard mirrored), the validator (`rpn::validate` twin) |
| `PerchFormal/Lowering.lean` | `build_program` twin + the doc-level meaning of a rule |
| `PerchFormal/Theorems.lean` | the evaluator/lowering proofs (below) |
| `PerchFormal/Canon.lean` | CANON v1 twin: the canonical JSON emitter for every `PolicyDoc` shape (including `threshold` principals and the `recovery` member), the `config_hash` and `rule_hash` preimages, and verified inverse parsers |
| `PerchFormal/CanonProofs.lean` | round-trips + `emitDoc_injective` (doc_hash names exactly one document) + the fragment-hash theorems (config_hash names one recovery configuration, rule_hash one rule) |
| `CheckAxioms.lean` | the axiom audit: fails unless every `PerchFormal` declaration depends only on `propext`, `Classical.choice`, and `Quot.sound` (a `sorry` would appear as `sorryAx`). CI runs it after `lake build` |
| `Main.lean` | `lake exe drt`. Replays `testdata/eval/eval-vectors.json` through the model, and round-trips Rust-emitted canonical documents and (after `--recovery`) recovery members through the verified canonicalizer |

## Theorems (all sorry-free)

CI checks this two ways: a source grep forbids the words, and `CheckAxioms.lean`
checks what every declaration actually depends on.

- **T1** lattice laws: `and`/`or` commutative + associative, De Morgan, double
  negation, `neg U = U`.
- **T2** fail-closed root: only `T` allows; an `U` conjunct can never raise a
  verdict to `T`; `U` under negation still denies (the fail-open trap).
- **T3** totality/termination: inherent. `eval` is a total function by
  structural recursion.
- **T4** `validate_sound`: a program accepted by `validate` never trips a
  defensive guard. The guarded machine agrees with a purely structural one,
  so a validated program's verdict is a pure function of its leaves
  ("Validation ⇒ analyzable").
- **T5** `zero_signers_denied`: every lowered rule (whose leaves fit the
  stack cap, guaranteed in Rust by compile's re-validation) evaluates to a
  definite `F` on any invocation with zero authenticated signers. This is
  INV-1 at the model level.
- **T7** `emitDoc_injective`: the CANON v1 canonical form is injective on the
  document domain, proved by exhibiting a verified inverse parser
  (`pDoc_rt : pDoc (emitDoc d ++ rest) = some (d, rest)`), covering the JCS
  escaping table, plain-decimal `u32`s, sorted keys, and omitted `None`s. So
  `doc_hash` identifies exactly one document up to a SHA-256 collision. The
  domain is every shape `perch_ir::canonical_json` emits: `external` and
  `delegated` signers, `all`/`threshold`/`self-authenticating` principals,
  every arg predicate, caps, expiries, and the optional `recovery` member
  (both profiles; `guardian-only`, `zk-only`, and `combined` modes with every
  guardian and ZK field; controller; optional baseline; replaceable ids; the
  three ledger counts). The proofs hold at any size; the doc compiler's
  caps (`MAX_DOC_*`) only narrow the domain. `canonical_bytes_identity`:
  parsing a document's canonical bytes returns that document, so its
  identity preimage is those same bytes. That is why a recovery target's
  two digests (`target_bytes_hash`, `target_doc_hash`) agree under CANON
  v1. As of our survey (2026-08), no other machine-verified implementation
  of an RFC 8785 subset exists.
- **T8** fragment hashes (`CANONICAL.md`, "Fragment hashes"):
  `configPreimage_injective` and `rulePreimage_injective`. The preimages
  `"perch/recovery/config" || recovery_canonical_json` and
  `"perch/rule" || rule_canonical_json` are injective (via `pRecovery_rt`
  and `pRule_rt`), so `config_hash` identifies exactly one recovery
  configuration and `rule_hash` exactly one rule text, up to a SHA-256
  collision. `configPreimage_ne_emitDoc`, `rulePreimage_ne_emitDoc`, and
  `rulePreimage_ne_configPreimage` separate the three hash domains: no two
  kinds of preimage coincide (the two tags share `perch/r` and then differ).
  `emitRecovery_infix_emitDoc` and `emitRule_infix_emitDoc`: each fragment
  is a substring of its document's canonical form, so `config_hash` ignores
  everything outside the `recovery` member (a key rotation is not a
  reconfiguration). That the code hashes exactly these preimages is tested,
  not proved (below).
- **T6** `lowering_preserves`: the machine over `build_program`'s postfix
  output computes exactly the rule's doc-level Kleene conjunction, where the
  doc side is stated over predicates directly and `leafEval_lowerPred` proves
  the op translation meaning-preserving. So encoding, machine, and
  translation are all inside the theorem; only the model↔Rust leaf-semantics
  link remains empirical (the vectors + differential suite below).

## What ties the model to the shipped code

The model is executable and replays the same frozen conformance vectors the
Rust implementation is tested against (`crates/perch-conformance`,
expectations hand-authored from `CANONICAL.md`), plus every Rust-emitted
canonical fixture:

```sh
just drt          # Rust side + Lean side over the same vectors and fixtures
# or directly:
cd formal && lake exe drt ../testdata/eval/eval-vectors.json \
  ../testdata/ci-publish*.canonical.json \
  --recovery ../testdata/recovery/config-*.canonical.json
```

Green means the hand-authored spec, the Rust evaluator, and this proved model
agree on every case, and that the model's canonicalizer parses and re-emits
the Rust canonicalizer's bytes for every fixture: five documents (external
and delegated signers, `all` and `threshold` principals, a cap,
`guardian-only` and `combined` recovery) and one recovery member per mode.
`crates/perch-ir/tests/recovery.rs` regenerates the recovery-member fixtures
from Rust and fails when they are stale.

The model↔Rust link is differential (empirical), not deductive. The
theorems are about the Lean emitter; the fixtures and the fuzz targets
(`fuzz/fuzz_targets/ir_parse_roundtrip.rs`,
`recovery_canonical_roundtrip.rs`) are the evidence that `canon.rs` emits
the same bytes. Two tests tie T8 to the code that computes the hashes:

- `config_hash`: `crates/integration-tests/tests/config_hash.rs` requires,
  for each recovery-member fixture, that the doc compiler's `config_hash`
  equal `sha256("perch/recovery/config" || fixture bytes)` recomputed with
  `sha2`, and that every single-field change move it to the recomputed hash
  of the changed text. It runs against the native compiler on every PR and,
  in `release_stack.rs`, against a release stack's compiler wasm (in CI, the
  one built from the PR's source; locally, also the deployed testnet one,
  fetched with `scripts/fetch-infra-wasm.sh --stack`).
- `rule_hash`: `testdata/rule-hashes.json` is cut out of the canonical
  fixtures by an independent script (`scripts/rule-hash-vectors.py`) and
  checked against the Rust `rule_hash` and the provenance `perch-compile`
  stamps into every program (`perch-recovery-interface/tests/vectors.rs`,
  `integration-tests/tests/fragment_hashes.rs`).

See PLAN.md phase 2 for the planned deepening (Verus or Aeneas).

## What is not modeled

The model covers two things: the per-invocation evaluator and lowering
(T1–T6), and the canonical form and its hashes (T7, T8). Nothing else in
the recovery stack has a model or a proof:

- **The recovery controller's state machine** (`crates/perch-recovery`):
  attempts and their lifecycle, the `Protected` freeze, cancellation and
  the cancel cap, evidence freshness and expiry, epochs, nullifier spending,
  baselines, upgrade approvals, and the two-digest target binding (`enforce`
  checks `sha256` of the completing bytes against `target_bytes_hash`, then
  `rcv_sync` checks the compiled identity against `target_doc_hash`). These
  are pinned by enforcing-auth integration tests
  (`crates/integration-tests/tests/recovery.rs`, `target_binding.rs`), not
  proofs. The only formal fact behind the claim that `target_bytes_hash ==
  target_doc_hash` under CANON v1 is `canonical_bytes_identity`: an honest
  completion's bytes compile to the identity the attempt recorded. T7 adds
  that the identity names one document. For the Rust parser the same round
  trip is fuzzed (`ir_parse_roundtrip` checks `parse(emit(doc)) == doc`).
- **Account authorization paths** (`crates/perch-smart-account`:
  `__check_auth`, OZ context-rule selection, `execute`, `apply_doc`,
  upgrades). Tests only (`account_capabilities.rs`, `matrix.rs`). That
  includes the delta `apply_doc`: T8 shows equal `rule_hash` preimages
  mean equal rule text, but that the account then touches exactly the
  changed rules is tested (the delta tests, the `apply_doc_delta` fuzz
  target), not proved. The configuration revision and `apply_doc`'s
  `expected_revision` (#110) are account state outside the document: no
  hash here covers them, and T7 names a document, not an account state.
  After A→B→A the same `doc_hash` returns at a later revision, by design
  (`revision.rs`).
- **The ZK circuit, verifier, adapter, and pool** (`circuits/`,
  `crates/perch-zk-adapter`, the membership pool): real-proof tests and
  cross-implementation Poseidon2 vectors (`docs/zk/README.md`), no proofs.
- **The document compiler** beyond the canonical bytes and `config_hash`:
  validation, `derive_target`, and the rest of the compiled recovery
  configuration.
- **The recovery statement's encoding** (`docs/recovery/statement.md`), so
  CANONICAL.md's claim that the fragment tags are separated from the
  statement tags is not proved.
- **SHA-256** itself: every "names exactly one" claim above holds up to a
  SHA-256 collision.

## Setup

```sh
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh   # installs elan
cd formal && lake build                                  # checks all proofs
lake env lean CheckAxioms.lean                           # audits their axioms
```
