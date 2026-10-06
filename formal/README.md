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
| `PerchFormal/Canon.lean` | CANON v1 twin: the canonical JSON emitter for every `PolicyDoc` shape (including `threshold` principals and the `recovery` member), `recovery_canonical_json`, the `config_hash` preimage, and verified inverse parsers |
| `PerchFormal/CanonProofs.lean` | round-trips + `emitDoc_injective` (doc_hash names exactly one document) + `emitRecovery_injective`/`configPreimage_injective` (config_hash names exactly one recovery configuration) |
| `Main.lean` | `lake exe drt`. Replays `testdata/eval/eval-vectors.json` through the model, and round-trips Rust-emitted canonical documents and (after `--recovery`) recovery members through the verified canonicalizer |

## Theorems (all sorry-free)

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
  three ledger counts). As of our survey (2026-08), no other
  machine-verified implementation of an RFC 8785 subset exists.
- **T8** `configPreimage_injective`: `recovery_canonical_json` is injective
  (`emitRecovery_injective`, via `pRecovery_rt`), and so is the
  `config_hash` preimage `"perch/recovery/config" || recovery_canonical_json`.
  So `config_hash` identifies exactly one recovery configuration up to a
  SHA-256 collision, and it ignores everything outside the `recovery`
  member by construction (a key rotation is not a reconfiguration).
  `configPreimage_ne_emitDoc` separates the two hash domains: no
  `config_hash` preimage is a document's canonical form. That the doc
  compiler hashes exactly this preimage is tested, not proved (below).
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
`guardian-only` and `combined` recovery) and one recovery member per mode. `crates/perch-ir/tests/recovery.rs` regenerates
the recovery-member fixtures from Rust and fails when they are stale.

The model↔Rust link is differential (empirical), not deductive: the
theorems are about the Lean emitter, and the fixtures and the fuzz targets
(`fuzz/fuzz_targets/ir_parse_roundtrip.rs`,
`recovery_canonical_roundtrip.rs`) are the evidence that `canon.rs` emits
the same bytes. `crates/integration-tests/tests/config_hash.rs` ties T8 to
the doc compiler: for each recovery-member fixture, the compiler's
`config_hash` must equal `sha256("perch/recovery/config" || fixture bytes)`
recomputed with `sha2`, and every single-field change must move it to the
recomputed hash of the changed text. It runs against the native compiler on
every PR and, in `release_stack.rs`, against a release stack's compiler wasm
(in CI, the one built from the PR's source; locally, also the deployed
testnet one, fetched with `scripts/fetch-infra-wasm.sh --stack`). See
PLAN.md phase 2 for the planned deepening (Verus or Aeneas).

## What is not modeled

The model covers two things: the per-invocation evaluator and lowering
(T1–T6), and the canonical form and its hashes (T7, T8). Nothing else in
the recovery stack has a model or a proof:

- **The recovery controller's state machine** (`crates/perch-recovery`):
  attempts and their lifecycle, the `Protected` freeze, cancellation and
  the cancel cap, evidence freshness and expiry, epochs, nullifier spending,
  baselines, upgrade approvals. These are pinned by enforcing-auth
  integration tests (`crates/integration-tests/tests/recovery.rs`), not
  proofs.
- **Account authorization paths** (`crates/perch-smart-account`:
  `__check_auth`, OZ context-rule selection, `execute`, `apply_doc`,
  upgrades). Tests only (`account_capabilities.rs`, `matrix.rs`).
- **The ZK circuit, verifier, adapter, and pool** (`circuits/`,
  `crates/perch-zk-adapter`, the membership pool): real-proof tests and
  cross-implementation Poseidon2 vectors (`docs/zk/README.md`), no proofs.
- **The document compiler** beyond the canonical bytes and `config_hash`:
  validation, `derive_target`, and the rest of the compiled recovery
  configuration.
- **SHA-256** itself: every "names exactly one" claim above holds up to a
  SHA-256 collision.

## Setup

```sh
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh   # installs elan
cd formal && lake build                                  # checks all proofs
```
