# Formal-verification and conformance impact of the recovery schema

Per repo verification conventions (`formal/README.md`, `docs/verification/PLAN.md`,
`docs/verification/THEORY.md`), every schema or semantics change is expected
to state its impact on the Lean model and `perch-conformance` explicitly —
covered, or scoped out with rationale. This is that statement for the
`recovery` field added to `PolicyDoc`.

## perch-conformance / eval-vectors: no impact, by design

`perch-conformance`'s vectors (`testdata/eval/eval-vectors.json`) and the
Lean `Semantics.lean`/`Lowering.lean`/`Theorems.lean` (T1–T6) model
**perch-program evaluation** — the RPN machine `__check_auth` runs per
invocation. `RecoveryConfig` never lowers to a perch-program op: it is not
installed as, or referenced by, any interpreter program. This isn't an
oversight; it's a load-bearing design decision — recovery state stays
outside the stateless interpreter entirely — and it is *why* recovery is
architecturally possible at all —
`docs/verification/THEORY.md`'s enforceability argument states plainly that
no execution monitor, including perch's, can enforce "the account can
always recover" (a liveness property), and that perch "addresses the
adjacent risk structurally instead" by keeping INV-2's policy-free admin
path independent of the interpreter. A recovery controller *is* that
structural answer, implemented as ordinary stateful contract logic outside
perch's own enforceable-fragment boundary — it was never a candidate for
inclusion in the per-invocation-safety-property model in the first place.

Concretely: `crates/perch-compile` (the crate that lowers `PolicyDoc` rules
into perch-program `InstallParams`) is untouched by adding recovery —
lowering happens entirely inside `perch-doc-compiler`, mapping
`perch_ir::RecoveryConfig` directly to a new wire type
(`CompiledRecoveryConfig`) with no perch-program involvement. So T1–T6 and
the eval-vectors conformance suite need no new cases and remain sound
exactly as before.

## Lean `Canon.lean` / `CanonProofs.lean` (T7, T8): covered

When the `recovery` field first landed, the Lean model of the canonical form
did not represent it, so `emitDoc_injective` (T7) covered only documents
without recovery (#88). The model now covers the member exactly as
`crates/perch-ir/src/canon.rs` emits it (`formal/PerchFormal/Canon.lean`):
both profiles; the `guardian-only`, `zk-only`, and `combined` modes with the
guardian fields (`guardians`, `quorum`) and every `ZkFactor` field
(`adapter`, `circuit-id`, `pool`, `enrollment-id`, `commitment`); the
controller; the optional baseline `doc-hash`; the replaceable signer ids;
and the three ledger counts. It also covers `threshold` principals, which
the model had lacked since they were added.

What is proved, sorry-free (`formal/PerchFormal/CanonProofs.lean`):

- **T7** `emitDoc_injective`: two documents with the same canonical bytes are
  the same document, with or without a `recovery` member. So `doc_hash`
  names one document up to a SHA-256 collision.
- **T8** `emitRecovery_injective` and `configPreimage_injective`: two
  recovery configurations with the same `recovery_canonical_json`, or the
  same `"perch/recovery/config" || recovery_canonical_json` preimage, are the
  same configuration. So `config_hash` (spec §3.2) names one configuration
  up to a SHA-256 collision. `configPreimage_ne_emitDoc`: no `config_hash`
  preimage is a document's canonical form.

How the model is tied to the Rust emitter, empirically: `lake exe drt`
parses and re-emits byte-identically both recovery document fixtures
(`ci-publish-recovery{,-combined}.canonical.json`) and one Rust-emitted
recovery member per mode (`testdata/recovery/config-*.canonical.json`,
regenerated and checked by `crates/perch-ir/tests/recovery.rs`). The fuzz
targets `ir_parse_roundtrip` and `recovery_canonical_roundtrip` check, on
the Rust side, that every recovery configuration round-trips through the
parser, that `recovery_canonical_json` is the document's member, and that
changing one field changes the text.

How T8 is tied to the doc compiler: `crates/integration-tests/tests/config_hash.rs`
compiles a document around each recovery-member fixture and requires
`config_hash = sha256("perch/recovery/config" || fixture bytes)`, recomputed
with `sha2`. It then changes each configuration field in turn (profile,
mode, every guardian and ZK field, controller, baseline, replaceable ids,
the three ledger counts) and requires the hash to move to the recomputed
hash of the changed text, and it requires a signer rotation to leave the
hash alone. The same check runs against the deployed compiler wasm in
`release_stack.rs`.

What this does not cover:

- That the Lean emitter and `canon.rs` agree on every input. That link is
  the fixtures and the fuzzing above, not a proof.
- What the fields mean: validation (`validate.rs`), `derive_target`, and
  the compiled configuration. The proofs are about bytes.
- That the compiler hashes exactly this preimage on every input. The test
  above covers the fixtures and their single-field changes, not a proof.
- The recovery controller's state machine, account authorization, and the
  ZK circuit, adapter, and pool. None has a formal model. See
  `docs/verification/PLAN.md` ("Coverage today") for the full list and the
  tests that cover them instead.
