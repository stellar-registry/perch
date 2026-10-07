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

## Lean `Canon.lean` / `CanonProofs.lean` (T7): explicitly scoped out, with rationale

`Canon.lean` is a hand-maintained Lean *twin* of `perch-ir`'s canonical-form
emitter (`crates/perch-ir/src/canon.rs`), and `CanonProofs.lean` proves
`emitDoc_injective` (T7) against the Lean model's own `Doc` type — not
against the Rust type directly. Extending Lean's `Doc` to add a `recovery`
field (plus the `RecoveryMode`/`GuardianSet`/`ZkVerifierConfig`/
`BaselineCommitment`/`PendingActivityPolicy` sub-types) and re-proving
injectivity over the enlarged domain is real, non-mechanical proof
engineering: a new sum-of-products shape enters the emitter and its
verified inverse parser, and `emitDoc_injective`'s proof structure would
need new cases throughout.

**This change does not do that work**, for two reasons stated plainly rather
than hidden:

1. **Correctness bar.** `formal/README.md` states every theorem here is
   "sorry-free." Extending a non-trivial injectivity proof under time
   pressure risks landing an admitted or subtly-wrong proof, which is worse
   than an honest gap — a `sorry` (or a proof that typechecks but doesn't
   actually establish what it claims) would silently narrow what T7 is
   worth without anyone noticing on a green CI run.
2. **No loss to the existing claim.** T7 continues to hold, exactly as
   proved, for every document Lean's `Doc` type can represent — which is
   every document *without* recovery. The Rust-side regression test
   (`crates/perch-ir/tests/recovery.rs::recovery_absent_documents_hash_exactly_as_before_this_field_existed`,
   backed by the unchanged `ci-publish{,-delegated,-threshold}` golden
   vectors) is exactly the condition that keeps this true: nothing about
   adding an *optional*, omitted-when-`None` field changes the canonical
   bytes of any document that doesn't use it. T7's proof over that domain
   is not weakened, invalidated, or cast into doubt by this change — it
   simply does not yet extend to the new domain.

**What this means concretely:** `just drt` (the differential Rust↔Lean
replay) is unaffected and continues to pass, because it replays
`testdata/eval/eval-vectors.json` and round-trips the existing
(recovery-absent) `ci-publish*.canonical.json` fixtures — none of which
gained a `recovery` field. The two new fixtures this change adds
(`ci-publish-recovery.json`, `ci-publish-recovery-combined.json`) are
**not** round-tripped through the Lean model, because Lean's `Doc` cannot
represent them yet. Their canonical-form and hash agreement is instead
verified the same way every other cross-language fixture in this repo is —
by the Rust (`crates/perch-ir/tests/recovery.rs`) and TypeScript
(`packages/perch-js/test/parity.test.ts`) suites agreeing on committed
bytes — which is real cross-implementation conformance, just not
machine-checked against the Lean model.

## Tracked follow-up

Extending `Canon.lean`/`CanonProofs.lean` to cover `RecoveryConfig` and
re-establishing `emitDoc_injective` over the enlarged domain is legitimate
future work, tracked here rather than attempted as part of this change. It
should be undertaken as its own reviewed change with room to get the
injectivity argument right, not bundled into a schema-and-controller
release. Tracked in [#88](https://github.com/stellar-registry/perch/issues/88).
