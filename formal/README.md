# The perch formal model

An executable Lean 4 twin of the perch-program v1 semantics — the
verification-guided-development backbone from
[`docs/verification/PLAN.md`](../docs/verification/PLAN.md), in the style of
[AWS Cedar's `cedar-spec`](https://github.com/cedar-policy/cedar-spec). No
dependencies beyond Lean core; the toolchain is pinned by `lean-toolchain`.

| File | Contents |
|---|---|
| `PerchFormal/Verdict.lean` | the Kleene verdict lattice + T1/T2 |
| `PerchFormal/Semantics.lean` | the op alphabet, leaf semantics (every fail-closed decode path), the guarded RPN machine (`rpn::eval` twin, every defensive guard mirrored), the validator (`rpn::validate` twin) |
| `PerchFormal/Lowering.lean` | `build_program` twin + the doc-level meaning of a rule |
| `PerchFormal/Theorems.lean` | the evaluator/lowering proofs (below) |
| `PerchFormal/Canon.lean` | CANON v1 twin: the canonical JSON emitter + its verified inverse parser |
| `PerchFormal/CanonProofs.lean` | round-trip + `emitDoc_injective` — doc_hash names exactly one document |
| `Main.lean` | `lake exe drt` — replays `testdata/eval/eval-vectors.json` through the model, and round-trips Rust-emitted `*.canonical.json` files through the verified canonicalizer |

## Theorems (all sorry-free)

- **T1** lattice laws: `and`/`or` commutative + associative, De Morgan, double
  negation, `neg U = U`.
- **T2** fail-closed root: only `T` allows; an `U` conjunct can never raise a
  verdict to `T`; `U` under negation still denies (the fail-open trap).
- **T3** totality/termination: inherent — `eval` is a total function by
  structural recursion.
- **T4** `validate_sound`: a program accepted by `validate` never trips a
  defensive guard — the guarded machine agrees with a purely structural one,
  so a validated program's verdict is a pure function of its leaves
  ("Validation ⇒ analyzable").
- **T5** `zero_signers_denied`: every lowered rule (whose leaves fit the
  stack cap — guaranteed in Rust by compile's re-validation) evaluates to a
  definite `F` on any invocation with zero authenticated signers — INV-1 at
  the model level.
- **T7** `emitDoc_injective`: the CANON v1 canonical form is injective on the
  document domain — proved by exhibiting a verified inverse parser
  (`pDoc_rt : pDoc (emitDoc d ++ rest) = some (d, rest)`), covering the JCS
  escaping table, plain-decimal `u32`s, sorted keys, and omitted `None`s. So
  `doc_hash` identifies exactly one document up to a SHA-256 collision. As of
  our survey (2026-08), no other machine-verified implementation of an
  RFC 8785 subset exists.
- **T6** `lowering_preserves`: the machine over `build_program`'s postfix
  output computes exactly the rule's doc-level Kleene conjunction, where the
  doc side is stated over predicates directly and `leafEval_lowerPred` proves
  the op translation meaning-preserving — so encoding, machine, and
  translation are all inside the theorem; only the model↔Rust leaf-semantics
  link remains empirical (the vectors + differential suite below).

## What ties the model to the shipped code

The model is executable and replays the same frozen conformance vectors the
Rust implementation is tested against (`crates/perch-conformance`,
expectations hand-authored from `CANONICAL.md`):

```sh
just drt          # Rust side + Lean side over the same vectors
# or directly:
cd formal && lake exe drt ../testdata/eval/eval-vectors.json
```

Green means the hand-authored spec, the Rust evaluator, and this proved model
agree on every case. The model↔Rust link is differential (empirical), not
deductive — see PLAN.md phase 2 for the planned deepening (Verus or Aeneas).

## Setup

```sh
curl -sSf https://elan.lean-lang.org/elan-init.sh | sh   # installs elan
cd formal && lake build                                  # checks all proofs
```
