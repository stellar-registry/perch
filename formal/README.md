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
| `PerchFormal/Theorems.lean` | the proofs (below) |
| `Main.lean` | `lake exe drt` — replays `testdata/eval/eval-vectors.json` through the model |

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
- **T5** `zero_signers_denied`: every lowered rule evaluates to a definite `F`
  on any invocation with zero authenticated signers — INV-1 at the model level.
- **T6** `lowering_preserves`: the machine over `build_program`'s postfix
  output computes exactly the rule's doc-level Kleene conjunction.

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
