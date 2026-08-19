# Verification plan — making perch provably correct

Status: **living document.** This is the layered roadmap for turning perch's correctness story
from "tested + Flux-checked" into "machine-checked against a formal model, differentially
tested across every implementation, and independently provable on the shipped wasm."

Companion docs: [`THEORY.md`](./THEORY.md) (what class of policies perch can enforce, as a
theorem), [`CANONICAL.md`](../../CANONICAL.md) (the normative spec the proofs target).

## Goals

Four correctness targets, in priority order:

| # | Target | Statement to establish |
|---|--------|------------------------|
| (a) | **Evaluator soundness** | `perch-program`'s fail-closed evaluation implements the canonical semantics exactly |
| (b) | **Lowering preservation** | `perch-compile` emits programs that admit *exactly* the invocations the source document admits |
| (c) | **Per-policy properties** | For a given document: "this policy admits only intended invocations" (dead rules, subsumption, intent conformance) |
| (d) | **Artifact-level guarantees** | (a)–(c) hold of the shipped wasm32 binary, not just the Rust source (rustc out of the trusted base) |

Strategy: **layered, verification-guided development** (the AWS Cedar pattern): an executable
formal model + machine-checked proofs + differential random testing against every production
implementation, with each layer shipping value on its own. Trust is staged: source-level
assurance runs continuously in CI; wasm-artifact-level proof runs happen per release.

## The model is the spec

The core artifact of this plan is an executable **Lean 4 model** (`formal/`) of:

1. the **Verdict lattice** (Kleene 3-valued, `False < Unknown < True`),
2. the **RPN evaluator** (`rpn::eval` semantics, including every defensive guard),
3. the **program validator** (`rpn::validate` stack simulation),
4. the **leaf predicate semantics** over an abstract invocation
   (contract / function / typed args / signer count / self address / ledger sequence),
5. the **lowering** (`build_program`: `MinSigners` floor + `FnIn` + arg predicates + `All`).

The model is deliberately host-agnostic: soroban `Val` decoding is abstracted to a typed
`Value` domain where decode failure is an explicit `VOther`-style case, matching the leaf
fail-closed rule (any decode failure ⇒ `Unknown`, never `False`).

Theorems, in dependency order (P* = proved in `formal/`, listed in `formal/README.md` as they
land):

- **T1 Lattice laws** — `and`/`or` commutative, associative, De Morgan, double negation,
  `¬Unknown = Unknown`. (Foundation; also pins the fail-open trap closed: a decode failure
  under `Not` still denies.)
- **T2 Fail-closed root** — only `True` allows; `Unknown` never allows, and is preserved by
  every composite.
- **T3 Totality/termination** — `eval` is a total function (structural recursion over the op
  list; free in Lean).
- **T4 Validation soundness** — `validate ok ⇒` evaluation never trips a defensive guard: the
  verdict is a pure fold of leaf verdicts (formally: the guarded stack machine and the
  unguarded one agree). This is the theorem behind "a validated program can neither diverge
  nor brick an account" currently pinned only by `tests/fragment_v1.rs`.
- **T5 INV-1 (signer floor)** — for every lowered (interpreter-attached) rule, zero
  authenticated signers ⇒ the program's verdict is `False` (not merely non-`True`).
- **T6 Lowering preservation** — `eval (build_program rule) inv = docSemantics rule inv` for
  all rules expressible in v1 and all invocations. This is target (b) at the model level.
- **T7 Monotonicity of attenuation** *(stretch)* — tightening a bound (subset `FnIn`, subset
  `StrIn`, smaller `notAfter`) never admits a previously denied invocation; the model-level
  justification of `attenuation::is_narrowing`.

The Rust implementation is then tied to the model **empirically but continuously** via
differential testing (below); tying it **deductively** (Aeneas extraction to Lean, or Verus
`spec fn` proofs on the Rust itself) is a later layer, deliberately deferred until the model
has paid rent.

## Differential testing (DRT)

Shared **eval-semantics golden vectors** (`testdata/eval/`): JSON cases of
`(program, invocation) → verdict`, covering every op, every fail-closed path (missing arg,
wrong type, over-long string, non-contract context), every structural-Unknown path (underflow,
overflow, zero arity, non-single result), and boundary values. Replayed by:

1. **Rust native** — `crates/perch-conformance` (test-only crate; builds real soroban values
   in a test Env, runs the real `rpn::eval`),
2. **the Lean model** — `formal/` executable replays the same files,
3. **the wasm32 artifact** *(later)* — same vectors through the compiled interpreter under a
   wasm engine, putting the shipped artifact inside the parity boundary,
4. **perch-js** — already covered for canon/doc_hash by the existing frozen vectors; perch-js
   has no evaluator, so eval vectors don't apply to it.

Beyond frozen vectors, `perch-conformance` also generates deterministic random cases
(splitmix64, fixed seed — same discipline as `tests/fragment_v1.rs`; no rng dependency) for
compile→eval differential testing: random valid docs + invocations, assert
`eval(compile(doc)) == reference doc semantics`. The same generator can emit a case file for
the Lean side, making the three-way diff `Lean model == Rust == (later) wasm`.

## Phases

### Phase 0 — baseline hardening (this PR)
- [x] Verification plan (this doc) + enforceability theory writeup (`THEORY.md`)
- [ ] Eval-semantics golden vectors (`testdata/eval/`) + `perch-conformance` replay/generate
- [ ] Deterministic differential tests: compile→eval vs reference doc semantics
- [ ] fast-check property tests in perch-js (canonicalization determinism, hash uniqueness
      sampling, parse/canon round-trip)
- [ ] Fuzz targets (`fuzz/`): eval-never-panics on arbitrary programs/invocations;
      compile→eval differential (build-only smoke in CI; long runs nightly/dispatch)
- [ ] `cargo-mutants` + `cargo-llvm-cov` recipes (justfile) + scheduled CI jobs — measures
      whether the suite would catch a silent fail-open

### Phase 1 — the model + proofs (this PR, continued)
- [ ] Lean 4 model under `formal/` (no external deps beyond Lean core)
- [ ] Theorems T1–T5 proved; T6 at least stated, proved if tractable in the first pass
- [ ] Lean replay of the eval vectors wired into `just drt` + CI job
- [ ] Graduate Flux job out of `continue-on-error` once its streak is green (separate PR)

### Phase 2 — deepening source-level assurance (follow-up PRs)
- [ ] T6/T7 completed; model covers `attenuation`/`analysis` claims
- [ ] doc_hash injectivity: property-test now; Lean/F* proof of the CANON v1 fragment later
      (no verified RFC 8785 implementation exists anywhere as of 2026-08 — this would be a first)
- [ ] Choose one deductive tie between model and Rust: Verus (`eval == spec_fn`, ghost code
      erased from the shipped crate) or Aeneas extraction to Lean. Decision gate: model + DRT
      running for a few weeks first.
- [ ] Model-based lifecycle testing (`proptest-state-machine`): install → invoke → rotate →
      expire against a reference state machine

### Phase 3 — wasm-artifact level, per release (staged trust)
- [ ] Wasm leg of the vectors: compiled interpreter replays `testdata/eval/` under the soroban
      test host
- [ ] **Certora Sunbeam**: CVLR rules over the compiled interpreter wasm (fail-closed,
      MinSigners floor, arg-bound/notAfter enforcement over symbolic payloads). *Needs a
      Certora account/key — blocked on maintainer.*
- [ ] **Komet** (Runtime Verification, K semantics) as an independent second opinion. *Needs
      kup/K toolchain — heavyweight install, maintainer call.*
- [ ] Engine-TCB mitigation: differential fuzz of the protocol-pinned soroban-wasmi revision
      against WasmRef-Isabelle (the Wasmtime oracle setup)

### Phase 4 — per-policy prover (product feature)
- [ ] `perch-analyze`: symbolic compiler PolicyDoc → SMT-LIB (quantifier-free, decidable),
      answering: intent conformance ("can never call X with arg N ≠ …"), subsumption
      ("rotation only narrows" — re-founding `attenuation::is_narrowing`), dead rules
      (re-founding `analysis::can_ever_authorize` with counterexamples), doc ↔ on-chain
      encoding equivalence (translation validation per install, seeded from
      `activation::verify_plan_matches_doc`)
- [ ] Prove the SMT encoding sound + complete in Lean (the cedar-policy-symcc / SymCert pattern)

### WASI (survey only — no code committed)
The abstraction ports: contract → WIT interface, function → WIT function, arg predicates →
canonical-ABI-lifted values, notAfter → clock capability; the `__check_auth` analogue is a
WASI-Virt-style interposition component embedding the same no_std interpreter. Known gap:
no per-call caller identity in the component model (signer binding degrades to per-instance
provenance). The one refactor this future would force: make `perch-program`'s leaf decoders
generic over an invocation view instead of `soroban_sdk` types. Tracked as design context, not
scheduled work.

## Trusted base by stage

| Stage | Trusted |
|---|---|
| Phases 0–2 | rustc+LLVM, Lean kernel (proofs) / Lean→C compiler + DRT glue (empirical link), soroban-env host, soroban-wasmi, SHA-256 |
| Phase 3 | removes rustc for interpreter properties (provers consume the wasm); adds prover+SMT-solver+host-model axioms — two independent stacks (Certora, K), agreement is the evidence |
| Always | Soroban protocol semantics (CAP-0071 host behavior), hardware, and the spec meaning what we intend |

## Known spec-coverage notes

- The IR predicate vocabulary (`is-self`, `address-eq`, `string-in`, `string-prefix`,
  `u32-eq`) is narrower than the frozen v1 op set (which also has `ArgSymEq`, `ArgBytesEq`,
  `ArgI128Eq`, `ArgCount`, `LedgerBefore`, `LedgerAtOrAfter`, `Any`, `Not`). The model and the
  vectors cover the **full op set**; lowering preservation (T6) covers the IR subset that
  `build_program` actually emits. Any future IR predicate must land in the model + vectors in
  the same PR.
- Rule expiry (`not_after_ledger`) lowers to OZ `valid_until = X-1` *outside* the program;
  T6 is stated over the program semantics, and the expiry boundary is pinned by vectors +
  compile tests (the X-1 off-by-one is exactly the kind of bug the vectors must fix in amber).
- Cumulative caps (`cap`) lower to the stateful OZ `spending_limit` sibling; out of scope for
  the stateless model by design (see `THEORY.md` for why this boundary is a theorem, not a
  limitation we chose arbitrarily).

## Tooling landscape

The full survey (148 projects, top candidates fact-checked 2026-08-19) behind these choices
lives outside the repo (session report); the load-bearing picks: **Lean 4 + cedar-spec
pattern** (backbone), **Flux** (already wired; cheap bounds invariants), **Kani** (bounded CI
proofs — limited today by soroban types needing a host, revisit after any pure-core refactor),
**Certora Sunbeam / Komet** (wasm-level, phase 3), **cedar-policy-symcc** (phase 4 template),
**WasmRef-Isabelle** (engine oracle).
