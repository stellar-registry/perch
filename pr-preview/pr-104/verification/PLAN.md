# Verification plan: making perch provably correct

Status: living document. This is the layered roadmap for turning perch's correctness story
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

The strategy is layered, verification-guided development (the AWS Cedar pattern): an executable
formal model + machine-checked proofs + differential random testing against every production
implementation, with each layer useful on its own. Trust is staged: source-level
assurance runs continuously in CI; wasm-artifact-level proof runs happen per release.

## Coverage today

What an auditor can rely on, by kind of evidence. "Proved" means a sorry-free Lean theorem
about the Lean model, checked by the `formal` job in `.github/workflows/assurance.yml`
(weekly, on dispatch, and on PRs touching `formal/`, `fuzz/`, `komet/`, `crates/perch-ir/`,
or the canonical fixtures). A proof about the model says nothing about the Rust code on its
own; the second table is what ties the two together, and it is evidence, not proof.

**Machine-proved (Lean, `formal/`):**

| Property | Theorem |
|---|---|
| Verdict lattice laws; only `True` allows, `Unknown` never does | T1, T2 |
| Evaluator totality; a validated program never trips a defensive guard | T3, T4 `validate_sound` |
| INV-1: a lowered rule denies an invocation with zero signers | T5 `zero_signers_denied` |
| Lowering preserves the rule's doc-level meaning | T6 `lowering_preserves` |
| `doc_hash` names one document: the canonical form is injective over every `PolicyDoc` shape, the `recovery` member included, at any size (the compiler's caps only narrow the domain) | T7 `emitDoc_injective` |
| Canonical bytes parse back to the document they encode, so their identity preimage is themselves: a recovery target's `target_bytes_hash` and `target_doc_hash` agree under CANON v1 | `canonical_bytes_identity` (from `pDoc_rt`) |
| The fragment hashes name one fragment each: `config_hash` one recovery configuration and `rule_hash` one rule text. Both preimages are injective, no two of the three preimage kinds (document, config, rule) coincide, and each fragment is a substring of its document's canonical form | T8 `configPreimage_injective`, `rulePreimage_injective`, `configPreimage_ne_emitDoc`, `rulePreimage_ne_emitDoc`, `rulePreimage_ne_configPreimage`, `emitRecovery_infix_emitDoc`, `emitRule_infix_emitDoc` |

All hash claims hold up to a SHA-256 collision.

**Differential and empirical (model ↔ shipped code):**

| Link | Evidence |
|---|---|
| Lean evaluator ↔ Rust `rpn::eval` | `testdata/eval/` vectors replayed by `perch-conformance` (every PR), the Lean model (`drt`), and the compiled wasm (`conformance-wasm`); the `eval_fail_closed` fuzz target |
| Lean canonicalizer ↔ Rust `canon.rs` | `drt` parses and re-emits every `testdata/*.canonical.json` document (five, covering both signer kinds, `all`/`threshold` principals, a cap, `guardian-only` and `combined` recovery) and the three `testdata/recovery/config-*.canonical.json` recovery members, which `crates/perch-ir/tests/recovery.rs` regenerates from Rust |
| Rust parse ↔ emit, recovery included | fuzz targets (`fuzz/fuzz_targets/`): `ir_parse_roundtrip` (arbitrary bytes, seeded with the fixtures) and `recovery_canonical_roundtrip` (arbitrary `RecoveryConfig`s: round-trip, determinism, member slice, one-field-change injectivity) |
| T8's preimage ↔ the compiler's `config_hash` | `crates/integration-tests/tests/config_hash.rs` (native compiler, every PR) and `release_stack.rs` (a release stack's compiler wasm: in CI the stack built from the PR's source, and the deployed testnet stack when its commit is in the branch's history): for each recovery-member fixture, `config_hash` equals `sha256("perch/recovery/config" \|\| fixture bytes)` recomputed with `sha2`; changing any one configuration field moves it to the recomputed hash of the changed text, and rotating a signer does not move it |
| T8's rule preimage ↔ the deployed code's `rule_hash` | `testdata/rule-hashes.json`, cut out of the canonical fixtures by an independent script (`scripts/rule-hash-vectors.py`), against `perch_recovery_interface::fragment::rule_hash` (`crates/perch-recovery-interface/tests/vectors.rs`) and the provenance `perch-compile` stamps into every program (`crates/integration-tests/tests/fragment_hashes.rs`) |
| Rust ↔ TypeScript canonical form | `packages/perch-js/test/parity.test.ts` on the document fixtures; `test/fragment.test.ts` pins `ruleHash` and `configHash` to the same values as Rust |
| `rpn::eval` wasm under K semantics | Komet, three properties, 50 fuzz examples each in CI; symbolic `komet prove` only locally (`komet/README.md`) |

**Not modeled, tested only.** None of the following has a formal model or a proof. They are
covered by enforcing-authorization integration tests (`crates/integration-tests/tests/`),
real-proof tests, and the testnet exercise:

- The recovery controller's state machine (`crates/perch-recovery`, spec §6): attempt
  lifecycle, the `Protected` freeze across authorization paths, cancellation rules and the
  cancel cap, evidence freshness and expiry, epochs, nullifier spending, baselines,
  upgrade approvals, and the two-digest target binding (spec §6.3 T1, T5; tested in
  `target_binding.rs`). The model supplies only the CANON facts that binding relies on
  (`canonical_bytes_identity`, T7).
- Account authorization paths (`crates/perch-smart-account`): `__check_auth`, OZ
  context-rule selection, `execute`, `apply_doc` and its delta (which rules it touches),
  the reserved-name guards, upgrades.
- The ZK circuit (`circuits/`), the vendored UltraHonk verifier, the adapter
  (`crates/perch-zk-adapter`), and the membership pool (`crates/perch-zk-pool`).
- The document compiler beyond the canonical bytes and `config_hash`: validation,
  `derive_target` (spec §7), and the rest of the compiled recovery configuration.
- The release pipeline and deployment verification (`docs/deploy/README.md`).
- The trusted base: the pinned OpenZeppelin `stellar-accounts` fork, the Soroban host,
  rustc/LLVM, and SHA-256.

## The model is the spec

The core artifact of this plan is an executable Lean 4 model (`formal/`) of:

1. the **Verdict lattice** (Kleene 3-valued, `False < Unknown < True`),
2. the **RPN evaluator** (`rpn::eval` semantics, including every defensive guard),
3. the **program validator** (`rpn::validate` stack simulation),
4. the **leaf predicate semantics** over an abstract invocation
   (contract / function / typed args / signer count / self address / ledger sequence),
5. the **lowering** (`build_program`: `MinSigners` floor + `FnIn` + arg predicates + `All`),
6. the **canonical form** (CANON v1) of a document and of its `recovery` member on its own,
   each with a verified inverse parser.

The model is deliberately host-agnostic: soroban `Val` decoding is abstracted to a typed
`Value` domain where decode failure is an explicit `VOther`-style case, matching the leaf
fail-closed rule (any decode failure ⇒ `Unknown`, never `False`).

Theorems, in dependency order (P* = proved in `formal/`, listed in `formal/README.md` as they
land):

- **T1 Lattice laws**: `and`/`or` commutative, associative, De Morgan, double negation,
  `¬Unknown = Unknown`. (Foundation; also pins the fail-open trap closed: a decode failure
  under `Not` still denies.)
- **T2 Fail-closed root**: only `True` allows; `Unknown` never allows, can never raise a
  conjunction to `True`, and is preserved under negation (in a disjunction a definite `True`
  branch wins, which is Kleene `or`, not a leak).
- **T3 Totality/termination**: `eval` is a total function (structural recursion over the op
  list; free in Lean).
- **T4 Validation soundness**: `validate ok ⇒` evaluation never trips a defensive guard. The
  verdict is a pure fold of leaf verdicts (formally: the guarded stack machine and the
  unguarded one agree). This is the theorem behind "a validated program can neither diverge
  nor brick an account" currently pinned only by `tests/fragment_v1.rs`.
- **T5 INV-1 (signer floor)**: for every lowered (interpreter-attached) rule, zero
  authenticated signers ⇒ the program's verdict is `False` (not merely non-`True`).
- **T6 Lowering preservation**: `eval (build_program rule) inv = docSemantics rule inv` for
  all rules expressible in v1 and all invocations, where `docSemantics` is stated over the
  doc-level predicates directly (no ops, no machine) and a per-predicate lemma proves the op
  translation meaning-preserving. Scope, precisely: this covers the encoding, the machine, and
  the `lowerPred` translation *within the model*; that the model's predicate meanings match the
  Rust leaf implementations is the empirical link carried by the shared vectors and the Rust
  differential suite (whose reference never looks at `Op` or the compiler). Together they are
  target (b); T6 alone is its machine-checked half.
- **T7 Canonical-form injectivity**: `emitDoc_injective`, over every `PolicyDoc` shape
  including the `recovery` member (proved; see `formal/README.md`).
- **T8 Fragment-hash identity**: the `config_hash` and `rule_hash` preimages are injective,
  separated from each other and from document bytes, and cut out of the document unchanged
  (proved).
- **T9 Monotonicity of attenuation** *(stretch, not proved)*: tightening a bound (subset
  `FnIn`, subset `StrIn`, smaller `notAfter`) never admits a previously denied invocation;
  the model-level justification of `attenuation::is_narrowing`.

The Rust implementation is then tied to the model empirically but continuously via
differential testing (below); tying it deductively (Aeneas extraction to Lean, or Verus
`spec fn` proofs on the Rust itself) is a later layer, deliberately deferred until the model
has proven useful.

## Differential testing (DRT)

Shared eval-semantics golden vectors (`testdata/eval/`): JSON cases of
`(program, invocation) → verdict`, covering every op, every fail-closed path (missing arg,
wrong type, over-long string, non-contract context), every structural-Unknown path (underflow,
overflow, zero arity, non-single result), and boundary values. Replayed by:

1. **Rust native**: `crates/perch-conformance` (test-only crate; builds real soroban values
   in a test Env, runs the real `rpn::eval`),
2. **the Lean model**: the `formal/` executable replays the same files,
3. **the wasm32 artifact** *(later)*: same vectors through the compiled interpreter under a
   wasm engine, putting the shipped artifact inside the parity boundary,
4. **perch-js**: already covered for canon/doc_hash by the existing frozen vectors; perch-js
   has no evaluator, so eval vectors don't apply to it.

Beyond frozen vectors, `perch-conformance` also generates deterministic random cases
(splitmix64, fixed seed, same discipline as `tests/fragment_v1.rs`; no rng dependency) for
compile→eval differential testing: random valid docs + invocations, assert
`eval(compile(doc)) == reference doc semantics`. The same generator can emit a case file for
the Lean side, making the three-way diff `Lean model == Rust == (later) wasm`.

## Phases

### Phase 0: baseline hardening (this PR)
- [x] Verification plan (this doc) + enforceability theory writeup (`THEORY.md`)
- [x] Eval-semantics golden vectors (`testdata/eval/`, 72 hand-authored cases) +
      `perch-conformance` replay
- [x] Deterministic differential tests: compile→eval vs reference doc semantics
      (400 random docs × 16 invocations; also INV-1/INV-2/expiry-boundary/doc_hash-two-paths)
- [x] fast-check property tests in perch-js (key-order independence, canonical round-trip,
      hash-injectivity sampling, builder ≡ wire form)
- [x] Fuzz targets (`fuzz/`): `eval_fail_closed` (totality + determinism on arbitrary
      programs/invocations), `ir_parse_roundtrip` (parser never panics; canonicalization
      idempotent; recovery text preserved), `recovery_canonical_roundtrip` (arbitrary
      recovery configurations round-trip, deterministically, and differ when a field
      does), with weekly/dispatch runs in `assurance.yml` and a short pass on PRs that
      touch them
- [x] `cargo-mutants` + `cargo-llvm-cov` recipes (justfile) + scheduled CI jobs
      (`assurance.yml`; mutants in burn-in)

### Phase 1: the model + proofs (this PR, continued)
- [x] Lean 4 model under `formal/` (no external deps beyond Lean core)
- [x] Theorems T1–T6 proved, sorry-free, including lowering preservation (T6)
- [x] Lean replay of the eval vectors wired as `just drt` + the `formal` CI job
- [x] Graduate Flux job out of `continue-on-error`, so flux failures now fail CI

### Phase 2: deepening source-level assurance (follow-up PRs)
- [ ] T9 completed; model covers `attenuation`/`analysis` claims
- [x] doc_hash injectivity: proved (`formal/PerchFormal/CanonProofs.lean`,
      `emitDoc_injective`). A verified inverse parser round-trips the canonical emitter, so
      two distinct documents can never share canonical bytes; the model emitter is pinned to
      the Rust emitter by round-tripping the frozen `*.canonical.json` fixtures in CI. To our
      knowledge the first machine-verified RFC 8785-subset implementation.
- [x] Recovery canonicalization (#88): the model covers `threshold` principals and the
      `recovery` member, so `emitDoc_injective` covers recovery documents, and
      `configPreimage_injective` proves `config_hash` names one recovery configuration.
      `rulePreimage_injective` does the same for #102's per-rule `rule_hash`, with the
      separation lemmas between document, config, and rule preimages.
      `drt` replays the recovery fixtures, including one recovery member per mode.
- [ ] Choose one deductive tie between model and Rust: Verus (`eval == spec_fn`, ghost code
      erased from the shipped crate) or Aeneas extraction to Lean. Decision gate: model + DRT
      running for a few weeks first.
- [ ] Model-based lifecycle testing (`proptest-state-machine`): install → invoke → rotate →
      expire against a reference state machine

### Phase 3: wasm-artifact level, per release (staged trust)
- [x] Wasm leg of the vectors: the compiled wasm32 artifact (`perch-bench-rpn`, wrapping the
      same `perch_program` entry points as the interpreter) replays `testdata/eval/` under the
      soroban test host via `just conformance-wasm`, gated in CI
- [ ] **Certora Sunbeam**: CVLR rules over the compiled interpreter wasm (fail-closed,
      MinSigners floor, arg-bound/notAfter enforcement over symbolic payloads). *Needs a
      Certora account/key, blocked on maintainer.*
- [x] **Komet** (Runtime Verification, K semantics) as an independent second opinion:
      `komet/` (three properties: INV-1 signer floor, `All` conjunction folding, fail-closed
      missing-arg deny) executed under RV's mechanized Soroban + KWasm semantics. The `komet`
      job in `assurance.yml` (Nix + the public `k-framework` Cachix cache, pinned to Komet
      v0.1.88; cargo-built wasm with the DataCount section stripped for pykwasm) runs
      `komet test`. Verified green in CI: all three pass 50/50 fuzz examples. The
      stronger `komet prove run` (symbolic, all `u32`) exceeds CI's time budget and is a
      documented local command. See `komet/README.md`.
- [ ] Engine-TCB mitigation: differential fuzz of the protocol-pinned soroban-wasmi revision
      against WasmRef-Isabelle (the Wasmtime oracle setup)

### Phase 4: per-policy prover (product feature)
- [x] `perch-analyze`: PolicyDoc → SMT-LIB (quantifier-free), discharged by z3, with
      `dead-rules` (unsat = proof of deadness, sharper than `analysis::can_ever_authorize`:
      it sees argument predicates), `only-calls` (intent conformance with witnesses: CI
      proves the shipped ci-publish fixture can only ever authorize publish/publish_hash),
      `can-call`, and `narrows` (semantic attenuation: catches arg-level widening invisible
      to `attenuation::is_narrowing`, plus expiry/cap loosening structurally)
- [ ] doc ↔ on-chain encoding equivalence (translation validation per install, seeded from
      `activation::verify_plan_matches_doc`)
- [ ] Prove the SMT encoding sound + complete in Lean (the cedar-policy-symcc / SymCert pattern)

### WASI (survey only, no code committed)
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
| Phase 3 | removes rustc for interpreter properties (provers consume the wasm); adds prover+SMT-solver+host-model axioms; two independent stacks (Certora, K), agreement is the evidence |
| Always | Soroban protocol semantics (CAP-0071 host behavior), hardware, and the spec meaning what we intend |

## Known spec-coverage notes

- The IR predicate vocabulary (`is-self`, `address-eq`, `string-in`, `string-prefix`,
  `u32-eq`) is narrower than the frozen v1 op set (which also has `ArgSymEq`, `ArgBytesEq`,
  `ArgI128Eq`, `ArgCount`, `LedgerBefore`, `LedgerAtOrAfter`, `Any`, `Not`). The model and the
  vectors cover the full op set; lowering preservation (T6) covers the IR subset that
  `build_program` actually emits. Any future IR predicate must land in the model + vectors in
  the same PR.
- Rule expiry (`not_after_ledger`) lowers to OZ `valid_until = X-1` *outside* the program;
  T6 is stated over the program semantics, and the expiry boundary is pinned by vectors +
  compile tests (the X-1 off-by-one is exactly the kind of bug the vectors must pin).
- Cumulative caps (`cap`) lower to the stateful OZ `spending_limit` sibling; out of scope for
  the stateless model by design (see `THEORY.md` for why this boundary is a theorem, not a
  limitation we chose arbitrarily).

## Tooling choices

The full survey (148 projects, top candidates fact-checked 2026-08-19) behind these choices
lives outside the repo (session report); the load-bearing picks: Lean 4 + cedar-spec
pattern (the core), Flux (already wired; cheap bounds invariants), Kani (bounded CI
proofs; limited today by soroban types needing a host, revisit after any pure-core refactor),
Certora Sunbeam / Komet (wasm-level, phase 3), cedar-policy-symcc (phase 4 template),
WasmRef-Isabelle (engine oracle).
