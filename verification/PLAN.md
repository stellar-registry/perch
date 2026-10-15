# Verification coverage

What is machine-proved about Perch, what is tied to the shipped code by
differential testing, and what is covered by tests only, at this revision.
The theorem statements and how to check them are in
[`formal/README.md`](../../formal/README.md); the class of policies a
stateless monitor can enforce is in [`THEORY.md`](./THEORY.md); the bytes
the canonical-form proofs are about are defined in
[`CANONICAL.md`](../../CANONICAL.md).

## Targets

| # | Target | Statement | Status |
|---|--------|-----------|--------|
| (a) | **Evaluator soundness** | `perch-program`'s fail-closed evaluation implements the canonical semantics exactly | Proved of the Lean model (T1–T4); tied to the Rust evaluator and a Wasm build of it by shared vectors |
| (b) | **Lowering preservation** | `perch-compile` emits programs that admit exactly the invocations the source rule admits | Proved of the model's lowering (T6); tied to Rust by the vectors and the compile→eval differential suite |
| (c) | **Per-policy properties** | A given document admits only intended invocations (dead rules, intent conformance, attenuation) | `perch-analyze` (SMT, z3), per document |
| (d) | **Artifact-level guarantees** | (a)–(c) hold of the shipped Wasm, not only the Rust source | Partial: the vectors replay through a Wasm contract wrapping the same evaluator entry points (`perch-bench-rpn`), and Komet checks three properties of the evaluator compiled to Wasm; neither is the deployed interpreter binary |

## Coverage today

### Machine-proved (Lean, `formal/`)

"Proved" means a Lean theorem about the Lean model that depends on no axiom
beyond `propext`, `Classical.choice`, and `Quot.sound` (so no `sorry`),
checked by `lake build`, a source grep, and the `CheckAxioms.lean` audit in
the `formal` job of `.github/workflows/assurance.yml`. That job runs weekly,
on dispatch, and on pull requests touching `formal/`, `fuzz/`, `komet/`,
`crates/perch-ir/`, the canonical fixtures, or the workflow. A proof about
the model says nothing about the Rust code on its own; the next table is
what ties the two, and it is evidence, not proof.

| Property | Theorem |
|---|---|
| Verdict lattice laws; only `True` allows, `Unknown` never does | T1, T2 |
| Evaluator totality; a validated program never trips a defensive guard | T3, T4 `validate_sound` |
| INV-1: a lowered rule denies an invocation with zero signers | T5 `zero_signers_denied` |
| Lowering preserves the rule's document-level meaning | T6 `lowering_preserves` |
| `doc_hash` names one document: the canonical form is injective over every `PolicyDoc` shape, the `recovery` member included, at any size | T7 `emitDoc_injective` |
| Canonical bytes parse back to the document they encode, so a recovery target's `target_bytes_hash` and `target_doc_hash` agree under CANON v1 | `canonical_bytes_identity` |
| `config_hash` names one recovery configuration and `rule_hash` one rule text; the document, configuration, and rule preimages never coincide; each fragment is a substring of its document's canonical form | T8 (`formal/README.md` lists the lemmas) |

Every hash claim holds up to a SHA-256 collision.

### Differential and empirical (model and shipped code)

| Link | Evidence | Runs |
|---|---|---|
| Lean evaluator ↔ Rust `rpn::eval` | the 72 hand-authored `testdata/eval/` vectors, replayed by `perch-conformance`, the Lean model (`just drt`), and the evaluator compiled to Wasm (`perch-bench-rpn`, `just conformance-wasm`); the compile→eval differential suite (400 random documents × 16 invocations, fixed seed); the `eval_fail_closed` fuzz target | every pull request (Rust and Wasm legs); `formal` job (Lean leg) |
| Lean canonicalizer ↔ Rust `canon.rs` | `drt` parses and re-emits every `testdata/*.canonical.json` document and the three `testdata/recovery/config-*.canonical.json` members; the `ir_parse_roundtrip` and `recovery_canonical_roundtrip` fuzz targets | `formal` and `fuzz` jobs |
| T8 ↔ the code that computes `config_hash` and `rule_hash` | `config_hash.rs`, `release_stack.rs`, `testdata/rule-hashes.json` with `vectors.rs` and `fragment_hashes.rs` ([`formal/README.md`](../../formal/README.md#what-ties-the-model-to-the-shipped-code)) | every pull request |
| Rust ↔ TypeScript canonical form and hashes | `packages/perch-js/test/parity.test.ts`; `test/fragment.test.ts` pins `ruleHash` and `configHash` to the Rust values | every pull request |
| `rpn::eval` Wasm under K semantics | Komet, three properties, 50 fuzz examples each; symbolic `komet prove run` locally only ([`komet/README.md`](../../komet/README.md)) | weekly, on dispatch |

### Other automated checks

| Check | Scope | Runs |
|---|---|---|
| Fuzzing (`fuzz/fuzz_targets/`) | `eval_fail_closed`, `ir_parse_roundtrip`, `recovery_canonical_roundtrip`, `apply_doc_delta` (the delta apply against the full-replace oracle) | weekly and on dispatch for 300 s per target; 60 s per target on pull requests touching the assurance paths |
| Flux refinement types | `perch-program` (`-Fcheck-overflow=strict`); functions Flux cannot check are marked `TRUST:` in the source | every pull request (`flux` job) |
| `perch-analyze` | SMT proofs about specific documents, e.g. the shipped `ci-publish` fixture can only authorize `publish`/`publish_hash` | every pull request (z3) |
| Mutation testing, branch coverage | `perch-program`, `perch-compile`, `perch-ir` (every mutant faces the whole workspace's tests) | weekly, on dispatch; findings are not merge gates |

### Not modeled, tested only

None of the following has a formal model or a proof. Enforcing-authorization
integration tests (`crates/integration-tests/tests/`), real-proof tests,
the release-stack suite, and the testnet exercise cover them.

- **The recovery controller's state machine** (`crates/perch-recovery`,
  [spec](../recovery/spec.md) §6): attempt lifecycle, the `Protected` freeze
  across authorization paths, cancellation and the cancel cap, evidence
  freshness and expiry, epochs, nullifier spending, baselines, upgrade
  approvals, and the two-digest target binding. The controller's two checks
  are not modeled: `enforce` comparing `sha256` of the completing
  `apply_doc` bytes with `target_bytes_hash`, and `rcv_sync` comparing the
  compiled identity with `target_doc_hash` (`target_binding.rs` tests both).
  The only formal fact behind `target_bytes_hash == target_doc_hash` under
  CANON v1 is `canonical_bytes_identity`; T7 adds that the identity names
  one document.
- **Account authorization** (`crates/perch-smart-account`): `__check_auth`,
  OZ context-rule selection, `execute`, `apply_doc` and its delta (which
  rules it touches), the reserved-name guards, upgrades, and the
  configuration revision with `apply_doc`'s `expected_revision`
  (`revision.rs`). T8 shows equal `rule_hash` preimages mean equal rule
  text; that `apply_doc` then touches exactly the changed rules is tested
  (`apply_delta.rs`, the `apply_doc_delta` fuzz target), not proved. The
  revision is account state outside the document, so no proved hash covers
  it: after A → B → A the same `doc_hash` returns at a later revision.
- **The ZK circuit, verifier, adapter, and pool** (`circuits/`,
  `vendor/ultrahonk-soroban-verifier`, `crates/perch-zk-adapter`,
  `crates/perch-zk-pool`): real-proof tests and cross-implementation
  Poseidon2 vectors ([`docs/zk/README.md`](../zk/README.md)).
- **The document compiler beyond canonical bytes and `config_hash`**:
  validation, `derive_target` (spec §7), and the rest of the compiled
  recovery configuration.
- **The recovery statement encoding**
  ([`statement.md`](../recovery/statement.md)). CANONICAL.md's claim that
  the fragment tags are separated from the statement tags is therefore not
  proved.
- **The release pipeline and deployment verification**
  ([`docs/deploy/README.md`](../deploy/README.md)).

## Trusted base

| Evidence | Trusted |
|---|---|
| Lean proofs | the Lean kernel, and that the model states what the spec means |
| Model ↔ code link | the Lean compiler and the replay glue (`Main.lean`), and the shared vectors' coverage |
| Every runtime claim | the Soroban host and its Wasm engine, rustc and LLVM, SHA-256, the pinned OpenZeppelin `stellar-accounts` fork, the CAP-0071 host behaviour in [`cap-0071.md`](../recovery/cap-0071.md), and the hardware |
| Komet's three properties | the K semantics of Soroban and Wasm (an independent stack); rustc is outside its trusted base, because Komet runs the compiled Wasm |

## Spec-coverage notes

- The IR predicate vocabulary (`is-self`, `address-eq`, `string-in`,
  `string-prefix`, `u32-eq`) is narrower than the frozen v1 op set (which
  also has `ArgSymEq`, `ArgBytesEq`, `ArgI128Eq`, `ArgCount`,
  `LedgerBefore`, `LedgerAtOrAfter`, `Any`, `Not`). The model and the vectors
  cover the full op set; T6 covers the IR subset that `build_program` emits.
  A new IR predicate must land in the model and the vectors together.
- Rule expiry (`not-after-ledger`) lowers to OZ `valid_until = X - 1`
  outside the program. T6 is stated over the program semantics, and the
  expiry boundary is pinned by vectors and compile tests.
- Cumulative caps (`cap`) lower to the stateful OZ `spending_limit` beside
  the interpreter. They are outside the stateless model by construction
  ([`THEORY.md`](./THEORY.md) explains why this boundary is a theorem).

## Not established

These are not done; none is relied on by a current claim. Further formal
models are deferred ([`DEFERRED.md`](../DEFERRED.md#additional-formal-models)).

- T9, monotonicity of attenuation: tightening a bound (a subset `FnIn` or
  `StrIn`, an earlier `notAfter`) never admits a previously denied
  invocation. `attenuation::is_narrowing` and `perch-analyze narrows` check
  it per pair of documents; the model does not prove it.
- A deductive tie between the model and the Rust code (Verus `spec fn`
  proofs or Aeneas extraction); the tie today is differential.
- Certora Sunbeam rules over the compiled interpreter Wasm (needs a Certora
  account), and a differential fuzz of the Soroban Wasm engine against a
  reference interpreter.
- Model-based lifecycle testing (install, invoke, rotate, expire against a
  reference state machine).
- Translation validation of each install against its document, beyond
  `activation::verify_plan_matches_doc`, and a Lean proof that
  `perch-analyze`'s SMT encoding is sound and complete.
