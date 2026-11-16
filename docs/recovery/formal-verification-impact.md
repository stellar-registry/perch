# Formal verification of the recovery schema

What the Lean model (`formal/`) establishes about recovery documents and
`config_hash` ([`spec.md`](spec.md) §3.2), what ties it to the shipped
code, and what has no formal model. The repository-wide coverage table is
`docs/verification/PLAN.md` ("Coverage today"); this file states the part
of it that concerns recovery.

## Boundary

**Proved:** facts about canonical encodings. The CANON v1 canonical form of
a document, the `recovery` member included, is injective, and the
`config_hash` preimage names one recovery configuration. Every hash claim
holds up to a SHA-256 collision.

**Not modeled, not proved:** the recovery runtime and the components it
relies on. (The interpreter's per-invocation evaluation is modeled, T1–T6,
but recovery never runs through it; see the last section.)

- The recovery controller's state machine (`crates/perch-recovery`, spec
  §6): attempts, evidence, the `Protected` freeze, cancellation and the
  cancel cap, epochs, nullifier spending, baselines, upgrade approvals, and
  the two-digest target binding.
- Account authorization (`crates/perch-smart-account`): `__check_auth`, OZ
  context-rule selection, `execute`, `apply_doc` and its delta, the
  reserved-name guard, upgrades, and the configuration revision.
- The ZK circuit (`circuits/`), the vendored UltraHonk verifier and its ZK
  delta, the adapter (`crates/perch-zk-adapter`), and the membership pool
  (`crates/perch-zk-pool`).
- The document compiler beyond the canonical bytes: validation
  (`validate.rs`), `derive_target` (spec §7), and the compiled
  configuration.

These are covered by tests, not proofs ([Contract tests](#contract-tests)).
Broader formal models are not part of this revision
([`DEFERRED.md`](../DEFERRED.md#additional-formal-models)).

## What is proved

`formal/PerchFormal/Canon.lean` models the canonical `recovery` member
exactly as `crates/perch-ir/src/canon.rs` emits it: both profiles; the
`guardian-only`, `zk-only`, and `combined` modes with the guardian fields
(`guardians`, `quorum`) and every `ZkFactor` field (`adapter`,
`circuit-id`, `pool`, `enrollment-id`, `commitment`); the controller; the
optional baseline `doc-hash`; the replaceable signer ids; and the three
ledger counts. It also models every other document shape the canonical
form covers, `threshold` principals included.

Proved in `formal/PerchFormal/CanonProofs.lean`, with no `sorry`
(`CheckAxioms.lean` fails unless every declaration depends only on
`propext`, `Classical.choice`, and `Quot.sound`):

- **T7** `emitDoc_injective`: two documents with the same canonical bytes are
  the same document, with or without a `recovery` member. So `doc_hash`
  names one document. `canonical_bytes_identity`: parsing a document's
  canonical bytes returns that document, so its identity preimage is those
  bytes.
- **T8** `emitRecovery_injective` and `configPreimage_injective`: two
  recovery configurations with the same `recovery_canonical_json`, or the
  same `"perch/recovery/config" || recovery_canonical_json` preimage, are
  the same configuration. So `config_hash` (spec §3.2) names one
  configuration. `configPreimage_ne_emitDoc`: no `config_hash` preimage is a
  document's canonical form. `emitRecovery_infix_emitDoc`: the recovery
  member is a substring of its document's canonical form, so `config_hash`
  ignores everything outside it (a key rotation is not a reconfiguration).

These are statements about the Lean model's emitter. They say nothing
about the Rust code on their own; the next section is what ties the two
together.

## Empirical Rust/Lean parity (evidence, not proof)

- **Lean emitter ↔ `canon.rs`.** `lake exe drt` (CI's `formal` job in
  `.github/workflows/assurance.yml`) parses and re-emits byte-identically
  every `testdata/*.canonical.json` document, the two recovery documents
  (`ci-publish-recovery{,-combined}.canonical.json`) included, and one
  Rust-emitted recovery member per mode
  (`testdata/recovery/config-*.canonical.json`, regenerated and checked by
  `crates/perch-ir/tests/recovery.rs`).
- **Rust parse ↔ emit.** The fuzz targets `ir_parse_roundtrip` and
  `recovery_canonical_roundtrip` check, on the Rust side, that every
  recovery configuration round-trips through the parser, that
  `recovery_canonical_json` is deterministic and is exactly the document's
  member, and that changing one field changes the text.
- **T8's preimage ↔ the compiler's `config_hash`.**
  `crates/integration-tests/tests/config_hash.rs` compiles a document
  around each recovery-member fixture and requires
  `config_hash = sha256("perch/recovery/config" || fixture bytes)`,
  recomputed with `sha2`. It then changes each configuration field in turn
  (profile, mode, every guardian and ZK field, controller, baseline,
  replaceable ids, the three ledger counts) and requires the hash to move
  to the recomputed hash of the changed text, and it requires a signer
  rotation to leave the hash alone. `release_stack.rs`
  (`the_stack_compiler_hashes_the_canonical_recovery_text`) runs the same
  check against a release stack's compiler wasm: in CI, the one built from
  the change's source, and the deployed testnet one when its commit is in
  the branch's history.

What this evidence does not establish:

- That the Lean emitter and `canon.rs` agree on every input. That link is
  the fixtures and the fuzzing, not a proof.
- That the compiler hashes exactly this preimage on every input. The tests
  cover the fixtures and their single-field changes.
- What the fields mean: validation, `derive_target`, and the compiled
  configuration. The proofs are about bytes.

## Contract tests

The runtime components in the [boundary](#boundary) are covered by
enforcing-authorization integration tests (`crates/integration-tests/tests/`),
real-proof tests on the release wasm (`release_stack.rs`), the adapter's and
pool's own tests, and the testnet exercise. Where each spec requirement is
tested: [`implementation.md`](implementation.md); the ZK backend:
[`docs/zk/README.md`](../zk/README.md#what-is-tested-and-how). Tests show
the cases they run, not every input.

## Cryptographic assumptions and audit

Nothing above proves a cryptographic property. The guarantees rest on:

- **SHA-256** collision resistance, for every hash claim above (`doc_hash`,
  `config_hash`, `rule_hash`) and for the recovery statement digest.
- **Poseidon2** (BN254, the parameters of noir-lang/poseidon v0.2.0)
  collision resistance, for the circuit's leaf, nullifier, and statement
  hash (spec §13.3).
- **UltraHonk** soundness and zero knowledge, for the ZK factor: a proof
  that verifies shows membership and knowledge of the enrolled secret, and
  reveals neither.

The verifier is NethermindEth's UltraHonk verifier, whose non-ZK flavor has
had an internal review and an OpenZeppelin audit. Perch's
`UltraKeccakZKFlavor` delta (`vendor/ultrahonk-soroban-verifier/src/zk.rs`)
is not audited; its audit is an open release criterion
([`docs/zk/README.md`](../zk/README.md#open-release-criteria)). No formal
model and no completed audit of the circuit, adapter, or pool is recorded
at this revision; all three are in the audit scope
([`docs/audit-scope.md`](../audit-scope.md)).

## Unaffected: perch-program evaluation (T1–T6)

`perch-conformance`'s vectors (`testdata/eval/eval-vectors.json`) and the
Lean `Semantics.lean`, `Lowering.lean`, and `Theorems.lean` (T1–T6) model
perch-program evaluation: the RPN machine the interpreter runs for each
invocation. A recovery configuration never lowers to a perch-program op. The
doc compiler maps `perch_ir::RecoveryConfig` directly to
`CompiledRecoveryConfig`, and `crates/perch-compile`, which lowers rules to
interpreter programs, has no recovery input. So T1–T6 and the eval vectors
cover no recovery behaviour, and recovery leaves them unchanged.

This is by design. Recovery state stays outside the stateless interpreter:
`docs/verification/THEORY.md` shows that no execution monitor can enforce
"the account can always recover" (a liveness property), and that Perch
addresses the adjacent risk structurally, by keeping INV-2's policy-free
admin path independent of the interpreter. The recovery controller is
ordinary stateful contract logic outside that enforceable fragment, so it
was never a candidate for the per-invocation safety model.
