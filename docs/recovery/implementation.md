# Recovery implementation map

Where [`spec.md`](spec.md) is implemented, which tests pin it, and how the
implementation behaves where the spec leaves the mechanism open. Covers the
recovery controller (`crates/perch-recovery`) and the account capabilities
it relies on (`crates/perch-smart-account`).

## Where each part lives

| Spec | Code | Tests |
| --- | --- | --- |
| §3.1 schema, §3.2 `config_hash` | `perch-ir` (`doc.rs`, `parse.rs`, `canon.rs::recovery_canonical_json`, `validate.rs`); `perch-doc-compiler::to_compiled_recovery` | `crates/perch-ir/tests/recovery.rs`; `crates/integration-tests/tests/config_hash.rs`; Lean T7/T8 and `drt` ([`formal-verification-impact.md`](formal-verification-impact.md)); `fuzz/fuzz_targets/recovery_canonical_roundtrip.rs` |
| §3.2 per-rule hash | `perch_ir::{rule_canonical_json, rule_hash}`; `perch_compile::rule_hash_onchain`; `perch_recovery_interface::fragment::rule_hash`; perch-js `ruleHash`, `configHash` | `crates/perch-ir/tests/rule_hash.rs`, `fragment_hashes.rs`, `packages/perch-js/test/fragment.test.ts` |
| §3.3 epoch, §5 evidence, §6 state machine, §10 `rcv_sync`, §11 nullifiers, §12 `rcv_upgrade` | `crates/perch-recovery/src/contract.rs` | `crates/integration-tests/tests/recovery.rs` |
| §3.4 enrollment ids, §8 revocation, §9 freeze, §12 upgrades, §15 reserved names, `execute`, `applied_doc` | `crates/perch-smart-account/src/lib.rs` | `recovery.rs`, `account_capabilities.rs` |
| §7 permitted changes | `perch_ir::recovery::derive_target`; `PerchDocCompiler::derive_target` | `crates/perch-ir/tests/recovery.rs`, `recovery.rs` |
| §7.5 delta apply | `crates/perch-smart-account/src/rules.rs` (`desired`, `reconcile`) | [below](#delta-apply-tests) |
| §7.5 document caps | `perch_doc_compiler::{MAX_DOC_SIGNERS, MAX_DOC_RULES, MAX_DOC_CANONICAL_BYTES, MAX_RULE_NAME_BYTES}` | `doc_caps.rs`; `release_stack.rs` `worst_case_*` |
| §7.6 grant documents | `crates/perch-smart-account/src/lib.rs` (`apply_grant_doc`, `check_grant`, `check_normal`, `drop_grant`, the grant index, the excluded-contract gate in `check_auth`, `complete_recovery`), `gate.rs` (the generation check, `StaleGrant`) | `grant_docs.rs`; `release_stack.rs` `docsplit_*` and the `worst_case_*` compromise flows ([`budgets.md`](budgets.md#grant-documents)) |
| §13 ZK adapter, §14 membership pool | `crates/perch-zk-adapter`, `crates/perch-zk-pool` | [`docs/zk/README.md`](../zk/README.md#what-is-tested-and-how) |
| §15 revision binding and the consumer interface: the `revision`/`configuration`/`document`/`capabilities` views, `apply_doc`'s `expected_revision`; the compiler's `limits`/`capabilities` | `PerchSmartAccount::{apply_doc, revision, configuration, document, capabilities}`, `apply` and `execute_upgrade` (`advance_revision`); `PerchDocCompiler::{limits, capabilities}` | `revision.rs`; `auth_vectors.rs` (signing digest and `AuthPayload` vectors for perch-js) |

Every test in `recovery.rs` and `account_capabilities.rs` runs under
enforcing authorization (`set_auths` with hand-built entries, see
`tests/support/mod.rs`), so the account's real `__check_auth`, its rule
selection, and the controller's `rcv_complete` all run. The one exception is
`the_controller_itself_refuses_a_zk_factor_changed_in_place`, which mocks
the authorization of a plain address standing in for a non-Perch account
that calls `rcv_sync` directly. The world uses the real account, compiler,
interpreter and spending limit (which only accounts without a stored
rule-eval rule set run), controller, and membership pool. Keys and guardians are
stand-in custom accounts. The ZK adapter is a mock that accepts only a
proof bound to the exact statement digest, enrollment id, and nullifier,
against a root the enrolled pool knows. Flows with real proofs on the
release wasm are in `release_stack.rs` ([`budgets.md`](budgets.md)).

## Spec requirements, code, and tests

The spec states each requirement; this table says where it is implemented
and which tests pin it. Test names are in `recovery.rs` unless another file
is named.

| Requirement | Spec | Code | Pinned by |
| --- | --- | --- | --- |
| `Protected` freeze on every path, from a mirror (`FreezeGate { attempt_id, until }`) in the account's instance storage, read by `__check_auth` without a cross-contract call | [§9](spec.md#9-activity-and-policy-restrictions), D1, D16 | account `check_auth`, `rcv_gate`, `complete_recovery` | `protected_freezes_every_path_except_the_completion` |
| `Loss` keeps ordinary activity; policy changes refused in the authorized window; the owner can always cancel | [§9](spec.md#9-activity-and-policy-restrictions), D1, D3, D5 | controller `rcv_sync`, `rcv_cancel` | `loss_keeps_ordinary_activity_but_blocks_policy_changes_and_the_owner_can_always_cancel` |
| Evidence-free attempts block nothing; authorization invalidates every sibling with one `invalidate_below` write | [§6.3](spec.md#63-transitions) T4, D2 | controller promotion | `evidence_free_attempts_freeze_nothing_and_block_nothing`, `the_first_authorized_attempt_invalidates_its_siblings` |
| A lost-key source is compared at promotion; a changed source is stored as `Invalidated` | [§6.3](spec.md#63-transitions) T4 | controller promotion | `a_lost_key_attempt_whose_source_changed_needs_a_fresh_attempt` |
| Attempt storage: temporary while collecting, persistent once authorized or when the evidence window exceeds the maximum TTL; `NoSuchAttempt` once the entry is gone | [§3.6](spec.md#36-storage-lifetime), [§6.2](spec.md#62-attempt-states) | controller `save` | not pinned by a test |
| Two-digest target binding: `target_doc_hash` and `target_bytes_hash` from one `derive_target`; `rcv_complete` checks the bytes, `rcv_sync` the identity | [§6.3](spec.md#63-transitions) T1, T5 | controller `begin_*`, `rcv_complete`, `rcv_sync` | `target_binding.rs`, `completion_must_submit_exactly_the_target_inside_its_window` |
| Completion marker: temporary, bound to `(attempt_id, target_doc_hash, ledger)`; a marker left by an unexecuted sub-invocation is ignored | [§6.3](spec.md#63-transitions) T5 | controller `rcv_complete`, `rcv_sync` (`CompletionMarker`) | `a_marker_left_by_an_unexecuted_sub_invocation_is_ignored` |
| Invoker-only hooks: reserved names refused in `__check_auth` and `execute`; the controller's configuration written only by `rcv_sync` | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths), D12 | account `check_auth`, `execute`; `perch_recovery_interface::account::is_reserved_invoker_only` | `hooks_are_unreachable_except_from_the_accounts_own_flows`, `account_capabilities.rs::execute_calls_as_the_account_and_refuses_invoker_only_hooks` |
| Account-document rules may be scoped to a controller, the account's own included (so it can act as a guardian there), not to its own ZK adapter or pool; a controller-scoped rule reaches only guardian approvals (I1–I3) | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths) | doc compiler validation; reserved-name guard | `a_controller_scoped_rule_reaches_no_reserved_controller_entry_point`, `a_perch_account_guards_another_at_its_own_controller_until_it_is_frozen` |
| The controller re-checks timing, quorum range, and the account not among its own guardians (`InvalidConfiguration`), the §3.4 factor rule (`RecoveryError::ZkFactorChangedInPlace`), and the circuit id and depth, because any contract can call `rcv_sync` for itself | [§3.1](spec.md#31-schema), [§3.4](spec.md#34-enrollment-ids), [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths) | controller `check_config`, `check_zk_wiring` | `an_account_cannot_be_its_own_guardian`, `the_controller_itself_refuses_a_zk_factor_changed_in_place`, `zk_enrollments_are_fresh_wired_and_never_changed_in_place` |
| The account refuses a reused enrollment id (`EnrollmentReused`) and a ZK factor changed in place (`PerchAccountError::ZkFactorChangedInPlace`) before any rule changes | [§3.4](spec.md#34-enrollment-ids) | account `apply` | `a_recovery_cannot_rotate_to_an_enrollment_id_the_account_used`, `zk_enrollments_are_fresh_wired_and_never_changed_in_place` |
| Nullifiers: one per `(account, enrollment)`, spent per account (`Spent{X}`), only by a completion; never reserved or released | [§11](spec.md#11-nullifiers), D9 | controller `verify_zk`, the completion branch of `rcv_sync`; `RecoveryStorage::nullifier` | `nullifiers_are_never_reserved_or_released`, `a_zk_completion_spends_the_nullifier_and_installs_the_declared_enrollment`, `one_accounts_completion_never_spends_anothers_nullifier` |
| Rotating a key is not a reconfiguration (`config_hash` over the recovery text); a completion is recognized by its marker | [§3.2](spec.md#32-configuration-identity), [§10](spec.md#10-completion-versus-reconfiguration), D8 | doc compiler `config_hash`; controller `rcv_sync` | `rotating_a_key_is_not_a_reconfiguration` |
| Epoch: every configuration change and completion kills earlier attempts and evidence; removal clears the configuration and the authorized attempt | [§3.3](spec.md#33-epoch), D10 | controller `rcv_sync`, `bump_epoch` | `every_configuration_change_kills_earlier_attempts_and_evidence` |
| `max-cancels` is a lifetime count per controller and account, kept across removal and re-enrollment | [§6.3](spec.md#63-transitions) T6, D5 | controller `RecoveryStorage::cancels` | `evidence_cancellation_counts_toward_max_cancels_only_for_authorized_attempts`, `the_cancellation_count_survives_removal_and_re_enrollment_at_the_same_controller` |
| `Protected` reconfiguration and its recorded evidence | [§5](spec.md#5-evidence-requirements), [§10](spec.md#10-completion-versus-reconfiguration), D4 | controller `approve_change`, `submit_zk_change`, `rcv_sync` | `protected_reconfiguration_needs_the_currently_enrolled_condition`, `protected_zk_reconfiguration_is_its_own_proven_action`, `approvals_cannot_outlive_the_enrolled_window` |
| Revocation: fingerprints over canonicalized keys (`batch_canonicalize_key`); a completion revokes the union of the replaced and the removed credentials; T1 refuses a target that keeps a replaced credential | [§7.1](spec.md#71-derivation), [§7.3](spec.md#73-replacement-rules), [§8](spec.md#8-revocation), D7 | doc compiler fingerprints, `derive_target`; account `complete_recovery` (`credential::revocations`) | `guardian_lost_key_recovery_installs_the_derived_target_and_revokes_the_old_key`, `swapping_credentials_between_slots_is_refused`, `replacement_sets_follow_the_permitted_change_rules`, `a_replaced_baseline_credential_never_returns` |
| Baselines and compromise recovery | [§3.5](spec.md#35-baselines), [§7.2](spec.md#72-sources) | controller `publish_baseline`, `begin_compromise` | `compromise_restores_the_baseline_and_revokes_everything_added_since`, `an_old_baseline_cannot_restore_a_revoked_credential` |
| Upgrades: delay, `Protected` condition over the exact Wasm, the recovery generation (account instance storage) making a queued request stale, a completion clearing it | [§12](spec.md#12-account-upgrades), D11 | account `schedule_upgrade`, `execute_upgrade`, `cancel_upgrade`; controller `rcv_upgrade` | `account_capabilities.rs`: `an_upgrade_waits_out_the_delay_then_replaces_the_code`, `cancelling_or_rescheduling_drops_the_pending_upgrade`, `any_recovery_transition_makes_a_queued_upgrade_stale`, `a_stale_upgrade_is_refused_without_being_cleared`, `a_completed_recovery_clears_the_pending_upgrade`, `enrolling_and_removing_recovery_stales_an_unenrolled_upgrade`, `a_controller_switch_and_an_executed_upgrade_advance_the_generation`, `upgrades_are_blocked_while_an_attempt_is_authorized`, `protected_upgrades_need_the_condition_over_the_exact_wasm` |
| The grant generation (account instance storage) advances by one on a completed recovery and on nothing else; a completion that would wrap it refuses with `GenerationExhausted` | [§12](spec.md#12-account-upgrades) | account `apply`, `complete_recovery`; view `grant_generation` | `revision.rs`: `the_grant_generation_advances_only_on_a_completed_recovery`; `recovery.rs`: `guardian_lost_key_recovery_installs_the_derived_target_and_revokes_the_old_key`, `a_zk_completion_spends_the_nullifier_and_installs_the_declared_enrollment`, `a_completion_that_would_wrap_the_grant_generation_is_refused` |
| Grant documents: no recovery member, no rule scoped to the account, its recovery controller, or its ZK adapter or pool, and no rule whose `functions` names a guardian approval (`GrantEscalation`); no grant rule casts a guardian approval at any controller (`PerchAuthError::GrantEscalation`, by `GUARDIAN_APPROVAL_FNS`); owner-only `apply_grant` and `remove_grant`; a grant only in normal form (`NotNormalForm`), its text rebuilt from its records and signer ids; a grant reconciled against its own records; the generation gate (`StaleGrant`) and the controller, adapter and pool guard for grants applied before enrollment (`PerchAuthError::GrantEscalation`) on every path; every completion wipes every grant; `gc_grant` only for wiped grants; the credential index refuses a wiped grant's credentials in every later document except a completion's target (`WipedCredential`); tags extended on read and restored, never absent, when archived; the freeze covers grants and the policy block does not | [§7.6](spec.md#76-grant-documents), D17 | account `apply_grant_doc`, `check_grant`, `names_guardian_approval`, `check_normal`, `excluded_contract`, `check_unwiped`, `check_auth`, `apply`, `complete_recovery`, `drop_grant`; `perch_recovery_interface::account::is_guardian_approval`; doc compiler `CompiledDoc::normal_form` (`perch_ir::normal_form`) | `grant_docs.rs` (every test); `grant_guardian_approvals.rs` (every test); `grant_rebuild.rs`; `rule_core_documents.rs` (the scoped traces); `release_stack.rs` `docsplit_guards_and_grant_manager` |
| The rule-eval rule set: the compiled model lowered on the account, each rule stored in its record; INV-1 and the anti-brick check on the stored rules | [§7.5](spec.md#75-bounded-completion-cost) | account `rule_set::lowered`, `apply_rules`, `install_account_rules`; view `rule_set`; doc compiler `compile_parsed` (`model_of`) | `rule_set.rs`; the stored set against the lowering and the installed rules after every apply in `rule_core_documents.rs`, `rule_eval_baseline.rs`, `auth_corpus.rs`, `apply_delta.rs` (`perch_testkit::rule_set`) |
| Rule-eval in `__check_auth`: `rule_eval::check_auth` over the chosen stored rules decides (`RuleEvalRefused`; an unknown id, `ContextRuleNotFound`; the recovery rule outside a completion refused), then the account's `authenticate` checks every signer; a completion left to the controller's `rcv_complete` (`authorize_completion`, over the account's record of the recovery rule, as OZ's `do_check_auth` decided it); a document rule carries no policy; each capped rule's spending record kept while the rule keeps its id and cap | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths), [§7.5](spec.md#75-bounded-completion-cost), [§12](spec.md#12-account-upgrades) | account `check_auth`, `gate::{authorize, drop_records}`, `rules::desired`, `apply_rules`, `apply_grant_doc`, `drop_grant`; `perch_rule_eval::{mirror, convert::calls}` | `gate.rs`; every verdict and record against rule-core's model in `rule_core_documents.rs` and against the recorded verdicts and OZ records in `rule_eval_baseline.rs`; `auth_corpus.rs`; the hand-written leaf vectors against rule-eval in `leaf_vectors.rs`; the spending records checked after every accepted authorization (`perch_testkit::rule_set::check_records`) |
| Bounded completion cost: the delta apply and the document caps | [§7.5](spec.md#75-bounded-completion-cost) | [Delta apply](#delta-apply-spec-75) below | [Delta apply tests](#delta-apply-tests); `release_stack.rs` `worst_case_*` ([`budgets.md`](budgets.md#document-caps)) |
| Configuration revision and `expected_revision`; ordinary signatures bind rule ids, not a revision | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths) "Revision binding" | account `advance_revision` (instance storage), `apply` | `revision.rs` |
| Storage lifetime and renewal | [§3.6](spec.md#36-storage-lifetime) | controller `renew`, `renew_nullifier`; account `renew(fingerprints, enrollment_ids)`; pool `renew_*` | pool: `renew_extends_every_entry_a_witness_needs`; the controller's and the account's `renew` are not pinned by a test |

## Implementation notes

What the spec leaves to the implementation, or what only its tests show.

- **Testing the two-digest binding under another identity scheme.**
  `target_binding.rs` checks the binding under the real compiler and under
  a test-only compiler whose identity is another function of the document
  (`perch_doc_compiler::testutils`, behind the `testutils` feature).
  `PERCH_TEST_COMPILER=stand-in` runs any suite built on `support::world()`
  that way: `recovery.rs` passes in full, and in `account_capabilities.rs`
  only `the_account_serves_its_full_canonical_applied_document`, which
  asserts that the stored bytes hash to the identity, fails, as a
  structured identity would make it.
  `PERCH_TEST_COMPILER=inconsistent-pair` makes every completion fail closed
  (`AttemptAuthorized`) and applies nothing. The controller reads the source
  identity (the account's `applied_doc_hash`, or the enrolled baseline) and
  never assumes an identity is a bytes digest, so a different identity
  scheme needs a new compiler and account, not a new controller.
- **Per-rule program provenance.** An interpreter program's
  `InstallParams.doc_hash` field carries its rule's `rule_hash`
  (`sha256("perch/rule" || rule bytes)`, spec §3.2), so a rule whose text
  is unchanged keeps byte-identical install parameters. Neither the doc
  compiler nor the account produces programs: the compiler returns each
  rule's signers and last ledger with the document's model, and the
  account stores the rule-eval rule the model lowers to. Programs exist
  only off chain (`perch-compile`, which the differential suites compare
  with rule-eval's lowering) and on accounts installed before rule-eval,
  whose interpreter stores them; `perch-compile::verify_plan_matches_doc`
  checks a plan's programs against their rules' hashes. `perch-deploy
  verify` checks each installed rule's stored rule-eval rule against the
  reviewed document's lowering, and that no rule is left over.
- **Configuration revision.** A `u64` in the account's instance storage,
  advanced at the end of every successful `apply` and in every executed
  upgrade. It is not `doc_hash`, which A -> B -> A restores while every
  re-added rule gets a new id, and not the recovery generation, which
  ordinary document changes leave alone. Advancing on every apply keeps
  "did anything change" logic out of the account; a re-apply costs
  consumers a spurious stale-revision result, which is safe.
  `configuration()` returns it with everything rule selection needs, read
  at one ledger. A completion may carry `expected_revision` too: the
  controller's `rcv_complete` reads only argument 0. Error meanings are in
  [the account interface](../account-interface.md#errors).
- **Account renewal.** Each revoked fingerprint and each enrolled id is its
  own persistent entry, so the account's `renew` takes the fingerprints and
  enrollment ids to extend; it also extends the instance, the applied
  document, and its fingerprints. It does not extend the installed-rule
  records or the rule-eval rule set (spec §3.6).
- **`execute`** returns the called function's value.

## Delta apply (spec §7.5)

`apply_doc`, completions included, changes only the rules that differ from
what is installed (`crates/perch-smart-account/src/rules.rs`).

**Records.** The account's own records are its rule registry. It keeps one
`RuleRecord` per installed rule: its id, name, each policy with `sha256` of
its install parameters' XDR, and the rule-eval rule that decides what it
allows. The rule's context type is `CallContract` of that rule's contract,
its `valid_until` and signers are that rule's, and it is the recovery rule
when its id is the instance's `RecoveryRule`, so each rule is stored once;
the views read records as the `InstalledRule`s they were (`rules::installed`).
The account document's records are one persistent entry (`RuleSet`), and each
grant document's are in its grant record. Ids come from
the account's counter (`NextRuleId`, instance storage, `rules::allocate`),
which never gives an id twice, so a spending record or grant tag keyed by
id never outlives its rule into another. `get_context_rule(id)` and
`get_context_rules_count()` are read from the records: a rule's
`signer_ids` and `policy_ids` are its signers' and policies' positions. `apply_doc` reconciles the compiled document
(`rules::desired`) against these records alone. It never scans the ids of
rules removed earlier, so applying a document, and completing a recovery,
costs the same however many documents came before.

**The rule-eval rule set** (`crates/perch-smart-account/src/rule_set.rs`).
A compiled document also carries its model (`CompiledDoc::model`, one
`perch_rule_eval::CompiledModel`). `apply_doc` lowers it on the account
with `rule_eval::lower`, drops the document rules `rules::desired` drops as
expired, and keeps the rest as `StoredRule`s in the records, which come out
of the reconcile in its order (`rules::records`): record `i` holds what
installed rule `i` enforces, the recovery rule last. The constructor stores
its admin rule the same way, and `rule_set()` returns the stored rules. Before the controller's
`rcv_sync`, `apply_doc` refuses `ModelInvalid` when the model is missing,
unreadable, or not one-for-one with the compiled rules and recovery;
`UnguardedRule` when a rule other than the recovery rule asks for no signer
(INV-1); and `AdminLockout` when no stored rule asks every one of its
signers for every function of the account with no condition, cap, or last
ledger. That check comes after the compiled-rule check (`admin_survives`),
and every document the compiled check accepts passes it. It also accepts an
n-of-n `threshold` self-admin rule, which the compiled check refuses because
it requires explicit `all` principals. `apply_grant` does the same
for a grant document with `rule_eval::lower_scoped`, under the account's
excluded set and the current grant generation, which every stored grant
rule carries, into the grant record's rules (view `grant_rule_set(grant)`).
Before that it refuses a document not in normal form (`check_normal`:
`CompiledDoc::normal_form`, an `address-eq` naming the account, a rule
already expired), so the grant record keeps the document's signer ids
instead of its text, and `perch_testkit::rebuild` and perch-js's
`rebuildGrantDoc` give the text back against its `doc_hash`.

**Rule-eval in `__check_auth`** (`crates/perch-smart-account/src/gate.rs`).
`check_auth` decides an authorization with rule-eval's `check_auth` on the
stored rules of the rules the payload chooses: a rule id is the stored rule
its record holds, among the admin records or, when a grant tag names its
grant, that grant's. It runs at the current ledger and grant generation,
under every signer the payload names, with the account's own spending
records, and refuses a chosen grant rule of another generation (a wiped
grant's) with `StaleGrant` and anything else it does not accept with
`RuleEvalRefused`, as it does a chosen recovery rule or a batch it cannot
read; a chosen id that names no installed rule fails with
`ContextRuleNotFound` (#3000), as OZ refused it, which perch-js reads as a
stale selection. `rule_eval::check_auth` reads only the chosen rules, so this is its
verdict over the whole stored set. The account's `authenticate` (`auth.rs`)
then checks every payload signer against OZ's digest (the account-bound
payload with the chosen ids), calling an `External` signer's verifier and
handing a `Delegated` one to the host as OZ's does, and the records
`check_auth` charged are stored. A document rule carries no policy. A
recovery completion (one `apply_doc` context selecting the recovery rule)
is decided by the controller's `rcv_complete` alone, so recovery never depends
on the evaluator: `authorize_completion` (`auth.rs`) checks the payload as
OZ's `do_check_auth` checked it for the recovery rule, from the account's
record of that rule — every chosen id the recovery rule's
(`ContextRuleNotFound`), every context a call on the account while the rule
is unexpired (`UnvalidatedContext`), no payload signer
(`UnauthorizedSigner`) — then calls the controller's
`rcv_complete(account, context, rule)` for each context, with the record's
signer count and scope as the `RecoveryRule`.
`tests/completion_differential.rs` runs this check and OZ's over a grid of
payloads and finds the same verdicts and the same contexts asked about,
OZ's `enforce` call carrying the same rule shape and no authenticated
signer. `tests/controller_differential.rs` runs the recovery flows and
each hook against the controller built with OZ's `Policy` hooks and the
account that calls them, and finds the same outcomes, events and
ledger. The account writes nothing to OZ's registry. An account
storing no admin set, which the constructor never leaves, authorizes
nothing but a completion (`RuleEvalRefused`). The
check reads a stored rule or record back from its XDR in one pass
(`perch_rule_eval::mirror`) and a batch of calls one host value at a time
(`perch_rule_eval::convert::calls`), so the account links no
`#[contracttype]` decoding of the mirrors and none of soroban-facade's
context decoding. Each capped rule's spending record (`SpendRecords(rule
id)`, one persistent entry, written when a charge changes it) is kept by an
apply exactly when the rule keeps its id and its stored cap
(`gate::drop_records`, which compares the old and new stored caps): a cap
change, a replacement or a removal in `apply_doc` or `apply_grant` drops
it, and so does removing its grant. With no old stored set every rule's
record is dropped, so every cap starts empty. `gate.rs` in the integration
tests shows the stored rule deciding against the record's signers both
ways, an account storing no set, and the records' lifecycle;
`rule_core_documents.rs` and `rule_eval_baseline.rs` compare
every verdict and record with rule-core's model and with the recorded
verdicts and OZ records of the code that installed the policies.

**Matching and ids.** Rules are matched by slot: the recovery rule by its
flag, a document rule by name and context type (its scope). A changed scope
is a different slot, so that rule is removed and added. Records whose slot
the document lacks are removed first. Then, in document order, a rule whose
slot is not installed is added under a new id; a rule identical to its
record (same signers in the same order, same policies with the same
parameters, same `valid_until`) keeps its record and id and nothing keyed
by it is written; and any other rule is edited in place under its id,
except a recovery rule that keeps its controller under a new configuration
(`rules::keeps_id`), which is removed and added again under a new id.

These are the ids OpenZeppelin's context-rule registry gave the same
documents, so the ids wallets select are unchanged
(`tests/oz_differential.rs`). That registry chose per rule between an
in-place edit and a replacement by the ledger writes each cost, and for a
document rule the edit never cost more; the recovery rule, with no signer
and one policy, could not be edited in place under the same controller
without passing through an empty rule or holding the controller twice, so
it was replaced.

**Install checks.** Every rule added or edited is held to OZ's install-time
limits (`rules::check`): at most 15 signers and 5 policies, a name of at
most 20 bytes, external keys of at most 256 bytes, and a signer or a
policy; each refusal has OZ's code (3010, 3011, 3015, 3013, 3004). A
compiled document always meets them: the compiler's caps are asserted
within them at build time (`MAX_DOC_SIGNERS`, `MAX_RULE_NAME_BYTES`) and the
IR caps keys at 256 bytes. The constructor installs signers no compiler has
seen, so it also refuses two that are one key (3007, `auth::check_distinct`):
two delegated signers with one address, or external signers whose verifier's
`batch_canonicalize_key` maps them to the same bytes, each verifier asked
once even for a lone key, as OZ's registry asked. An apply does not ask:
the compiler refuses a key that is not its verifier's canonical form
(`KeyNotCanonicalizable`) and two signers with one verifier and key
(`DuplicateSignerKey`), so two signers of one compiled rule are distinct
canonical keys, which their verifier cannot map to one
(`tests/install_checks.rs`).

**Recovery rule.** Installing the recovery rule, under a new id or with a
new controller, calls the controller's `rcv_install(account, config_hash,
rule)`, which checks the rule's shape and that `rcv_sync` stored that
configuration. Removing it calls no controller hook.

**Bounds and state.** An apply writes the admin records and the stored set
(one entry each, each only when it changes), the instance, and the spending
records it drops; it never writes more entries or emits more event bytes than a full replace
(tested). The rule set that results has the same normalized structure and
installation parameters as a full replace would leave; its authorization
matches a full replace except for a kept spending record and
expiry-sensitive behavior. An in-place edit keeps the rule id, and with it
the rule's spending record when its stored cap is unchanged. A rule
installed again gets a new id and an empty record.

**Events.** The account emits one `DocApplied` per application: `doc_hash`
as its topic; the configuration revision and the delta's counts as data
(rules added, removed, and edited in place; signers and policies added and
removed by the in-place edits). A rule installed again under a new id
counts once as removed and once as added, and its signers and policies are
in no count. A completion also emits `CredentialRevoked` per revoked
credential. Rule changes emit no per-item event, so an indexer reads the
installed rules from the account (`configuration()`, `applied_doc`, the
rule views); one that wants every signer change, a replaced rule's
included, diffs the rules it reads before and after the apply. The
constructor announces its admin rule as OZ's registry announces a rule:
`context_rule_added` with the rule's id, name, contract, no last ledger,
its signers' positions as their ids, and no policy.

**Re-apply and failure.** Re-applying the applied document changes no rule:
it writes the authorization nonce and the account instance (the advanced
revision) and emits only `DocApplied`. `apply_doc` returns an error or traps
on any failure, and the whole reconcile runs inside that one invocation, so
a partial delta never persists.

## Delta apply tests

The oracle is a second account contract, identical except that its
`apply_doc` removes every installed rule and adds every document rule
(`perch_smart_account::testutils::apply_doc_full_replace`).
`perch_testkit::delta` generates documents from bytes (signers drawn from a
fixed key pool, rules over a fixed set of names and scopes, caps, expiries,
recovery on or off) and compares complete state: the installed rules,
signers, and policies (ids normalized to names and values), every storage
key and value, the canonical applied document, and its hash. The delta
world mocks authorization and lifts resource limits: these tests check
equivalence and accounting; authorization and atomicity are
`delta_security.rs`'s, under enforcing authorization.

Equivalence is over normalized rule structure and installation parameters,
not over spending records. A kept rule's record survives an in-place edit
but a full replace gives the rule a new id and an empty record, so on a
rule whose cap is already partly spent the delta and the oracle diverge by
construction. The generator applies to fresh state,
where no window is yet spent; persistent spending budgets across replacements
are deferred ([`DEFERRED.md`](../DEFERRED.md)). The generator's current
coverage, including ledger advances, is documented in
[`perch-testkit::delta`](../../crates/perch-testkit/src/delta.rs).

| Property | Test |
| --- | --- |
| Any document sequence: the delta account and the oracle accept and refuse the same documents and end every step in the same state (proptest, shrinking) | `apply_delta.rs::delta_apply_matches_full_replace` |
| Re-applying the applied document emits only `DocApplied` and writes two entries, the nonce and the instance (the revision); a reformatted copy of it touches no rule | `reapplying_the_applied_document_is_a_no_op`, `reformatting_the_same_document_is_a_no_op` |
| A→B→C equals A→C; A→B→A restores A, and a rule unchanged across all three keeps its id (history counters aside: the recovery generation, the configuration revision, and the controller epoch) | `transitions_compose`, `a_transition_and_its_reverse_restore_the_state` |
| Each rule is kept, edited in place, installed again under a new id, removed, or added as the id rule says (stated independently in the test); `DocApplied`'s counts equal the diff of the records; the account emits nothing else; nothing keyed by an unchanged rule is written (its OZ entry, spending record, grant tag, or another contract's state for it); the delta emits no more event bytes and writes no more entries (host figures) than the full replace | `events_and_writes_are_exactly_the_diff` |
| A full swap at the signer cap (every key of an 8-signer rule replaced by 8 fresh keys) is one in-place edit | `a_full_swap_at_the_signer_cap_is_one_edit` |
| An edit where nothing survives (signer, functions, cap) keeps the id | `an_edit_where_nothing_survives_keeps_the_id` |
| A one-signer rule's only signer is swapped in place (the compromise shape) | `a_one_signer_rule_swaps_its_only_signer_in_place` |
| Adding signers up to the cap is one in-place edit | `adding_several_signers_is_one_edit` |
| The recovery rule takes a new id for a new configuration at its controller, and keeps its id across a controller switch | `recovery_changes_edit_only_the_recovery_rule`, `a_new_controller_is_swapped_in_place`; `rules.rs` unit test `only_a_recovery_rule_reconfigured_at_its_controller_takes_a_new_id` |
| After every accepted apply, the recovery rule's record has zero signers, the account as its contract, no last ledger, and the controller as its one policy, and OZ's registry holds no rule | `perch_testkit::rule_set::check`, run by every suite that checks the stored set |
| Every grant document `apply_grant` accepts rebuilds byte for byte from its records and signer ids, and each spelling outside normal form is refused and writes nothing | `grant_rebuild.rs`; every grant apply of every suite through `perch_testkit::rule_set::check_grant`; perch-js `grant.test.ts` over `testdata/grant-rebuild/vectors.json` |
| A completion's check against OZ's `do_check_auth` over a registry holding only the recovery rule: signers present, a wrong id, an expired rule, a wrong context, a second context, mismatched lengths, a refusing controller, and the order of the checks give the same verdicts and codes and ask the controller about the same contexts with the same rule shape | `completion_differential.rs` |
| Against the controller built with OZ's `Policy` hooks and the account that calls them (those builds' wasm, `PERCH_PREV_CONTROLLER_WASM`, `PERCH_PREV_ACCOUNT_WASM`): lost-key, compromise under a freeze, ZK rotation, cancellation and expiry, removal and a controller switch give the same outcomes, `__check_auth` codes, events and ledger after every step; `enforce`/`install` and `rcv_complete`/`rcv_install` over rule shapes, contexts, configuration hashes and attempt windows give the same verdicts and ledger, and the accepted marker completes alike | `controller_differential.rs` (`#[ignore]`d: needs the builds) |
| The constructor's install checks (OZ's codes), and a compiled document never reaching the canonical-duplicate check | `install_checks.rs` |
| Against the OZ-registry account it replaces (that build's wasm, `PERCH_OZ_ACCOUNT_WASM`, beside the controller built with it, `PERCH_OZ_CONTROLLER_WASM`): generated account and grant document sequences give the same outcomes, ids, views and events; generated authorizations get the same verdicts; a recovery flow under enforcing authorization reads the same | `oz_differential.rs` (`#[ignore]`d: needs the build) |
| Named cases: functions, scope, cap parameters, added and shared signers and policies, rename, remove and re-add, a key swapped under one id, minimal and maximal documents, reordering, expiry, a recovery-only change | the remaining `apply_delta.rs` tests |
| Revoked credentials stay refused after an in-place edit; the freeze and generation behave as under the full replace; reserved names stay closed; a delta in the authorized window changes nothing | `delta_security.rs`: `a_revoked_credential_cannot_return_through_an_in_place_edit`, `the_freeze_and_the_generation_behave_as_under_the_full_replace`, `reserved_names_hold_after_a_controller_scoped_rule_is_edited_in_place`, `a_delta_inside_an_authorized_window_is_refused_and_changes_nothing` |
| The recovery rule's install failing mid-delta (its controller refusing `rcv_install`, after a removal and an in-place edit), and the budget running out at 20, 40, 60, 80, 90, 95, and 99% of the delta's instructions, revert everything under enforcing authorization | `a_recovery_rule_install_failing_mid_delta_reverts_every_edit`, `budget_exhaustion_mid_delta_reverts_every_edit` |
| Changing one rule's functions or cap changes only that rule's stored rule, and no record | `apply_delta.rs`: `a_rule_keeping_its_name_with_new_functions_changes_only_its_stored_rule`, `new_cap_parameters_change_only_that_rules_stored_cap`, `a_changed_rule_leaves_the_other_stored_rules_alone`; `perch-compile` `a_programs_provenance_is_its_rules_hash_alone` |
| On the release wasm: each signer transition leaves exactly the target signers (a joining key acts, a leaving key cannot); a rejected transition (a duplicate key, or the budget running out at 25, 50, 75, and 95% of a full rotation) leaves every ledger entry unchanged | `release_stack.rs`: `signer_transitions` (paths and costs in [`budgets.md`](budgets.md#signer-transitions)), `a_rejected_signer_transition_changes_nothing` |
| Arbitrary document sequences (coverage-guided) | `fuzz/fuzz_targets/apply_doc_delta.rs`, in the assurance fuzz pass |
| Grant documents interleaved with account documents (spec §7.6): each grant holds exactly its own document's rules, grant operations leave the account document and other grants untouched, refused operations change nothing | `apply_grant_delta.rs` (proptest and a named sequence); `fuzz/fuzz_targets/apply_grant_delta.rs`, in the assurance fuzz pass |

`PERCH_DELTA_CASES` sets the proptest case count (defaults: 48 for the
oracle and accounting properties, 32 for the algebra properties and the
grant-document property).

## Not covered here

- Real proofs and the release circuit: [`docs/zk/`](../zk/README.md).
  Resource measurements: [`budgets.md`](budgets.md).
- Registry publication, the release pipeline, and the testnet deployment:
  [`docs/deploy/`](../deploy/README.md).
- Wallet integration: Nido.
