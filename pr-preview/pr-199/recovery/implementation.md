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
| §13 ZK adapter, §14 membership pool | `crates/perch-zk-adapter`, `crates/perch-zk-pool` | [`docs/zk/README.md`](../zk/README.md#what-is-tested-and-how) |
| §15 revision binding and the consumer interface: the `revision`/`configuration`/`document`/`capabilities` views, `apply_doc`'s `expected_revision`; the compiler's `limits`/`capabilities` | `PerchSmartAccount::{apply_doc, revision, configuration, document, capabilities}`, `apply` and `execute_upgrade` (`advance_revision`); `PerchDocCompiler::{limits, capabilities}` | `revision.rs`; `auth_vectors.rs` (signing digest and `AuthPayload` vectors for perch-js) |

Every test in `recovery.rs` and `account_capabilities.rs` runs under
enforcing authorization (`set_auths` with hand-built entries, see
`tests/support/mod.rs`), so the account's real `__check_auth`, OZ rule
selection, and the controller's `enforce` all run. The one exception is
`the_controller_itself_refuses_a_zk_factor_changed_in_place`, which mocks
the authorization of a plain address standing in for a non-Perch account
that calls `rcv_sync` directly. The world uses the real account, compiler,
interpreter, controller, and membership pool. Keys and guardians are
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
| Two-digest target binding: `target_doc_hash` and `target_bytes_hash` from one `derive_target`; `enforce` checks the bytes, `rcv_sync` the identity | [§6.3](spec.md#63-transitions) T1, T5 | controller `begin_*`, `enforce`, `rcv_sync` | `target_binding.rs`, `completion_must_submit_exactly_the_target_inside_its_window` |
| Completion marker: temporary, bound to `(attempt_id, target_doc_hash, ledger)`; a marker left by an unexecuted sub-invocation is ignored | [§6.3](spec.md#63-transitions) T5 | controller `enforce`, `rcv_sync` (`CompletionMarker`) | `a_marker_left_by_an_unexecuted_sub_invocation_is_ignored` |
| Invoker-only hooks: reserved names refused in `__check_auth` and `execute`; the controller's configuration written only by `rcv_sync` | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths), D12 | account `check_auth`, `execute`; `perch_recovery_interface::account::is_reserved_invoker_only` | `hooks_are_unreachable_except_from_the_accounts_own_flows`, `account_capabilities.rs::execute_calls_as_the_account_and_refuses_invoker_only_hooks` |
| Rules may be scoped to the account's own controller (so it can act as a guardian there), not to its own ZK adapter or pool; a controller-scoped rule reaches only guardian approvals (I1–I3) | [§15](spec.md#15-invoker-only-hooks-and-other-authorization-paths) | doc compiler validation; reserved-name guard | `a_controller_scoped_rule_reaches_no_reserved_controller_entry_point`, `a_perch_account_guards_another_at_its_own_controller_until_it_is_frozen` |
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
  is unchanged keeps byte-identical install parameters and is not
  reinstalled. The interpreter only stores the field: the source document
  never reaches it, so it cannot recompute the hash.
  `perch-compile::verify_plan_matches_doc` and `perch-deploy verify` check
  each installed program against its own rule's hash, and that no program
  is left over.
- **Configuration revision.** A `u64` in the account's instance storage,
  advanced at the end of every successful `apply` and in every executed
  upgrade. It is not `doc_hash`, which A -> B -> A restores while OZ gives
  every re-added rule a new id, and not the recovery generation, which
  ordinary document changes leave alone. Advancing on every apply keeps
  "did anything change" logic out of the account; a re-apply costs
  consumers a spurious stale-revision result, which is safe.
  `configuration()` returns it with everything rule selection needs, read
  at one ledger. A completion may carry `expected_revision` too: the
  controller's `enforce` reads only argument 0. `StaleRevision` is the last
  code of the account's error enum.
- **Account renewal.** Each revoked fingerprint and each enrolled id is its
  own persistent entry, so the account's `renew` takes the fingerprints and
  enrollment ids to extend; it also extends the instance, the applied
  document, and its fingerprints. It does not extend the installed-rule
  records or OZ's context-rule, signer, and policy entries (spec §3.6).
- **`execute`** returns the called function's value.

## Delta apply (spec §7.5)

`apply_doc`, completions included, changes only the rules that differ from
what is installed (`crates/perch-smart-account/src/rules.rs`).

**Records.** The account keeps one `InstalledRule` record per installed
rule: OZ id, the recovery flag, name, context type, `valid_until`, signers,
and each policy with `sha256` of its install parameters' XDR. The records
are one persistent entry. `apply_doc` reconciles the compiled document
(`rules::desired`) against these records alone. It never scans the ids of
rules removed earlier, so applying a document, and completing a recovery,
costs the same however many documents came before.

**Matching and order.** Rules are matched by slot: the recovery rule by its
flag, a document rule by name and context type (its scope). A changed scope
is a different slot, so that rule is removed and added. Records whose slot
the document lacks are removed first, so their signers and policies leave
OZ's registries before anything is added. Then, in document order, a rule
whose slot is not installed is added; a rule identical to its record (same
signers, same policies with the same parameters, same `valid_until`) is
not touched (no OZ call, no write keyed by it, no event); and any other
rule is reconciled one of two ways:

- **Edited in place** under its id (`rules::edit`). When the target has
  signers, one `reconcile_signers_no_events` call replaces the signer set
  (OZ checks the final set as a whole: size, key sizes, canonical
  duplicates; retained signers keep their registry ids; the rule is written
  once), then policies change, removals first, so their count never
  exceeds OZ's per-rule limit. When the target has no signers but the
  current rule has signers or a surviving policy, the policies change first
  and the signers go last. When neither side has signers and no policy
  survives, policies under new addresses are added first (only if there
  are any and the peak stays within OZ's `MAX_POLICIES`, 5), then the old
  ones removed, then changed policies re-added. A changed `valid_until` is updated. A policy
  whose install parameters change is removed and re-added.
- **Replaced whole** under a new id: the rule is removed and the target
  rule added. This is the only way when no in-place order keeps the rule
  non-empty within OZ's limits, for example the recovery rule (no signers,
  one policy) when its policy's parameters change.

**The choice.** `rules::Cost { events, writes }` prices each way, compared
in that order, the in-place edit on a tie. Every OZ mutation runs through
its `_no_events` variant (`add_context_rule_no_events`,
`remove_context_rule_no_events`, `reconcile_signers_no_events`,
`add_policy_no_events`, `remove_policy_no_events`,
`update_context_rule_valid_until_no_events`), and the spending-limit policy
installs and uninstalls without events, so `events` is always 0 and the
choice is by `writes`. `writes` counts, per OZ operation, the rule's own
entry, the registry entry of each signer or policy added or removed (plus
its lookup entry when the first reference registers it or the last
deregisters it), and the interpreter's program or the spending limit's
window when that policy is installed or uninstalled; the controller's
hooks write nothing, and the account's instance entry is not counted. An
entry two operations write counts twice, so the price ranks the two ways;
it is not the host's per-transaction write count. Both ways are priced
against the signer and policy registry reference counts derived from the
records at that point of the apply. `rules::edit` and `rules::replace` are
generic over one `Effects` trait, so the same sequence drives the pricing
(`Meter`) and the OZ calls (`Apply`).

**Bounds and state.** A full replace replaces every rule and deregisters
and re-registers every signer and policy, so taking the cheaper way per
rule means no apply writes more ledger entries than a full replace. Writes
are the only priced resource: an in-place edit can cost more instructions
than a replacement, which is what binds at the document caps
([`budgets.md`](budgets.md#document-caps)). The rule set that results has the
same normalized structure and installation parameters as a full replace would
leave; its authorization matches a full replace except for retained runtime
policy state (a kept spending-limit window) and expiry-sensitive behavior. An
in-place edit keeps the rule id, the retained signers' registry ids, and the
kept policies' state.
A replaced rule gets a new id and its policies are reinstalled, which
resets a spending limit's window.

**Events.** The account emits one `DocApplied` per application: `doc_hash`
as its topic; the configuration revision and the delta's counts as data
(rules added, removed, and edited in place; signers and policies added and
removed by the in-place edits). A rule replaced whole counts once as
removed and once as added, and its signers and policies are in no count. A
completion also emits `CredentialRevoked` per revoked credential. OZ emits
no per-item rule, signer, or policy events, so an indexer reads the
installed rules from the account (`configuration()`, `applied_doc`, OZ's
rule views); one that wants every signer change, a replaced rule's
included, diffs the rules it reads before and after the apply.

**Re-apply and failure.** Re-applying the applied document changes no rule:
it writes the authorization nonce and the account instance (the advanced
revision) and emits only `DocApplied`. `apply_doc` returns an error or traps
on any failure, and the whole reconcile runs inside that one invocation, so
a partial delta never persists.

The `_no_events` variants and `reconcile_signers` come from the pinned OZ
fork, theahaco/stellar-contracts-OZ at `3372676` (fork pull requests #4 and
#5; see [`DEFERRED.md`](../DEFERRED.md#oz-quiet-events-fork-pull-requests)).

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
not over retained per-policy runtime state. A kept rule's spending-limit
window survives an in-place edit but a full replace reinstalls its policy and
resets the window, so on a rule whose cap is already partly spent the delta
and the oracle diverge by construction. The generator applies to fresh state,
where no window is yet spent; persistent spending budgets across replacements
are deferred ([`DEFERRED.md`](../DEFERRED.md)). The generator also never
advances the ledger between steps, so a rule whose `not-after-ledger` expires
mid-sequence is outside the oracle's coverage.

| Property | Test |
| --- | --- |
| Any document sequence: the delta account and the oracle accept and refuse the same documents and end every step in the same state (proptest, shrinking) | `apply_delta.rs::delta_apply_matches_full_replace` |
| Re-applying the applied document emits only `DocApplied` and writes two entries, the nonce and the instance (the revision); a reformatted copy of it touches no rule | `reapplying_the_applied_document_is_a_no_op`, `reformatting_the_same_document_is_a_no_op` |
| A→B→C equals A→C; A→B→A restores A, and a rule unchanged across all three keeps its id (history counters aside: the recovery generation, the configuration revision, and the controller epoch) | `transitions_compose`, `a_transition_and_its_reverse_restore_the_state` |
| Each rule takes its planned step; a changed rule takes the cheaper way (in place on a tie, replacement when no in-place order exists); `DocApplied`'s counts equal the plan and the diff of the records; the account emits nothing else; nothing keyed by an unchanged rule is written; the delta emits no more event bytes and writes no more entries (host figures) than the full replace | `events_and_writes_are_exactly_the_diff` |
| Forcing every changed rule in place, or every one replaced, ends in the same state as the cheapest path and emits no per-item OZ or spending-limit event (the model's event price, 0) | `both_paths_are_priced_exactly` |
| A full swap at the signer cap (every key of an 8-signer rule replaced by 8 fresh keys) is editable in place: `reconcile_signers` checks only the final set, so no order needs room for old and new keys side by side | `a_full_swap_is_editable_in_place_at_the_signer_cap` |
| An edit where nothing survives but the target has a signer swaps the signers, then the policies; forced in place, it ends in the same state as the cheapest path | `an_edit_where_nothing_survives_swaps_the_signers_then_the_policies` |
| A one-signer rule's only signer is swapped in place (the compromise shape) | `a_one_signer_rule_swaps_its_only_signer_in_place` |
| Adding signers up to the cap is one in-place `reconcile_signers`, priced at one rule write plus two entries per new signer | `adding_several_signers_is_one_batch` |
| Per-operation prices; adding first stays within OZ's five policies per rule | `rules.rs` unit tests: `signers_are_priced_by_their_registry_reference_count`, `a_signer_swap_writes_the_rule_once`, `policies_are_priced_with_their_own_hooks`, `whole_rules_and_expiries_are_priced_by_their_writes`, `an_in_place_order_exists_up_to_the_policy_limit`, `events_outrank_writes` |
| Named cases: functions, scope, cap parameters, added and shared signers and policies, rename, remove and re-add, a key swapped under one id, minimal and maximal documents, reordering, expiry, a recovery-only change | the remaining `apply_delta.rs` tests |
| Revoked credentials stay refused after an in-place edit; the freeze and generation behave as under the full replace; reserved names stay closed; a delta in the authorized window changes nothing | `delta_security.rs`: `a_revoked_credential_cannot_return_through_an_in_place_edit`, `the_freeze_and_the_generation_behave_as_under_the_full_replace`, `reserved_names_hold_after_a_controller_scoped_rule_is_edited_in_place`, `a_delta_inside_an_authorized_window_is_refused_and_changes_nothing` |
| A policy install failing mid-delta, and the budget running out at 20, 40, 60, 80, 90, 95, and 99% of the delta's instructions, revert everything under enforcing authorization | `a_policy_install_failing_mid_delta_reverts_every_edit`, `budget_exhaustion_mid_delta_reverts_every_edit` |
| Changing one rule reinstalls only that rule's program | `apply_delta.rs::new_cap_parameters_edit_only_that_rule`, `perch-compile` `a_programs_provenance_is_its_rules_hash_alone` |
| On the release wasm: each signer transition leaves exactly the target signers (a joining key acts, a leaving key cannot); a rejected transition (a duplicate key, or the budget running out at 25, 50, 75, and 95% of a full rotation) leaves every ledger entry unchanged | `release_stack.rs`: `signer_transitions` (paths and costs in [`budgets.md`](budgets.md#signer-transitions)), `a_rejected_signer_transition_changes_nothing` |
| Arbitrary document sequences (coverage-guided) | `fuzz/fuzz_targets/apply_doc_delta.rs`, in the assurance fuzz pass |

`PERCH_DELTA_CASES` sets the proptest case count (defaults: 48 for the
oracle and accounting properties, 32 for the algebra properties).

## Not covered here

- Real proofs and the release circuit: [`docs/zk/`](../zk/README.md).
  Resource measurements: [`budgets.md`](budgets.md).
- Registry publication, the release pipeline, and the testnet deployment:
  [`docs/deploy/`](../deploy/README.md).
- Wallet integration: Nido.
