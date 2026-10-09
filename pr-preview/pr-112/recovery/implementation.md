# Recovery implementation map

Where [`spec.md`](spec.md) is implemented, which tests pin it, and the
choices the implementation made where the spec leaves room. This is
workstream 3 of epic [#99](https://github.com/stellar-registry/perch/issues/99):
the one recovery controller and the shared account capabilities.

## Where each part lives

| Spec | Code | Tests |
| --- | --- | --- |
| §3.1 schema, §3.2 `config_hash` | `perch-ir` (`doc.rs`, `parse.rs`, `canon.rs::recovery_canonical_json`, `validate.rs`); `perch-doc-compiler::to_compiled_recovery` | `crates/perch-ir/tests/recovery.rs` |
| §3.3 epoch, §6 state machine, §10 `rcv_sync`, §11 nullifiers | `crates/perch-recovery/src/contract.rs` | `crates/integration-tests/tests/recovery.rs` |
| §3.4 enrollment ids, §8 revocation, §9 freeze, §15 reserved names | `crates/perch-smart-account/src/lib.rs` (`apply_doc`, `check_auth`, `rcv_gate`) | `recovery.rs`, `account_capabilities.rs` |
| §3.5 baselines | `PerchRecovery::publish_baseline` | `recovery.rs` (compromise tests) |
| §7 permitted changes | `perch_ir::recovery::derive_target`; `PerchDocCompiler::derive_target` | `crates/perch-ir/tests/recovery.rs`, `recovery.rs` |
| §3.2 per-rule hash | `perch_ir::{rule_canonical_json, rule_hash}`; `perch_compile::rule_hash_onchain`; `perch_recovery_interface::fragment::rule_hash`; perch-js `ruleHash`, `configHash` | `crates/perch-ir/tests/rule_hash.rs`, `fragment_hashes.rs`, `packages/perch-js/test/fragment.test.ts` |
| §7.5 delta apply | `crates/perch-smart-account/src/rules.rs` (`desired`, `reconcile`) | `apply_delta.rs`, `delta_security.rs`, `fuzz/fuzz_targets/apply_doc_delta.rs` |
| §7.5 document caps | `perch_doc_compiler::{MAX_DOC_SIGNERS, MAX_DOC_RULES, MAX_DOC_CANONICAL_BYTES, MAX_RULE_NAME_BYTES}` | `doc_caps.rs`; `release_stack.rs` `worst_case_*` (see below) |
| §12 upgrades | `PerchSmartAccount::{schedule_upgrade, execute_upgrade, cancel_upgrade}`; `PerchRecovery::rcv_upgrade` | `account_capabilities.rs` |
| §15 `execute`, `applied_doc` | `PerchSmartAccount::{execute, applied_doc}` | `account_capabilities.rs` |
| Consumer interface (#108): configuration revision, `revision`/`configuration`/`document`/`capabilities` views, `apply_doc`'s `expected_revision` (RFC #109 §3c); the compiler's `limits`/`capabilities` | `PerchSmartAccount::{apply_doc, revision, configuration, document, capabilities}`, `apply` and `execute_upgrade` (`advance_revision`); `PerchDocCompiler::{limits, capabilities}` | `revision.rs`; `auth_vectors.rs` (signing digest and `AuthPayload` vectors for perch-js) |

Every test in `recovery.rs` and `account_capabilities.rs` runs under
enforcing authorization (`set_auths` with hand-built entries, see
`tests/support/mod.rs`), so the account's real `__check_auth`, OZ rule
selection, and the controller's `enforce` all run. The world uses the real
account, compiler, interpreter, controller, and membership pool. Keys and
guardians are stand-in custom accounts. The ZK adapter is a mock that
accepts only a proof bound to the exact statement digest, enrollment id,
and nullifier, against a root the enrolled pool knows. Real-proof runs
against the release artifacts belong to the integration layer.

## Issues closed by the implementation

| Issue | What closes it | Pinned by |
| --- | --- | --- |
| #84 activity during recovery | `Protected` freeze mirror in `check_auth`; `Loss` keeps activity; `rcv_sync` refuses policy changes in the window | `protected_freezes_every_path_except_the_completion`, `loss_keeps_ordinary_activity_but_blocks_policy_changes_and_the_owner_can_always_cancel` |
| #89 evidence-free griefing | Collecting attempts freeze and block nothing; authorization invalidates siblings in O(1) | `evidence_free_attempts_freeze_nothing_and_block_nothing`, `the_first_authorized_attempt_invalidates_its_siblings` |
| #90 direct `install` | Reserved names refused in `check_auth` and `execute`; configuration written only by `rcv_sync` | `hooks_are_unreachable_except_from_the_accounts_own_flows`, `execute_calls_as_the_account_and_refuses_invoker_only_hooks` |
| #91 nullifier release | No reservations; only a completion spends | `nullifiers_are_never_reserved_or_released`, `a_zk_completion_spends_the_nullifier_and_installs_the_declared_enrollment` |
| #92 key rotation vs. reconfiguration | `config_hash` over the recovery text; completion recognized by its marker | `rotating_a_key_is_not_a_reconfiguration`, the ZK completion test |
| #93 stale configuration and attempts | Per-account epoch; removal clears the controller's state | `every_configuration_change_kills_earlier_attempts_and_evidence` |
| #86 real authorization tests (account paths) | Enforcing-auth harness | both suites |
| Review of #102: unbounded completion, replaced baseline credential, unenrolled upgrade | Installed-rule records; revocation union; recovery generation | `completion_cost_does_not_grow_with_policy_churn`, `a_replaced_baseline_credential_never_returns`, `enrolling_and_removing_recovery_stales_an_unenrolled_upgrade` |

## Choices within the spec

- **Freeze mirror (D16).** The account stores `FreezeGate { attempt_id,
  until }` in instance storage, so `__check_auth` reads it without a
  cross-contract call. `rcv_gate` clears it only for the attempt it was set
  for.
- **Completion marker.** `enforce` writes a temporary-storage marker bound
  to `(attempt_id, target_doc_hash, ledger)`; `rcv_sync` consumes it and
  treats the call as a completion only if the compiled document is that
  target, in that ledger, while that attempt is still the authorized one.
  `enforce` also runs for an authorization tree's sub-invocations that
  never execute, so a stale marker is dropped rather than trusted.
- **Two-digest target binding (RFC #109 §1, option A).** An attempt
  records two digests from its one `derive_target` call. `target_doc_hash`
  is the compiler's identity of the target. `target_bytes_hash` is the
  controller's `sha256` of the canonical bytes returned. `enforce` compares
  `sha256` of the completing `apply_doc` argument with the bytes digest.
  `rcv_sync` then requires the account's compiled identity to equal
  `target_doc_hash`. The source identity is read rather than hashed: the
  account's `applied_doc_hash` (lost-key) or the enrolled baseline
  (compromise). The controller therefore never assumes that an identity is
  a bytes digest, and a different identity scheme needs a new compiler and
  account, not a new controller. `target_binding.rs` checks this under the
  real compiler and under a test-only compiler whose identity is another
  function of the document (`perch_doc_compiler::testutils`, behind the
  `testutils` feature). Setting `PERCH_TEST_COMPILER=stand-in` runs any
  suite that way: `recovery.rs` passes all 29 tests, and in
  `account_capabilities.rs` only the test asserting that the stored bytes
  hash to the identity fails, as a structured identity would make it.
  Setting `PERCH_TEST_COMPILER=inconsistent-pair` makes every completion fail
  closed (`AttemptAuthorized`) and applies nothing.
- **Spent nullifiers are recorded per account** (spec §11's `Spent{X}`).
  Any contract can enroll itself at the shared controller with an adapter
  of its choosing, so a controller-wide record would let it mark a victim's
  (public) nullifier spent and block every later proof by the victim.
  `one_accounts_completion_never_spends_anothers_nullifier` pins this.
- **Hooks re-check what the compiler validates** (non-zero timing, quorum
  range, the account not among its own guardians), because any contract can
  call `rcv_sync` for itself.
- **Change approvals are refused during an authorized window** (§9: only
  that attempt's cancellation evidence is accepted).
- **Attempt storage.** Collecting attempts live in temporary storage for
  their evidence window. An attempt that is authorized, or whose evidence
  window is longer than the network's maximum entry TTL, is persistent. An
  attempt recorded `Invalidated` while collecting stays where it was. Its
  record therefore lasts at least its evidence window, after which the
  attempt has expired anyway. Once the entry is gone, evidence for it is
  refused as `NoSuchAttempt` rather than `AttemptNotLive`.
- **Stale lost-key source (T4).** The submission that meets the condition
  succeeds and records the attempt as `Invalidated` (a stored state, with an
  `AttemptInvalidated` event). Refusing would roll the check back and leave
  the attempt promotable if the document later changed back.
  `a_lost_key_attempt_whose_source_changed_needs_a_fresh_attempt` pins both
  halves.
- **Upgrade staleness and the recovery generation (§12).** The account keeps
  its recovery generation, the pending request, and its rule-id list in
  instance storage, which is persistent and is read on every call anyway.
  The generation advances on every `rcv_sync` outcome other than
  `Unchanged` (twice for a controller switch, once per side) and on every
  executed upgrade. `execute_upgrade` refuses a stale request with
  `StaleUpgrade` (also when the controller's own epoch check finds it
  stale) and leaves it in place: a failed invocation keeps none of its
  writes, and the request can never execute because the generation never
  decreases. Scheduling replaces it, cancelling removes it, and a
  completion clears it. `a_stale_upgrade_is_refused_without_being_cleared`
  and `a_completed_recovery_clears_the_pending_upgrade` pin this.
- **Fingerprints.** The doc compiler fingerprints every declared signer,
  canonicalizing external keys through the verifier's
  `batch_canonicalize_key` (the call OZ uses for duplicate signers).
  `derive_target` also returns the source credentials in the replaced
  slots, with keys canonicalized the same way. The controller records them
  at T1 and returns them in `Completion`, and the account revokes
  `credential::revocations` of them, the applied document, and the target
  (§8). T1 refuses a replacement set whose target would keep one of the
  credentials it replaces.
- **Delta apply (§7.5).** The account keeps an `InstalledRule` record per
  rule it installed (id, slot, expiry, signers, and each policy with a
  digest of its install parameters) and reconciles those records against
  the compiled document. Rules are matched by slot (the recovery flag,
  otherwise name and context type). Unmatched installed rules are removed
  first, so their signers and policies leave the registries before
  anything is added. A changed scope is a different slot, so the rule is
  removed and added. Any other changed rule is reconciled whichever of two
  ways costs less (`rules::Cost`, the in-place edit on a tie):
  - **edited in place** under its id: its expiry is updated, and signers
    and policies are removed then added (or, when none would survive, added
    first, so the rule is never left with neither). New signers go in one
    OZ `batch_add_signer` call, with one duplicate check and one rule
    write; a change with no new signers makes no such call;
  - **replaced whole** under a new id, the only way when no in-place order
    keeps the rule valid.

  The cost model prices the exact OZ operations each way runs. One
  `Effects` sequence drives both a `Meter` and the real calls, so the
  model and the execution cannot drift apart. Prices are contract-event
  bytes first, then ledger writes as a tiebreak, against the signer and
  policy registry counts derived from the records. Event sizes are
  `ContractEvent` XDR, the measure the network's events limit counts,
  including the spending limit's install and uninstall events. A full
  replace replaces every rule and churns every registration, so taking the
  cheaper way per rule never emits more than it does. A replaced rule's
  policies are reinstalled, which resets a spending limit's window, as the
  full replace always did. An in-place edit keeps the id and the kept
  policies' state.

  An unchanged rule, signer, or policy emits no event and writes nothing.
  Re-applying the applied document writes only the authorization nonce and
  the instance (the configuration revision). It
  never scans the ids of rules deleted earlier, so applying a document, and
  completing a recovery, costs the same however many documents came
  before. `apply_doc` returns an error or traps on any failure, so a
  partial delta never persists.
- **Per-rule program provenance.** An interpreter program's
  `InstallParams.doc_hash` field carries its rule's `rule_hash`
  (`sha256("perch/rule" || rule bytes)`, `CANONICAL.md` "Fragment
  hashes"), not the whole document's hash, so a rule whose text is
  unchanged keeps byte-identical install parameters and is not
  reinstalled. The interpreter's Wasm and types are unchanged.
  `perch-compile::verify_plan_matches_doc` and `perch-deploy verify` check
  each installed program against its own rule's hash, and that no program
  is left over.
- **§15 compile-time scope rule, narrowed.** The compiler refuses rules
  scoped to the document's own ZK adapter or pool, but not its controller: a
  perch account must be able to approve, as a guardian, recoveries at the
  controller it uses itself (D16), which needs a rule scoped to it. The
  reserved-name guard protects the controller's hooks: every entry point
  that acts on an account's own recovery state under its authorization is
  reserved (§15 I1), every other one takes a guardian's approval of another
  account's statement (I2), so a rule scoped to the controller reaches only
  guardian approvals (I3).
  `a_controller_scoped_rule_reaches_no_reserved_controller_entry_point`
  pins it.
- **Guardian set.** The controller refuses a configuration that lists the
  account among its own guardians (`InvalidConfiguration`).
- **Document caps.** 8 declared signers, 11 rules, 8 192 canonical bytes,
  and rule names of at most OZ's 20 bytes, sized against the measured
  worst-case completion (`budgets.md`, "Document caps"). The binding limit
  is instructions: the thief who keeps every name and changes every
  program is edited in place, at 73.6% at the caps. Written entries are
  next (70.5%, the renamed thief). Every stack contract links a 64 KiB wasm
  stack (`build.rs`): with rustc's 1 MiB default, every cross-contract
  call's VM cost more than 1 MB of the transaction's memory.
- **Quiet OZ mutations and `DocApplied`.** `apply_doc` performs every
  rule, signer, and policy mutation through OZ's `_no_events` variants
  (theahaco/stellar-contracts-OZ PR #4, pinned), and the spending-limit
  policy installs and uninstalls quietly. It emits one `DocApplied` per
  application: `doc_hash` as its topic, and the delta's counts (rules
  added, removed, and edited in place; signers and policies added and
  removed by the in-place edits). A rule replaced whole counts once as
  removed and once as added, and its signers and policies are in no
  count. `apply_delta.rs` checks the counts against the plan and the diff
  of the installed rules, and that the account emits nothing else. An
  indexer reads the installed rules from the account (`applied_doc`, OZ's
  rule views); it cannot replay OZ's per-item events, which no longer
  exist, so one that wants every signer change (a replaced rule's
  included) diffs the rules it reads before and after the apply.
- **`reconcile_signers`.** An in-place edit changes a rule's signers in
  one OZ `reconcile_signers_no_events` call (theahaco/stellar-contracts-OZ
  PR #5, pinned). The call checks the final set whole, keeps retained
  signers' ids, and writes the rule once. When the target has signers the
  swap goes first; when it has none, the policies change first and the
  signers go last.
- **Configuration revision (#108).** A `u64` in instance storage: 0
  after the constructor, advanced by one at the end of every successful
  `apply` (owner apply, enrollment, reconfiguration, removal, controller
  switch, completion, and a re-apply of the same document alike) and in
  every executed upgrade, and by nothing else. It is not `doc_hash`, which
  A -> B -> A restores while OZ gives every re-added rule a new id, and not
  the recovery generation, which ordinary document changes leave alone.
  Advancing on every apply keeps "did anything change" logic out of the
  account; a re-apply costs consumers a spurious stale-revision result,
  which is safe. `DocApplied` carries it as data, and `configuration()`
  returns it with everything rule selection needs, read at one ledger.
  `apply_doc`'s optional `expected_revision` refuses with `StaleRevision`
  (the account error enum's last code, so earlier codes keep their values)
  unless the account is at that revision, so a document prepared against
  one configuration never silently overwrites another device's change.
  `None` applies over the current revision. A completion may carry it too:
  the controller's `enforce` reads only argument 0. Ordinary transactions
  are not bound to a revision: OZ signs the invocation and the selected
  rule ids, so a selected rule removed or replaced since signing fails
  closed (`ContextRuleNotFound`), and one edited in place runs under its
  new content (`revision.rs` pins both). Re-applying the applied document
  now writes the instance as well as the nonce.
- **`execute`** returns the called function's value.
- **`max-cancels` is a lifetime count per controller and account.**
  Nothing resets it. Removing recovery and re-enrolling at the same
  controller keeps it, because removal clears the configuration and kills
  the attempts but not the count. Switching controllers starts a new one
  (T6). `the_cancellation_count_survives_removal_and_re_enrollment_at_the_same_controller`
  pins it.
- **A lost-key source is compared at promotion.** If the applied document
  changes and then changes back before any evidence meets the condition,
  the attempt promotes over the same snapshot it was opened for. Once a
  submission has met the condition against a changed document, the attempt
  is invalidated for good (above).
- **Account renewal.** Revoked-set and enrolled-id entries are one
  persistent entry each, so the account's `renew` takes the fingerprints and
  enrollment ids to extend.

## Delta apply tests

The oracle is a second account contract, identical except that its
`apply_doc` removes every installed rule and adds every document rule (the
pre-delta behaviour, `perch_smart_account::testutils::apply_doc_full_replace`).
`perch_testkit::delta` generates documents from bytes (signers drawn from a
fixed key pool, rules over a fixed set of names and scopes, caps, expiries,
recovery on or off) and compares complete state: the installed rules,
signers, and policies (ids normalized to names and values), every storage
key and value, the canonical applied document, and its hash.

| Property | Test |
| --- | --- |
| Any document sequence leaves the delta account and the oracle in the same state (proptest, shrinking) | `apply_delta.rs::delta_apply_matches_full_replace` |
| Re-applying the applied document emits only `DocApplied` and writes only the nonce and the instance (the revision) | `reapplying_the_applied_document_is_a_no_op` |
| A→B→C equals A→C; A→B→A restores A (history counters aside: the recovery generation, the configuration revision, and the controller epoch) | `transitions_compose`, `a_transition_and_its_reverse_restore_the_state` |
| Each changed rule takes the cheaper path. Its events are exactly that path's and are priced to the byte against the host's figure. The delta emits no more event bytes, and writes no more entries, than the full replace | `events_and_writes_are_exactly_the_diff` |
| Both prices the choice compares are exact: forcing every changed rule in place, or every one replaced, emits exactly the priced bytes and reaches the full-replace state | `both_paths_are_priced_exactly` |
| Crossovers. A 3-key policy-free rule rotates 1–2 keys in place and 3 by replacement. An 8-key rule with both policies rotates up to 6 in place and 7–8 by replacement. Each count's measured bytes equal the cheaper forced path's | `rotating_the_admin_rules_keys_switches_to_replacement_where_it_is_cheaper`, `rotating_a_capped_rules_keys_switches_to_replacement_where_it_is_cheaper` |
| An in-place order exists up to OZ's signer limit (8 + 7) and not past it (8 + 8) | `a_full_swap_can_be_edited_in_place_up_to_the_signer_limit` |
| Named cases: functions, scope, cap parameters, added and shared signers and policies, rename, remove and re-add, a key swapped under one id, a one-signer swap in place (the compromise shape), minimal and maximal documents, reformatting, reordering, expiry, a recovery-only change | the remaining `apply_delta.rs` tests |
| Revoked credentials stay refused after an in-place edit; the freeze and generation behave as under the full replace; reserved names stay closed; a delta in the authorized window changes nothing | `delta_security.rs` |
| A failing policy install, and budget exhaustion at every point of a delta, revert everything under enforcing auth | `delta_security.rs` |
| Changing one rule reinstalls only that rule's program | `apply_delta.rs::new_cap_parameters_edit_only_that_rule`, `perch-compile` `a_programs_provenance_is_its_rules_hash_alone` |
| Arbitrary document sequences (coverage-guided) | `fuzz/fuzz_targets/apply_doc_delta.rs`, in the assurance fuzz pass |

`PERCH_DELTA_CASES` sets the proptest case count (CI defaults: 32 to 48 per property; a 400-case sweep also passes).

## Not covered here

- Real proofs, the release circuit, and resource measurements: workstream 2
  and the integration layer.
- Registry publication, release pipeline, testnet deployment: workstream 4
  ([`docs/deploy/`](../deploy/README.md)).
- Wallet integration: Nido.
