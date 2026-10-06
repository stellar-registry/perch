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
| §7.5 document caps | `perch_doc_compiler::{MAX_DOC_SIGNERS, MAX_DOC_RULES, MAX_DOC_CANONICAL_BYTES, MAX_RULE_NAME_BYTES}` | `doc_caps.rs`; `release_stack.rs` `worst_case_*` (see below) |
| §12 upgrades | `PerchSmartAccount::{schedule_upgrade, execute_upgrade, cancel_upgrade}`; `PerchRecovery::rcv_upgrade` | `account_capabilities.rs` |
| §15 `execute`, `applied_doc` | `PerchSmartAccount::{execute, applied_doc}` | `account_capabilities.rs` |

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
| Review of #102: unbounded completion, replaced baseline credential, unenrolled upgrade | Tracked rule ids; revocation union; recovery generation | `completion_cost_does_not_grow_with_policy_churn`, `a_replaced_baseline_credential_never_returns`, `enrolling_and_removing_recovery_stales_an_unenrolled_upgrade` |

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
  their evidence window; an attempt that is authorized, or whose evidence
  window is longer than the network's maximum entry TTL, is persistent.
- **Stale lost-key source (T4).** The promoting submission is refused with
  `AttemptNotLive` and changes nothing; the attempt can never promote, so a
  fresh attempt is required.
- **Upgrade staleness and the recovery generation (§12).** The account keeps
  its recovery generation, the pending request, and its rule-id list in
  instance storage, which is persistent and is read on every call anyway.
  The generation advances on every `rcv_sync` outcome other than
  `Unchanged` (twice for a controller switch, once per side) and on every
  executed upgrade. A stale request is cleared and `execute_upgrade`
  returns `Ok(false)` without upgrading: the spec's "refused" cannot also
  clear it, because a failed invocation keeps none of its writes.
  `Ok(true)` means it upgraded.
- **Fingerprints.** The doc compiler fingerprints every declared signer,
  canonicalizing external keys through the verifier's
  `batch_canonicalize_key` (the call OZ uses for duplicate signers).
  `derive_target` also returns the source credentials in the replaced
  slots, with keys canonicalized the same way. The controller records them
  at T1 and returns them in `Completion`, and the account revokes
  `credential::revocations` of them, the applied document, and the target
  (§8). T1 refuses a replacement set whose target would keep one of the
  credentials it replaces.
- **Bounded rule replacement (§7.5).** The account records the ids of the
  rules it installs and removes exactly those on the next `apply_doc`. It
  never scans the ids of rules deleted earlier, so applying a document, and
  completing a recovery, costs the same however many documents came before.
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
- **Document caps.** 6 declared signers, 8 rules, 8 192 canonical bytes,
  and rule names of at most OZ's 20 bytes, sized against the measured
  worst-case completion (`budgets.md`, "Document caps"). The binding limit
  is contract events. Every stack contract links a 64 KiB wasm stack
  (`build.rs`): with rustc's 1 MiB default, every cross-contract call's VM
  cost more than 1 MB of the transaction's memory.
- **`execute`** returns the called function's value.
- **`max-cancels` is a lifetime count per controller.** Nothing resets it;
  switching controllers starts a new one (T6).
- **A lost-key source is compared at promotion.** If the applied document
  changes and then changes back before promotion, the attempt promotes over
  the same snapshot it was opened for.
- **Account renewal.** Revoked-set and enrolled-id entries are one
  persistent entry each, so the account's `renew` takes the fingerprints and
  enrollment ids to extend.

## Not covered here

- Real proofs, the release circuit, and resource measurements: workstream 2
  and the integration layer.
- Registry publication, release pipeline, testnet deployment: workstream 4
  ([`docs/deploy/`](../deploy/README.md)).
- Wallet integration: Nido.
