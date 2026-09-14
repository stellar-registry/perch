# Recovery controller: design, governance, and upgrade policy

This documents `crates/perch-recovery`: what it generalizes from the
validated Nido Stage 3 experiment, how completion actually authorizes
`apply_doc` (Variant A), the reconfigure-authorization rule that governs
every change to enrolled `Protected` recovery, and how the controller itself
is governed.

## What's generalized from the validated experiment, and what's changed

Nido's Stage 3 controller validated the shape this crate implements:
initiation/delay/expiry/cancel/completion state machine, guardian and ZK
evidence against one frozen proposal, `config_hash` commitment, and Variant A
completion (recovery authorizes the account's own document-apply operation
rather than a dedicated raw mutator). `crates/perch-recovery` keeps all of
that. Three things are deliberately different, each for a stated reason:

1. **Enrollment happens through the document, not a side-channel `enroll`
   call.** Nido's controller predates perch's schema support for recovery
   (§3 of the follow-up review): it received `RecoveryConfig` as a direct
   call argument because there was nowhere else for it to live. Now that
   `perch-ir`/`perch-doc-compiler` carry it (see
   [`schema.md`](schema.md)), enrollment and reconfiguration are just what
   happens when `apply_doc` installs a compiled document whose `recovery`
   section differs from before — the OZ `Policy::install` hook receives the
   compiled config as its install params, the same mechanism every other
   perch policy (the interpreter, `spending_limit`) already uses.
2. **`Protected` reconfigure is general, not additive-only.** Nido's
   `reconfigure` entry point accepted exactly two transitions
   (`GuardianOnly→Combined`, `ZkOnly→Combined`) and rejected everything else,
   including under `Loss` — a scope decision for their bounded experiment,
   not a requirement from the authoritative decision record. That record's
   §2 states plainly: *"Protected configuration changes: Require ordinary
   admin authorization plus the enrolled recovery condition,"* with no
   restriction to additive transitions, and §2.1: *"A downgrade uses the
   current, stronger requirements"* — implying a downgrade is possible, not
   forbidden. `guard_apply_doc` (below) implements the general rule; the two
   additive transitions Nido validated remain reachable as the common case
   (they're just ordinary instances of "config changed while `Protected`,"
   authorized by guardian quorum with no new cryptography needed), and the
   guardian-authorized path is fully general with no extra risk. The
   ZK-authorized path reuses the same statement-hashing approach used for
   initiation (a new domain tag, `Action::Reconfigure`, over the same kind of
   32-byte digest) — not a new cryptographic primitive, so there was no
   reason to inherit Nido's narrower "no Reconfigure-domain circuit exists
   yet" limitation, which was about a *specific* circuit they'd built and
   tested, not an interface constraint. See "ZK adapter scope" below for what
   *is* still deliberately not shipped.
3. **No circuit.** See "ZK adapter scope" below.

## Variant A completion, precisely

The account's `apply_doc(doc_json, recovery_evidence)` is the **only**
completion path — there is no dedicated recovery-mutation entry point. A
completed attempt is one whose `apply_doc` call was authorized through the
account's own OZ context-rule mechanism, by a **separate, zero-signer
`self-admin` rule named `"recovery"`** whose sole attached policy is the
adopted controller — installed by `perch-smart-account`'s `apply_doc`
alongside the document's ordinary rules whenever `recovery` is enrolled (see
[`account-mutation-paths.md`](account-mutation-paths.md)).

Soroban's own context-rule selection is what makes this work: a caller's
`AuthPayload` names *which* `context_rule_id` authorizes a given call. For
the `"recovery"` rule — zero declared signers, one attached policy — OZ's
`do_check_auth` defers all validation to that policy's `enforce()`
(`stellar_accounts::smart_account::storage::get_validated_context_by_id`:
*"With policies, defer full validation to enforce()"* — confirmed by reading
the pinned dependency). So selecting the `"recovery"` rule with zero
signatures and calling `apply_doc(target_doc_json, ...)` reaches
`PerchRecovery::enforce`, which:

1. Reads the account's current attempt; refuses unless it is
   `AuthorizedPending`.
2. Refuses if the ledger sequence is before `executable_after` (timelock) or
   at/after `expires_at`.
3. Refuses unless `sha256(target_doc_json)` equals the attempt's frozen
   `target_doc_hash` — set once, at `begin_lost_key_attempt`/
   `begin_compromise_attempt`, never recomputed.
4. Only then: marks the attempt `Completed`, appends its
   `replaced_credentials` to the account's permanent revoked set, spends its
   nullifier (if ZK-sourced) — atomically, as part of authorization
   succeeding, before `apply_doc`'s body (the compile/install) even runs.

**Why the ordinary admin rule can't shortcut this:** the admin rule and the
recovery rule are independent, alternative authorizations for the same
`CallContract(self)` scope. An ordinary admin-authorized `apply_doc` call
never touches `enforce()` at all (it selects the *admin* rule); it can apply
any document the admin chooses to sign for, exactly as before recovery
existed — that is normal account administration, not a recovery bypass.
What `enforce()` prevents is a call *claiming* the recovery rule's authority
(zero signers, relying on the policy) without a live, correctly-targeted,
timelock-elapsed attempt behind it — proven directly in
`crates/integration-tests/tests/recovery.rs` by driving `do_check_auth`
with an explicit rule selection (mirroring `matrix.rs`'s own pattern), the
same mechanism the host uses for a real `__check_auth` invocation.

**Why atomicity holds without a completion-grant flag:** everything in step
4 happens inside the same top-level Soroban invocation as `apply_doc`'s own
body. If the document fails to compile or install (any `DocCompilerError`,
the anti-brick check), the whole transaction reverts — including the
attempt-consuming mutation above — so there is no reachable state where the
attempt is spent but the account's rules are unchanged. This closes the
follow-up review §3.1 gap by construction (no ledger-scoped grant to leave
stale or ungated) rather than by hardening a fragile flag.

## The `guard_apply_doc` gate and why it — not `install`/`uninstall` — is authoritative

`stellar_accounts::smart_account::storage::remove_context_rule` calls a
policy's `uninstall` via `try_uninstall` and **discards the result even if
it panics** (confirmed by reading the pinned dependency directly — this is
exactly the class of gap the follow-up review §3.2 flags in a different
codebase). Since `apply_doc` wipes and reinstalls the *entire* rule set on
every call, a policy that tried to block a `Protected` account's
reconfiguration from inside `uninstall` would simply be ignored, and the
rule would be removed anyway.

The actual gate is `perch-smart-account`'s `apply_doc`, which — whenever
`PerchStorage::recovery_controller` names a currently-adopted instance —
cross-calls that instance's `guard_apply_doc(account, new_recovery,
recovery_evidence)` **before** touching any context rule:

1. **Unconditional:** if a live attempt exists (`CollectingEvidence`, or
   `AuthorizedPending` and not yet expired), refuse. This is property 9
   (configuration consistency), independent of §7's still-open freeze/continue
   question — see [`section-7-gate.md`](section-7-gate.md) — and it is what
   makes `apply_doc`'s own timing "for free" for completion: `enforce` (§
   above) already flips a legitimate completion's attempt to `Completed`
   *before* `guard_apply_doc` runs, so this check reads `false` for exactly
   that call and blocks every other concurrent or racing call.
2. **No change, or no prior enrollment:** always fine — establishing new
   protection, or reapplying an unchanged configuration (including as a side
   effect of a legitimate completion, whose target document carries the same
   `recovery` section as before), needs nothing extra.
3. **Currently `Loss`:** ordinary admin authorization (already established
   by `apply_doc`'s own `require_auth`) is sufficient for *any* new
   configuration, including removing it — §2.1.
4. **Currently `Protected`:** requires the *currently* enrolled condition's
   evidence over a digest binding `(account, controller, Reconfigure,
   old_config_hash, new_config_hash_or_removal)` — guardian quorum via
   `require_auth_for_args` for a guardian-capable mode, a ZK proof over the
   same digest for a ZK-capable mode, both for `Combined`. See
   `crates/integration-tests/tests/recovery.rs`'s
   `protected_reconfigure_requires_guardian_evidence_admin_alone_is_refused`
   for this proven end-to-end (admin alone, no evidence, is refused).

`install`/`uninstall` are therefore plain bookkeeping: `install` shape-checks
the rule it's attached to and writes the config (the gate already ran);
`uninstall` is a deliberate no-op.

## ZK adapter scope

`crates/perch-recovery/src/zk.rs` fixes the **statement** a proof must be
over (network, account, controller, action, config hash, target-or-removal,
attempt nonce, delay — every field the follow-up review §5.3 names for a
proposal commitment) and a minimal, proof-system-agnostic verifier interface
(`verify_proof(statement, nullifier, proof, pool) -> bool`). It ships **no
circuit** and is not tested against one. This is deliberate, per §5.4:
*"Proof-system portability is an interface goal; supporting multiple proof
systems in the first release is not a requirement."* Building and
validating an actual circuit is real cryptographic work with its own review
needs, out of proportion to a schema-and-controller stage; the interface is
designed so a future circuit can be dropped in (any verifier satisfying this
trait) without changing the controller. `ZkOnly`/`Combined` modes are fully
represented in storage, compiled correctly, and gated identically to
`GuardianOnly` — only the "does a real ZK circuit exist to generate proofs
against" question is out of scope here, tracked as follow-up work.

## Controller governance: no admin, ever

The controller has no constructor, no owner/admin storage key, and no entry
point that changes its own code's behavior globally — see
[`vk-and-controller-immutability.md`](vk-and-controller-immutability.md) for
the full requirement and why. Per-account state changes only through: the
account's own authorization (`install`, gated by `guard_apply_doc` upstream),
the enrolled guardians' own authorization (`submit_guardian_approval`,
`submit_guardian_cancel`), or a valid proof against the enrolled verifier
(`submit_zk_proof`, `submit_zk_cancel`). "Upgrading" the controller is
deploying a new instance and an account explicitly adopting it through its
own document — never anything at the existing address.

## Adversarial properties proven end-to-end

`crates/integration-tests/tests/recovery.rs` (guardian-only mode, driving
the real `do_check_auth`/`Policy::enforce` path):

- No attempt at all → completion refused.
- Below guardian quorum → completion refused, and does not promote.
- Quorum reached, before the timelock elapses → completion refused.
- Quorum reached, wrong target document → completion refused, attempt not
  consumed.
- Quorum reached, at/after the timelock, exact target → completes.
- Replaying the same completion → refused (already `Completed`).
- An attempt pending blocks an ordinary `apply_doc` call unconditionally.
- Guardian quorum exactly at the boundary (2 of 3, then 3 of 3) promotes
  only once quorum is actually reached.
- Cancellation evidence is a separate domain from initiation evidence — an
  initiation approval does not count toward cancelling the same attempt.
- A cancelled attempt allows a fresh one afterward.
- A `Protected` reconfiguration (here: disabling recovery entirely) with
  ordinary admin authorization alone is refused.

`crates/perch-ir/tests/recovery.rs` and `crates/perch-recovery` (unit-level,
via `perch_doc_compiler` types) cover the schema/wire side: guardian-only
carries no ZK field at all, `zk-only` carries no guardian field, quorum
bounds, credential-fingerprint resolution, and the canonical-form regression
for documents without recovery.

Not yet covered (tracked, not silently assumed sound): a live ZK circuit
exercising `submit_zk_proof`/`submit_zk_cancel` against a real verifier (no
circuit is shipped — see "ZK adapter scope"); a rule-teardown scenario where
`uninstall` itself panics (this crate's `uninstall` is a no-op by design, so
the property to check is narrower than Nido's — that removal always
succeeds regardless — which follows directly from `uninstall` never being
able to fail); and the full §7 pending-activity enforcement beyond policy
mutation (see [`section-7-gate.md`](section-7-gate.md)).
