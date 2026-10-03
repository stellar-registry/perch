# Recovery controller: design, governance, and upgrade policy

This documents `crates/perch-recovery`: how completion authorizes
`apply_doc`, the reconfigure-authorization rule that governs every change to
enrolled `Protected` recovery, and how the controller itself is governed.

## Design choices, and why

A companion smart-account implementation
([nidohq/nido#206](https://github.com/nidohq/nido/pull/206)) validated the
overall shape this crate implements: an initiation/delay/expiry/cancel/completion
state machine, guardian and ZK evidence checked against one frozen proposal,
a `config_hash` commitment, and completion by authorizing the account's own
document-apply operation rather than a dedicated raw mutator ("Variant A"
below). `crates/perch-recovery` keeps that overall shape, with three
deliberate differences:

1. **Enrollment happens through the document, not a side-channel `enroll`
   call.** That companion implementation received `RecoveryConfig` as a
   direct call argument, because its target account contract's document
   schema had no field for it. Perch's own schema now carries it (see
   [`schema.md`](schema.md)), so enrollment and reconfiguration are just
   what happens when `apply_doc` installs a compiled document whose
   `recovery` section differs from before — the OZ `Policy::install` hook
   receives the compiled config as its install params, the same mechanism
   every other perch policy (the interpreter, `spending_limit`) already
   uses.
2. **`Protected` reconfigure is general, not additive-only.** That
   companion implementation's `reconfigure` entry point accepted exactly two
   transitions (`GuardianOnly→Combined`, `ZkOnly→Combined`) and rejected
   everything else, including under `Loss` — a scope decision for its own
   bounded experiment. Here, a `Protected` account requires ordinary admin
   authorization *plus* the currently enrolled recovery condition to change
   or disable recovery — with no restriction to additive transitions, and a
   downgrade is possible (using the *current*, stronger requirements), not
   forbidden. `guard_apply_doc` (below) implements that general rule; the
   two additive transitions the companion implementation validated remain
   reachable as the common case (they're just ordinary instances of "config
   changed while `Protected`," authorized by guardian quorum with no new
   cryptography needed), and the guardian-authorized path is fully general
   with no extra risk. The ZK-authorized path reuses the same
   statement-hashing approach used for initiation (a new domain tag,
   `Action::Reconfigure`, over the same kind of 32-byte digest) — not a new
   cryptographic primitive, so there was no reason to inherit the narrower
   "no reconfigure-domain circuit exists yet" limitation the companion
   implementation had, which was about a *specific* circuit it had built
   and tested, not an interface constraint. See "ZK adapter scope" below for
   what *is* still deliberately not shipped.
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
attempt is spent but the account's rules are unchanged. A ledger-scoped
completion grant that merely records "a completion happened this ledger,"
without binding *which* mutation it authorized, would not give this
guarantee; this design avoids that class of gap by construction rather than
by hardening a fragile flag.

## Caller authentication on `install`, `enforce`, and `guard_apply_doc`

All three are exported contract functions on a deployed `PerchRecovery`
instance, reachable by a direct call from anyone — not only via OZ's real
install flow or `perch-smart-account`'s `apply_doc`. Each therefore starts
with `<the relevant account>.require_auth()`:

- **`install`** — without it, anyone could call it directly for an arbitrary
  `smart_account` address, overwriting that account's enrolled config with
  attacker-chosen guardians/verifier/profile, entirely bypassing
  `guard_apply_doc`'s reconfiguration gate (which never runs for a direct
  `install` call).
- **`enforce`** (via `complete`) — `context: Context` is an ordinary function
  argument the caller fully controls; nothing about receiving a
  `Context::Contract` value proves it reflects what the host is actually
  authorizing. Without the gate, anyone who knows or reconstructs a pending
  attempt's target document bytes could call `enforce` directly with a
  forged context, consuming the attempt (revoking credentials, spending its
  nullifier) without `apply_doc`'s body ever running.
- **`guard_apply_doc`** — without it, anyone who obtains valid reconfigure
  evidence (for example by observing the real `apply_doc` transaction before
  it lands) could call this entry point standalone, burning a one-time ZK
  nullifier or a guardian's signature with no document ever changing:
  front-running and denial-of-service against the real reconfiguration.

Each succeeds for free on its real path and fails for a direct, unrelated
caller, via Soroban's invoker-contract authorization — the host's documented
first-checked path for `require_auth`: *"if contract C invokes contract D,
then C authorized D... requires no credentials as the host literally
observes the call from C to D"* (`soroban-env-host`'s `auth` module docs).
On the real path, `smart_account`'s own wasm is the direct invoker of each of
these cross-calls (OZ's `do_check_auth` invokes `enforce`; `apply_doc`
invokes `guard_apply_doc` before touching any context rule and invokes
`install` while re-installing its rules), so the check passes without
needing a signature — it is not in tension with `enforce` running under a
zero-signer context rule. A direct call from anywhere else has no such
invoker relationship and is rejected before touching storage. This is
verified directly against the pinned `soroban-env-host`'s own
`require_auth_internal`/`maybe_check_invoker_contract_auth` (invoker checked
first, unconditionally, before the account-authorization-tracker path that a
custom account's own recursive `__check_auth` reentry would otherwise
conflict with).

## Binding guardian evidence to a specific attempt

`submit_guardian_approval` and `submit_guardian_cancel` authenticate a digest
— built by `zk::statement` from `(account, controller, action, config_hash,
target_or_removal, attempt_id, delay_ledgers)` — via
`require_auth_for_args`, the same statement shape (and, for approval, the
same statement) a ZK initiation or cancellation proof is verified against.
Authenticating only the bare `(account, guardian)` call arguments, as an
earlier version of this crate did, would let a guardian's signature be
delayed and later consumed for a *different* attempt than the one they
actually approved — the account could declare a fresh attempt after the
first was cancelled or expired, and a stale but still-valid signature over
just `(account, guardian)` would satisfy it. Binding to the attempt's id,
action, and target closes that: a signature is only ever valid for the exact
attempt the guardian saw.

## The `guard_apply_doc` gate and why it — not `install`/`uninstall` — is authoritative

`stellar_accounts::smart_account::storage::remove_context_rule` calls a
policy's `uninstall` via `try_uninstall` and **discards the result even if
it panics** (confirmed by reading the pinned dependency directly). Since
`apply_doc` wipes and reinstalls the *entire* rule set on every call, a
policy that tried to block a `Protected` account's reconfiguration from
inside `uninstall` would simply be ignored, and the rule would be removed
anyway.

The actual gate is `perch-smart-account`'s `apply_doc`, which — whenever
`PerchStorage::recovery_controller` names a currently-adopted instance —
cross-calls that instance's `guard_apply_doc(account, new_recovery,
recovery_evidence)` **before** touching any context rule:

1. **Unconditional:** if a live attempt exists (`CollectingEvidence`, or
   `AuthorizedPending` and not yet expired), refuse. This has to hold
   regardless of whether the account's chosen pending-activity policy
   applies here (see [`pending-activity-policy.md`](pending-activity-policy.md)
   for that separate, still-open question) — it's what makes `apply_doc`'s
   own timing "for free" for completion: `enforce` (above) already flips a
   legitimate completion's attempt to `Completed` *before* `guard_apply_doc`
   runs, so this check reads `false` for exactly that call and blocks every
   other concurrent or racing call.
2. **No change, or no prior enrollment:** always fine — establishing new
   protection, or reapplying an unchanged configuration (including as a side
   effect of a legitimate completion, whose target document carries the same
   `recovery` section as before), needs nothing extra.
3. **Currently `Loss`:** ordinary admin authorization (already established
   by `apply_doc`'s own `require_auth`) is sufficient for *any* new
   configuration, including removing it.
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
over — network, account, controller, action, config hash, target-or-removal,
attempt nonce, delay — and a minimal, proof-system-agnostic verifier
interface (`verify_proof(statement, nullifier, proof, pool) -> bool`). It
ships **no circuit** and is not tested against one. Building and validating
an actual circuit is real cryptographic work with its own review needs,
out of proportion to this change; the interface is designed so a future
circuit can be dropped in (any verifier satisfying this trait) without
changing the controller. `ZkOnly`/`Combined` modes are fully represented in
storage, compiled correctly, and gated identically to `GuardianOnly` — only
"does a real ZK circuit exist to generate proofs against" is out of scope
here, tracked as follow-up work in [issue #85](https://github.com/stellar-registry/perch/issues/85).

## Bounding permissionless evidence collection

`begin_lost_key_attempt`/`begin_compromise_attempt` are permissionless —
declaring intent carries no authority, so nothing gates who may call them.
Without a bound on how long the resulting attempt may sit in
`CollectingEvidence`, a single such call would block every ordinary
`apply_doc` indefinitely (via `guard_apply_doc`'s unconditional live-attempt
check) if the enrolled mode's evidence simply never arrives — a
permissionless, no-cost denial-of-service against the account's own ordinary
administration. `Attempt::evidence_deadline`, set at `begin_attempt` to
`created_at + expiry_ledgers` (the account's own configured recovery-process
budget, reused rather than adding a second schema field for the same kind of
window), bounds this: `is_live` treats a `CollectingEvidence` attempt as
no-longer-live once its deadline passes, at which point `guard_apply_doc`
stops blocking, and a fresh attempt can replace it.

## What the commitment does, and does not, verify

`target_doc_hash` and `config_hash` are content-addressed commitments —
`sha256` of specific bytes — checked for exact equality. They prove the
account applies *exactly the document that was committed to*, byte for byte.
They do **not** parse or inspect that document's contents on-chain: the
controller has no JSON parser and no `perch-ir` dependency in its deployable
build, by design (it stays a small, auditable piece of logic with no
document-schema coupling beyond the wire types `perch-doc-compiler` already
produces).

Two consequences follow, and are evidence-provider/reviewer responsibilities
rather than on-chain-enforced properties:

- **A compromise-recovery target must actually be the approved baseline's
  content** — the controller only checks that `target_doc_hash` equals the
  enrolled `baseline.doc_hash` (see `begin_compromise_attempt`); it cannot
  independently verify what that baseline hash "means" beyond having been
  declared at enrollment. Reviewing that a declared baseline hash genuinely
  names a real, previously-approved document is part of enrollment review —
  the same way reviewing that a `Scope::Contract` address is the intended
  contract is part of ordinary rule review (see
  [`schema.md`](schema.md)'s "Non-circular baseline commitment").
- **A target document's actual content should only replace the credentials
  named in `replaced_credentials`, and should not reintroduce a previously
  revoked credential** — the controller checks that the caller's *declared*
  `replaced_credentials` are a subset of the enrolled `replaceable` set at
  attempt creation, but it cannot inspect the target document's actual
  signer list at completion time to confirm the applied document's real
  diff matches that declaration, or that it avoids every credential in the
  account's permanent `revoked` set. Guardians and ZK-circuit designers are
  the parties who see the actual target document before approving or
  proving against its hash; that review — confirming the document only
  changes what it claims to, and does not resurrect a revoked credential —
  is where this property is enforced, not on-chain. Whoever operates a
  recovery-enrolled account should treat "the evidence provider verified the
  target document's actual diff before signing" as part of what a guardian's
  or prover's approval means, the same way any multisig signer is expected
  to review what they're signing before approving it — not something the
  hash commitment can substitute for.

## Keeping permanent state alive

Soroban persistent storage entries have a finite maximum TTL (`Env::storage()
.max_ttl()`) — there is no "forever" setting. The controller extends the
relevant entries to that current maximum on every write, and additionally on
read in the highest-traffic path (`require_config`, used by every
begin/approve/proof/cancel call) and inside `guard_apply_doc` (every
`apply_doc` call on an enrolled account) — but an entry nothing ever touches
again (an enrolled but otherwise-idle account's config, revoked set, or a
long-completed attempt's spent nullifier) will still eventually expire
absent some renewal.

`PerchRecovery::renew(account)` is the explicit, permissionless keep-alive
for exactly that gap: it extends every one of `account`'s existing recovery
entries (config, current/most recent attempt and its nullifier if spent,
revoked set, and the lifetime counters) to the current maximum. It changes
nothing about what any of that state means — it only ever extends TTL — so
anyone (a keeper script, a wallet's own periodic background job) can call it
safely and without authorization. An integration relying on recovery staying
available (or on revocation staying permanent) through long account
inactivity should call `renew` periodically; this is a genuine platform
constraint recovery inherits, not a gap specific to this controller's logic.

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

`crates/integration-tests/tests/recovery.rs` (guardian-only mode for
completion, driving the real `do_check_auth`/`Policy::enforce` path;
guardian-only/ZK-only/`Combined` for cancellation, the latter two against a
mock verifier — see "ZK adapter scope" for what that does and doesn't
prove):

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
- `Combined`-mode cancellation requires BOTH a guardian quorum AND a valid ZK
  cancellation proof for the same attempt — guardian quorum alone does not
  cancel, a ZK proof alone does not cancel, and only once both factors are
  present does the attempt cancel.
- A cancelled attempt allows a fresh one afterward.
- A cancellation factor (guardian or ZK) arriving after an attempt has
  already completed is refused, not silently accepted — a completed attempt
  can never be flipped back to `Cancelled`.
- A completed attempt's nullifier is never released back to unspent by a
  later `begin_*_attempt` call — only a cancelled or expired attempt's
  nullifier is released.
- A `Protected` reconfiguration (here: disabling recovery entirely) with
  ordinary admin authorization alone is refused.
- A suspected-compromise attempt whose target does not equal the enrolled
  baseline is refused; the actual baseline is accepted.
- A `CollectingEvidence` attempt stops blocking ordinary `apply_doc` calls
  once its evidence deadline elapses, and a fresh attempt can then replace
  it.
- A ZK initiation proof's nullifier is reserved immediately: reusing it for
  a *different* statement (the cancellation domain, on the same attempt) is
  refused before either use completes — not only once one of them does.
- Fingerprinting a signer's credential is hex-case-insensitive: re-declaring
  the identical physical key under different hex casing resolves to the same
  fingerprint.

`crates/perch-recovery/src/zk.rs`'s own unit test pins down that
`statement()` — the digest guardian signatures and ZK proofs are bound to —
actually varies with every one of account/controller/action/config/target/
attempt-id/delay, independent of any authorization mocking.

`crates/perch-ir/tests/recovery.rs` and `crates/perch-recovery` (unit-level,
via `perch_doc_compiler` types) cover the schema/wire side: guardian-only
carries no ZK field at all, `zk-only` carries no guardian field, quorum
bounds, credential-fingerprint resolution, and the canonical-form regression
for documents without recovery.

Not yet covered (tracked, not silently assumed sound):
- a live ZK circuit exercising `submit_zk_proof`/`submit_zk_cancel` against a real verifier (no circuit is shipped — see "ZK adapter scope"). Tracked in [#85](https://github.com/stellar-registry/perch/issues/85).
- a rule-teardown scenario where `uninstall` itself panics (this crate's `uninstall` is a no-op by design, so the property to check is narrower — that removal always succeeds regardless — which follows directly from `uninstall` never being able to fail); 
- the full pending-activity enforcement beyond blocking conflicting document changes (see [`pending-activity-policy.md`](pending-activity-policy.md)). Tracked in [#84](https://github.com/stellar-registry/perch/issues/84).
- a live rejection of a direct, unauthenticated call to `install`/ `enforce`/`guard_apply_doc` under genuinely enforcing (non-mocked) authorization — the existing suite runs under mocked auth throughout (see "Caller authentication" above for the reasoning verified instead against the pinned host source directly). Tracked in [#86](https://github.com/stellar-registry/perch/issues/86).
