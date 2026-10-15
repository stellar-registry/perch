# Recovery specification

**Status: normative.** This document specifies perch account recovery at
this revision: states, transitions, who may authorize what, which document
changes a recovery may make, account upgrades, the ZK boundary, and the
membership pool. Where any other document disagrees with it, this document
wins.

Companion material:

- [`statement.md`](statement.md): byte layouts of the recovery statement,
  credential fingerprints, and replacement sets.
- `crates/perch-recovery-interface`: the code half of this spec (statement
  types, encodings, the ZK adapter, verifier, and pool interfaces, the
  account constants). `testdata/recovery/statement-v2.json` holds vectors
  produced by an independent implementation
  (`scripts/recovery-statement-vectors.py`).
- [`budgets.md`](budgets.md): measured resource budgets and the pool-depth
  rule.
- [`cap-0071.md`](cap-0071.md): the CAP-0071 delegated-auth and
  invoker-auth host behaviour this spec relies on, with the tests that pin it.
- [`implementation.md`](implementation.md): where each section is
  implemented and which tests pin it.

Keywords: **must**, **must not**, **may** are requirements on the
implementation (the controller, the account, the adapter, the pool, the doc
compiler). "Refuse" means the call fails and changes no state. Soroban
rolls back every write of a failing invocation, so no transition in this
spec both refuses and records something: a transition either succeeds and
writes, or refuses and writes nothing. Error names are given as
`Enum::Variant`; `RecoveryError` is the controller's, `PerchAccountError`
and `PerchAuthError` the account's, `DocCompilerError` the doc compiler's,
`ZkAdapterError` the adapter's, and `PoolError` the pool's.

## Summary of requirements

Other documents cite these requirements by ID.

| # | Topic | Requirement | Section |
| --- | --- | --- | --- |
| D1 | Activity during recovery | `Protected`: while an attempt is authorized, the account authorizes nothing except that attempt's completion, on every path. `Loss`: ordinary activity continues. The profile alone fixes this; there is no separate activity setting. | §9 |
| D2 | Evidence-free attempts | Anyone may open an attempt. Any number of attempts may collect evidence at once, and a collecting attempt blocks nothing. | §6 |
| D3 | Authorized window | From authorization until completion, cancellation, or expiry, both profiles refuse every policy change except that attempt's completion, and refuse upgrade scheduling and execution. | §9, §12 |
| D4 | Reconfiguration | `Loss`: owner authorization. `Protected`: owner authorization plus the enrolled condition's evidence over a `Reconfigure` statement (`Combined`: guardian quorum and a ZK proof). | §5, §10 |
| D5 | Cancellation | The enrolled condition's evidence over a `Cancel` statement, in both profiles. Under `Loss`, owner authorization alone also cancels, and that veto is never capped. An evidence-based cancellation of an authorized attempt counts toward `max-cancels`. | §6 |
| D6 | Permitted changes | The target document is derived on-chain from the source and a declared replacement set. For lost-key the source is the applied-document snapshot; for compromise it is the enrolled baseline's signers and rules, with the current recovery section. Nobody chooses a target hash. | §7 |
| D7 | Revocation | A credential a recovery replaces leaves the account, so the target may not keep it in any slot (swaps and no-op replacements are refused at T1), and it never authorizes again. A completion revokes the union of (a) the credentials it explicitly replaced in its source document, the baseline included, and (b) every credential it removed from the current document. Both go into the account's permanent revoked set. Every applied document is checked against that set, on every path. | §7.3, §8 |
| D8 | Completion vs. reconfiguration | A completion is recognised by the attempt consumed in the same invocation. It may change exactly what its replacement set declares. Configuration identity is the canonical text of the recovery section, so rotating a signer's key is not a reconfiguration. | §10 |
| D9 | Nullifiers | One nullifier per enrolled ZK credential, owned by that `(account, enrollment)`. It is either unspent or spent. Only a completion of that account spends it; nothing ever un-spends it. Proofs for any action need it unspent. Nullifiers are never reserved, so there is nothing to release. | §11 |
| D10 | Stale state | Leaves and nullifiers bind an enrollment id the configuration names, and the account refuses to re-enroll an id it used before. Every configuration change and every completion bumps the per-account epoch, and evidence or attempts from an older epoch are dead. | §3, §11 |
| D11 | Upgrades | Owner authorization (plus, under `Protected`, condition evidence over an `Upgrade` statement binding the Wasm hash and the epoch). Executable after 120 960 ledgers. An account-owned **recovery generation** invalidates the request whenever recovery configuration changes, including across unenrolled → enrolled → unenrolled. Executing an upgrade advances it. Blocked during an authorized attempt. | §12 |
| D12 | Invoker-only hooks | The account never authorizes a reserved hook name (`install`, `uninstall`, `enforce`, `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `rcv_insert`, `rcv_gate`) through `__check_auth`, and never calls one through `execute`. Controller, pool, and policy hooks are reachable only from the account's own controlled flows. That name guard, not a ban on rules scoped to the controller, is what protects the controller: a document may scope rules to its own controller so the account can act as a guardian there. Guardian and ZK evidence is always submitted through non-reserved entry points and recorded; hooks only read the records. | §2, §5, §15 |
| D13 | Statement | One `RecoveryStatement`, encoded at fixed width and hashed with SHA-256. Guardians authorize the digest and the circuit binds it. | §4 |
| D14 | ZK boundary | The controller passes the structured statement to an adapter. The adapter checks the circuit id, field canonicality, root membership in the enrolled pool, and the proof. Public inputs are `root, nullifier, statement_hash`. | §13 |
| D15 | Pool | Depth 32 (chosen by `budgets.md`'s depth rule; a depth-24 build is the fallback). A full tree rolls over automatically. Roots are accepted as `(tree_id, root)`, and every root a tree has ever had stays acceptable. | §14 |
| D16 | No re-entry | Soroban refuses to re-enter a contract already on the call stack. No hook calls back into the account; the account passes what hooks need. The `Protected` freeze is a mirror in the account's own storage, set by the controller through the account's invoker-only `rcv_gate`, never a cross-contract read from `__check_auth`. | §9, §15 |

## 1. Scope and vocabulary

In scope: guardian, ZK, and combined recovery for perch smart accounts under
the `Loss` and `Protected` profiles; recovery reconfiguration; account
upgrades on recovery-enrolled accounts; the membership pool and ZK
verification boundary.

Not covered: carrying accounts, addresses, ZK secrets, commitments, or
attempts over from deployments built without this recovery support;
mainnet rollout; concealing which accounts use ZK recovery (§14.3); dummy
commitments; more than one ZK backend; CAP-0085 governance-managed
executables.

Recovery requires an account whose Wasm implements this specification. An
account's doc compiler and `apply_doc` are fixed by its Wasm (§16), so an
account built without recovery support cannot enroll in place.

| Term | Meaning |
| --- | --- |
| account | A perch smart account built with this spec's recovery support. Always a contract (`C...`) address. |
| `L` | The current ledger sequence, `e.ledger().sequence()`. All timing is in ledger counts. |
| owner authorization | The account authorizing through any of its ordinary context rules (in practice the self-admin rule), via `__check_auth`. Never the recovery rule. |
| recovery rule | The zero-signer context rule the account installs while recovery is enrolled. Its only policy is the controller, and it authorizes only a completion (§6.3 T5, §10). |
| controller | The constructorless, immutable recovery-controller instance named by the applied document's `recovery.controller`. |
| condition | The enrolled mode's evidence requirement over a given statement (§5). |
| statement | A `RecoveryStatement` (§4). Every piece of evidence is bound to exactly one. |
| attempt | A lost-key or compromise recovery in progress, identified by `(account, attempt_id)`. |
| epoch | The controller's per-account counter, starting at 0 and increasing by one every time the account's recovery configuration changes at that controller (§3.3). |
| enrollment id | The 32-byte identifier of the account's current ZK credential (§3.1). |
| adapter, pool | The two ZK contracts (§13, §14). The adapter embeds the proof verifier and its verification key. |

## 2. Roles and trust

| Party | Holds | Trusted for |
| --- | --- | --- |
| Owner | The admin signers of the applied document | `Loss`: everything, including vetoing recovery. `Protected`: ordinary activity outside an authorized window. Not trusted to change recovery configuration or upgrade the account without the condition. |
| Guardians | Their own Stellar addresses (`G...` or `C...`) | Approving exactly the statements they sign. Guardians must check out of band that the replacement credentials they approve belong to the person recovering. The chain cannot check that. |
| ZK secret holder | The secret behind the enrolled commitment | Same as a guardian quorum, for the ZK factor. |
| Anyone | Nothing | Opening attempts, submitting evidence others produced, completing an attempt whose evidence and timelock are satisfied, publishing a baseline whose hash is enrolled, renewing storage. None of these needs authority. |
| Controller, adapter (with its embedded verifier), pool, doc compiler | Code at a content-addressed address | Behaving as their published source says, forever. They have no admin and cannot be upgraded in place (§16). |
| Indexer, relayer | Off-chain copies of public data | Availability only. Nothing an indexer returns is trusted without on-chain checks: a stale or wrong witness produces a proof the pool refuses. |

**Threat model by profile.**

- `Loss` assumes the owner's key may be lost, but not stolen. It protects
  against loss, and lets the owner veto a recovery they did not ask for
  (owner cancellation), for example one opened by a colluding guardian
  quorum.
- `Protected` assumes the owner's key may be stolen. For recovery
  configuration, upgrades, and the authorized window, the condition is
  trusted over the owner key.
- No profile can tell apart two parties who hold the same factor. Under
  `ZkOnly`, a thief of the ZK secret races the owner. Under `GuardianOnly`, a
  colluding quorum is the owner as far as recovery can tell. `Combined`
  requires both factors.
- Under `Protected`, `max-cancels` bounds a cancellation war between two
  holders of the cancelling factor. Once it is used up, the next attempt to
  be authorized completes, whoever opened it. Under `Loss`, the owner's veto
  (T7) is never capped, so condition-holders cannot use up the cap to remove
  it.
- `Protected` without a baseline does not protect against a thief who holds
  the owner key. Any document change invalidates a collecting lost-key
  attempt (Transitions T4), and only compromise recovery is immune to that.
  The protocol keeps `baseline` optional; wallets should require one for
  `Protected`.
- **A rule scoped to the account's own controller is safe, and needed.** An
  account that is a guardian of other accounts at the controller it uses
  itself signs those approvals in contexts naming that controller
  (`submit_guardian`, `approve_change`). Its document therefore needs a
  rule scoped to the controller, or a `Default` rule.

  The reserved-name guard (§15, invariant I1) is what keeps such a rule's
  signers away from the controller's sensitive entry points. It refuses all
  eight reserved names — `install`, `uninstall`, `enforce`, `rcv_sync`,
  `rcv_cancel`, `rcv_upgrade`, `rcv_insert`, and `rcv_gate` (D12, §15) — on any
  contract, whatever rule is selected. What such a rule
  grants is exactly what it says: its signers approve, as this account,
  statements for accounts that list this account as a guardian. The account
  cannot list itself (§15), so the rule never touches the account's own
  recovery.

## 3. Configuration

### 3.1 Schema

`recovery` is an optional member of the policy document. A document without
it enrolls no recovery, and its canonical form has no `recovery` key
(`CANONICAL.md` omits absent members). When present it is:

```text
recovery: {
  profile:        "loss" | "protected",
  mode:           { type: "guardian-only", guardians: [addr], quorum: u32 }
                | { type: "zk-only",  adapter, circuit-id, pool, enrollment-id, commitment }
                | { type: "combined", guardians, quorum, adapter, circuit-id, pool, enrollment-id, commitment },
  controller:     C-address,
  baseline?:      { doc-hash: hex32 },
  replaceable:    [signer id],          // non-empty, declared signers
  delay-ledgers:  u32 > 0,
  expiry-ledgers: u32 > 0,
  max-cancels:    u32 > 0
}
```

| Field | Meaning and constraints |
| --- | --- |
| `profile` | `loss` or `protected` (§2). Independent of `mode`: every mode pairs with either profile. |
| `mode` | A tagged variant carrying only its own fields. A `guardian-only` mode has no adapter, pool, or enrollment id, and no path consults one (§5). |
| `guardians`, `quorum` | Non-empty, distinct `G...` or `C...` addresses; `1 ≤ quorum ≤` the number of guardians. The account may not list itself (§15). |
| `adapter` | The ZK adapter the controller calls (§13), a `C...` address. It embeds its verifier. |
| `circuit-id` | Exactly 32 bytes: `sha256` of the adapter's embedded verification key. The adapter refuses any other value. |
| `pool` | The membership pool (§14), a `C...` address. Required for ZK modes; root acceptance is bound to this pool. |
| `enrollment-id` | 32 random bytes naming the current ZK credential. It is bound into the leaf and the nullifier (§3.4, §11). |
| `commitment` | The credential's inner commitment `Poseidon2(DOM_LEAF, secret)`, a canonical BN254 field element. The account inserts the leaf from it (§14.2). |
| `controller` | The adopted recovery controller, a `C...` address. |
| `baseline` | Optional. The canonical hash of the baseline document compromise recovery restores (§3.5). Without it only lost-key recovery is available. |
| `replaceable` | Non-empty, distinct ids of declared signers a recovery may replace. The compiled form keeps signer ids, not credential fingerprints, so rotating a key is not a reconfiguration (§3.2). Revocation fingerprints credentials separately (§8). |
| `delay-ledgers`, `expiry-ledgers`, `max-cancels` | Non-zero. Timing is in ledgers (§4, §6.2); `max-cancels` is a lifetime count (§6.3 T6). |

Hashes, `circuit-id`, `enrollment-id`, and `commitment` are written as 64
lowercase hex characters. The doc compiler refuses a document that breaks
these constraints (`DocCompilerError::DocParse` for an unknown field or a
bad shape, `DocInvalid` for a bad value), and a rule scoped to the
document's own adapter or pool (§15). A document does not know which
account applies it, so only the controller refuses a self-listing account.
The controller re-checks the timing terms and the quorum range in
`rcv_sync` as well (`RecoveryError::InvalidConfiguration`), because any
contract can call `rcv_sync` for itself.

The commitment is part of the document, so `config_hash` binds it. Through
`config_hash`, so do the owner's signature on `doc_json`, every
reconfiguration approval, and every attempt's derived target.

The account takes the commitment only from the compiled document, never
from a call argument, so nobody who resubmits the same approvals with a
stolen owner key, or who submits a recovery completion first, can
substitute another. The commitment is public: it is in the applied
document, and the pool's insertion event reveals the leaf. The secret must
therefore be a uniformly random field element with at least 128 bits of
entropy, because a guessable secret can be found offline.

The compiled form is `perch_recovery_interface::config::CompiledRecoveryConfig`.
It is defined in the interface crate rather than the doc compiler, so the
compiler, the account, and the controller share one definition. It carries
`config_hash` (§3.2) and the replaceable signer ids.

### 3.2 Configuration identity

`config_hash = sha256("perch/recovery/config" || C)`
(`config::config_hash`), where `C` is the canonical JSON (`CANONICAL.md`)
of the document's `recovery` member. The doc compiler computes it and
returns it with the compiled configuration. Evidence providers compute it
from the document they are shown.

Configuration identity is therefore the reviewed text: profile, mode,
guardians, quorum, adapter, circuit id, pool, enrollment id, commitment,
controller, baseline hash, replaceable signer ids, and timing. Rotating a
signer's key elsewhere in the document does not change it. Renaming a
replaceable signer id does. [`formal-verification-impact.md`](formal-verification-impact.md)
states what the Lean model proves about this preimage and the canonical
recovery member.

**Per-rule hash.** Next to `config_hash`, each rule has a
`rule_hash = sha256("perch/rule" || R)` (`fragment::rule_hash`), where `R`
is exactly the bytes the rule contributes to the canonical document: one
element of the `rules` array (`CANONICAL.md`, "Fragment hashes"; vectors in
`testdata/rule-hashes.json`).

- **Provenance.** An installed interpreter program carries its rule's
  `rule_hash` as provenance, instead of the whole document's `doc_hash`.
  Editing one rule, or any non-rule member, then leaves every other rule's
  install parameters unchanged, which lets `apply_doc` reinstall only the
  rules that changed.
- **Scope.** A `rule_hash` covers the rule text and its signer ids, not the
  signers' credentials. Only `doc_hash` identifies the whole document.
- **Domain separation.** The `perch/rule` and `perch/recovery/config` tags
  are prefix-free and cannot begin a canonical document (which starts with
  `{`), so the three hashes never share a preimage.

### 3.3 Epoch

The controller keeps a per-account `epoch: u64`. It starts at 0 and
increments by one on every successful enrollment, reconfiguration
(including a controller switch away from or to this controller), removal,
completed recovery, and executed account upgrade. It never decreases and
is never reset. Every statement binds `(epoch, config_hash)`. Every attempt
records the epoch it was opened under and is dead under any other.

The epoch belongs to one controller, and an unenrolled account has none.
Upgrade staleness is therefore judged by the account's own counterpart,
the **recovery generation** (§12). The account keeps it, it advances on
every recovery transition at any controller, and it continues through
periods without recovery.

Removing recovery and enrolling again, or enrolling a different guardian
set, therefore bumps the epoch. Every attempt and every piece of evidence
from before is dead, whether or not some other path left it in storage.

### 3.4 Enrollment ids

An enrollment id names one ZK credential. Clients generate ids as 32 random
bytes.

**Ids are never reused.** The **account** keeps the append-only set of
every enrollment id it has enrolled, and `apply_doc` refuses a
configuration whose enrollment id differs from the current one and is in
that set (`PerchAccountError::EnrollmentReused`). A retired or consumed
credential's leaf can therefore never become valid again, including after a
switch to a different controller, whose nullifier records start empty. At
T1 the controller applies the same check to the enrollment a replacement
set declares (`RecoveryError::EnrollmentIdReused`, §7.3 rule 4), and the
pool refuses a second insertion for the same `(account, enrollment_id)`
(`PoolError::EnrollmentIdTaken`, §14.2).

**Unchanged, or a new id.** The ZK factor `(adapter, circuit-id, pool,
enrollment-id, commitment)` either stays entirely unchanged across an
`apply_doc` or carries a new `enrollment-id`
(`config::zk_factor_transition_ok`). Adding or removing the factor is
outside this rule. Both the account and the controller enforce it:

- **The account**, in `apply_doc`, compares the compiled factor with the
  factor of its applied document and refuses before calling any controller
  or changing any rule (`PerchAccountError::ZkFactorChangedInPlace`). This
  check holds across a switch between controllers.
- **The controller**, in `rcv_sync`, compares the new factor with the factor
  of the configuration it stores for the account, at enrollment and at
  reconfiguration (`check_zk_wiring`), and refuses with
  `RecoveryError::ZkFactorChangedInPlace`. At an enrollment it stores no
  factor, so the comparison passes there. This check is what binds a
  contract that is not a perch account and calls the shared controller's
  `rcv_sync` for itself.

The account inserts a leaf exactly when the enrollment id changes, into the
configured pool, from the compiled document's commitment
(`config::leaf_to_insert`, §14.2).

**Wiring.** Whenever the ZK factor changes at enrollment or
reconfiguration, `rcv_sync` refuses with `RecoveryError::ZkWiringMismatch`
unless:

- the adapter's `circuit_id()` equals `circuit-id`;
- the adapter's `tree_depth()` equals the pool's `depth()`.

Without these checks a factor could be enrolled that no proof can ever
satisfy, which would permanently lock a `Protected` account's
reconfiguration and upgrades. A completion's ZK rotation changes only the
enrollment id and the commitment (§7.3 rule 4), so it keeps wiring that was
already checked.

### 3.5 Baselines

`baseline.doc-hash` names the canonical hash of the baseline document a
compromise recovery restores. A baseline is approved by approving the
recovery configuration that names it. Under `Loss` that is the owner; under
`Protected` it is the owner plus the condition. Changing or removing it is a
reconfiguration. The chain does not check that the baseline was ever the
account's applied document (the account stores only its current one). What
it enforces is that only the approved configuration can name one.

The baseline's content must be on-chain before a compromise attempt can
open. `publish_baseline(account, doc_json)` on the controller is
permissionless. It compiles `doc_json` with the account's doc compiler and
stores the canonical bytes only if:

- the canonical hash equals the enrolled `baseline.doc-hash`;
- the document compiles for this network;
- an admin rule survives the anti-brick check.

Otherwise it refuses with `RecoveryError::BaselineMismatch`, or
`RecoveryError::NoBaseline` when the configuration names no baseline.
Anyone holding the reviewed document may publish it. Publishing changes no
authority.

A baseline document's own `recovery` member is ignored (§7.2). This keeps
the commitment non-circular and prevents a compromise recovery from rolling
the recovery configuration back to whatever the baseline carried.

### 3.6 Storage lifetime

Every counter and set this specification relies on lives in persistent or
instance storage. An archived persistent entry is unavailable, never
absent: a transaction that touches it must restore it first. A counter
therefore cannot silently reset to zero through TTL expiry. Perch's
contracts extend the persistent entries they write to the network maximum,
except where the table says otherwise, and permissionless renewal entry
points extend existing entries without changing their meaning:

| Contract | State | Renewed by |
| --- | --- | --- |
| Controller | Configuration, published baseline, epoch, attempt-id counter, `invalidate_below`, cancellation count, the authorized attempt's id and record | `renew(account)` |
| Controller | Spent nullifiers, one entry per `(account, nullifier)` (§11) | `renew_nullifier(account, nullifier)` |
| Controller | Recorded change approvals, one entry per `(account, digest)` (§5) | Not renewed. A write extends the entry only far enough to cover its `valid_until`, after which the approval is stale anyway. |
| Account | Instance storage: applied `doc_hash`, adopted controller, recovery-rule id, applied ZK factor, freeze mirror (§9), recovery generation, pending upgrade and request counter (§12), configuration revision (§15) | `renew(fingerprints, enrollment_ids)`; writes do not extend the instance |
| Account | Applied document bytes and fingerprints; the revoked set and the enrolled-id set, one entry per fingerprint or id | The same `renew`, for the entries it names |
| Account | Installed-rule records (§7.5) | Not by `renew`; extended when written |
| Account (OZ storage) | Context-rule, signer, and policy entries | Not by `renew`. OZ extends an entry it reads to 30 days when fewer than 29 remain; nothing else extends them. |
| Pool | Tree states, every root, every leaf, enrollment records, the current-tree pointer (§14) | `renew_tree`, `renew_root`, `renew_leaves`, `renew_enrollment` |

Collecting attempts may live in temporary storage with a TTL of at least
their evidence window. Losing one to expiry is equivalent to its evidence
window ending. The controller stores a collecting attempt persistently when
its evidence window is longer than the network's maximum TTL, and every
attempt once it is authorized. The completion marker (§6.3 T5) is
temporary.

## 4. The recovery statement

```text
RecoveryStatement {
  network_id: BytesN<32>,          // e.ledger().network_id()
  account:    Address,             // contract
  controller: Address,             // contract; for Reconfigure, the currently adopted one
  config:     { epoch: u64, config_hash: BytesN<32> },
  timing:     { delay_ledgers: u32, expiry_ledgers: u32, valid_until_ledger: u32 },
  subject:    LostKey(AttemptSubject) | Compromise(AttemptSubject)
            | Cancel { attempt_id, attempt_statement }
            | Reconfigure(Remove | Set(new_config_hash))
            | Upgrade { request_id, wasm_hash }
}
AttemptSubject { attempt_id, source_doc_hash, target_doc_hash, replacements_hash }
```

`source_doc_hash` and `target_doc_hash` are document identities. The
attempt's `target_bytes_hash` (T1) is not in the statement: evidence approves
the identity, and application proves the applied document has it (T5).

The encoding (`statement.md`) is fixed-width per action. The byte at
offset 25 is the action code (1 lost-key, 2 compromise, 3 cancel,
4 reconfigure, 5 upgrade), which also selects the subject layout. The digest is `sha256(encoding)`.

**Construction.** The controller builds every statement from its own state.
A caller never supplies one. The caller supplies only:

- the evidence;
- for `Reconfigure` and `Upgrade`, the subject and the `valid_until_ledger`
  being approved (to `approve_change`/`submit_zk_change`, and again, as
  `approval_valid_until`, to the `apply_doc` or `schedule_upgrade` that uses
  the approval). The consuming hook rebuilds the subject from the compiled
  configuration or the Wasm hash the account passes.

Evidence providers read the exact statement to sign or prove from the
controller's `statement(account, attempt_id, domain)` and
`change_statement(account, subject, valid_until)` views.

**Binding.** Guardians authorize `require_auth_for_args((digest,))` inside
a non-reserved controller entry point that records their approval:
`submit_guardian` for attempts, `approve_change` for reconfiguration and
upgrades. Reserved hooks only read recorded approvals.

This placement matters. A guardian's `__check_auth` sees the function its
approval is collected in, and a guardian that is itself a perch account
refuses every reserved name (§15; `cap-0071.md` C7). The ZK circuit binds the
digest through the `statement_hash` public input (§13). In `Combined` mode
both factors therefore approve the identical statement.

**Freshness.** Evidence for statement `S` is accepted at ledger `L` only if
`L ≤ S.valid_until_ledger` (`RecoveryStatement::check_fresh`). Who sets the
bound depends on the action:

- `LostKey`/`Compromise`: the controller, to the attempt's evidence
  deadline (§6.2).
- `Cancel`: the controller, to the attempt's `cancel_until =
  evidence_deadline + delay_ledgers + expiry_ledgers`, fixed at T1 and never
  earlier than the attempt's last live ledger. Approvals gathered over
  several transactions therefore all sign one statement, and the attempt's
  liveness is the effective bound.
- `Reconfigure`/`Upgrade`: the evidence provider. For these, evidence is
  also refused unless `S.valid_until_ledger − L ≤ S.expiry_ledgers`, so a
  standing approval cannot outlive the account's own recovery window.

`check_fresh` refuses with `StatementError::EvidenceExpired` or
`StatementError::EvidenceWindowTooLong`; the controller reports both as
`RecoveryError::EvidenceExpired`. Guardian clients should also set
Soroban's `signature_expiration_ledger` no later than `valid_until_ledger`.

**Timing.** Every timing term is a ledger count. There is no seconds field
and no seconds-to-ledgers conversion anywhere. Protocol constants are
defined in ledgers (`ACCOUNT_UPGRADE_DELAY_LEDGERS`). Where a constant is
described in days, that is its nominal duration at 5-second ledgers, not a
conversion of a user-supplied value.

**Replay.** A statement names one account, network, controller, epoch,
configuration, action, and subject. The places replay is stopped:

| Statement | What stops replay |
| --- | --- |
| Lost-key/compromise approval | The attempt id (never reused), and each guardian counted at most once per attempt and domain |
| ZK initiation | The attempt id; the nullifier is spent at completion (§11) |
| Cancellation | The attempt id plus that attempt's statement digest; each factor counted once per attempt |
| Reconfiguration | The epoch, which the applied change bumps |
| Upgrade | The request id, consumed by execution or cancellation, and the epoch |

Soroban auth-entry nonces stop the same signed entry from being submitted
twice.

## 5. Evidence requirements

`condition(mode, S)`, for a statement `S`:

| Mode | Satisfied when |
| --- | --- |
| `GuardianOnly` | At least `quorum` distinct enrolled guardians have authorized `digest(S)`. |
| `ZkOnly` | The enrolled adapter accepted one proof for `S` with the enrolled binding, and that proof's nullifier is unspent (§11). |
| `Combined` | Both of the above, for the same `S`. |

| Transition | Owner authorization | Condition | Statement |
| --- | --- | --- | --- |
| Open an attempt | — | — (permissionless) | — |
| Authorize an attempt | — | Required | `LostKey` / `Compromise` |
| Complete an authorized attempt | — | Already satisfied; timing only | — |
| Cancel, `Protected` | — | Required | `Cancel` |
| Cancel, `Loss` | Sufficient alone | Or the condition | `Cancel` |
| Enroll (no prior configuration) | Required | — | — |
| Reconfigure or remove, `Loss` | Required | — | — |
| Reconfigure or remove, `Protected` | Required | Required, of the **currently** enrolled configuration | `Reconfigure` |
| Schedule an upgrade, `Loss` or not enrolled | Required | — | — |
| Schedule an upgrade, `Protected` | Required | Required | `Upgrade` |
| Execute or cancel an upgrade | Required | — (approval checked at scheduling; staleness at execution) | — |

Attempt evidence (initiation and cancellation) may accumulate across
transactions. Each guardian calls the controller's evidence entry point with
its own authorization, and a ZK proof is submitted on its own.

Reconfiguration and upgrade evidence is recorded before it is used:

- `approve_change(account, subject, valid_until, guardian)` records one
  guardian's approval. The controller builds the statement from its own
  state and the given subject.
- `submit_zk_change(account, subject, valid_until, evidence)` records a proof
  the adapter verified. It does not spend the nullifier.

Both refuse a subject that is not `Reconfigure` or `Upgrade`
(`InvalidStatement`), a factor already recorded for that digest
(`AlreadyCounted`), and any submission while an attempt is authorized and
live (`AttemptAuthorized`, §9).

Records are keyed by the statement digest, so they die with the epoch or
the freshness bound. The consuming `rcv_sync` or `rcv_upgrade` rebuilds the
digest from the change being applied and the account's
`approval_valid_until`, then counts the recorded approvals. Only distinct,
enrolled guardians are counted. Records that do not satisfy the condition
are refused with `RecoveryError::ConditionNotMet`.

This keeps the cost of proof verification (`budgets.md`) out of the
transaction that compiles and installs a document, whose own worst case the
document caps are sized for (§7.5).

Guardian-only recovery requires no ZK machinery: a `GuardianOnly`
configuration has no adapter, pool, or enrollment id, and no path consults
one.

## 6. State machine

### 6.1 Per-account states

```text
                 enroll (owner)                     remove (owner [+condition if Protected])
   Unenrolled ───────────────────▶ Enrolled(e) ─────────────────────────────▶ Unenrolled
                                     │   ▲
                       reconfigure ──┘   │  every change: epoch e → e+1
                       complete ─────────┘
```

While `Enrolled`, the account has any number of collecting attempts and at
most one authorized attempt.

### 6.2 Attempt states

```text
            begin                      condition satisfied
  (none) ─────────▶ Collecting ──────────────────────────────▶ Authorized ──complete──▶ Completed
                       │                                           │
                       ├─ evidence deadline passes ─▶ Expired       ├─ cancel ─▶ Cancelled
                       ├─ cancel ─▶ Cancelled                       └─ L ≥ expires_at ─▶ Expired
                       ├─ epoch change / sibling authorized ─▶ (dead; derived)
                       └─ stale lost-key source at Transition T4 (see below) ─▶ Invalidated (stored)
```

The stored states are `Collecting`, `Authorized`, `Completed`,
`Cancelled`, and `Invalidated`.

- **`Expired` is derived, never stored.** It is read from the ledger
  against the attempt's windows.
- **`Invalidated` is stored for exactly one cause:** T4 finding a lost-key
  attempt's source changed. The evidence call that ran T4 succeeds, writes
  `AttemptState::Invalidated`, and emits `AttemptInvalidated`.

  The attempt was still collecting, so the record sits in temporary
  storage (§3.6) and lasts **at least its evidence window** — unless its
  evidence window is longer than the network's maximum TTL, in which case
  §3.6 stores it persistently. For a temporary record, after the entry
  expires evidence naming that attempt is refused as `NoSuchAttempt`. A
  persistent record is archived rather than deleted, is restored on access,
  and stays refused as `AttemptNotLive`. Either way the attempt can never be
  promoted: its evidence window has ended.
- **Every other invalidation is derived:** an epoch change, or a sibling's
  authorization (`invalidate_below`). Nothing is written for these, because
  the cause is already in storage and an attempt from an older epoch or
  below `invalidate_below` reads as dead.

An attempt is **live** when its recorded epoch equals the current epoch and
either:

- it is `Collecting`, its id is at least the account's `invalidate_below`
  (so a sibling's authorization has not invalidated it), and
  `L ≤ evidence_deadline`; or
- it is `Authorized`, it is the account's recorded authorized attempt, and
  `L < expires_at`.

A terminal attempt (`Completed`, `Cancelled`, or `Invalidated`) is never
live. Evidence for an attempt that is not live is refused with
`AttemptNotLive`, or `NoSuchAttempt` when no record exists.

| Window | Ledgers |
| --- | --- |
| Evidence | `created_at ≤ L ≤ evidence_deadline`, with `evidence_deadline = created_at + expiry_ledgers` (inclusive) |
| Timelock | `authorized_at ≤ L < executable_after`, with `executable_after = authorized_at + delay_ledgers` |
| Completion | `executable_after ≤ L < expires_at`, with `expires_at = executable_after + expiry_ledgers` |

All additions are checked; an overflowing `u32` refuses the transition
(`RecoveryError::LedgerOverflow`).

### 6.3 Transitions

**T1 Begin** — `begin_lost_key(account, replacements)` or
`begin_compromise(account, replacements)`. Permissionless. Returns the
attempt id.

Refuses if any of the following hold:

- the account is not enrolled (`NotEnrolled`);
- an attempt is authorized and live (`AttemptAuthorized`);
- the replacement set does not encode canonically, or carries a ZK
  enrollment when the mode has no ZK factor or none when it has one
  (`InvalidReplacements`);
- for compromise: no baseline is enrolled (`NoBaseline`) or its content is
  unpublished (`BaselineNotPublished`);
- `derive_target` refuses the replacement set (§7.3 rules 1–3, 5, 6, or
  rule 4's commitment check). The controller reports every `derive_target`
  refusal as `InvalidReplacements`;
- the ZK enrollment id was enrolled by the account before, per the
  account's `is_enrolled_id` (§7.3 rule 4; `EnrollmentIdReused`);
- a credential in the target, or a replacement credential, is revoked, per
  the account's `is_revoked` (rule 7; `CredentialRevoked`);
- a replaced source credential still appears in the target (rule 8;
  `ReplacedCredentialRetained`).

The checks against the account's history (enrolled ids, revoked set) are
the controller's. `derive_target` writes no storage and sees only the
documents, the action, and the replacement set (plus the verifiers it calls
to canonicalize keys). T1 is an external entry point, so the controller may
read the account's views there (D16).

Otherwise:

1. Assigns `attempt_id` from the per-account counter (never reused).
2. Records `epoch`, `created_at = L`, `evidence_deadline`, `cancel_until`,
   the source identity, the derived target's two digests, the target
   configuration hash (§10, which fixes the ZK enrollment the completion
   installs), the replacement-set hash, and the credentials occupying the
   replaced signer slots in the source (the completion revokes them, §8). The target
   digests both come from the one `derive_target` call:
   - `target_doc_hash`: the target's document identity, as the compiler
     computed it;
   - `target_bytes_hash`: `sha256` of the canonical bytes `derive_target`
     returned, computed by the controller from those bytes.

   Under CANON v1 the two are equal. They are kept apart so that a different
   identity scheme needs a new compiler and account, not a new controller.
   The source identity is read, never computed from bytes: the account's
   `applied_doc_hash` (lost-key) or the enrolled baseline (compromise, §7.2).
3. Emits `AttemptBegun`.

Opening an attempt grants nothing and blocks nothing (D2). Opening many
costs their openers fees and rent, and has no effect on the account or on
other attempts.

**T2 Guardian evidence** — `submit_guardian(account, attempt_id, domain,
guardian)`, where `domain` is `Initiate` or `Cancel`. Requires `guardian`'s
`require_auth_for_args((digest,))` for the attempt's statement in that
domain. Refuses if any of the following hold:

- the mode has no guardian factor (`ModeHasNoGuardians`);
- `guardian` is not enrolled (`NotAGuardian`);
- the attempt is not live (`AttemptNotLive`, `NoSuchAttempt`);
- for `Initiate`, the attempt is not collecting (`AttemptNotCollecting`);
- the guardian already counted in this domain (`AlreadyCounted`);
- the statement is not fresh (`EvidenceExpired`).

Records the approval, then attempts promotion (T4) or cancellation (T6).

**T3 ZK evidence** — `submit_zk(account, attempt_id, domain, evidence)`.
Permissionless. Same refusals as T2 for the ZK factor (`ModeHasNoZk` in
place of the guardian checks; `AlreadyCounted` once a proof counted in that
domain). Then:

1. The adapter must accept the evidence for the statement and the enrolled
   binding (`ZkEvidenceRejected` otherwise).
2. The nullifier must be unspent (§11; `NullifierSpent`).
3. Records the factor (for `Initiate`, with its nullifier), then attempts T4
   or T6.

**T4 Promote** — internal, after any initiation evidence. If the condition
is satisfied for a live collecting attempt `A`:

- for lost-key, if the account's current applied-document hash differs from
  `A.source_doc_hash`, `A` is invalidated. The evidence call that triggered
  the check **succeeds**, stores `AttemptState::Invalidated`, and emits
  `AttemptInvalidated`. Refusing instead would roll the invalidation back,
  leaving `A` promotable if the document later changed back. A fresh
  attempt is required, and its evidence starts over;
- otherwise `A` becomes `Authorized` with `authorized_at = L` and its
  windows are fixed. `invalidate_below` is set to the attempt-id counter,
  which invalidates every other collecting attempt in O(1), however many an
  attacker opened. Under `Protected`, the controller calls the account's
  `rcv_gate(attempt_id, expires_at)` to set the freeze mirror (§9); if that
  call fails, the promotion fails with it. `AttemptAuthorized` is emitted.

Promotion refuses while another attempt is authorized and live
(`AttemptAuthorized`).

**T5 Complete** — `apply_doc(target_bytes, …)` selecting the zero-signer
recovery rule. OZ defers the whole check to the rule's one policy
(`cap-0071.md` C5), the controller's `enforce`, which requires all of:

- no signers were authenticated, and the rule has the recovery rule's shape
  (`MalformedContextRule`);
- the context is `apply_doc` on this account (`WrongTarget`);
- an authorized live attempt `A` exists (`AttemptNotLive`);
- `executable_after ≤ L < expires_at` (`NotExecutableYet` before the
  timelock ends);
- `sha256(target_bytes) = A.target_bytes_hash` (`WrongTarget`).

`enforce` binds the exact bytes of the context it authorizes: for that
context a different document is refused, and so is a non-canonical spelling of
the target (same identity, other bytes). `enforce` then writes a completion
marker `(attempt_id, A.target_doc_hash, L)` in temporary storage.

The marker records only the canonical **identity** of the target, not the
exact bytes of the invocation that will consume it. The account's `apply_doc`
body runs `rcv_sync` with the identity of the document it compiled, and
`rcv_sync` removes any marker it finds and treats the call as a completion
when the marker's identity equals that identity, the marker was written in the
current ledger, and its attempt is still the authorized one. It does **not**
re-check the consuming invocation's input bytes against `A.target_bytes_hash`.
Otherwise it classifies the call as an ordinary change (§10).

`enforce` runs for every context in an authorization tree, including a
sub-invocation that never executes, so a marker can be left behind. Because
consumption is by identity, within the same ledger and authorized window an
`apply_doc` under ordinary owner authorization that carries a differently
formatted spelling of the same canonical target can consume such a leftover
marker and be classified as a completion rather than refused as an ordinary
write. The completed document is still the authorized canonical target — the
identity is bound, so this neither installs a different policy nor bypasses the
`Protected` freeze — but the exact-input-byte / same-invocation guarantee
across a leftover marker is **not** enforced today. Tightening it (have
`rcv_sync` receive the completing invocation's input-byte hash and require it
to equal `A.target_bytes_hash`) is tracked in
[`../DEFERRED.md`](../DEFERRED.md) ("Completion input-byte binding"); it is an
account↔controller ABI change, so it reaches only newly-built accounts.

Application therefore binds the identity, not the exact input bytes. If the two
digests ever disagreed (a faulty compiler), the only bytes `enforce` accepts
would compile to another identity. Then `rcv_sync` would refuse the apply as an
ordinary change during the authorized window (`AttemptAuthorized`), nothing
would be applied, and the attempt could only be cancelled or expire.

On a completion the account applies its own completion effects (§10),
including clearing its freeze mirror. Every write belongs to the same
invocation, so a failure
anywhere (compile, revocation check, anti-brick, pool insertion) reverts all
of it, including the consumption. Completion is permissionless once its
evidence and timelock are satisfied. Nobody can change what it installs,
because the target, the new credentials, and the new ZK commitment are all
fixed by `A`.

**T6 Cancel by evidence** — when the cancellation condition is satisfied for
a live attempt `A`:

1. `A` becomes `Cancelled`. If `A` was authorized under `Protected`, the
   controller calls the account's `rcv_gate(attempt_id, 0)` to lift the
   freeze.
2. If `A` was authorized, the account's cancellation count increments, and
   the cancellation is refused instead if the count has reached
   `max-cancels` (`MaxCancelsReached`). The controller keeps a **lifetime**
   count per account. Removing recovery and enrolling again at the same
   controller does not reset it. Switching to another controller starts a
   new count, and that switch needs the reconfiguration authority (§10).
3. Emits `AttemptCancelled`, which records whether the cancellation counted.

Cancelling a collecting attempt never counts: it blocks nothing, so
cancelling it only tidies state.

**T7 Cancel by owner (`Loss` only)** — the account's
`cancel_recovery(attempt_id)` under owner authorization invokes the
controller's `rcv_cancel`. The controller refuses under `Protected`
(`OwnerCancelRefused`), and the account refuses when no controller is
adopted (`PerchAccountError::RecoveryNotEnrolled`). Otherwise T6's effects
apply, except that an owner cancellation is never counted toward or refused
by `max-cancels`. If it were, holders of the condition could use the cap up
by authorizing and cancelling their own attempts, then authorize one more
that the owner could no longer stop. Once the attempt is cancelled the
window has ended, so the owner may then reconfigure, for example to remove a
guardian set that opened it.

**T8 Expire** — derived. No transaction is needed. The first transition
that touches an expired attempt treats it as terminal.

**T9 Enroll, reconfigure, remove** — through `apply_doc` only (§10).

**T10 Renew** — permissionless TTL extension of existing entries (§3.6).
Changes no meaning.

### 6.4 Attempt replacement

- Collecting attempts never replace each other. They coexist, and evidence
  names an attempt id.
- The first to satisfy its condition is authorized, and its authorization
  invalidates the rest. Evidence already given to an invalidated attempt
  does not carry over.
- Opening an attempt while one is authorized is refused. The authorized
  attempt can only complete, be cancelled, or expire.
- After it ends, any number of new attempts may open. Each needs its full
  condition from scratch.
- Guardian non-response never relaxes a requirement. An attempt whose
  evidence does not arrive simply expires.

## 7. Permitted document changes

A recovery may change exactly what its replacement set declares. The chain
enforces this by deriving the target itself, not by checking a
caller-chosen hash.

### 7.1 Derivation

`derive_target(source_json, current_json, action, replacements)` is an
entry point of the doc compiler, the one contract that parses documents.
`source_json` is the account's applied document (lost-key) or the published
baseline (compromise). `current_json` is the applied document, whose
recovery member the target keeps. `action` is `LostKey` or `Compromise`.

The controller calls it at T1 through the account's own compiler (§16). It
returns a `DerivedTarget`:

- the target's canonical bytes and `doc_hash`;
- the target's configuration hash;
- the canonical fingerprint of every credential in the target (for rule 7);
- the credentials occupying the replaced signer slots in the source. For
  compromise these are the **baseline's** credentials. They are recorded at
  T1 and revoked at completion (§8).

The compiler writes no storage and needs no authorization. It does make
read-only calls: to canonicalize external keys, it calls each verifier's
`batch_canonicalize_key` (OZ `Verifier`; the batched form of
`canonicalize_key`). The fingerprints and the replaced credentials it
returns are therefore already canonical. The controller compares them for
rules 7 and 8 without canonicalizing anything itself.

Completers obtain the canonical bytes by simulating the same call.

### 7.2 Sources

| Action | Source | `source_doc_hash` |
| --- | --- | --- |
| Lost-key | The account's applied canonical document at T1 (the agreed snapshot), read through the account's full-document view | The account's `applied_doc_hash` at T1 |
| Compromise | The published baseline's signers and rules, with its `recovery` member replaced by the account's current one | The enrolled baseline hash |

If a lost-key source changes before the attempt is authorized, the attempt
must start over (T4). After authorization the source cannot change, because
policy changes are blocked (§9).

### 7.3 Replacement rules

The replacement set (`credential::ReplacementSet`) lists
`(signer_id, credential)` pairs in strictly ascending id order. When the mode
has a ZK factor it also carries exactly one `ZkEnrollment { id,
commitment }`; otherwise it carries none. T1 refuses unless every rule
below holds:

- `derive_target` checks rules 1–3, 5, 6, and the commitment half of
  rule 4.
- The controller checks the enrollment-id half of rule 4 against the
  account's `is_enrolled_id`.
- The controller checks rule 7 against the account's `is_revoked`, and
  rule 8 itself.

1. Every `signer_id` is in the current configuration's `replaceable` and is
   declared in the source.
2. A replacement credential has the same kind as the credential it
   replaces. An external credential must use the same verifier contract as
   the one it replaces, so recovery can never route a signer slot through a
   verifier the account had not already adopted for that slot.
3. Lost-key attempts replace at least one signer. Compromise attempts may
   replace none, which restores the baseline as is.

   The compiler refuses an empty lost-key set:
   - `perch_ir`'s `DeriveError::EmptyReplacements` raises the refusal;
   - `derive_target` surfaces it as `DocCompilerError::ReplacementRefused`.

   `ReplacementSet::encode` accepts an empty set, because compromise needs
   one. The interface's `StatementError::EmptyReplacements` is therefore
   reserved and never produced.
4. A ZK enrollment's commitment is a canonical field element (compiler),
   and its id is not in the account's set of enrolled ids (§3.4;
   controller, via `is_enrolled_id`). The target's
   `recovery.mode.enrollment-id` and `commitment` become the new values.
   Nothing else in the recovery section changes.
5. Nothing else changes: rules, other signers, network, version.
6. The target passes full document validation (which rejects duplicate key
   material), the document caps (§7.5), the anti-brick check, and network
   binding.
7. No credential in the target, and no replacement credential, is in the
   account's revoked set (compared by canonical fingerprint, §8).
8. **No explicitly replaced source credential appears anywhere in the
   target** (compared by canonical fingerprint;
   `credential::replaced_credentials_leave`). This refuses a no-op
   replacement (a slot "replaced" by its own credential) and a swap of
   credentials between slots.

   Rule 8 is what makes D7 hold. A swapped credential retained in another
   slot would keep authorizing from there, and §8 would revoke a credential
   the target installs. Under rule 8, every replaced credential leaves the
   account at completion and is revoked there.

Rule 7 means an old baseline cannot restore a credential revoked after the
baseline was approved: the compromise attempt must replace that slot, or it
is refused. After any completed recovery, the wallet should have the
baseline re-approved (a reconfiguration) so that compromise recovery stays
usable without extra replacements.

### 7.4 What this does and does not establish

**Enforced on-chain:** the target equals the source with exactly the
declared replacements. The replacements are what every guardian and prover
approved, because `replacements_hash` and `target_doc_hash` are in the
statement. Every replaced credential leaves the account and is revoked,
and revoked credentials do not return. The recovery section is
unchanged except for the declared ZK rotation.

**Not enforced on-chain, and who owns it:**

- *That the replacement credentials belong to the person recovering.*
  Guardians own this, by out-of-band identity checks before signing. ZK
  provers own it implicitly: whoever holds the secret chooses.
- *That a lost-key source is benign.* Lost-key keeps everything in the
  current document, including anything an attacker added. An owner who
  suspects compromise uses compromise recovery.
- *That a baseline was once the account's real document.* The enroller and,
  under `Protected`, the condition-holders who approved the configuration
  naming it own this.
- *That a circuit proves what this spec says.* The adapter's author and its
  reviewers own this (§13). The controller checks only the adapter's
  verdict.

### 7.5 Bounded completion cost

Under `Protected`, a thief holding the owner key can change the document
before an attempt is authorized. Completion cost must therefore not be
theirs to choose.

**Apply is a delta.** Every `apply_doc`, completion included, matches the
target's rules to the installed ones **by slot: the recovery rule by its
role; a document rule by its name and compiled scope (context type)**:

- A slot whose compiled rule is identical is left untouched. "Compiled
  rule" means scope, signers as resolved credentials, `valid_until`, and
  every attached policy with its install parameters, which carry the
  rule's `rule_hash` (§3.2). Equal `rule_hash` alone is not enough: rotating
  a signer's key leaves the rule text unchanged but changes its compiled
  signers.
- A slot that differs is reconciled whichever of two ways a deterministic
  cost model prices lower, the in-place edit on a tie:
  - (a) **edited in place** under its existing rule id:
    - a changed `valid_until` is updated;
    - signers and policies present in both are kept;
    - the signer set changes in one `reconcile_signers` call, which checks
      the final set as a whole and keeps retained signers' registry ids;
    - when the target has signers, the swap runs first and then the
      policies, removals first, so their count never exceeds OZ's
      per-rule limit; when it has none, the policies change first and the
      signers go last, so the rule is never empty;
    - a policy whose install parameters change counts as removed and
      re-added.
  - or (b) **replaced whole** under a new rule id: the rule is removed and
    the target rule added.

  The model prices the exact OZ operation sequence each way would run, from
  the diff and the signer and policy registry reference counts at that point.
  Every OZ mutation runs through its `_no_events` variant (the account emits
  one `DocApplied` per apply instead), so the price is the ledger entries
  each operation writes. An in-place edit costs one rule write for the
  signer swap plus each changed signer's and policy's entries; a
  replacement costs a rule removal and addition plus deregistering,
  re-registering, and reinstalling everything the rule keeps.
- Replacement is the only way when no in-place order keeps the rule
  non-empty within OZ's per-rule limits (`MAX_SIGNERS` 15, `MAX_POLICIES`
  5): neither side has signers, nothing survives, and the new policies
  cannot be added first. Example: the recovery rule, which has no signers,
  when its only policy's parameters change. Adding first is impossible (one
  policy per address) and removing first would empty it. A changed scope
  is a different slot (removed and added).
- An installed rule whose slot the target lacks is removed, before
  anything is added; a target rule whose slot is not installed is added.
- A document rule whose `not-after-ledger` has already passed at the
  applying ledger is **dropped** rather than installed: its lowered
  `valid_until` is below the current sequence, so it authorizes nothing and
  OZ's `add_context_rule` would refuse it (`PastValidUntil`). Dropping it
  instead of trapping is what keeps "a document that compiles also installs"
  true for time-bounded rules, and keeps a recovery target installable when
  one of its bounded rules (a session or CI key) expires between the
  baseline's publish and the completion: the completion installs the
  baseline minus the dead rule. The drop depends only on the applying
  ledger, so the delta and a full replace still install the same set. A
  thief who holds the owner key therefore cannot brick compromise recovery
  by deleting a baseline rule that later expires — the completion drops it
  deterministically. The anti-brick check (§3.5, §7.3) keeps this from ever
  stranding the account: a policy-free self-admin rule that carries any
  `not-after-ledger` — already past or still in the future — does **not**
  count as the surviving admin rule, so a document whose only admin rule is
  bounded is refused outright rather than installed and later dropped into a
  brick.

The installed rule set that results has the same normalized structure and
installation parameters as a full replace; its authorization matches a full
replace except for retained runtime policy state (a kept spending-limit window,
see [`implementation.md`](implementation.md)) and expiry-sensitive behavior. A
full replace takes replacement for every rule and deregisters and
re-registers every signer and policy, so taking the cheaper way per rule
means no apply writes more ledger entries than a full replace. Writes are
not the only limit: the in-place path can cost more instructions than a
replacement, so the document caps are sized with flows that force each
path (`budgets.md`). The account keeps one record per installed rule (id,
slot, valid_until, signers, and each policy with a digest of its install
parameters), bounded by the rule cap plus the recovery rule. It never scans
historical rule ids, which grow without bound with every past apply.

**Policy state.** A replaced rule gets a new id and its policies are
reinstalled, which resets their state (a spending limit's window). So does
a policy reinstalled because its parameters changed. An in-place edit keeps
the id and the kept policies' state. A completion is an `apply_doc` like any
other: a recovery that replaces a rule, or changes its spending limit's
parameters, gives that rule a fresh window, which under compromise recovery
includes retained baseline signers. A spending window that persists across
a replacement is not supported
([`DEFERRED.md`](../DEFERRED.md#persistent-spending-budgets-across-replacements)).

A completion also revokes every removed credential and compiles the target.
Two rules bound that cost:

- **Document caps.** The doc compiler refuses, on every `apply_doc` and in
  `derive_target`, a document exceeding fixed caps
  (`DocCompilerError::DocTooLarge`): `perch_doc_compiler::MAX_DOC_SIGNERS` =
  8 declared signers, `MAX_DOC_RULES` = 11 document rules,
  `MAX_DOC_CANONICAL_BYTES` = 8 192 canonical bytes, and
  `MAX_RULE_NAME_BYTES` = 20 (OZ's context-rule name limit). The recovery
  rule is not a document rule and is installed in addition to the 11. The
  compiler's `limits` view returns these caps. They are sized so that the
  worst-case completion fits the transaction budget: the measurements and
  the choice are in `budgets.md`, and `release_stack.rs`'s `worst_case_*`
  tests hold them in CI. The worst case is a maximum-size pre-recovery
  document whose every slot differs from a maximum-size target, after any
  amount of prior rule churn. Larger caps are not supported at this
  revision
  ([`DEFERRED.md`](../DEFERRED.md#versioned-policy-backend-and-larger-limits)).
- **Bounded revocation writes.** The revoked set is one persistent entry per
  fingerprint, so a completion writes at most one entry per removed
  credential, a number the caps bound.

## 8. Revocation

- The account keeps a permanent, append-only set of credential fingerprints
  (`credential::Credential::fingerprint`). Nothing clears it: neither
  removing recovery, nor switching controllers, nor upgrading.
- A completion revokes the union of two sets
  (`credential::revocations`):
  1. **The explicitly replaced source credentials.** These are the
     credentials that occupied the replaced signer slots in the attempt's
     source: the applied document for lost-key, the baseline for
     compromise. The controller records them at T1 and returns them in
     `SyncOutcome::Completed`.
  2. **Every credential removed from the current document.** That is,
     every credential in the account's applied document immediately before
     the completion that is absent from the target. The account computes
     this at completion; its applied document cannot change after
     authorization (§9).

  For lost-key the two sets coincide. Rule 8 (§7.3) guarantees that
  neither set contains a credential the target installs, so the completion
  never revokes what it applies. The account emits `CredentialRevoked` for
  each fingerprint it adds.

  For compromise they differ, and each matters on its own:
  - Set 2 covers everything added since the baseline. The recovery cannot
    tell an attacker's additions from the owner's, so it revokes all of
    them; the owner re-adds a legitimate one under a fresh key.
  - Set 1 covers a baseline credential that the recovery replaced but that
    was already absent from the current document. Example: the baseline
    names owner A, the current document has moved to owner B, and the
    recovery replaces A's slot with C. Without set 1, A would stay
    unrevoked, and a second compromise recovery with no replacements would
    restore A and let it authorize again. With it, that second attempt
    fails §7.3 rule 7.
- Every `apply_doc`, on every path, refuses a compiled document containing a
  revoked credential (`PerchAccountError::RevokedCredential`).
- Fingerprints are computed over the verifier's canonical key bytes (OZ
  `Verifier::canonicalize_key`, called in its batched form
  `batch_canonicalize_key`), so a revoked key cannot return under a
  different encoding. Delegated addresses are already canonical.
- **A document's declared external keys must already be canonical.** The
  doc compiler refuses any signer whose `key` is not byte-for-byte its
  verifier-canonical form (`DocCompilerError::KeyNotCanonicalizable`) rather
  than silently canonicalizing it — CANON refuses non-canonical input, it does
  not repair it. This holds for an applied document and for a recovery
  attempt's replacement keys alike (`derive_target` compiles the target the
  same way). Two consequences: a document's `doc_hash` and a recovery
  attempt's `replacements_hash` bind exactly the key bytes the installed
  credential uses, never a spelling the credential drops; and two signers can
  no longer hide one physical key under two encodings (e.g. a WebAuthn key
  with and without its credential-id suffix), which would otherwise read as an
  independent co-signer. The credential-id a wallet needs to select a passkey
  is client-side metadata; it is not part of the on-chain key.
- A spent ZK credential stays dead through its nullifier (§11), and its
  enrollment id can never be enrolled again (§3.4).

## 9. Activity and policy restrictions

| Operation | No live attempt | Only collecting attempts | Authorized, `Loss` | Authorized, `Protected` |
| --- | --- | --- | --- | --- |
| Ordinary authorization (`__check_auth` for any context, including as a CAP-0071 delegate) | allowed | allowed | allowed | **refused** |
| `execute` | allowed | allowed | allowed | **refused** |
| `apply_doc` under owner authorization, any document | allowed (reconfiguration gated per §5) | allowed | **refused** | **refused** |
| `apply_doc` completing the authorized attempt | — | — | allowed (T5) | allowed (T5) |
| Schedule or execute an upgrade | allowed (§12) | allowed | **refused** | **refused** |
| Cancel an upgrade | allowed | allowed | allowed | **refused** (no owner authorization exists) |
| Owner cancellation (T7) | — | `Loss` only | allowed | — |
| Begin, submit evidence, publish baseline, renew | allowed | allowed | begin refused; evidence only for the authorized attempt's cancellation | same as `Loss` |

**The `Protected` freeze must hold on every authorization path.** It is
enforced inside the account's `__check_auth`, from a **mirror in the
account's own storage**: `(frozen_attempt, frozen_until)` (`FreezeGate {
attempt_id, until }`, the account's `recovery_gate` view).

- The adopted controller sets the mirror through the account's invoker-only
  `rcv_gate` when a `Protected` attempt is authorized (T4).
- The controller clears it (`frozen_until = 0`) when that attempt is
  cancelled (T6). A clear for any other attempt id leaves the mirror as it
  is.
- The account clears it itself on `SyncOutcome::Completed`.
- It lapses on its own at `frozen_until = expires_at`
  (`account::is_frozen`).

`rcv_gate` refuses any caller other than the adopted controller, which
authorizes by invoker authorization, and refuses when no controller is
adopted (`PerchAccountError::RecoveryNotEnrolled`). It emits
`FreezeChanged`.

While the mirror is set, `__check_auth` refuses every context except a
single `apply_doc` context on the account itself that selects the recovery
rule, which the controller's `enforce` then validates (T5). The refusal is
`PerchAuthError::AccountFrozen`.

A cross-contract read of the controller from `__check_auth` would not work.
Soroban refuses to re-enter a contract already on the call stack, even for a
read. When this account approves, as a guardian, an action at the same
controller, the controller is on the stack while this account's
`__check_auth` runs, so the read would make every such approval fail
(`cap-0071.md` C8).

The freeze covers:

- **Signature-based authorization** of any context.
- **CAP-0071 delegation.** When this account is a delegated signer of
  another account, the host invokes this account's `__check_auth` with the
  delegating account's contexts. The freeze refuses them, so a frozen
  account cannot authorize anything as a delegate (`cap-0071.md`, property
  C3).
- **`execute` and every other account entry point.** Each requires the
  account's own authorization before it acts, which reaches `__check_auth`.
  The one exception is `rcv_gate`: only the adopted controller can call it,
  and it can only set or clear the mirror. A frozen account has no entry
  point that can make it the invoker of anything.
- **Policies.** They run inside an authorization that `__check_auth` already
  admitted.

**The policy block (D3) holds in both profiles.** It is enforced in
`rcv_sync`, which every `apply_doc` reaches when a controller is adopted.
While an attempt is authorized and live, `rcv_sync` refuses unless this
invocation is that attempt's completion (`AttemptAuthorized`).

**What the freeze cannot reach.** The freeze stops the account from
authorizing anything new. A permission it granted earlier stays usable by
whoever holds it: a token allowance, or an approval another contract
stored. No account code can revoke those, so wallets should keep
allowances short-lived and small.

**Evidence-free griefing.** A collecting attempt freezes nothing, blocks no
policy change, no upgrade, and no other attempt (D2). Only satisfying a
condition, which requires the enrolled guardians or secret, starts an
authorized window.

## 10. Completion versus reconfiguration

Every `apply_doc` on an account with an adopted controller calls that
controller's `rcv_sync(account, doc_hash, recovery, approval_valid_until)`
before touching any context rule. It passes the compiled document's
canonical hash, its compiled recovery member (zero or one entry), and the
freshness bound of any recorded reconfiguration approvals. The call returns
a `SyncOutcome` (`Unchanged`, `Enrolled`, `Reconfigured`, `Removed`, or
`Completed(Completion { attempt_id, replaced })`) telling the account which
of its own effects to apply. Every outcome other than `Unchanged` advances
the account's recovery generation (§12). The controller cannot read the
account back during the call (D16).

The call is invoker-only (§15). `rcv_sync` both decides and writes. No
separate `install` call ever writes configuration. `install` is
bookkeeping: it checks that the recovery rule has the required shape
(`MalformedContextRule`) and was installed for the stored configuration's
hash (`InvalidConfiguration`). `uninstall` writes nothing, because OZ
discards `uninstall` failures and so `uninstall` can gate nothing.

**The recovery rule.** While the applied document enrolls recovery, the
account installs one extra context rule: named `recovery`, scoped to the
account itself (`CallContract(account)`), with no signers, and with one
policy, the adopted controller, installed with the configuration's
`config_hash` as its parameter. It is matched by role, never by name, so a
document rule that happens to be named `recovery` is a different rule. A
new `config_hash` (a reconfiguration, or a ZK-rotating completion) or a new
controller changes its policy, so the rule is replaced (§7.5); removal
removes it.

`rcv_sync` classifies the call exactly one way:

| Case | Recognised by | Authorization | Effects |
| --- | --- | --- | --- |
| Completion | A completing marker from this invocation's `enforce` (T5) whose target identity equals the `doc_hash` argument (the identity of the document the account compiled) | Already established by the attempt | The compiled configuration must name this controller and its hash must equal the attempt's target configuration hash (unchanged, or ZK-rotated as declared); otherwise `WrongTarget`. Consumes the marker, marks the attempt `Completed`, spends its nullifier, stores the target configuration, and bumps the epoch. Returns `Completed(Completion { attempt_id, replaced })`, where `replaced` holds the attempt's recorded source credentials. The account inserts the new leaf from the compiled target's ZK factor (§14.2), records the new enrollment id as used, revokes `replaced` together with every credential the completion removed from its current document (§8), clears any pending upgrade, and clears its freeze mirror. |
| No change | `config_hash` and controller unchanged, and not a completion | Owner authorization (already required by `apply_doc`) | Refuses if an attempt is authorized and live (§9); otherwise nothing. |
| Enroll | No configuration stored | Owner authorization | Refuses unless the configuration names this controller (`InvalidConfiguration`) and passes §3.1's re-checks and §3.4's wiring check. Stores the configuration and bumps the epoch. The account records the enrollment id as used. |
| Reconfigure | `config_hash` differs, controller unchanged | `Loss`: owner. `Protected`: owner plus the stored configuration's condition over `Reconfigure(Set(new))`, from recorded approvals (§5) | Refuses during an authorized window, and unless the new configuration passes §3.1's re-checks and §3.4. Stores the new configuration, bumps the epoch, and invalidates every attempt. |
| Remove or switch away | No recovery section, or a different controller | Same as reconfigure, with `Reconfigure(Remove)` or `Reconfigure(Set(new))` evaluated by the **current** controller | Clears this controller's configuration for the account and bumps its epoch. When switching, the account then calls the new controller's `rcv_sync`, which treats the call as an enrollment. |

Consequences:

- **Key rotation is not reconfiguration.** Rotating a replaceable
  signer's key leaves the recovery text, and therefore `config_hash`,
  unchanged.
- **A completion is never routed through reconfiguration checks.** A ZK
  rotation that is part of a completion is allowed precisely because the
  attempt declared it.
- **Omitting the recovery section is removal.** It is gated like any
  removal. A completion's derived target always carries the recovery
  section, so a completion is never mistaken for a removal.
- **The controller's state follows the document.** Removal clears it,
  and every change bumps the epoch.

## 11. Nullifiers

`nullifier = Poseidon2(DOM_NULLIFIER, account_hi, account_lo, enrollment_hi,
enrollment_lo, secret)`. It is one value per enrolled credential, the same
for every action, and it binds the account and the enrollment id: only that
`(account, enrollment)` owns it. The controller records spent nullifiers,
keyed by `(account, nullifier)`:

```text
unspent (absent) ──completion of an attempt of X that used it──▶ Spent{X}   (permanent)
```

| Event | Rule |
| --- | --- |
| Canonicality | The adapter refuses a nullifier or root `≥ r`; otherwise `n` and `n + r` would verify as one credential while the controller stored them as two. |
| Any ZK proof (initiation, cancellation, reconfiguration, upgrade) | Requires the nullifier unspent for this account (`NullifierSpent`). Never changes the record. |
| Completion of attempt `A` of account `X` that used ZK evidence | Requires `A`'s recorded nullifier unspent; marks it `Spent{X}` in the same invocation. |
| Anything else | No transition. Nothing un-spends a nullifier, and no operation releases one, so no operation can release another account's or attempt's claim. |

**Spent records are per account.** Any contract can enroll itself at the
shared controller with an adapter of its choosing. A controller-wide record
would let such a contract mark a victim's nullifier spent (a nullifier is
public once a proof uses it) and so block every later proof by the victim.
The controller's `nullifier_spent(account, nullifier)` view reads the
record.

**Accepting a proof reserves nothing.** Several live attempts may carry the
same unspent nullifier. This is safe:

- A proof is bound to its attempt by the statement, so it cannot be reused
  for another attempt.
- Two attempts carrying the same credential cannot both complete: the first
  authorization invalidates the other, and completion bumps the epoch.

Because nothing is reserved, a holder of a stolen secret cannot tie the
credential up in junk attempts: under `Combined` the owner's attempt can
still collect its ZK factor, and under `ZkOnly` the same credential can
still cancel.

**Spending consumes the credential.** A ZK-evidenced completion spends the
enrolled credential's nullifier and installs the fresh enrollment its
replacement set declared (§7.3). The account always leaves recovery with a
working ZK factor that the recovering party holds. A `Protected` account is
never left with a dead factor that would make it impossible to reconfigure
or upgrade.

This liveness holds only when the recovering party correctly generated and
retained the new secret. The replacement set declares the fresh enrollment's
commitment, but the statement proves possession of the *old* secret, not of
the replacement; the protocol does not check knowledge of the replacement
secret. A party that completes with a replacement commitment whose secret it
did not keep installs a ZK factor it cannot later prove.

## 12. Account upgrades

**Recovery generation.** The account keeps `recovery_generation: u64` in
its own storage. It starts at 0, never decreases, and is never reset. It
advances by one:

- in `apply_doc`, whenever an `rcv_sync` call returns anything other than
  `SyncOutcome::Unchanged`: enrollment, reconfiguration, removal, either
  side of a controller switch (so a switch advances it twice), or a
  completed recovery;
- in `execute_upgrade`, when an upgrade executes.

The generation is the account-level definition of "the recovery
configuration changed". The controller's epoch (§3.3) cannot serve: it
belongs to one controller and does not exist while the account is
unenrolled. Consider a request scheduled while unenrolled, then recovery
enrolled and removed again before execution. The final state has no
controller, exactly as at scheduling, so comparing controllers or epochs
would let the old request execute. The generation has moved twice, so the
request is stale.

Every account, enrolled or not, upgrades in two steps:

1. **`schedule_upgrade(wasm_hash, approval_valid_until)`** — owner
   authorization. If a controller is adopted, the account calls
   `rcv_upgrade(account, UpgradeStep::Schedule(UpgradeSubject { request_id,
   wasm_hash }, approval_valid_until))`. That call refuses during an
   authorized window (`AttemptAuthorized`) and, under `Protected`, checks
   the recorded condition over the subject (§5; `ConditionNotMet`). It
   returns the controller's current epoch. The account's
   `next_upgrade_request_id` view tells approvers which `request_id` to
   approve.

   The account records an `account::UpgradeRequest { request_id,
   wasm_hash, generation, controller_epoch, executable_at }` and emits
   `UpgradeScheduled`:
   - `generation` is the current recovery generation;
   - `controller_epoch` is the epoch returned above, or none when
     unenrolled;
   - `executable_at = L + ACCOUNT_UPGRADE_DELAY_LEDGERS` (120 960 ledgers);
     an overflow refuses (`PerchAccountError::TimingOverflow`).

   One request at a time; scheduling another drops the previous one
   (`UpgradeDropped`). `request_id` comes from a per-account counter and is
   never reused.
2. **`execute_upgrade(request_id)`** — owner authorization. The account
   refuses, in this order:
   - no pending request (`NoPendingUpgrade`), or a `request_id` other than
     the pending one's (`UpgradeRequestMismatch`);
   - **stale:** the request's `generation` differs from the current
     recovery generation (`PerchAccountError::StaleUpgrade`), whether or not
     the delay has passed (`UpgradeRequest::readiness` checks staleness
     first);
   - **not yet:** `L < executable_at` (`UpgradeNotReady`).

   A stale request is not cleared by the refusal: a refused invocation rolls
   back its writes. Nothing needs clearing anyway. The generation never
   decreases, so a stale request can never execute; it stays inert until
   `schedule_upgrade` replaces it, `cancel_upgrade` removes it, or a
   completion clears the slot. Wallets read staleness from the
   `pending_upgrade` and `recovery_generation` views.

   If a controller is adopted, the account then calls `rcv_upgrade(account,
   UpgradeStep::Execute(controller_epoch))`. As a second check, that call
   refuses if an attempt is authorized (`AttemptAuthorized`) or the
   controller's epoch moved (`RecoveryError::StaleUpgrade`, "recorded under
   an older epoch"), then bumps the epoch.

   The account drops the request, advances its recovery generation and its
   configuration revision, emits `UpgradeExecuted`, and calls
   `update_current_contract_wasm(wasm_hash)`. The epoch bump invalidates
   collecting attempts, whose targets the old code's doc compiler derived,
   and every outstanding approval.

**`cancel_upgrade()`** takes owner authorization and refuses when nothing is
pending (`NoPendingUpgrade`).

| Rule | Why |
| --- | --- |
| The approval binds the exact Wasm hash, the epoch, and `config_hash` | A Protected approval cannot be carried to different code or a different configuration. |
| Any recovery-generation change makes a queued request stale | This is the validation of queued approvals when configuration changes. It is account-owned, so it holds across controllers and across periods without recovery. Enrollment, reconfiguration, removal, controller switches, completion, and an executed upgrade all advance it, so a successful recovery invalidates every outstanding request. Completion also clears the slot explicitly. |
| Blocked while an attempt is authorized | Upgrading must not race or neuter an in-flight recovery. |
| The delay applies to every account | The delay is 120 960 ledgers, seven days at 5-second ledgers. Accounts without recovery get the same window to notice a stolen key. |

The upgraded code inherits the account's storage, including the revoked
set, the recovery generation, and the recovery wiring. Whether new code
honours them cannot be enforced from the old code. That is why `Protected`
requires the condition to approve the exact Wasm.

## 13. ZK adapter boundary

### 13.1 Adapter boundary

To check a proof, the controller calls one ZK contract, the adapter its
stored configuration names, with three values (it calls the pool directly
only for `depth()`, §3.4):

- the structured `RecoveryStatement` it built (§4), never a bare digest;
- the `ZkBinding { pool, enrollment_id, circuit_id }`, built from its
  stored configuration only;
- the submitted `ZkEvidence { tree_id, root, nullifier, proof }`.

The adapter derives the account and the statement digest from the one
statement, so it cannot be handed an inconsistent pair. The circuit binds
`statement_hash = P2(DOM_AUTH, account, enrollment, digest)` (§13.3), and
every other statement field (network, controller, action, configuration
through `config_hash`, subject, timing) enters through the digest. The
proof therefore binds the full configuration, the action, and ledger
timing, and the statement encoding can change without a new circuit.

The adapter returns `Ok` or a `ZkAdapterError`, which the controller
reports as `RecoveryError::ZkEvidenceRejected`. The adapter stores nothing.
Its one ledger effect is through the pool: a matched `is_known_root`
extends that root entry's TTL (§14.3). The controller alone checks
freshness (§4) and owns all nullifier state (§11).

### 13.2 Interfaces (`perch_recovery_interface::zk`)

- `ZkAdapterInterface::verify(statement, binding, evidence) -> Result<(),
  ZkAdapterError>`, `circuit_id()`, and `tree_depth()`. The release adapter
  (`perch-zk-adapter`) is stateless and constructorless, and compiles in its
  verifier and verification key. It runs these checks in order and returns
  the first failure:
  1. `binding.circuit_id` is its own, `sha256` of its VK (`CircuitMismatch`);
  2. the statement projects onto circuit fields: its account and
     controller are contracts (`InvalidStatement`);
  3. root and nullifier are canonical field elements (`NonCanonicalField`);
  4. the proof is exactly `PROOF_BYTES` (16 224) long, the size of a
     zero-knowledge UltraHonk proof; a non-ZK proof is refused by length
     (`MalformedProof`);
  5. `pool.is_known_root(tree_id, root)` on `binding.pool` (`UnknownRoot`,
     or `PoolUnavailable` if the call fails);
  6. `verify_proof(public_inputs(root, nullifier, statement_hash), proof)`
     (`ProofRejected`, or `VerifierUnavailable` if the embedded key does
     not parse).

  `verify` does not compare depths. The controller compares the adapter's
  `tree_depth()` with the pool's `depth()` when it enrolls a factor (§3.4).
- `ProofVerifierInterface::verify_proof(public_inputs, proof) -> Result<(),
  ProofVerifierError>`: the raw, VK-baked verifier. The release adapter
  exposes it as its own entry point; there is no separate verifier
  contract. The verifier is NethermindEth's UltraHonk verifier plus perch's
  zero-knowledge flavor (`UltraKeccakZKFlavor`, keccak oracle), vendored at
  `vendor/ultrahonk-soroban-verifier`; [`docs/zk/`](../zk/README.md)
  describes it and the provenance of each part.
- `MembershipPoolInterface::is_known_root(tree_id, root)`, `depth()`, and
  `rcv_insert(account, enrollment_id, commitment)` (§14).

### 13.3 Circuit

```text
public:  root, nullifier, statement_hash
private: secret, account_hi, account_lo, enrollment_hi, enrollment_lo,
         digest_hi, digest_lo, leaf_index, siblings[D]

inner = P2(DOM_LEAF, secret)
leaf  = P2(DOM_BIND, account_hi, account_lo, enrollment_hi, enrollment_lo, inner)
assert merkle_root(leaf, leaf_index, siblings) == root         // leaf_index decomposed to D little-endian bits in-circuit (range-checks it to [0, 2^D)); interior P2(l, r)
assert P2(DOM_NULLIFIER, account_hi, account_lo, enrollment_hi, enrollment_lo, secret) == nullifier
assert P2(DOM_AUTH, account_hi, account_lo, enrollment_hi, enrollment_lo, digest_hi, digest_lo) == statement_hash
```

- `P2` is Noir's `Poseidon2::hash` (noir-lang/poseidon v0.2.0), matching
  `soroban-poseidon`'s host Poseidon2. Interior Merkle nodes are untagged
  `P2(l, r)`.
- The `hi`/`lo` values are the 16-byte big-endian halves of 32-byte values
  (`split_hi_lo`). Collision resistance of `P2` makes range checks
  unnecessary: the adapter computes `statement_hash` from in-range halves.
- The domain tags are `BE(sha256(label)) mod r` for labels
  `perch/recovery/zk/v2/{leaf,bind,nullifier,auth}`. The `v2` labels keep
  these tags distinct from the `v1` tags of Nido's earlier recovery
  circuit, so no `v1` proof, leaf, or nullifier can be reinterpreted under
  this circuit.
- Depth `D` is 32 in the release build. A depth-24 build of the circuit,
  adapter, and pool is the fallback `budgets.md`'s depth rule names.
- `circuit_id = sha256(vk)`. The VK is compiled into the adapter
  (`crates/perch-zk-adapter/vk/`), and `circuits/manifest.json` pins its
  hash with the circuit's sources and artifacts.

## 14. Membership pool

### 14.1 Shape

- One constructorless, immutable pool per version. It has no admin, no
  factory authority, and no upgrade entry point. Depth `D` is a build
  constant.
- Trees are numbered `tree_id: u32` from 0. Leaf indices and counts are
  `u64`, because a depth-32 tree's capacity of `2^32` does not fit in `u32`.
- `is_known_root(tree_id, root)` accepts every root tree `tree_id` has ever
  had, and refuses anything else, including roots of other pools. The pool
  keeps a root → tree entry per insertion, paid for by the inserter. Trees
  are append-only, so a historical root is as sound as the latest one. An
  empty tree's root is never accepted, because no leaf could be proven
  under it.

  A recent-roots window would be a denial of service: anyone can insert
  leaves bound to their own address, so an attacker who inserted faster
  than a victim could prove would push the victim's root out of the window.
  Under `Protected` `ZkOnly`, that would block the owner's ZK cancellation
  while a thief's attempt ran out its delay.
- `depth()` reports `D`; the controller checks it against the adapter's
  `tree_depth()` at enrollment (§3.4).

### 14.2 Insertion

`rcv_insert(account, enrollment_id, commitment)` is invoker-only (§15). The
account calls it from `apply_doc` when the compiled configuration names a
new enrollment id (at enrollment, at a ZK reconfiguration, and at a
ZK-rotating completion), passing the compiled document's enrollment id and
commitment, never a call argument. The pool:

1. Refuses an account that is not a contract (`AccountNotContract`) and a
   non-canonical commitment (`NonCanonicalCommitment`).
2. Refuses an `(account, enrollment_id)` pair it has already inserted
   (`EnrollmentIdTaken`).
3. Computes `leaf = P2(DOM_BIND, account split, enrollment split,
   commitment)` itself; a caller never supplies a wrapped leaf.
4. Appends it to the active tree, records the new root, the leaf, and the
   enrollment's position, and emits `LeafInserted { account, tree_id,
   enrollment_id, index, leaf, root }`.

`rcv_insert` returns nothing (`zk::MembershipPoolInterface`). A refusal
fails the call, and with it the `apply_doc`. Clients read a leaf's position
from the pool's `enrollment(account, enrollment_id)` view or the event. When
an insertion fills the active tree, the same call seals it and makes
`tree_id + 1` the active tree. A full tree never blocks enrollment.

Insertion failure (for example, the account is out of fee budget) reverts
the whole `apply_doc`, so no configuration ever names an enrollment whose
leaf is absent.

### 14.3 Earlier trees and witnesses

- A sealed tree never changes. Its witnesses can be computed once and cached
  by the client.
- Tree states, roots, leaves, and enrollment records are persistent,
  renewable (`renew_tree`, `renew_root`, `renew_leaves`,
  `renew_enrollment`), and restorable after archival. A matched
  `is_known_root` also extends that root's entry. A prover whose root entry
  has been archived restores it, or proves against a newer root.
- Every leaf is stored, so any witness can be rebuilt from the pool's
  storage alone (`leaves(tree_id, start, count)`, at most 64 per call),
  without depending on RPC event retention. `LeafInserted` events carry the
  same data for indexers. Clients should keep their own leaf's position.
- A proof against a root the pool never had is refused as `UnknownRoot`
  (a wrong witness). The fix is a correct witness and a new proof. Nothing
  about the account changes.

Enrollment is public: the event names the account. Concealing enrollment is
out of scope.

## 15. Invoker-only hooks and other authorization paths

`account.require_auth()` inside a hook is meant to mean "the account's own
code is making this call". Soroban satisfies it two ways: invoker-contract
authorization, and a signature through the account's `__check_auth`. The
second is a bypass: without a guard, a document rule scoped to the
controller would let its signers call `install` directly.

The account must therefore:

1. **refuse in `__check_auth`** any context whose function name is in
   `account::RESERVED_INVOKER_ONLY_FNS` (`install`, `uninstall`, `enforce`,
   `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `rcv_insert`, `rcv_gate`), on
   any contract, before OZ's `do_check_auth`
   (`PerchAuthError::ReservedFunction`). Names match exactly. Matching by
   name also covers controllers and policies the account adopted in the
   past;
2. **refuse in `execute`** a call to a reserved name
   (`PerchAccountError::ReservedFunction`). `execute` makes the account the
   invoker, which would otherwise grant invoker authorization to whoever can
   authorize `execute`;
3. **refuse at compile time**, as defence in depth, a rule whose
   `Scope::Contract` is the document's own ZK adapter or pool. The account
   never needs to authorize a call to either. A rule scoped to the
   document's **own controller is allowed**: an account that is a guardian
   at the controller it uses itself must authorize `submit_guardian` and
   `approve_change` there (§2). Rule 1 is what protects the controller's
   sensitive entry points, not this compile-time check.

`cap-0071.md` pins the host behaviour this relies on (properties C5, C6,
and C7).

**External-signer digest binds the account address.** Before OZ's
`do_check_auth`, the account's `check_auth` re-binds the host's
`signature_payload` to the account's own 32-byte contract id —
`sha256(AUTH_ADDR_DOMAIN || account_id || signature_payload)`, where
`AUTH_ADDR_DOMAIN = "perch/account/auth-addr-v1"` — and OZ then layers the
selected rule ids on top. The digest an `External` signer authenticates
against is therefore unique to this account, and `capabilities().auth_digest`
reports the scheme as `addr_oz_v1` so a client knows which digest to sign.
This is necessary because Soroban's authorization preimage
(`HashIdPreimage::SorobanAuthorization`, for a non-delegated custom-account
credential) binds the invocation, nonce, network and expiration but **not** the
address of the account whose `__check_auth` runs, and the host's per-account
nonce namespace prevents reuse only within one account. Without the fold, an
`External` signature collected for one account is replayable on another that
shares the key and the selected rule ids. `Signer::Delegated` (CAP-0071)
signers never consume this digest — the host validates them under
`SorobanAuthorizationWithAddress`, which is already address-bound — so they are
unaffected. Off-chain signers (`perch-js`'s `signingDigest`, `perch-deploy`'s
`perch_auth_digest`) reproduce the fold byte-for-byte; `auth_vectors.rs` pins
them against the digest the on-chain `check_auth` actually hands a verifier.

**Invariants this section maintains.**

- **I1.** Every controller, pool, or policy entry point that acts on an
  account's own recovery state under that account's authorization has a
  reserved name. These are `rcv_sync`, `rcv_cancel`, `rcv_upgrade`,
  `install`, `uninstall`, `enforce`, and the pool's `rcv_insert`; the
  account's own `rcv_gate` is reserved too. Adding such an entry point
  without adding its name to `RESERVED_INVOKER_ONLY_FNS` breaks the spec.
- **I2.** Every other controller entry point that takes an address's
  authorization takes it as a guardian (`submit_guardian`,
  `approve_change`), bound to another account's statement digest. Signing
  one never changes the signer's own recovery state.
- **I3.** By I1 and I2, a signature path into the controller, whether
  through a rule scoped to it or a `Default` rule, can reach only guardian
  approvals. A rule scoped to the document's own controller is therefore
  allowed, and the reserved-name guard alone protects the hooks.

**No re-entry (D16).** Soroban refuses any call into a contract already on
the call stack (`cap-0071.md` C8). The rules that follow from it:

- **Hooks never call back into the account.** That covers `rcv_sync`,
  `rcv_cancel`, `rcv_upgrade`, `enforce`, `install`, and the pool's
  `rcv_insert`. The account passes each of them what it needs:
  - the compiled document hash and configuration;
  - the approval freshness bound;
  - the upgrade step;
  - the leaf's `(enrollment_id, commitment)`.
- **The controller reads the account only from its own external entry
  points.** These are `begin_*`, `publish_baseline`, and evidence
  submission, through `account::RecoveryAccountClient`.
- **`__check_auth`'s own checks never read the controller.** The freeze is
  a local mirror (§9). The controller runs beneath `__check_auth` only as
  the recovery rule's policy: OZ's `do_check_auth` calls its `enforce` when
  a context selects the recovery rule, which only a completion's
  `apply_doc` does (T5).
- **Evidence for an account should not be submitted through that account's
  own `execute`.** The account would then be on the stack when the
  controller reads its views or sets its freeze mirror, and the submission
  would fail. This is a usability limit, not a security one.
- **No configuration may list the account among its own guardians.** The
  controller refuses one with `InvalidConfiguration`.

**One write path.** `apply_doc` is the only entry point that changes the
account's context rules, signers, or policies. The account implements OZ's
`SmartAccount` without exporting it, so `add_context_rule`, `add_signer`,
`add_policy`, and the other piecemeal mutation entry points do not exist on
the deployed contract (`apply_doc.rs::piecemeal_mutation_entry_points_do_not_exist`).

**Entry points**

| Contract | Entry point | Authorization |
| --- | --- | --- |
| Account | `__constructor(admin_signers)` | Deploy time only. Installs rule 0, `admin`, scoped to the account, with the given signers. |
| Account | `__check_auth` | Reserved names (rule 1), then the freeze (§9), then OZ `do_check_auth`. The order does not matter for security: each step only refuses. |
| Account | `apply_doc(doc_json, approval_valid_until, expected_revision)` | Owner authorization, or the recovery rule (completion only); refused with `StaleRevision` when `expected_revision` is set and the account is at another configuration revision. Then, in order: compile (`Compiler(..)` errors), `AdminLockout`, `RevokedCredential`, `ZkFactorChangedInPlace`, `EnrollmentReused`, the controller's `rcv_sync` (`Recovery(..)` errors), rule reconciliation, leaf insertion, completion effects. Emits `DocApplied`. |
| Account | `execute(target, fn, args)` | Owner authorization; reserved names refused |
| Account | `schedule_upgrade`, `execute_upgrade`, `cancel_upgrade` | Owner authorization (§12) |
| Account | `cancel_recovery(attempt_id)` | Owner authorization; `Loss` only |
| Account | `rcv_gate(attempt_id, frozen_until)` | Invoker-only: the adopted controller's authorization, and the caller must be the adopted controller |
| Account | `renew(fingerprints, enrollment_ids)` | Permissionless (§3.6) |
| Account | `applied_doc`, `applied_doc_hash`, `doc_compiler`, `infra`, `is_revoked`, `is_enrolled_id`, `recovery_controller`, `recovery_gate`, `pending_upgrade`, `next_upgrade_request_id`, `recovery_generation`, `revision`, `configuration`, `document`, `capabilities`, `installed_rules`, `get_context_rules_count`, `get_context_rule` | None (read-only). The views the controller calls (`applied_doc`, `applied_doc_hash`, `doc_compiler`, `is_revoked`, `is_enrolled_id`, `next_upgrade_request_id`) plus `rcv_gate` make up `account::RecoveryAccountClient`; the rest are for wallets. |
| Controller | `rcv_sync`, `rcv_cancel`, `rcv_upgrade` (`controller::RecoveryHooksClient`), `install`, `uninstall`, `enforce` | Invoker-only: `account.require_auth()` reachable only from the account's own flows |
| Controller | `begin_lost_key`, `begin_compromise`, `submit_zk`, `submit_zk_change`, `publish_baseline`, `renew`, `renew_nullifier` | Permissionless |
| Controller | `submit_guardian`, `approve_change` | The guardian's `require_auth_for_args((digest,))` (non-reserved names, so guardians that are perch accounts can sign) |
| Controller | `config`, `epoch`, `next_attempt_id`, `attempt`, `attempt_live`, `activity_gate`, `statement(account, attempt_id, domain)`, `change_statement(account, subject, valid_until)`, `change_evidence`, `nullifier_spent`, `baseline` | None (read-only; evidence providers fetch the exact statement to sign or prove) |
| Pool | `rcv_insert` (returns nothing; `zk::MembershipPoolClient`) | Invoker-only |
| Pool | `is_known_root`, `depth`, `version`, `enrollment`, `current_tree`, `tree`, `leaves`; `renew_tree`, `renew_root`, `renew_leaves`, `renew_enrollment` | None. `is_known_root` and the `renew_*` calls extend entry TTLs and change nothing else. |
| Adapter | `verify`, `verify_proof`, `circuit_id`, `vk`, `tree_depth`, `version` | None (writes nothing) |
| Doc compiler | `compile_doc`, `derive_target`, `limits`, `capabilities` | None (pure) |

**Revision binding.** The account's configuration revision (`revision`
view, a `u64`) is 0 after the constructor and advances by one on every
successful `apply_doc`, including a re-apply of the same document, and on
every executed upgrade. Nothing else changes it. Only `apply_doc` can be
bound to a revision, through `expected_revision`, which is checked right
after authorization and before compiling. Ordinary authorization is not
bound to a revision: a signature binds the invocation and the selected rule
ids (OZ's `sha256(signature_payload || context_rule_ids.to_xdr())`).
A transaction signed at revision r whose selected rule was removed or
replaced before inclusion fails closed (`ContextRuleNotFound`); one whose
selected rule was edited in place keeps the rule's id and executes under
the rule as it is at inclusion. Binding a revision into ordinary
authorization would change every signer's digest and is not supported
([`DEFERRED.md`](../DEFERRED.md#revision-bound-ordinary-signatures)).
`crates/integration-tests/tests/revision.rs` pins both cases.

## 16. Dependency layering and immutability

```text
perch-recovery-interface (library: statement, encodings, interfaces)
   ▲            ▲                                ▲         ▲
controller    adapter (embeds verifier and VK)   pool    account ──pins──▶ doc compiler, interpreter, spending limit
```

- **No deployable links another deployable's contract.** They agree
  through the interface crate's types and contract clients. The controller
  and the account also use the doc compiler's crate with its `contract`
  feature off (its client, compiled types, and `admin_survives`), so there
  are no circular build-time pins.
- **The account names its controller, adapter, and pool in its document.**
  They are adoptable per account, by document.
- **Build-time pins.** The account pins its doc compiler, interpreter, and
  spending-limit policy (`registry_contract!`, each address derived from
  the build-time wasm hash); a new version of any of them reaches an
  account only through an account upgrade (§12). The adapter compiles in
  its verifier and verification key.
- **Derivation uses the account's compiler.** The controller calls
  `derive_target` and `publish_baseline` through the compiler the account
  reports (`doc_compiler` view), so derived targets and applied documents
  are canonicalised by the same code.
- **Immutable, constructorless, versioned.** Controller, adapter, and pool
  have no constructor, no admin key, no pause, no parameter setter, and no
  upgrade entry point. The stateful ones (controller, pool) keep only
  per-account and per-tree storage. They are deployed content-addressed:
  an address is `deployer(registry, sha256(wasm))`, so a new version is a
  new address. Publishing it changes nothing for existing accounts: they
  adopt it only by applying a document that names it, gated like any
  reconfiguration (§10).
- **Pinned hashes are deployed hashes.** Every pinned hash must be the hash
  of the Wasm actually built and deployed. `scripts/fetch-infra-wasm.sh`
  fetches each pin from the chain at the address the deployment manifest
  records, and refuses it unless its `sha256` is the manifest's hash and the
  address is `deployer(registry, sha256(wasm))`.
