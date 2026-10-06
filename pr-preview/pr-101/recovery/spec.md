# Recovery specification

**Status: authoritative draft for epic
[#99](https://github.com/stellar-registry/perch/issues/99).** This document is
the single source of truth for perch account recovery: states, transitions,
who may authorize what, which document changes a recovery may make, account
upgrades, the ZK boundary, and the membership pool. Where any other document
in `docs/recovery/` disagrees with it, this document wins; those documents
describe the implementation that predates it.

Companion material:

- [`statement.md`](statement.md): byte layouts of the recovery statement,
  credential fingerprints, and replacement sets.
- `crates/perch-recovery-interface`: the code half of this spec (statement
  types, encodings, the ZK adapter, verifier, and pool interfaces, the
  account constants). `testdata/recovery/statement-v2.json` holds vectors
  produced by an independent implementation
  (`scripts/recovery-statement-vectors.py`).
- [`budgets.md`](budgets.md): resource budgets still to be measured, and the
  rule that picks the pool depth.
- [`cap-0071.md`](cap-0071.md): the CAP-0071 delegated-auth and
  invoker-auth host behaviour this spec relies on, with the tests that pin it.

Keywords: **must**, **must not**, **may** are requirements on the
implementation (the controller, the account, the adapter, the pool, the doc
compiler). "Refuse" means the call fails and changes no state. Soroban
rolls back every write of a failing invocation, so no transition in this
spec both refuses and records something: a transition either succeeds and
writes, or refuses and writes nothing.

## Decision summary

| # | Topic | Decision | Section |
| --- | --- | --- | --- |
| D1 | Activity during recovery | `Protected`: while an attempt is authorized, the account authorizes nothing except that attempt's completion, on every path. `Loss`: ordinary activity continues. The `pending-activity` field is removed. | §9 |
| D2 | Evidence-free attempts | Anyone may open an attempt. Any number may collect evidence at once, and a collecting attempt blocks nothing. | §6 |
| D3 | Authorized window | From authorization until completion, cancellation, or expiry, both profiles refuse every policy change except that attempt's completion, and refuse upgrade scheduling and execution. | §9, §12 |
| D4 | Reconfiguration | `Loss`: owner authorization. `Protected`: owner authorization plus the enrolled condition's evidence over a `Reconfigure` statement (`Combined`: guardian quorum and a ZK proof). | §5, §10 |
| D5 | Cancellation | The enrolled condition's evidence over a `Cancel` statement, in both profiles. Under `Loss`, owner authorization alone also cancels, and that veto is never capped. An evidence-based cancellation of an authorized attempt counts toward `max-cancels`. | §6 |
| D6 | Permitted changes | The target document is derived on-chain from the source and a declared replacement set. For lost-key the source is the applied-document snapshot; for compromise it is the enrolled baseline's signers and rules, with the current recovery section. Nobody chooses a target hash. | §7 |
| D7 | Revocation | A credential a recovery replaces leaves the account, so the target may not keep it in any slot (swaps and no-op replacements are refused at T1), and it never authorizes again. A completion revokes the union of (a) the credentials it explicitly replaced in its source document, the baseline included, and (b) every credential it removed from the current document. Both go into the account's permanent revoked set. Every applied document is checked against that set, on every path. | §7.3, §8 |
| D8 | Completion vs. reconfiguration | A completion is recognised by the attempt consumed in the same invocation. It may change exactly what its replacement set declares. Configuration identity is the canonical text of the recovery section, so rotating a signer's key is not a reconfiguration. | §10 |
| D9 | Nullifiers | One nullifier per enrolled ZK credential, owned by that `(account, enrollment)`. It is either unspent or spent. Only a completion of that account spends it; nothing ever un-spends it. Proofs for any action need it unspent. There are no reservations, so there is nothing to release (#91). | §11 |
| D10 | Stale state | Leaves and nullifiers bind an enrollment id the configuration names, and the account refuses to re-enroll an id it used before. Every configuration change and every completion bumps the per-account epoch, and evidence or attempts from an older epoch are dead. | §3, §11 |
| D11 | Upgrades | Owner authorization (plus, under `Protected`, condition evidence over an `Upgrade` statement binding the Wasm hash and the epoch). Executable after 120 960 ledgers. An account-owned **recovery generation** invalidates the request whenever recovery configuration changes, including across unenrolled → enrolled → unenrolled. Executing an upgrade advances it. Blocked during an authorized attempt. | §12 |
| D12 | Invoker-only hooks | The account never authorizes a reserved hook name (`install`, `uninstall`, `enforce`, `rcv_*`) through `__check_auth`, and never calls one through `execute`. Controller, pool, and policy hooks are reachable only from the account's own controlled flows. That name guard, not a ban on rules scoped to the controller, is what protects the controller: a document may scope rules to its own controller so the account can act as a guardian there. Guardian and ZK evidence is always submitted through non-reserved entry points and recorded; hooks only read the records. | §2, §5, §15 |
| D13 | Statement | One `RecoveryStatement`, encoded at fixed width and hashed with SHA-256. Guardians authorize the digest and the circuit binds it. | §4 |
| D14 | ZK boundary | The controller passes the structured statement to an adapter. The adapter checks the circuit id, field canonicality, root membership in the enrolled pool, and the proof. Public inputs stay `root, nullifier, statement_hash`. | §13 |
| D15 | Pool | Depth 32, or depth 24 if depth 32 misses the budget rule. A full tree rolls over automatically. Roots are accepted as `(tree_id, root)`, and every root a tree has ever had stays acceptable. | §14 |
| D16 | No re-entry | Soroban refuses to re-enter a contract already on the call stack. No hook calls back into the account; the account passes what hooks need. The `Protected` freeze is a mirror in the account's own storage, set by the controller through the account's invoker-only `rcv_gate`, never a cross-contract read from `__check_auth`. | §9, §15 |

## 1. Scope and vocabulary

In scope: guardian, ZK, and combined recovery for perch smart accounts under
the `Loss` and `Protected` profiles; recovery reconfiguration; account
upgrades on recovery-enrolled accounts; the membership pool and ZK
verification boundary.

Out of scope (epic #99): preserving existing accounts, addresses, secrets,
commitments, or pending attempts (fresh deployments only); mainnet rollout;
concealing which accounts use ZK recovery; dummy commitments; more than one
ZK backend; CAP-0085 governance-managed executables.

| Term | Meaning |
| --- | --- |
| account | A perch smart account built with this spec's recovery support. Always a contract (`C...`) address. |
| `L` | The current ledger sequence, `e.ledger().sequence()`. All timing is in ledger counts. |
| owner authorization | The account authorizing through any of its ordinary context rules (in practice the self-admin rule), via `__check_auth`. Never the recovery rule. |
| controller | The constructorless, immutable recovery-controller instance named by the applied document's `recovery.controller`. |
| condition | The enrolled mode's evidence requirement over a given statement (§5). |
| statement | A `RecoveryStatement` (§4). Every piece of evidence is bound to exactly one. |
| attempt | A lost-key or compromise recovery in progress, identified by `(account, attempt_id)`. |
| epoch | The controller's per-account configuration epoch (§3.3). |
| enrollment id | The 32-byte identifier of the account's current ZK credential (§3.1). |
| adapter, verifier, pool | The three ZK contracts (§13, §14). |

## 2. Roles and trust

| Party | Holds | Trusted for |
| --- | --- | --- |
| Owner | The admin signers of the applied document | `Loss`: everything, including vetoing recovery. `Protected`: ordinary activity outside an authorized window. Not trusted to change recovery configuration or upgrade the account without the condition. |
| Guardians | Their own Stellar addresses (`G...` or `C...`) | Approving exactly the statements they sign. Guardians must check out of band that the replacement credentials they approve belong to the person recovering. The chain cannot check that. |
| ZK secret holder | The secret behind the enrolled commitment | Same as a guardian quorum, for the ZK factor. |
| Anyone | Nothing | Opening attempts, submitting evidence others produced, completing an attempt whose evidence and timelock are satisfied, publishing a baseline whose hash is enrolled, renewing storage. None of these needs authority. |
| Controller, adapter, verifier, pool, doc compiler | Code at a content-addressed address | Behaving as their published source says, forever. They have no admin and cannot be upgraded in place (§16). |
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
  attempt (T4), and only compromise recovery is immune to that. Wallets
  should require a baseline for `Protected`; that product choice is Nido's
  (nidohq/nido#220).
- **A rule scoped to the account's own controller is safe, and needed.** An
  account that is a guardian of other accounts at the controller it uses
  itself signs those approvals in contexts naming that controller
  (`submit_guardian`, `approve_change`). Its document therefore needs a
  rule scoped to the controller, or a `Default` rule.

  The reserved-name guard (§15, invariant I1) is what keeps such a rule's
  signers away from the controller's sensitive entry points. It refuses
  `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `install`, `uninstall`, and
  `enforce` on any contract, whatever rule is selected. What such a rule
  grants is exactly what it says: its signers approve, as this account,
  statements for accounts that list this account as a guardian. The account
  cannot list itself (§15), so the rule never touches the account's own
  recovery.

## 3. Configuration

### 3.1 Schema (changes from the pre-spec schema)

Fresh deployments only, so no compatibility shim is required. The
document's `recovery` member becomes:

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

| Change | Why |
| --- | --- |
| `pending-activity` removed | D1 fixes the behaviour per profile; a field that could contradict the profile is a hazard (#84). |
| ZK `verifier` renamed `adapter` | The controller calls the adapter (§13). The adapter pins its verifier at build time. |
| `circuit-id` is exactly 32 bytes | It is `sha256` of the verifier's embedded verification key. The adapter refuses any other value. |
| `pool` required for ZK modes | The one supported backend is pool-based. Root acceptance is bound to this pool. |
| `enrollment-id` added (ZK modes) | 32 random bytes naming the current ZK credential. It is bound into the leaf and the nullifier (§3.4, §11). |
| `commitment` added (ZK modes) | The credential's inner commitment `Poseidon2(DOM_LEAF, secret)`, a canonical field element. The account inserts the leaf from it (§14.2). |
| Compiled `replaceable` stays signer ids | Fingerprints in the compiled configuration made rotating a key look like reconfiguration (#92). Revocation fingerprints credentials separately (§8). |

The commitment is part of the document, so `config_hash` binds it. Through
`config_hash`, so do the owner's signature on `doc_json`, every
reconfiguration approval, and every attempt's derived target.

A commitment passed as a call argument instead could be swapped by anyone
who resubmits the same approvals with a stolen owner key, or by whoever
submits a recovery completion first. The commitment is public either way:
the pool's insertion event reveals the leaf. The secret must therefore be a
uniformly random field element with at least 128 bits of entropy, because a
guessable secret can be found offline.

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
controller, baseline hash, replaceable signer ids, and timing. Rotating a signer's key
elsewhere in the document does not change it (#92). Renaming a replaceable
signer id does.

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

This closes the stale-attempt class (#93): removing recovery and enrolling
again, or enrolling a different guardian set, bumps the epoch. Every attempt
and every piece of evidence from before is dead, whether or not some other
path left it in storage.

### 3.4 Enrollment ids

An enrollment id names one ZK credential. The **account** keeps the
append-only set of every enrollment id it has enrolled, and `apply_doc`
refuses a configuration that names a previously enrolled id other than the
current one. A retired or consumed credential's leaf can therefore never
become valid again, including after a switch to a different controller,
whose nullifier records start empty. Clients generate ids as 32 random
bytes.

The ZK factor `(adapter, circuit-id, pool, enrollment-id, commitment)`
either stays entirely unchanged across an `apply_doc` or carries a new
`enrollment-id`. The account inserts a leaf exactly when the enrollment id
changes, into the configured pool, from the compiled document's commitment.

Whenever the ZK factor changes, at enrollment or reconfiguration,
`rcv_sync` refuses unless:

- the adapter's `circuit_id()` equals `circuit-id`;
- the adapter's `tree_depth()` equals the pool's `depth()`.

Without these checks a factor could be enrolled that no proof can ever
satisfy, which would permanently lock a `Protected` account's
reconfiguration and upgrades.

### 3.5 Baselines

`baseline.doc-hash` names the canonical hash of the baseline document a
compromise recovery restores. A baseline is approved by approving the
recovery configuration that names it. Under `Loss` that is the owner; under
`Protected` it is the owner plus the condition. Changing or removing it is a
reconfiguration. The chain does not check that the baseline was ever the
account's applied document. What it enforces is that only the approved
configuration can name one.

The baseline's content must be on-chain before a compromise attempt can
open. `publish_baseline(account, doc_json)` on the controller is
permissionless. It compiles `doc_json` with the account's doc compiler and
stores the canonical bytes only if:

- the canonical hash equals the enrolled `baseline.doc-hash`;
- the document compiles for this network;
- an admin rule survives the anti-brick check.

Anyone holding the reviewed document may publish it. Publishing changes no
authority.

A baseline document's own `recovery` member is ignored (§7.2). This keeps
the commitment non-circular and prevents a compromise recovery from rolling
the recovery configuration back to whatever the baseline carried.

### 3.6 Storage lifetime

Per-account controller state (configuration, epoch, authorized attempt,
`invalidate_below`, cancellation count, attempt-id counter, recorded change
approvals), the account's revoked set, enrolled-id set, freeze mirror
(§9), recovery generation, and pending upgrade (§12), nullifier records, and
the pool's roots and frontier live in persistent storage. An archived persistent entry is unavailable, never
absent: a transaction touching it fails until someone restores it. A
counter therefore cannot silently reset to zero through TTL expiry.
Permissionless `renew` entry points extend these entries to the network
maximum.

Collecting attempts may live in temporary storage with a TTL of at least
their evidence window. Losing one to expiry is equivalent to its evidence
window ending.

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

Guardian clients should also set Soroban's `signature_expiration_ledger` no
later than `valid_until_ledger`.

**Timing.** Every timing term is a ledger count. There is no seconds field
and no seconds-to-ledgers conversion anywhere. Nido's
`AVG_LEDGER_CLOSE_SECS` conversion (nidohq/nido#218) has no counterpart.
Protocol constants are defined in ledgers (`ACCOUNT_UPGRADE_DELAY_LEDGERS`).
Where a constant is described in days, that is its nominal duration at
5-second ledgers, not a conversion of a user-supplied value.

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
  the adapter verified.

Records are keyed by the statement digest, so they die with the epoch or
the freshness bound. The consuming `rcv_sync` or `rcv_upgrade` rebuilds the
digest from the change being applied and the account's
`approval_valid_until`, then counts the recorded approvals. Only distinct,
enrolled guardians are counted.

This keeps proof verification (about 180 million instructions in Nido's
measurement) out of the transaction that compiles and installs a document.

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
                       └─ stale lost-key source at T4 ─▶ Invalidated (stored)
```

The stored states are `Collecting`, `Authorized`, `Completed`,
`Cancelled`, and `Invalidated`.

- **`Expired` is derived, never stored.** It is read from the ledger
  against the attempt's windows.
- **`Invalidated` is stored for exactly one cause:** T4 finding a lost-key
  attempt's source changed. The evidence call that ran T4 succeeds, writes
  `AttemptState::Invalidated`, and emits `AttemptInvalidated`.
- **Every other invalidation is derived:** an epoch change, or a sibling's
  authorization (`invalidate_below`). Nothing is written for these, because
  the cause is already in storage and an attempt from an older epoch or
  below `invalidate_below` reads as dead.

An attempt is **live** when all of the following hold:

- its recorded epoch equals the current epoch;
- it is not terminal (`Completed`, `Cancelled`, or `Invalidated`);
- it is the authorized attempt, or its id is at least the account's
  `invalidate_below` (so a sibling's authorization has not invalidated it);
- `Collecting` and `L ≤ evidence_deadline`, or `Authorized` and
  `L < expires_at`.

| Window | Ledgers |
| --- | --- |
| Evidence | `created_at ≤ L ≤ evidence_deadline`, with `evidence_deadline = created_at + expiry_ledgers` (inclusive) |
| Timelock | `authorized_at ≤ L < executable_after`, with `executable_after = authorized_at + delay_ledgers` |
| Completion | `executable_after ≤ L < expires_at`, with `expires_at = executable_after + expiry_ledgers` |

All additions are checked; an overflowing `u32` refuses the transition.

### 6.3 Transitions

**T1 Begin** — `begin_lost_key(account, replacements)` or
`begin_compromise(account, replacements)`. Permissionless.

Refuses if any of the following hold:

- the account is not enrolled;
- an attempt is authorized and live;
- `derive_target` refuses the replacement set (§7.3 rules 1–3, 5, 6, or
  rule 4's commitment check);
- the ZK enrollment id was enrolled by the account before, per the
  account's `is_enrolled_id` (§7.3 rule 4; `EnrollmentIdReused`);
- a credential in the target, or a replacement credential, is revoked, per
  the account's `is_revoked` (rule 7; `CredentialRevoked`);
- a replaced source credential still appears in the target (rule 8;
  `ReplacedCredentialRetained`);
- for compromise: no baseline is enrolled or its content is unpublished.

The checks against the account's history (enrolled ids, revoked set) are
the controller's. `derive_target` is pure and sees only the two documents
and the replacement set. T1 is an external entry point, so the controller
may read the account's views there (D16).

Otherwise:

1. Assigns `attempt_id` from the per-account counter (never reused).
2. Records `epoch`, `created_at = L`, `evidence_deadline`, `cancel_until`,
   the source hash, the derived target hash, the target configuration hash
   (§10), the replacement-set hash, the ZK enrollment the completion
   installs, and the credentials occupying the replaced signer slots in the
   source (the completion revokes them, §8).
3. Emits `AttemptBegun`.

Opening an attempt grants nothing and blocks nothing (D2). Opening many
costs their openers fees and rent, and has no effect on the account or on
other attempts.

**T2 Guardian evidence** — `submit_guardian(account, attempt_id, domain,
guardian)`, where `domain` is `Initiate` or `Cancel`. Requires `guardian`'s
`require_auth_for_args((digest,))` for the attempt's statement in that
domain. Refuses if any of the following hold:

- the mode has no guardian factor;
- `guardian` is not enrolled;
- the attempt is not live;
- for `Initiate`, the attempt is not collecting;
- the guardian already counted in this domain;
- the statement is not fresh.

Records the approval, then attempts promotion (T4) or cancellation (T6).

**T3 ZK evidence** — `submit_zk(account, attempt_id, domain, evidence)`.
Permissionless. Same refusals as T2 for the ZK factor. Then:

1. The adapter must accept the evidence for the statement and the enrolled
   binding.
2. The nullifier must be unspent (§11).
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

Promotion refuses while another attempt is authorized and live.

**T5 Complete** — `apply_doc(target_bytes, …)` selecting the zero-signer
recovery rule (Variant A). The controller's `enforce` requires all of:

- the context is `apply_doc` on this account;
- an authorized live attempt `A` exists;
- `executable_after ≤ L < expires_at`;
- `sha256(target_bytes) = A.target_doc_hash`.

Then `enforce` marks `A` completing, bound to `(attempt_id,
target_doc_hash)`. The account's `apply_doc` body runs `rcv_sync` with
the compiled document's hash, which consumes that marker and returns
`SyncOutcome::Completed`. The account then applies its own completion
effects (§10), including clearing its freeze mirror. Every write
belongs to the same invocation, so a failure anywhere (compile, revocation
check, anti-brick, pool insertion) reverts all of it, including the
consumption. Completion is permissionless once its evidence and timelock
are satisfied. Nobody can change what it installs, because the target, the
new credentials, and the new ZK commitment are all fixed by `A`.

**T6 Cancel by evidence** — when the cancellation condition is satisfied for
a live attempt `A`:

1. `A` becomes `Cancelled`. If `A` was authorized under `Protected`, the
   controller calls the account's `rcv_gate(attempt_id, 0)` to lift the
   freeze.
2. If `A` was authorized, the account's cancellation count increments, and
   the cancellation is refused instead if the count has reached
   `max-cancels`. The controller keeps the count per account. Switching to
   another controller starts a new count, and that switch needs the
   reconfiguration authority (§10).
3. Emits `AttemptCancelled`.

Cancelling a collecting attempt never counts: it blocks nothing, so
cancelling it only tidies state.

**T7 Cancel by owner (`Loss` only)** — the account's
`cancel_recovery(attempt_id)` under owner authorization invokes the
controller's `rcv_cancel`. The controller refuses under `Protected`.
Otherwise T6's effects apply, except that an owner cancellation is never
counted toward or refused by `max-cancels`. If it were, holders of the
condition could use the cap up by authorizing and cancelling their own
attempts, then authorize one more that the owner could no longer stop.
Once the attempt is cancelled the window has ended, so the owner may then
reconfigure, for example to remove a guardian set that opened it.

**T8 Expire** — derived. No transaction is needed. The first transition
that touches an expired attempt treats it as terminal.

**T9 Enroll, reconfigure, remove** — through `apply_doc` only (§10).

**T10 Renew** — permissionless TTL extension of existing entries. Changes
no meaning.

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

`derive_target(source_json, recovery_json, replacements)` is a pure entry
point of the doc compiler, the one contract that parses documents.

The controller calls it at T1 through the account's own compiler (§16). It
returns:

- the target's canonical bytes and hash;
- the target's configuration hash;
- every signer credential in the target, as declared;
- the credentials occupying the replaced signer slots in the source. For
  compromise these are the **baseline's** credentials. They are recorded at
  T1 and revoked at completion (§8).

The compiler is pure and makes no verifier calls. The controller therefore
canonicalizes the returned credentials (`Verifier::batch_canonicalize_key`)
and fingerprints them (`Credential::fingerprint`) for rules 7 and 8.

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
4. A ZK enrollment's commitment is a canonical field element (compiler),
   and its id is not in the account's set of enrolled ids (§3.4;
   controller, via `is_enrolled_id`). The target's
   `recovery.mode.enrollment-id` and `commitment` become the new values.
   Nothing else in the recovery section changes.
5. Nothing else changes: rules, other signers, network, version.
6. The target passes full document validation (which rejects duplicate key
   material), the anti-brick check, and network binding.
7. No credential in the target, and no replacement credential, is in the
   account's revoked set (compared by canonical fingerprint, §8).
8. **No explicitly replaced source credential appears anywhere in the
   target** (compared by canonical fingerprint;
   `credential::replaced_credentials_leave`). This refuses a no-op
   replacement (a slot "replaced" by its own credential) and a swap of
   credentials between slots.

   The alternative, treating a retained credential as not replaced, would
   let a swapped key keep authorizing from its new slot. That would break
   D7's guarantee that a credential a recovery replaces never authorizes
   again, and §8 would revoke a credential the target installs. With
   rule 8, every replaced credential leaves the account at completion and
   is revoked there.

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
  naming it own this (#87, #94).
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
    - when something on the rule survives, removals run first, so its
      counts never exceed OZ's per-rule limits mid-edit; when nothing
      survives, additions run first, so it is never empty;
    - a policy whose install parameters change counts as removed and
      re-added.
  - or (b) **replaced whole** under a new rule id: the rule is removed and
    the target rule added.

  The model prices the exact OZ operation sequence each way would run, from
  the diff and the signer and policy registry reference counts at that point
  (registrations and deregistrations are events of their own): contract-event
  bytes first (the ContractEvent XDR the per-transaction events limit counts,
  including the spending-limit policy's install and uninstall events), then
  ledger entries written as the tiebreak. An in-place edit costs per changed
  signer and policy; a replacement costs a rule removal and addition plus
  deregistering, re-registering, and reinstalling everything the rule keeps.
- Replacement is the only way when nothing on the slot survives and no order
  of additions and removals keeps it non-empty within OZ's per-rule limits
  (`MAX_SIGNERS` 15, `MAX_POLICIES` 5). Example: the recovery rule, which has
  no signers, when its only policy's parameters change. Adding first is
  impossible (one policy per address) and removing first would empty it. A
  changed scope is a different slot (removed and added).
- An installed rule whose slot the target lacks is removed, before
  anything is added; a target rule whose slot is not installed is added.

The installed rule set that results authorizes exactly what a full replace
would. A full replace takes replacement for every rule and deregisters and
re-registers every signer and policy, so taking the cheaper way per rule
means no apply emits more event bytes than a full replace. A replaced rule
gets a new id and its policies are reinstalled, resetting their state (a
spending limit's window), as a full replace always did; an in-place edit
keeps the id and the kept policies' state. The account keeps one record per
installed rule (id, slot, valid_until, signers, and each policy with a
digest of its install parameters) bounded by the rule cap (plus the
recovery rule). It never scans historical rule ids, which grow without bound with
every past apply (#102 review, P1).

A completion also revokes every removed credential and compiles the target.
Two rules bound that cost:

- **Document caps.** The doc compiler refuses, on every `apply_doc` and in
  `derive_target`, a document exceeding fixed caps on signers, rules, and
  canonical size. The caps are sized so that the worst-case completion
  fits the transaction budget (`budgets.md`). The worst case is a
  maximum-size pre-recovery document whose every slot differs from a
  maximum-size target, after any amount of prior rule churn.
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
  never revokes what it applies.

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
  revoked credential.
- Fingerprints are computed over the verifier's canonical key bytes
  (`Verifier::batch_canonicalize_key`), so a revoked key cannot return under
  a different encoding. Delegated addresses are already canonical.
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
account's own storage**: `(frozen_attempt, frozen_until)`.

- The adopted controller sets the mirror through the account's invoker-only
  `rcv_gate` when a `Protected` attempt is authorized (T4).
- The controller clears it (`frozen_until = 0`) when that attempt is
  cancelled (T6).
- The account clears it itself on `SyncOutcome::Completed`.
- It lapses on its own at `frozen_until = expires_at`
  (`account::is_frozen`).

`rcv_gate` refuses any caller other than the adopted controller, which
authorizes by invoker authorization.

While the mirror is set, `__check_auth` refuses every context except a
single `apply_doc` context on the account itself that selects the recovery
rule, which the controller's `enforce` then validates (T5).

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
invocation is that attempt's completion.

**What the freeze cannot reach.** The freeze stops the account from
authorizing anything new. A permission it granted earlier stays usable by
whoever holds it: a token allowance, or an approval another contract
stored. No account code can revoke those, so wallets should keep
allowances short-lived and small.

**Evidence-free griefing (#89).** A collecting attempt freezes nothing,
blocks no policy change, no upgrade, and no other attempt (D2). Only
satisfying a condition, which requires the enrolled guardians or secret,
starts an authorized window.

## 10. Completion versus reconfiguration

Every `apply_doc` on an account with an adopted controller calls that
controller's `rcv_sync(account, doc_hash, recovery, approval_valid_until)`
before touching any context rule. It passes the compiled document's
canonical hash, its compiled recovery member (zero or one entry), and the
freshness bound of any recorded reconfiguration approvals. The call returns
a `SyncOutcome` (`Unchanged`, `Enrolled`, `Reconfigured`, `Removed`, or
`Completed(Completion { attempt_id, replaced })`) telling the account which
of its own effects to apply. Every outcome other than `Unchanged` advances
the account's recovery generation (§12). The controller cannot read the account back during the call (D16).

The call is invoker-only (§15). `rcv_sync` both decides and writes. No
separate `install` call ever writes configuration: `install` is
bookkeeping, and `uninstall` is a no-op, because OZ discards `uninstall`
failures.

`rcv_sync` classifies the call exactly one way:

| Case | Recognised by | Authorization | Effects |
| --- | --- | --- | --- |
| Completion | A completing marker from this invocation's `enforce` (T5) whose target hash equals the `doc_hash` argument | Already established by the attempt | The compiled configuration hash must equal the attempt's target configuration hash (unchanged, or ZK-rotated as declared). Consumes the marker, marks the attempt `Completed`, spends its nullifier, and bumps the epoch. Returns `Completed(Completion { attempt_id, replaced })`, where `replaced` holds the attempt's recorded source credentials. The account inserts the new leaf from the compiled target's ZK factor (§14.2), records the new enrollment id as used, revokes `replaced` together with every credential the completion removed from its current document (§8), clears any pending upgrade, and clears its freeze mirror. |
| No change | `config_hash` and controller unchanged, and not a completion | Owner authorization (already required by `apply_doc`) | Refuses if an attempt is authorized and live (§9); otherwise nothing. |
| Enroll | No configuration stored | Owner authorization | Stores the configuration and bumps the epoch. The account records the enrollment id as used. |
| Reconfigure | `config_hash` differs, controller unchanged | `Loss`: owner. `Protected`: owner plus the stored configuration's condition over `Reconfigure(Set(new))`, from recorded approvals (§5) | Refuses during an authorized window. Stores the new configuration, bumps the epoch, and invalidates every attempt. |
| Remove or switch away | No recovery section, or a different controller | Same as reconfigure, with `Reconfigure(Remove)` or `Reconfigure(Set(new))` evaluated by the **current** controller | Clears this controller's configuration for the account and bumps its epoch. When switching, the account then calls the new controller's `rcv_sync`, which treats the call as an enrollment. |

Consequences:

- **Key rotation is not reconfiguration (#92).** Rotating a replaceable
  signer's key leaves the recovery text, and therefore `config_hash`,
  unchanged.
- **A completion is never routed through reconfiguration checks
  (nido#219).** A ZK rotation that is part of a completion is allowed
  precisely because the attempt declared it.
- **Omitting the recovery section is removal.** It is gated like any
  removal. A completion's derived target always carries the recovery
  section, so a completion is never mistaken for a removal.
- **The controller's state follows the document (#93).** Removal clears it,
  and every change bumps the epoch.

## 11. Nullifiers

`nullifier = Poseidon2(DOM_NULLIFIER, account_hi, account_lo, enrollment_hi,
enrollment_lo, secret)`. It is one value per enrolled credential, the same
for every action, and it binds the account and the enrollment id: only that
`(account, enrollment)` owns it. The controller records spent nullifiers:

```text
unspent (absent) ──completion of an attempt of X that used it──▶ Spent{X}   (permanent)
```

| Event | Rule |
| --- | --- |
| Canonicality | The adapter refuses a nullifier or root `≥ r`; otherwise `n` and `n + r` would verify as one credential while the controller stored them as two. |
| Any ZK proof (initiation, cancellation, reconfiguration, upgrade) | Requires the nullifier unspent. Never changes the record. |
| Completion of attempt `A` of account `X` that used ZK evidence | Requires `A`'s recorded nullifier unspent; marks it `Spent{X}` in the same invocation. |
| Anything else | No transition. Nothing un-spends a nullifier, and no operation releases one, so no operation can release another account's or attempt's claim (#91). |

**Why there are no reservations.** The pre-spec controller reserved a
nullifier for the attempt whose proof arrived first, and released it later.
That added no safety:

- A proof is bound to its attempt by the statement, so it cannot be reused
  for another attempt.
- Two attempts carrying the same credential cannot both complete: the first
  authorization invalidates the other, and completion bumps the epoch.

It did add a denial of service. Under `Combined`, a holder of a stolen
secret could keep the credential reserved for junk attempts, so the owner's
attempt could never collect its ZK factor. It also made `ZkOnly`
cancellation by the same credential impossible, and its release step was
the source of #91. Several live attempts may therefore carry the same
unspent nullifier.

**Spending consumes the credential.** A ZK-evidenced completion spends the
enrolled credential's nullifier and installs the fresh enrollment its
replacement set declared (§7.3). The account always leaves recovery with a
working ZK factor that the recovering party holds. A `Protected` account is
never left with a dead factor that would make it impossible to reconfigure
or upgrade.

## 12. Account upgrades

**Recovery generation.** The account keeps `recovery_generation: u64` in
its own storage. It starts at 0, never decreases, and is never reset. It
advances by one:

- in `apply_doc`, whenever an `rcv_sync` call returns anything other than
  `SyncOutcome::Unchanged`: enrollment, reconfiguration, removal, either
  side of a controller switch, or a completed recovery;
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
   `rcv_upgrade(account, UpgradeStep::Schedule(Upgrade { request_id,
   wasm_hash }, approval_valid_until))`. That call refuses during an
   authorized window and, under `Protected`, checks the recorded condition
   over the subject (§5). It returns the controller's current epoch. The
   account's `next_upgrade_request_id` view tells approvers which
   `request_id` to approve.

   The account records an `account::UpgradeRequest { request_id,
   wasm_hash, generation, controller_epoch, executable_at }`:
   - `generation` is the current recovery generation;
   - `controller_epoch` is the epoch returned above, or none when
     unenrolled;
   - `executable_at = L + ACCOUNT_UPGRADE_DELAY_LEDGERS` (120 960 ledgers).

   One request at a time; scheduling another cancels the previous one.
   `request_id` comes from a per-account counter and is never reused.
2. **`execute_upgrade(request_id)`** — owner authorization. The checks run
   in this order (`UpgradeRequest::readiness`):
   - **Stale:** the request's `generation` differs from the current
     recovery generation. The call is refused (`StaleUpgrade`), whether or
     not the delay has passed. It does **not** clear the request: a refused
     invocation rolls back its writes. Nothing needs clearing anyway. The
     generation never decreases, so a stale request can never execute; it
     stays inert until `schedule_upgrade` replaces it, `cancel_upgrade`
     removes it, or a completion clears the slot. Wallets read staleness
     from the `pending_upgrade` and `recovery_generation` views.

     The alternative, a successful "cleanup" outcome that removes the
     request without upgrading, was rejected. It would make a call that
     did not upgrade report success.
   - **Not yet:** `L < executable_at`. Refused.
   - Also refused if the request is not the pending one, or an attempt is
     authorized and live.

   If a controller is adopted, the account then calls `rcv_upgrade(account,
   UpgradeStep::Execute(controller_epoch))`. As a second check, that call
   refuses if the controller's epoch moved or an attempt is authorized,
   then bumps the epoch.

   The account advances its recovery generation and calls
   `update_current_contract_wasm(wasm_hash)`. The epoch bump invalidates
   collecting attempts, whose targets the old code's doc compiler derived,
   and every outstanding approval.

**`cancel_upgrade()`** takes owner authorization.

| Rule | Why |
| --- | --- |
| The approval binds the exact Wasm hash, the epoch, and `config_hash` | A Protected approval cannot be carried to different code or a different configuration. |
| Any recovery-generation change makes a queued request stale | This is the validation of queued approvals when configuration changes. It is account-owned, so it holds across controllers and across periods without recovery. Enrollment, reconfiguration, removal, controller switches, completion, and an executed upgrade all advance it, so a successful recovery invalidates every outstanding request. Completion also clears the slot explicitly. |
| Blocked while an attempt is authorized | Upgrading must not race or neuter an in-flight recovery. |
| The delay applies to every account | The epic retains a seven-day delay. Accounts without recovery get the same window to notice a stolen key. |

The upgraded code inherits the account's storage, including the revoked
set, the recovery generation, and the recovery wiring. Whether new code
honours them cannot be enforced from the old code. That is why `Protected`
requires the condition to approve the exact Wasm.

## 13. ZK adapter boundary

### 13.1 Options evaluated

| Option | Shape | Verdict |
| --- | --- | --- |
| A. Opaque digest (pre-spec perch) | Controller passes a 32-byte SHA-256 statement to `verify_proof(statement, nullifier, proof, pool)` | The circuit cannot bind the account to the leaf and nullifier without trusting that the caller's digest and account agree, and the pool sits behind an opaque `Option<Address>`. No working circuit existed for it. |
| B. Per-field circuit binding (Nido `zk_recovery_doc`) | `auth_hash = P2_15(action, account, network, controller, doc hash, cfg version, baseline, nonce, timelock seconds)` | It works, but binds only a `u32` configuration version (not the configuration), carries a seconds timelock, and needs a new circuit and VK for every statement change. |
| **C. Structured statement to adapter, digest in circuit (chosen)** | Controller passes the structured `RecoveryStatement` and the enrolled `ZkBinding`. The adapter derives the account, enrollment id, and digest from them, and the circuit binds `statement_hash = P2_7(DOM_AUTH, account, enrollment, digest)` | Full configuration binding (through `config_hash` in the digest), action separation, and ledger timing. The statement can evolve without a circuit change. Nido's circuit topology (leaf/bind/nullifier, three public inputs, UltraHonk) is kept. |

### 13.2 Interfaces (`perch_recovery_interface::zk`)

- `ZkAdapterInterface::verify(statement, binding, evidence) -> Result<(),
  ZkAdapterError>` and `circuit_id()`. The adapter is stateless and
  constructorless, and pins its verifier at build time. It runs these
  checks in order:
  1. `binding.circuit_id` is its own;
  2. root and nullifier are canonical field elements;
  3. `pool.is_known_root(tree_id, root)` on `binding.pool`;
  4. `verify_proof(public_inputs(root, nullifier, statement_hash), proof)`.
- `ProofVerifierInterface::verify_proof(public_inputs, proof)`. The verifier
  is VK-baked and ABI-compatible with Nido's constructorless
  `nido-recovery-verifier`.
- `MembershipPoolInterface::is_known_root(tree_id, root)`.

The controller builds `ZkBinding { pool, enrollment_id, circuit_id }` from
its stored configuration only, and owns all nullifier state (§11).

### 13.3 Circuit

```text
public:  root, nullifier, statement_hash
private: secret, account_hi, account_lo, enrollment_hi, enrollment_lo,
         digest_hi, digest_lo, path_siblings[D], path_bits[D]

inner = P2(DOM_LEAF, secret)
leaf  = P2(DOM_BIND, account_hi, account_lo, enrollment_hi, enrollment_lo, inner)
assert merkle_root(leaf, path_siblings, path_bits) == root     // bits boolean, interior P2(l, r)
assert P2(DOM_NULLIFIER, account_hi, account_lo, enrollment_hi, enrollment_lo, secret) == nullifier
assert P2(DOM_AUTH, account_hi, account_lo, enrollment_hi, enrollment_lo, digest_hi, digest_lo) == statement_hash
```

- `P2` is Noir's `Poseidon2::hash` (noir-lang/poseidon v0.2.0), matching
  `soroban-poseidon`'s host Poseidon2. Interior Merkle nodes are untagged
  `P2(l, r)`, as in Nido.
- The `hi`/`lo` values are the 16-byte big-endian halves of 32-byte values
  (`split_hi_lo`). Collision resistance of `P2` makes range checks
  unnecessary: the adapter computes `statement_hash` from in-range halves.
- The domain tags are `BE(sha256(label)) mod r` for labels
  `perch/recovery/zk/v2/{leaf,bind,nullifier,auth}`. These are Nido's
  derivation with new labels, so no v1 artifact can be reinterpreted under
  v2.
- Depth `D` is 32, or 24 under the budget rule (`budgets.md`).
- `circuit_id = sha256(vk)`.

**Differences from Nido's working circuit, all deliberate:**

- `statement_hash` replaces the arity-15 `auth_hash`;
- the enrollment id enters the leaf and the nullifier;
- depth is 32 rather than 24;
- new domain labels.

The circuit, VK, verifier Wasm, and fixtures are regenerated (workstream 2).
Existing Nido artifacts are inputs, not release artifacts.

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
  are append-only, so a historical root is as sound as the latest one.

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

1. Refuses a non-canonical commitment.
2. Computes `leaf = P2(DOM_BIND, account split, enrollment split,
   commitment)` itself; a caller never supplies a wrapped leaf. Refuses an
   `(account, enrollment_id)` pair it has already inserted.
3. Appends it to the active tree and emits `LeafInserted { tree_id, index,
   leaf, account, enrollment_id }`.

`rcv_insert` returns nothing (`zk::MembershipPoolInterface`). A refusal
fails the call, and with it the `apply_doc`. Clients read a leaf's position
from the pool's views and events. When an insertion fills the active tree,
the same call seals it and opens `tree_id + 1`. A full tree never
blocks enrollment.

Insertion failure (for example, the account is out of fee budget) reverts
the whole `apply_doc`, so no configuration ever names an enrollment whose
leaf is absent.

### 14.3 Earlier trees and witnesses

- A sealed tree never changes. Its witnesses can be computed once and cached
  by the client.
- Root entries and the active frontier are persistent, renewable
  (`renew_tree`), and restorable after archival. A prover whose root entry
  has been archived restores it, or proves against a newer root.
- Witnesses come from `LeafInserted` events. RPC event retention is short,
  so the reusable indexer must persist every event, and clients should keep
  their own leaf's position.
- A proof against a root the pool never had is refused as `UnknownRoot`
  (a wrong witness). The fix is a correct witness and a new proof. Nothing
  about the account changes.

Enrollment is public: the event names the account. Concealing enrollment is
out of scope.

## 15. Invoker-only hooks and other authorization paths

`account.require_auth()` inside a hook is meant to mean "the account's own
code is making this call". Soroban satisfies it two ways: invoker-contract
authorization, and a signature through the account's `__check_auth`. The
second is the bypass in #90: a document rule scoped to the controller let
its signers call `install` directly.

The account must therefore:

1. **refuse in `__check_auth`** any context whose function name is in
   `account::RESERVED_INVOKER_ONLY_FNS` (`install`, `uninstall`, `enforce`,
   `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `rcv_insert`, `rcv_gate`), on
   any contract, before OZ's `do_check_auth`. Matching by name also covers controllers and
   policies the account adopted in the past;
2. **refuse in `execute`** a call to a reserved name. `execute` makes the
   account the invoker, which would otherwise grant invoker authorization to
   whoever can authorize `execute`;
3. **refuse at compile time**, as defence in depth, a rule whose
   `Scope::Contract` is the document's own ZK adapter or pool. The account
   never needs to authorize a call to either. A rule scoped to the
   document's **own controller is allowed**: an account that is a guardian
   at the controller it uses itself must authorize `submit_guardian` and
   `approve_change` there (§2). Rule 1 is what protects the controller's
   sensitive entry points, not this compile-time check.

`cap-0071.md` pins the host behaviour this relies on (properties C5, C6,
and C7).

**Invariants this section maintains.**

- **I1.** Every controller, pool, or policy entry point that acts on an
  account's own recovery state under that account's authorization has a
  reserved name. Today those are `rcv_sync`, `rcv_cancel`, `rcv_upgrade`,
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
- **`__check_auth` never calls the controller.** The freeze is a local
  mirror (§9).
- **Evidence for an account should not be submitted through that account's
  own `execute`.** The account would then be on the stack when the
  controller reads its views or sets its freeze mirror, and the submission
  would fail. This is a usability limit, not a security one.
- **No configuration may list the account among its own guardians.** The
  controller refuses one with `InvalidConfiguration`.

**Entry points**

| Contract | Entry point | Authorization |
| --- | --- | --- |
| Account | `__check_auth` | Freeze (§9), then reserved names, then OZ `do_check_auth` |
| Account | `apply_doc(doc_json, approval_valid_until)` | Owner authorization, or the recovery rule (completion only) |
| Account | `execute(target, fn, args)` | Owner authorization; reserved names refused |
| Account | `schedule_upgrade`, `execute_upgrade`, `cancel_upgrade` | Owner authorization (§12) |
| Account | `cancel_recovery(attempt_id)` | Owner authorization; `Loss` only |
| Account | `rcv_gate(attempt_id, frozen_until)` | Invoker-only: the adopted controller's authorization, and the caller must be the adopted controller |
| Account | `applied_doc`, `applied_doc_hash`, `is_revoked`, `is_enrolled_id`, `pending_upgrade`, `next_upgrade_request_id`, `recovery_generation`, `doc_compiler`, rule views | None (read-only; `account::RecoveryAccountClient`) |
| Controller | `rcv_sync`, `rcv_cancel`, `rcv_upgrade` (`controller::RecoveryHooksClient`), `install`, `uninstall`, `enforce` | Invoker-only: `account.require_auth()` reachable only from the account's own flows |
| Controller | `begin_lost_key`, `begin_compromise`, `submit_zk`, `submit_zk_change`, `publish_baseline`, `renew` | Permissionless |
| Controller | `submit_guardian`, `approve_change` | The guardian's `require_auth_for_args((digest,))` (non-reserved names, so guardians that are perch accounts can sign) |
| Controller | `config`, `epoch`, `attempt`, `statement(account, attempt_id, domain)` | None (read-only; evidence providers fetch the exact statement to sign or prove) |
| Pool | `rcv_insert` (returns nothing; `zk::MembershipPoolClient`) | Invoker-only |
| Pool | `is_known_root`, `depth`, tree views, `renew_tree` | None |
| Adapter | `verify`, `circuit_id`, `tree_depth` | None (pure) |

## 16. Dependency layering and immutability

```text
perch-recovery-interface (library: statement, encodings, interfaces)
   ▲            ▲              ▲               ▲
controller    adapter ──pins──▶ verifier     pool        account ──pins──▶ doc compiler, interpreter, spending limit
```

- **No deployable depends on another deployable's crate.** They agree
  through the interface crate's types and contract clients, so there are no
  circular build-time pins.
- **The account names its controller, adapter, and pool in its document.**
  They are adoptable per account, by document.
- **Build-time pins.** The account pins its doc compiler and interpreter
  (`registry_contract!`); a new version of either reaches an account only
  through an account upgrade (§12). The adapter pins its verifier.
- **Derivation uses the account's compiler.** The controller calls
  `derive_target` and `publish_baseline` through the compiler the account
  reports (`doc_compiler` view), so derived targets and applied documents
  are canonicalised by the same code.
- **Immutable, constructorless, versioned.** Controller, adapter, verifier,
  and pool have no constructor, no admin key, no pause, no parameter setter,
  and no upgrade entry point. The stateful ones (controller, pool) keep only
  per-account and per-tree storage. A new version is a new
  content-addressed address. Publishing it changes nothing for existing
  accounts: they adopt it only by applying a document that names it, gated
  like any reconfiguration (§10).
- **Nido contracts not carried forward.** Nido's admin-upgradable
  constructor verifier (`zk-verifier`) and its constructor-configured,
  admin-upgradable, factory-authority pool (`zk-recovery`) are not part of
  this stack. Their working parts (the UltraHonk verifier, the Poseidon2
  frontier, account-bound insertion) are ported under these rules.
- **Registry resolution (#95).** Fixing the stale compiler/interpreter
  fetch source is workstream 4. This spec requires only that every pinned
  hash be the hash actually built and deployed.

## 17. Issue map

| Issue | Where | Status after this spec |
| --- | --- | --- |
| perch #84 pending activity | D1, §9 | Decided (`Protected` freezes, `Loss` continues); `pending-activity` removed. Implementation: workstream 3. |
| perch #85 no circuit | §13 | Interface aligned with Nido's working proof system. Circuit, verifier, adapter: workstream 2. |
| perch #86 real auth tests | §15, `cap-0071.md` | Host semantics pinned under enforcing auth here. Controller and account tests: workstream 3. |
| perch #87, #94 baseline review and audiences | §3.5, §7.4 | Specified who owns each unenforced property. |
| perch #88 Lean canon coverage | — | Not affected. Still open. |
| perch #89 evidence-free griefing | D2, §6.4, §9 | Specified. |
| perch #90 direct `install` | D12, §10, §15 | Specified. |
| perch #91 nullifier release | §11 | Specified: nullifiers are only ever spent, never released. |
| perch #92 key rotation trips reconfigure | §3.2, §10 | Specified. |
| perch #93 stale config and attempts | §3.3, §10 | Specified (epochs, clear on removal). |
| perch #95 stale fetch source | §16 | Workstream 4. |
| nido #217 invoker auth on enroll | D12 | Specified. |
| nido #218 seconds approximation | §4 | Removed; ledger counts only. |
| nido #219 completion vs reconfigure | §10 | Specified. |
| nido #220 compromise opt-out | §3.5 | Protocol keeps `baseline` optional; the product choice is Nido's. |
| nido #230 ZK reconfigure domain | §4, §5, §13 | `Reconfigure` action with real ZK evidence; circuit is workstream 2. |
| nido #221, #224, #225, #226 | — | Workstreams 4–5. |
