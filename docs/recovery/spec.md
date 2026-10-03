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
compiler). "Refuse" means the call fails and changes no state.

## Decision summary

| # | Topic | Decision | Section |
| --- | --- | --- | --- |
| D1 | Activity during recovery | `Protected`: while an attempt is authorized, the account authorizes nothing except that attempt's completion, on every path. `Loss`: ordinary activity continues. The `pending-activity` field is removed. | §9 |
| D2 | Evidence-free attempts | Anyone may open an attempt. Any number may collect evidence at once, and a collecting attempt blocks nothing. | §6 |
| D3 | Authorized window | From authorization until completion, cancellation, or expiry, both profiles refuse every policy change except that attempt's completion, and refuse upgrade scheduling and execution. | §9, §12 |
| D4 | Reconfiguration | `Loss`: owner authorization. `Protected`: owner authorization plus the enrolled condition's evidence over a `Reconfigure` statement (`Combined`: guardian quorum and a ZK proof). | §5, §10 |
| D5 | Cancellation | The enrolled condition's evidence over a `Cancel` statement, in both profiles. Under `Loss`, owner authorization alone also cancels. Cancelling an authorized attempt counts toward `max-cancels`. | §6 |
| D6 | Permitted changes | The target document is derived on-chain from the source and a declared replacement set. For lost-key the source is the applied-document snapshot; for compromise it is the enrolled baseline's signers and rules, with the current recovery section. Nobody chooses a target hash. | §7 |
| D7 | Revocation | Credentials a recovery replaces, plus every credential a compromise recovery removes, enter the account's permanent revoked set. Every applied document is checked against that set, on every path. | §8 |
| D8 | Completion vs. reconfiguration | A completion is recognised by the attempt consumed in the same invocation. It may change exactly what its replacement set declares. Configuration identity is the canonical text of the recovery section, so rotating a signer's key is not a reconfiguration. | §10 |
| D9 | Nullifiers | One nullifier per enrolled ZK credential, owned by that `(account, enrollment)`. It is either unspent or spent. Only a completion of that account spends it; nothing ever un-spends it. Proofs for any action need it unspent. There are no reservations, so there is nothing to release (#91). | §11 |
| D10 | Stale state | Leaves and nullifiers bind an enrollment id the configuration names, and the account refuses to re-enroll an id it used before. Every configuration change and every completion bumps the per-account epoch, and evidence or attempts from an older epoch are dead. | §3, §11 |
| D11 | Upgrades | Owner authorization (plus, under `Protected`, condition evidence over an `Upgrade` statement binding the Wasm hash and the epoch). Executable after 120 960 ledgers. Any epoch change invalidates the request. Blocked during an authorized attempt. | §12 |
| D12 | Invoker-only hooks | The account never authorizes a reserved hook name (`install`, `uninstall`, `enforce`, `rcv_*`) through `__check_auth`, and never calls one through `execute`. Controller, pool, and policy hooks are reachable only from the account's own controlled flows. | §15 |
| D13 | Statement | One `RecoveryStatement`, encoded at fixed width and hashed with SHA-256. Guardians authorize the digest and the circuit binds it. | §4 |
| D14 | ZK boundary | The controller passes the structured statement to an adapter. The adapter checks the circuit id, field canonicality, root membership in the enrolled pool, and the proof. Public inputs stay `root, nullifier, statement_hash`. | §13 |
| D15 | Pool | Depth 32, or depth 24 if depth 32 misses the budget rule. A full tree rolls over automatically. Roots are accepted as `(tree_id, root)`, and every sealed tree's final root is retained permanently. | §14 |

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
  requires both factors. `max-cancels` bounds a cancellation war; it does not
  pick a winner.

## 3. Configuration

### 3.1 Schema (changes from the pre-spec schema)

Fresh deployments only, so no compatibility shim is required. The
document's `recovery` member becomes:

```text
recovery: {
  profile:        "loss" | "protected",
  mode:           { type: "guardian-only", guardians: [addr], quorum: u32 }
                | { type: "zk-only",  adapter, circuit-id, pool, enrollment-id }
                | { type: "combined", guardians, quorum, adapter, circuit-id, pool, enrollment-id },
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
| Compiled `replaceable` stays signer ids | Fingerprints in the compiled configuration made rotating a key look like reconfiguration (#92). Revocation fingerprints credentials separately (§8). |

The ZK commitment is not part of the document. The `apply_doc` that adopts
a new enrollment id carries the commitment as an argument, and the account
inserts the leaf in the same invocation (§14.2). Owner authorization signs
those arguments. A recovery completion's commitment is bound by the
attempt's replacement set instead (§7.3).

### 3.2 Configuration identity

`config_hash = sha256("perch/recovery/config" || C)`, where `C` is the
canonical JSON (`CANONICAL.md`) of the document's `recovery` member. The doc
compiler computes it and returns it with the compiled configuration.
Evidence providers compute it from the document they are shown.

Configuration identity is therefore the reviewed text: profile, mode,
guardians, quorum, adapter, circuit id, pool, enrollment id, controller,
baseline hash, replaceable signer ids, and timing. Rotating a signer's key
elsewhere in the document does not change it (#92). Renaming a replaceable
signer id does.

### 3.3 Epoch

The controller keeps a per-account `epoch: u64`. It starts at 0 and
increments by one on every successful enrollment, reconfiguration
(including a controller switch away from or to this controller), removal,
and completed recovery. It never decreases and is never reset. Every
statement binds `(epoch, config_hash)`. Every attempt records the epoch it
was opened under and is dead under any other. A queued upgrade records it
too and is stale under any other (§12).

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
cancellation count, attempt-id counter), the account's revoked set and
enrolled-id set, nullifier records, and the pool's roots and frontier live
in persistent storage. An archived persistent entry is unavailable, never
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
- for `Reconfigure` and `Upgrade`, the `valid_until_ledger` it signed;
- for `Reconfigure`, the compiled new configuration (passed by the account
  from the document being applied);
- for `Upgrade`, the Wasm hash (passed by the account).

**Binding.** Guardians authorize `require_auth_for_args((digest,))` inside
the controller entry point that consumes their approval. The ZK circuit
binds the digest through the `statement_hash` public input (§13). In
`Combined` mode both factors therefore approve the identical statement.

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

Reconfiguration and upgrade evidence must be complete in the transaction
that uses it. The evidence travels in `RecoveryEvidence`, and each listed
guardian's authorization is an auth entry in the same transaction. A
guardian listed twice, or listed but not enrolled, is not counted. A listed
guardian whose authorization is missing fails the transaction.

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
                       └─ epoch change / sibling authorized /
                          stale lost-key source ─▶ Invalidated
```

`Expired` and `Invalidated` are derived, not stored. An attempt is **live**
when all of the following hold:

- its recorded epoch equals the current epoch;
- it is not terminal;
- it is not invalidated by a sibling's authorization;
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
- the replacement set is invalid (§7);
- for compromise: no baseline is enrolled or its content is unpublished.

Otherwise:

1. Assigns `attempt_id` from the per-account counter (never reused).
2. Records `epoch`, `created_at = L`, `evidence_deadline`, `cancel_until`,
   the source hash, the derived target hash, the target configuration hash
   (§10), the replacement-set hash, and the ZK enrollment the completion
   installs.
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
  `A.source_doc_hash`, `A` is invalidated: a fresh attempt is required, and
  its evidence starts over;
- otherwise `A` becomes `Authorized` with `authorized_at = L`, its windows
  are fixed, every other collecting attempt of the account is invalidated,
  and `AttemptAuthorized` is emitted.

Promotion refuses while another attempt is authorized and live.

**T5 Complete** — `apply_doc(target_bytes, …)` selecting the zero-signer
recovery rule (Variant A). The controller's `enforce` requires all of:

- the context is `apply_doc` on this account;
- an authorized live attempt `A` exists;
- `executable_after ≤ L < expires_at`;
- `sha256(target_bytes) = A.target_doc_hash`.

Then `enforce` marks `A` completing, bound to `(attempt_id,
target_doc_hash)`. The account's `apply_doc` body runs `rcv_sync`, which
consumes that marker and performs the completion effects (§10). Every write
belongs to the same invocation, so a failure anywhere (compile, revocation
check, anti-brick, pool insertion) reverts all of it, including the
consumption. Completion is permissionless once its evidence and timelock
are satisfied. Nobody can change what it installs, because the target, the
new credentials, and the new ZK commitment are all fixed by `A`.

**T6 Cancel by evidence** — when the cancellation condition is satisfied for
a live attempt `A`:

1. `A` becomes `Cancelled`.
2. If `A` was authorized, the account's cancellation count increments, and
   the cancellation is refused instead if the count has reached
   `max-cancels`.
3. Emits `AttemptCancelled`.

Cancelling a collecting attempt never counts: it blocks nothing, so
cancelling it only tidies state.

**T7 Cancel by owner (`Loss` only)** — the account's
`cancel_recovery(attempt_id)` under owner authorization invokes the
controller's `rcv_cancel`. The controller refuses under `Protected`.
Otherwise T6's effects apply, including the `max-cancels` count for an
authorized attempt. Once the attempt is cancelled the window has ended, so
the owner may then reconfigure, for example to remove a guardian set that
opened it.

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
- the fingerprints of every credential in the target (for T1's revocation
  check, §7.3 rule 7).

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
below holds (rules 1–6 checked by `derive_target`, rule 7 by the controller
against the account's `revoked` view):

1. Every `signer_id` is in the current configuration's `replaceable` and is
   declared in the source.
2. A replacement credential has the same kind as the credential it
   replaces. An external credential must use the same verifier contract as
   the one it replaces, so recovery can never route a signer slot through a
   verifier the account had not already adopted for that slot.
3. Lost-key attempts replace at least one signer. Compromise attempts may
   replace none, which restores the baseline as is.
4. A ZK enrollment's id is not in the account's set of enrolled ids
   (§3.4), and its commitment is a canonical field element. The target's
   `recovery.mode.enrollment-id` becomes the new id. Nothing else in the
   recovery section changes.
5. Nothing else changes: rules, other signers, network, version.
6. The target passes full document validation (which rejects duplicate key
   material), the anti-brick check, and network binding.
7. No credential in the target, and no replacement credential, is in the
   account's revoked set (compared by canonical fingerprint, §8).

Rule 7 means an old baseline cannot restore a credential revoked after the
baseline was approved: the compromise attempt must replace that slot, or it
is refused. After any completed recovery, the wallet should have the
baseline re-approved (a reconfiguration) so that compromise recovery stays
usable without extra replacements.

### 7.4 What this does and does not establish

**Enforced on-chain:** the target equals the source with exactly the
declared replacements. The replacements are what every guardian and prover
approved, because `replacements_hash` and `target_doc_hash` are in the
statement. Revoked credentials do not return. The recovery section is
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

## 8. Revocation

- The account keeps a permanent, append-only set of credential fingerprints
  (`credential::Credential::fingerprint`). Nothing clears it: neither
  removing recovery, nor switching controllers, nor upgrading.
- A completion adds every credential present in the account's applied
  document immediately before it and absent from the target. The account
  computes this at completion; its applied document cannot change after
  authorization (§9). For lost-key that is exactly the replaced credentials.
  For compromise it also includes everything added since the baseline: the
  recovery cannot tell an attacker's additions from the owner's, so it
  revokes all of them, and the owner re-adds a legitimate one under a fresh
  key.
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
enforced inside the account's `__check_auth`. When a controller is adopted,
`__check_auth` reads the controller's `activity_gate(account)` view. If an
attempt is authorized and live under `Protected`, it refuses every context
except a single `apply_doc` context on the account itself that selects the
recovery rule, which the controller's `enforce` then validates (T5). The
freeze covers:

- **Signature-based authorization** of any context.
- **CAP-0071 delegation.** When this account is a delegated signer of
  another account, the host invokes this account's `__check_auth` with the
  delegating account's contexts. The freeze refuses them, so a frozen
  account cannot authorize anything as a delegate (`cap-0071.md`, property
  C3).
- **`execute` and every other account entry point.** Each requires the
  account's own authorization before it acts, which reaches `__check_auth`.
  A frozen account has no entry point that can make it the invoker of
  anything.
- **Policies.** They run inside an authorization that `__check_auth` already
  admitted.

**The policy block (D3) holds in both profiles.** It is enforced in
`rcv_sync`, which every `apply_doc` reaches when a controller is adopted.
While an attempt is authorized and live, `rcv_sync` refuses unless this
invocation is that attempt's completion.

**Evidence-free griefing (#89).** A collecting attempt freezes nothing,
blocks no policy change, no upgrade, and no other attempt (D2). Only
satisfying a condition, which requires the enrolled guardians or secret,
starts an authorized window.

## 10. Completion versus reconfiguration

Every `apply_doc` on an account with an adopted controller calls that
controller's `rcv_sync(account, compiled_recovery, evidence, zk_commitment)`
before touching any context rule.

The call is invoker-only (§15). `rcv_sync` both decides and writes. No
separate `install` call ever writes configuration: `install` is
bookkeeping, and `uninstall` is a no-op, because OZ discards `uninstall`
failures.

`rcv_sync` classifies the call exactly one way:

| Case | Recognised by | Authorization | Effects |
| --- | --- | --- | --- |
| Completion | A completing marker from this invocation's `enforce` (T5) whose target hash equals the compiled document's hash | Already established by the attempt | The compiled configuration hash must equal the attempt's target configuration hash (unchanged, or ZK-rotated as declared). Consumes the marker, marks the attempt `Completed`, spends its nullifier, and bumps the epoch. The account inserts the new leaf (§14.2), records the new enrollment id as used, appends the revocations (§8), and clears any pending upgrade. |
| No change | `config_hash` and controller unchanged, and not a completion | Owner authorization (already required by `apply_doc`) | Refuses if an attempt is authorized and live (§9); otherwise nothing. |
| Enroll | No configuration stored | Owner authorization | Stores the configuration and bumps the epoch. The account records the enrollment id as used. |
| Reconfigure | `config_hash` differs, controller unchanged | `Loss`: owner. `Protected`: owner plus the stored configuration's condition over `Reconfigure(Set(new))` | Refuses during an authorized window. Stores the new configuration, bumps the epoch, and invalidates every attempt. |
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

Every account, enrolled or not, upgrades in two steps:

1. **`schedule_upgrade(wasm_hash, evidence)`** — owner authorization, plus
   under `Protected` the controller's `rcv_upgrade` check of the condition
   over `Upgrade { request_id, wasm_hash }`. Refused during an authorized
   window. Records `{ request_id, wasm_hash, epoch, controller,
   executable_at = L + ACCOUNT_UPGRADE_DELAY_LEDGERS }`, where the delay is
   120 960 ledgers. One request at a time; scheduling another cancels the
   previous one. `request_id` comes from a per-account counter and is never
   reused.
2. **`execute_upgrade(request_id)`** — owner authorization. Refuses if any
   of the following hold:
   - `L < executable_at`;
   - an attempt is authorized and live;
   - the recorded `(epoch, controller)` differs from the current one;
   - the request is not the pending one.

   A stale request is cleared. On success, calls
   `update_current_contract_wasm(wasm_hash)`.

**`cancel_upgrade()`** takes owner authorization.

| Rule | Why |
| --- | --- |
| The approval binds the exact Wasm hash, the epoch, and `config_hash` | A Protected approval cannot be carried to different code or a different configuration. |
| Any epoch change makes a queued request stale | This is the validation of queued approvals when configuration changes. Reconfiguration, removal, and completion all bump the epoch, so a successful recovery invalidates every outstanding request. Completion also clears the slot explicitly. |
| Blocked while an attempt is authorized | Upgrading must not race or neuter an in-flight recovery. |
| The delay applies to every account | The epic retains a seven-day delay. Accounts without recovery get the same window to notice a stolen key. |

The upgraded code inherits the account's storage, including the revoked
set and the recovery wiring. Whether new code honours them cannot be
enforced from the old code. That is why `Protected` requires the condition
to approve the exact Wasm.

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
- `is_known_root(tree_id, root)` accepts a sealed tree's final root, and the
  active tree's last `R` roots (`R` a build constant; workstream 2 sizes it
  against insertion rate and proving latency). It refuses anything else,
  including roots of other pools.

### 14.2 Insertion

`rcv_insert(account, enrollment_id, commitment)` is invoker-only (§15). The
account calls it from `apply_doc` when the applied configuration names a new
enrollment id: at enrollment, at a ZK reconfiguration, and at a ZK-rotating
completion, with the commitment fixed by the attempt. The pool:

1. Refuses a non-canonical commitment.
2. Computes `leaf = P2(DOM_BIND, account split, enrollment split,
   commitment)` itself; a caller never supplies a wrapped leaf.
3. Appends it to the active tree and emits `LeafInserted { tree_id, index,
   leaf, account, enrollment_id }`.

When an insertion fills the active tree, the same call seals it (storing
its final root permanently) and opens `tree_id + 1`. A full tree never
blocks enrollment.

Insertion failure (for example, the account is out of fee budget) reverts
the whole `apply_doc`, so no configuration ever names an enrollment whose
leaf is absent.

### 14.3 Earlier trees and witnesses

- A sealed tree never changes. Its witnesses can be computed once and cached
  by the client.
- The final roots and the active frontier are persistent, renewable
  (`renew_tree`), and restorable after archival.
- Witnesses come from `LeafInserted` events. RPC event retention is short,
  so the reusable indexer must persist every event, and clients should keep
  their own leaf's position.
- A proof against an active-tree root that has left the retained window is
  refused as `UnknownRoot`. The fix is a fresh witness and a new proof.
  Nothing about the account changes.

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
   `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `rcv_insert`), on any contract,
   before OZ's `do_check_auth`. Matching by name also covers controllers and
   policies the account adopted in the past;
2. **refuse in `execute`** a call to a reserved name. `execute` makes the
   account the invoker, which would otherwise grant invoker authorization to
   whoever can authorize `execute`;
3. **refuse at compile time**, as defence in depth, a rule whose
   `Scope::Contract` is the document's own controller, adapter, or pool.

`cap-0071.md` pins the host behaviour this relies on (properties C5 and C6).

**Entry points**

| Contract | Entry point | Authorization |
| --- | --- | --- |
| Account | `__check_auth` | Freeze (§9), then reserved names, then OZ `do_check_auth` |
| Account | `apply_doc(doc_json, evidence, zk_commitment)` | Owner authorization, or the recovery rule (completion only) |
| Account | `execute(target, fn, args)` | Owner authorization; reserved names refused |
| Account | `schedule_upgrade`, `execute_upgrade`, `cancel_upgrade` | Owner authorization (§12) |
| Account | `cancel_recovery(attempt_id)` | Owner authorization; `Loss` only |
| Account | `applied_doc`, `applied_doc_hash`, `revoked`, `enrolled_ids`, `pending_upgrade`, `doc_compiler`, rule views | None (read-only) |
| Controller | `rcv_sync`, `rcv_cancel`, `rcv_upgrade`, `install`, `uninstall`, `enforce` | Invoker-only: `account.require_auth()` reachable only from the account's own flows |
| Controller | `begin_lost_key`, `begin_compromise`, `submit_zk`, `publish_baseline`, `renew` | Permissionless |
| Controller | `submit_guardian` | The guardian's `require_auth_for_args((digest,))` |
| Controller | `config`, `epoch`, `attempt`, `activity_gate`, `statement(account, attempt_id, domain)` | None (read-only; evidence providers fetch the exact statement to sign or prove) |
| Pool | `rcv_insert` | Invoker-only |
| Pool | `is_known_root`, tree views, `renew_tree` | None |
| Adapter | `verify`, `circuit_id` | None (pure) |

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
