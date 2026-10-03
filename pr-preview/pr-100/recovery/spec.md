# Recovery specification

**Status: authoritative (draft under review, epic [#99](https://github.com/stellar-registry/perch/issues/99)).**
This is the single source of truth for perch account recovery: states,
transitions, who may authorize what, which document changes a recovery may
make, account upgrades, and the membership pool. Where any other document in
`docs/recovery/` disagrees with this one, this one wins.

The code half lives in `crates/perch-recovery-interface` (statement,
encodings, adapter and pool interfaces); the byte layouts are in
[`statement.md`](statement.md); measurements to be taken are in
[`budgets.md`](budgets.md); the delegated-auth host behaviour this spec
relies on is in [`cap-0071.md`](cap-0071.md).

> Skeleton commit: section headings and the decision summary are final in
> intent; section bodies are being filled in on this branch.

## Decision summary

| # | Topic | Decision |
| --- | --- | --- |
| D1 | Activity during recovery | `Protected`: once an attempt's evidence is satisfied, the account authorizes nothing except that attempt's completion, on every path. `Loss`: ordinary activity continues. Replaces the `pending-activity` field, which is removed. |
| D2 | Evidence-free attempts | Attempts may be opened permissionlessly and several may collect evidence at once; a collecting attempt blocks nothing (no freeze, no policy block, no upgrade block, no block on other attempts). |
| D3 | Authorized window | From promotion to completion/cancellation/expiry, both profiles refuse every policy change except that attempt's completion, and refuse upgrade scheduling and execution. |
| D4 | Reconfiguration | `Loss`: owner authorization. `Protected`: owner authorization plus the currently enrolled condition's evidence over a `Reconfigure` statement (`Combined`: guardian quorum and a ZK proof). |
| D5 | Cancellation | The enrolled condition's evidence over a `Cancel` statement, in every profile; additionally owner authorization alone under `Loss`. Cancellations of authorized attempts count toward `max-cancels`. |
| D6 | Permitted changes | The target is derived on-chain from the source (lost-key: the applied document snapshot; compromise: the enrolled baseline's rules with the current recovery section) and a declared replacement set. Callers never choose a target hash. |
| D7 | Revocation | Replaced credentials (and, for compromise, every credential the recovery removes) enter the account's permanent revoked set; every applied document is checked against it, on every path. Fingerprints are over verifier-canonical keys. |
| D8 | Completion vs. reconfiguration | Completion is recognised by the consumed attempt in the same invocation; it may change exactly what its replacement set declares (signer credentials, ZK enrollment id) and nothing else. Configuration identity is the canonical recovery-section text, so key rotation is not reconfiguration. |
| D9 | Nullifiers | One nullifier per enrolled ZK credential. Reserved by one live attempt of the same account at a time; spent by that attempt's completion; released only by its owner attempt's end. Cancel/reconfigure/upgrade proofs need it unspent but do not reserve or spend it. |
| D10 | Stale enrollment | Leaves and nullifiers bind an enrollment id the configuration names; an old leaf cannot satisfy a newer enrollment. Every configuration change bumps the controller's epoch; evidence and attempts from an older epoch are dead. |
| D11 | Upgrades | Owner authorization (+ `Protected`: condition evidence over an `Upgrade` statement binding the Wasm hash and config epoch); executable after `ACCOUNT_UPGRADE_DELAY_LEDGERS` (120 960); invalidated by any epoch change; blocked during an authorized attempt. |
| D12 | Invoker-only hooks | The account never signs (via `__check_auth`) or `execute`s a call to a reserved hook name (`install`, `uninstall`, `enforce`, `rcv_*`), so controller/pool/policy hooks are reachable only from the account's own controlled flows. |
| D13 | Statement | One `RecoveryStatement` (network, account, controller, config epoch+hash, ledger timing with a freshness bound, action-specific subject), SHA-256 over a fixed-width encoding; guardians authorize the digest, the circuit binds the digest. |
| D14 | ZK boundary | The controller calls an adapter with the structured statement; the adapter checks circuit id, field canonicality, root membership in the enrolled pool, and the proof. Circuit public inputs stay `root, nullifier, statement_hash`. |
| D15 | Pool | Depth-32 target (depth-24 fallback by the budget rule), automatic rollover to a new tree when full, `(tree_id, root)` acceptance, sealed trees' final roots retained permanently. |

## Sections

1. Scope and vocabulary
2. Roles and trust
3. Configuration
4. The recovery statement
5. Evidence requirements
6. State machine
7. Permitted document changes
8. Revocation
9. Activity and policy restrictions
10. Completion versus reconfiguration
11. Nullifiers
12. Account upgrades
13. ZK adapter boundary
14. Membership pool
15. Invoker-only hooks and other authorization paths
16. Dependency layering and immutability
17. Issue map
