# Account mutation path inventory

Every entry point that can change a `PerchAccount`'s stored authorization
state (context rules, signers, applied `doc_hash`), or a recovery
controller's per-account state. This is the concrete answer to "review...
all account mutation paths."

## The account itself (`crates/perch-account`, `crates/perch-smart-account`)

| Entry point | File:line | What it can change | Authorization |
|---|---|---|---|
| `PerchAccount::__constructor` | `crates/perch-account/src/lib.rs:31-33` | Installs rule 0: the initial admin, `self-admin` scope. Runs once, at deploy. | Deploy-time only; not callable afterward. |
| `PerchSmartAccount::apply_doc` | `crates/perch-smart-account/src/lib.rs` (`fn apply_doc`) | **The sole write path.** Atomically replaces the entire context-rule set from a compiled document; installs or removes the `"recovery"` rule; updates `applied_doc_hash` and `recovery_controller`. | `e.current_contract_address().require_auth()` — satisfied by the ordinary admin rule, **or** by the adopted recovery controller's `enforce()` via the `"recovery"` rule (Variant A completion) — two independent, alternative authorizations for the same scope. Additionally gated by `guard_apply_doc` (below) whenever a controller is currently enrolled. |

Every other OZ `SmartAccount` mutation entry point
(`add_context_rule`, `remove_context_rule`, `add_signer`, `remove_signer`,
`add_policy`, `remove_policy`, `update_context_rule_name`,
`update_context_rule_valid_until`) is implemented (to satisfy the
`SmartAccount` supertrait) but **not exported** — doc-only is structural, not
conventional, and proven by
`crates/integration-tests/tests/apply_doc.rs::piecemeal_mutation_entry_points_do_not_exist`.
There is no entry point reachable on a deployed `PerchAccount` that can
mutate rules other than `apply_doc`.

`PerchStorage` (`crates/perch-smart-account/src/lib.rs`) additionally tracks
`recovery_controller: InstanceItem<Address>` — set/cleared only inside
`apply_doc`, in lockstep with whether the applied document enrolls recovery.

## The recovery controller (`crates/perch-recovery`)

None of these mutate the *account's own* rule set directly — they mutate the
controller's own per-account state, which then gates or is read by
`apply_doc` (above).

`install`, `enforce`, and `guard_apply_doc` are exported contract functions
like any other on a deployed `PerchRecovery` instance — callable directly by
anyone, not only via OZ's real install flow or `perch-smart-account`'s
`apply_doc`. Each therefore starts with `<the account>.require_auth()`,
which — via Soroban's invoker-contract authorization — succeeds for free
when the caller genuinely is the account's own wasm making this exact
cross-call, and fails for a direct, unrelated caller. See `contract.rs`'s
doc comments on `install`/`complete`/`guard_apply_doc` for the full
reasoning.

| Entry point | What it changes | Authorization |
|---|---|---|
| `Policy::install` | Writes the enrolled `CompiledRecoveryConfig` for an account. | `smart_account.require_auth()` (see above). Reachable only via `apply_doc`'s own rule-(re)installation; the actual authorization *decision* already happened in `guard_apply_doc` before this runs — see [`controller-governance.md`](controller-governance.md) for why `install` itself cannot be the gate. |
| `Policy::enforce` | Consumes a live, authorized, correctly-targeted attempt (marks `Completed`, revokes credentials, spends a nullifier). | `smart_account.require_auth()` (see above), plus reachable only when the `"recovery"` context rule is selected for an `apply_doc` call — see `controller-governance.md`'s "Variant A completion." |
| `Policy::uninstall` | Nothing (deliberate no-op). | N/A — see `controller-governance.md` for why. |
| `guard_apply_doc` | Nothing by itself (a check); refusing it blocks the `apply_doc` call that invoked it. | `account.require_auth()` (see above); called only from `perch-smart-account`'s `apply_doc`, before it touches any context rule. Internally requires guardian/ZK evidence when gating a `Protected` change. |
| `begin_lost_key_attempt` / `begin_compromise_attempt` | Creates or replaces the account's attempt. | Permissionless — declaring intent carries no authority (matches a companion smart-account implementation's own validated design). `begin_compromise_attempt` additionally requires a baseline to be enrolled, and requires its target to equal that baseline exactly. |
| `submit_guardian_approval` | Adds to `Attempt::guardian_approvals`; may promote to `AuthorizedPending`. | The named guardian's `require_auth_for_args` over a digest binding this exact attempt (id, action, target, enrolled config) — not just the bare `(account, guardian)` arguments, so a signature can't be redirected to a different attempt. |
| `submit_zk_proof` | Marks `Attempt::zk_verified`; may promote. Reserves the proof's nullifier immediately (not deferred to completion). | Permissionless — a verified proof is itself the authorization; the controller recomputes the statement from its own stored attempt, never trusting a caller-supplied one. |
| `submit_guardian_cancel` | Tallies a cancel vote (a domain separate from initiation approval); cancels once the mode's cancellation evidence is complete. | The named guardian's `require_auth_for_args` over a digest binding this attempt and the `Cancel` action — the same binding requirement as `submit_guardian_approval`. |
| `submit_zk_cancel` | Cancels on a valid proof over the `Cancel`-domain statement. | Permissionless, same rationale as `submit_zk_proof`. |
| `renew` | Nothing semantically — extends every one of an account's existing recovery-related persistent entries to the network's current maximum TTL. | Permissionless — see `controller-governance.md`'s "Keeping permanent state alive." |
| `get_config`, `config_hash`, `get_attempt`, `has_pending` | Nothing (read-only). | None. |

## What this means for the review

- **Exactly one path changes what an account's admin key or app rules are:**
  `apply_doc`, always. Recovery does not add a second way to set rules — it
  adds a second *authorization* for the same call (the `"recovery"` rule
  alongside the admin rule), and a pre-check (`guard_apply_doc`) that can
  additionally require evidence before that call proceeds when a `Protected`
  recovery configuration itself is what's changing.
- **No entry point anywhere lets a party without the enrolled recovery
  condition author a document-level change while claiming recovery's
  authority.** `enforce`'s checks (live, authorized, unexpired, exact target)
  are the only way the `"recovery"` rule ever authorizes anything, and they
  cannot be short-circuited by any other reachable path (see
  `controller-governance.md`'s discussion of `install`/`uninstall` not being
  trustworthy gates, and why the real gate sits in `apply_doc` instead).
- **The controller's own per-account state has no admin/owner mutation path
  at all** — see [`vk-and-controller-immutability.md`](vk-and-controller-immutability.md).
