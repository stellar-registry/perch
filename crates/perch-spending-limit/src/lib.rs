#![no_std]
//! `perch-spending-limit` — the one stateful policy perch composes with.
//!
//! perch's interpreter is stateless: its verdict is a pure function of the
//! installed program and *this* invocation, so it can express who may call what
//! (function set, argument predicates, an M-of-N signer floor) but **not** a
//! cumulative cap — a running total across transactions has no home in a
//! side-effect-free evaluator. OpenZeppelin's `spending_limit` policy keeps
//! exactly that state (a rolling per-ledger-window total, re-persisted on every
//! enforce), so perch *composes* with it rather than absorbing it: a capped rule
//! attaches both the interpreter (the per-call constraints + the INV-1 signer
//! floor) and this policy (the cumulative cap) to one OZ context rule, and OZ
//! enforces every attached policy (AND) — a transfer must satisfy the per-call
//! program *and* stay under the rolling cap.
//!
//! This crate is a thin, deployable wrapper: it forwards the three `Policy`
//! lifecycle methods to [`stellar_accounts::policies::spending_limit`], adding no
//! logic of its own. It is a content-addressed stateless singleton like the
//! interpreter and doc-compiler — one deployed instance is multi-tenant-safe
//! because `spending_limit` keys all state by `(smart_account, context_rule_id)`.
//!
//! The cap's parameters ([`SpendingLimitAccountParams`]) are `spending_limit`
//! (the cumulative i128 ceiling) and `period_ledgers` (the rolling window). The
//! tracked token is pinned by the OZ context rule type
//! (`CallContract(token)`) — the capped rule must be scoped to that token — so
//! it is not part of the install params here.

use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Vec};
use stellar_accounts::policies::{spending_limit, Policy};
use stellar_accounts::smart_account::{ContextRule, Signer};

/// Re-exported so appliers and tests name the install params from one place:
/// `{ spending_limit: i128, period_ledgers: u32 }`.
pub use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

/// The deployable spending-limit policy contract. Attached beside the perch
/// interpreter on a capped rule; enforces the cumulative cap OZ-side.
#[contract]
pub struct PerchSpendingLimit;

#[contractimpl]
impl Policy for PerchSpendingLimit {
    type AccountParams = SpendingLimitAccountParams;

    /// Enforce the rolling-window cap: reads the transfer amount from the
    /// invoked `transfer(from, to, amount)` context, adds it to the running
    /// total for `(smart_account, rule)`, and panics if the window's cumulative
    /// spend would exceed `spending_limit`. Must be authorized by the account
    /// (the wrapped call does `smart_account.require_auth()`).
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::enforce(
            e,
            &context,
            &authenticated_signers,
            &context_rule,
            &smart_account,
        )
    }

    /// Initialize the cap for `(smart_account, rule)`: validate the params
    /// (`spending_limit > 0`, `period_ledgers > 0`, rule scoped to a contract)
    /// and store the empty spending window.
    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &install_params, &context_rule, &smart_account)
    }

    /// Remove the cap's state for `(smart_account, rule)`.
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl PerchSpendingLimit {
    /// Wrapper revision, mirroring the interpreter's `program_version()`: lets
    /// an applier (or a pin cross-check) confirm on-chain which wrapper
    /// generation a content-addressed instance runs without fetching its wasm.
    pub fn policy_version() -> u32 {
        1
    }
}
