#![no_std]
//! The perch interpreter: the deployable contract implementing OpenZeppelin's
//! `Policy` trait by evaluating a stored constraint program.
//!
//! This is the entire policy-evaluation surface of perch — there is no
//! per-policy codegen anywhere. (The workspace's other deployables,
//! `perch-account` and `perch-ed25519-verifier`, are thin OZ compositions with
//! no policy logic.) One immutable instance per network; the address is
//! derived from the registry id and this contract's wasm hash.
//!
//! ## Security contract
//! - **Multi-tenant auth (C1):** `smart_account` is an *argument* to the Policy
//!   trait, and one interpreter instance serves every account. Every mutating
//!   or authorizing entry point (`install`, `uninstall`, `enforce`) calls
//!   `smart_account.require_auth()` first, so nobody can plant or drop another
//!   account's `(account, rule)` state. Reads are not gated:
//!   [`PerchInterpreter::get_program`] is a public view — programs live in
//!   ledger state, which is world-readable over RPC regardless, so auth there
//!   would be theater, not protection.
//! - **Dangling-deny (C2):** `enforce` panics `NotInstalled` when no program
//!   exists for the rule — a rule that still lists the interpreter after an
//!   uninstall degrades to deny, never allow.
//! - **Signer sufficiency (C3/C4):** `signer_count` is the number of
//!   *authenticated* signers OZ passes, never the rule's configured set; and
//!   `enforce` denies outright when that set is empty, a defense-in-depth floor
//!   behind the compiler's `MinSigners` injection (INV-1).
//!
//! ## Fail-closed activation
//!
//! `install` never activates an unusable or surprise program: it rejects one
//! that fails structural `validate` ([`Error::InvalidProgram`]), refuses to
//! overwrite an existing attachment ([`Error::AlreadyInstalled`], so the
//! current policy stays in force), and requires the account's own auth. It
//! stores each rule's `doc_hash` for provenance but cannot recompute it
//! on-chain — the source document never reaches the interpreter — so a client
//! verifies `doc_hash` against the reviewed document *before* attaching, via
//! `perch_compile::verify_plan_matches_doc`. Together these are perch's
//! OPA-style activation: an attachment is either hash-verified against a
//! reviewed document or refused, never silently swapped.
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/6>

use perch_program::{rpn, EvalInputs, InstallParams, Verdict, PROGRAM_VERSION};
use soroban_sdk::{
    auth::Context, contract, contracterror, contractimpl, contracttype, panic_with_error, Address,
    Env, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{ContextRule, Signer};

const DAY_IN_LEDGERS: u32 = 17_280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    /// The program evaluated to something other than `True`, or no signer
    /// authenticated. The transaction is not authorized.
    Denied = 1,
    /// No program is installed for this `(account, rule)`.
    NotInstalled = 2,
    /// A program is already installed for this `(account, rule)`.
    AlreadyInstalled = 3,
    /// The install params carry a program that fails structural validation.
    InvalidProgram = 4,
}

#[contracttype]
enum DataKey {
    /// The install params for one `(smart_account, context_rule_id)`.
    Program(Address, u32),
}

#[contract]
pub struct PerchInterpreter;

#[contractimpl]
impl PerchInterpreter {
    /// Program wire-format version this interpreter evaluates. Unknown versions
    /// are rejected at install time — fail closed. Used by lift/diff + wallets.
    pub fn program_version(_env: Env) -> u32 {
        PROGRAM_VERSION
    }

    /// The install params stored for one `(account, rule)`, or `None`.
    /// Exposes `doc_hash` so lift/diff can check provenance against the
    /// reviewed document rather than guess from the lowered rule.
    ///
    /// Deliberately unauthenticated (unlike the C1-gated entry points):
    /// programs are ledger state and readable over RPC by anyone, so gating
    /// this view would only break tooling, not hide anything.
    pub fn get_program(
        env: Env,
        smart_account: Address,
        context_rule_id: u32,
    ) -> Option<InstallParams> {
        env.storage()
            .persistent()
            .get(&DataKey::Program(smart_account, context_rule_id))
    }
}

#[contractimpl]
impl Policy for PerchInterpreter {
    type AccountParams = InstallParams;

    fn enforce(
        env: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // C1: only the account may drive its own authorization.
        smart_account.require_auth();

        // C4: defense-in-depth signer floor. OZ defers signer sufficiency to
        // policies once any policy attaches, so an empty auth payload could
        // otherwise reach a program that never checks the count.
        if authenticated_signers.is_empty() {
            panic_with_error!(env, Error::Denied);
        }

        // C2: a missing program denies (dangling rule → DoS, never allow).
        let key = DataKey::Program(smart_account.clone(), context_rule.id);
        let params: InstallParams = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic_with_error!(env, Error::NotInstalled));
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);

        // C3: signer_count is the AUTHENTICATED count, never the configured set.
        let inputs = EvalInputs {
            context: &context,
            signer_count: authenticated_signers.len(),
            self_addr: &smart_account,
        };
        if rpn::eval(env, &params.program, &inputs) != Verdict::True {
            panic_with_error!(env, Error::Denied);
        }
    }

    fn install(
        env: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        let key = DataKey::Program(smart_account.clone(), context_rule.id);
        if env.storage().persistent().has(&key) {
            panic_with_error!(env, Error::AlreadyInstalled);
        }
        // Reject an unevaluable program up front — a validated program never
        // trips eval's defensive Unknown paths.
        if rpn::validate(&install_params.program).is_err() {
            panic_with_error!(env, Error::InvalidProgram);
        }
        env.storage().persistent().set(&key, &install_params);
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
    }

    fn uninstall(env: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();

        let key = DataKey::Program(smart_account.clone(), context_rule.id);
        if !env.storage().persistent().has(&key) {
            panic_with_error!(env, Error::NotInstalled);
        }
        env.storage().persistent().remove(&key);
    }
}

#[cfg(test)]
mod tests;
