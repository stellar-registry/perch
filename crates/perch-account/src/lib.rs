//! The perch smart account, deployable shell: the account the factory
//! deploys, and the account type of the perch author that publishes perch's
//! wasm releases.
//!
//! All behavior comes from [`perch_smart_account::PerchSmartAccount`], whose
//! `apply_doc` is **the only way authorization data changes** (parse/compile
//! happens in the shared stateless `perch-doc-compiler` contract). There is
//! no piecemeal mutation API: `add_context_rule`, `add_signer`,
//! `add_policy`, … do not exist on this contract. Doc-only is structural,
//! not conventional.
//!
//! It executes calls as itself (`execute`), serves its full applied document
//! (`applied_doc`), and upgrades only through the seven-day
//! `schedule_upgrade` → `execute_upgrade` path (`docs/recovery/spec.md` §12).
#![no_std]

// These names are used by the trait macro expansions.
use perch_smart_account::{ContextRule, Signer};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, String, Symbol, Val, Vec};

pub use perch_smart_account::{
    AccountCapabilities, AccountConfiguration, FreezeGate, GrantRecord, InfraPins, InstalledRule,
    PerchAccountError, PerchAuthError, StoredRule, UpgradeRequest,
};

#[contract]
pub struct PerchAccount;

#[contractimpl]
impl PerchAccount {
    /// Install rule 0, `admin`: a self-admin rule for `admin_signers`, with
    /// full owner authority.
    // docs/account-interface.md, "Constructor".
    pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
        perch_smart_account::install_account_rules(e, &admin_signers);
    }
}

perch_smart_account::impl_perch_smart_account!(PerchAccount);
