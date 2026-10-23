//! The perch smart account, deployable shell: the account the factory
//! deploys, and the account type of the perch author that publishes perch's
//! wasm releases.
//!
//! All behavior comes from libraries — OZ evaluation plus
//! [`perch_smart_account::PerchSmartAccount`], whose `apply_doc` is **the only
//! way authorization data changes** (parse/compile happens in the shared
//! stateless `perch-doc-compiler` contract). `SmartAccount` is implemented
//! but deliberately NOT exported: the piecemeal mutation entry points
//! (`add_context_rule`, `add_signer`, `add_policy`, …) do not exist on this
//! contract. Doc-only is structural, not conventional.
//!
//! It executes calls as itself (`execute`), serves its full applied document
//! (`applied_doc`), and upgrades only through the seven-day
//! `schedule_upgrade` → `execute_upgrade` path (`docs/recovery/spec.md` §12).
#![no_std]

#[allow(unused_imports)]
// These names are used by the trait macro expansions.
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, Symbol, Val, Vec};
#[allow(unused_imports)]
use stellar_accounts::smart_account::{ContextRule, Signer};

#[allow(unused_imports)]
pub use perch_smart_account::{
    AccountCapabilities, AccountConfiguration, FreezeGate, InfraPins, InstalledRule,
    PerchAccountError, PerchAuthError, UpgradeRequest,
};

#[contract]
pub struct PerchAccount;

#[contractimpl]
impl PerchAccount {
    /// Deploy-time rule 0, `admin`: a policy-free self-admin rule for the
    /// admin signers. A rule scoped to the account authorizes every entry
    /// point that requires the account's own authorization — `apply_doc`,
    /// `execute` (arbitrary calls as the account), the upgrade entry points,
    /// and `cancel_recovery` — so this is full owner authority, not
    /// `apply_doc` alone.
    pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
        perch_smart_account::install_admin(e, &admin_signers);
    }
}

perch_smart_account::impl_perch_smart_account!(PerchAccount);
