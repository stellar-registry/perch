//! The perch smart account, deployable shell: author of the perch wasm
//! releases and manager of the `unverified/perch` subregistry.
//!
//! All behavior comes from libraries — OZ evaluation (`do_check_auth`) plus
//! [`perch_smart_account::PerchSmartAccount`], whose `apply_doc` is **the only
//! way authorization data changes**. `SmartAccount` is implemented but
//! deliberately NOT exported: the piecemeal mutation entry points
//! (`add_context_rule`, `add_signer`, `add_policy`, …) do not exist on this
//! contract. Doc-only is structural, not conventional.
//!
//! The account is not upgradeable and has no execution entry point: replacing
//! it means deploying a new account and moving registry name ownership.
#![no_std]

use perch_smart_account::PerchSmartAccount;
#[allow(unused_imports)]
// Address/Bytes/BytesN are used by the PerchSmartAccount default-fn macro expansion.
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, Bytes, BytesN, Env, Vec,
};
#[allow(unused_imports)] // ContextRule is used by the macro expansion.
use stellar_accounts::smart_account::{
    self, AuthPayload, ContextRule, Signer, SmartAccount, SmartAccountError,
};

pub use perch_smart_account::PerchAccountError;

#[contract]
pub struct PerchAccount;

#[contractimpl]
impl PerchAccount {
    /// Deploy-time rule 0: the admin signers may manage this account (i.e.
    /// call `apply_doc`) — and nothing else.
    pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
        perch_smart_account::install_admin_root(e, &admin_signers);
    }
}

#[contractimpl]
impl CustomAccountInterface for PerchAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

/// Satisfies the supertrait WITHOUT exporting entry points: OZ's mutation
/// surface does not exist on this contract.
impl SmartAccount for PerchAccount {}

#[contractimpl(contracttrait)]
impl PerchSmartAccount for PerchAccount {}
