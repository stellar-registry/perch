//! The perch smart account: author of the perch wasm releases and manager of
//! the `unverified/perch` subregistry. Authorization is delegated entirely to
//! OZ's smart-account context rules; the ci-publish perch policy (enforced by
//! perch-interpreter) is installed post-deploy through `add_context_rule`.
//!
//! The account is deliberately immutable (no `Upgradeable`, no execution entry
//! point): replacing it means deploying a new account and moving registry name
//! ownership. The only custom code is the constructor; everything else is OZ
//! default-trait delegation.
#![no_std]

#[allow(unused_imports)]
// Address/Val/Symbol/BytesN are used by the SmartAccount default-fn macro expansion.
use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, BytesN, Env, Map, String, Symbol, Val, Vec,
};
#[allow(unused_imports)] // ContextRule is used by the SmartAccount default-fn macro expansion.
use stellar_accounts::smart_account::{
    self, AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccount, SmartAccountError,
};

#[contract]
pub struct PerchAccount;

#[contractimpl]
impl PerchAccount {
    /// Installs rule id 0: "admin-root", scoped `CallContract(self)` — the
    /// admin signers may manage this account (rules, signers, policies) and
    /// nothing else. Scoping to self rather than `Default` keeps the admin key
    /// from silently authorizing arbitrary calls; every other capability is
    /// granted by an explicit, doc-reviewed context rule installed later.
    pub fn __constructor(e: &Env, admin_signers: Vec<Signer>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::CallContract(e.current_contract_address()),
            &String::from_str(e, "admin-root"),
            None,
            &admin_signers,
            &Map::new(e),
        );
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

#[contractimpl(contracttrait)]
impl SmartAccount for PerchAccount {}
