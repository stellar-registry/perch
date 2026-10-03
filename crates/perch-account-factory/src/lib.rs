//! The perch account factory: deploys `perch-account` instances of exactly
//! one wasm, pinned at build time.
//!
//! - **Pinned.** The account wasm hash and the WebAuthn verifier's content
//!   address are baked in from this crate's `wasm/` cache when it is built
//!   (see [`pins`]). Publishing a newer account or verifier never changes what
//!   an existing factory deploys: a new account build is a new factory, at a
//!   new address.
//! - **Bound to the signers.** An account's address commits to the admin
//!   signers it is created with, not only to the caller's salt: the deploy
//!   salt is `sha256(salt || xdr(admin_signers))`. Nobody can create an
//!   account at an address someone else predicted with different signers.
//! - **Constructorless and immutable.** No admin, no setters, no upgrade, no
//!   storage. Creation is permissionless: the new account's constructor
//!   installs its admin rule, and every later change goes through the
//!   account's own `apply_doc`.
#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, vec, xdr::ToXdr, Address, Bytes, BytesN, Env, Vec,
};
use stellar_accounts::smart_account::Signer;

/// Wire version of this factory's interface. Bumped on any change a client
/// could observe; a new version is always a new wasm and a new address.
pub const VERSION: u32 = 1;

/// What the factory deploys and the passkey verifier it names, both pinned
/// from the git-ignored `wasm/` cache at build time.
pub mod pins {
    perch_registry_resolve::registry_contract! {
        mod: account,
        wasm_name: "perch-account",
        wasm_file: "wasm/perch-account.wasm",
    }
    perch_registry_resolve::registry_contract!(perch_webauthn_verifier);
}

/// Emitted for every account the factory creates.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCreated {
    #[topic]
    pub account: Address,
    pub salt: BytesN<32>,
    pub admin_signers: Vec<Signer>,
}

#[contract]
pub struct PerchAccountFactory;

#[contractimpl]
impl PerchAccountFactory {
    /// See [`VERSION`].
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// The pinned `perch-account` wasm hash every account is deployed from.
    pub fn account_wasm_hash(e: &Env) -> BytesN<32> {
        pins::account::hash(e)
    }

    /// The pinned WebAuthn verifier passkey signers name.
    pub fn webauthn_verifier(e: &Env) -> Address {
        pins::perch_webauthn_verifier::address(e)
    }

    /// The address [`Self::create`] deploys for `salt` and `admin_signers`.
    pub fn address_of(e: &Env, salt: BytesN<32>, admin_signers: Vec<Signer>) -> Address {
        e.deployer()
            .with_current_contract(deploy_salt(e, &salt, &admin_signers))
            .deployed_address()
    }

    /// Deploy an account whose constructor installs `admin_signers` as its
    /// admin rule. Permissionless. Fails if that account already exists.
    pub fn create(e: &Env, salt: BytesN<32>, admin_signers: Vec<Signer>) -> Address {
        let account = e
            .deployer()
            .with_current_contract(deploy_salt(e, &salt, &admin_signers))
            .deploy_v2(pins::account::hash(e), (admin_signers.clone(),));
        AccountCreated {
            account: account.clone(),
            salt,
            admin_signers,
        }
        .publish(e);
        account
    }

    /// The admin signer [`Self::create_passkey`] installs for `key_data`
    /// (the 65-byte secp256r1 public key, optionally followed by the
    /// credential id).
    pub fn passkey_signer(e: &Env, key_data: Bytes) -> Signer {
        Signer::External(pins::perch_webauthn_verifier::address(e), key_data)
    }

    /// The address [`Self::create_passkey`] deploys.
    pub fn passkey_address(e: &Env, salt: BytesN<32>, key_data: Bytes) -> Address {
        Self::address_of(e, salt, vec![e, Self::passkey_signer(e, key_data)])
    }

    /// Deploy an account administered by one passkey, verified by the pinned
    /// WebAuthn verifier.
    pub fn create_passkey(e: &Env, salt: BytesN<32>, key_data: Bytes) -> Address {
        Self::create(e, salt, vec![e, Self::passkey_signer(e, key_data)])
    }
}

/// `sha256(salt || xdr(admin_signers))`: an address commits to its signers.
fn deploy_salt(e: &Env, salt: &BytesN<32>, admin_signers: &Vec<Signer>) -> BytesN<32> {
    let mut preimage = Bytes::from_array(e, &salt.to_array());
    preimage.append(&admin_signers.clone().to_xdr(e));
    e.crypto().sha256(&preimage).to_bytes()
}

#[cfg(test)]
mod test;
