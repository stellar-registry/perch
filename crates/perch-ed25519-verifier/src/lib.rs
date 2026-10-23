//! Deployable ed25519 verifier: the on-chain contract that smart accounts
//! reference as the `verifier` half of a `Signer::External(verifier, key)`.
//! Constructorless, with no state, admin, or upgrade path: it is deployed
//! content-addressed (`deploy_stateless`) once per network and shared. The
//! perch policy documents (`signers[].verifier`) name this contract's address.
#![no_std]

use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};
use stellar_accounts::verifiers::{ed25519, Verifier};

#[contract]
pub struct PerchEd25519Verifier;

#[contractimpl]
impl Verifier for PerchEd25519Verifier {
    type KeyData = BytesN<32>;
    type SigData = BytesN<64>;

    /// Whether `sig_data` is a valid ed25519 signature over
    /// `signature_payload` by the 32-byte public key `key_data`. An invalid
    /// signature traps rather than returning `false`, like OZ's verifier.
    fn verify(
        e: &Env,
        signature_payload: Bytes,
        key_data: BytesN<32>,
        sig_data: BytesN<64>,
    ) -> bool {
        ed25519::verify(e, &signature_payload, &key_data, &sig_data)
    }

    /// The 32-byte public key as `Bytes`: an ed25519 key has one encoding.
    /// OZ uses it to detect duplicate signers, and the compiler to
    /// fingerprint credentials.
    fn canonicalize_key(e: &Env, key_data: BytesN<32>) -> Bytes {
        ed25519::canonicalize_key(e, &key_data)
    }

    /// [`Self::canonicalize_key`] for each key, in input order.
    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        ed25519::batch_canonicalize_key(e, &keys_data)
    }
}
