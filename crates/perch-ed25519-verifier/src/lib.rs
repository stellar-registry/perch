//! Deployable ed25519 verifier: the on-chain contract that smart accounts
//! reference as the `verifier` half of a `Signer::External(verifier, key)`.
//! Deployed once per network and shared; it holds no state. The perch policy
//! documents (`signers[].verifier`) name this contract's address.
#![no_std]

use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env, Vec};
use stellar_accounts::verifiers::{ed25519, Verifier};

#[contract]
pub struct PerchEd25519Verifier;

#[contractimpl]
impl Verifier for PerchEd25519Verifier {
    type KeyData = BytesN<32>;
    type SigData = BytesN<64>;

    fn verify(
        e: &Env,
        signature_payload: Bytes,
        key_data: BytesN<32>,
        sig_data: BytesN<64>,
    ) -> bool {
        ed25519::verify(e, &signature_payload, &key_data, &sig_data)
    }

    fn canonicalize_key(e: &Env, key_data: BytesN<32>) -> Bytes {
        ed25519::canonicalize_key(e, &key_data)
    }

    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        ed25519::batch_canonicalize_key(e, &keys_data)
    }
}
