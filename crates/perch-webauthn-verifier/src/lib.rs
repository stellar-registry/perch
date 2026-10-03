//! Deployable WebAuthn verifier: the on-chain contract a passkey signer names
//! as the `verifier` half of `Signer::External(verifier, key)`.
//!
//! `key` is the 65-byte uncompressed secp256r1 public key, optionally followed
//! by the credential id (client metadata, stripped by `canonicalize_key`).
//! The signature is the XDR of OZ's `WebAuthnSigData`: the authenticator data,
//! the client data JSON, and the 64-byte signature. Verification is OZ's
//! `webauthn::verify`: `type` is `webauthn.get`, the challenge is the
//! base64url signature payload, user presence and user verification are set,
//! the backup flags are consistent, and the signature checks.
//!
//! Constructorless and stateless, with no admin and no upgrade path: every
//! instance of one wasm verifies identically, so it is deployed
//! content-addressed (`deploy_stateless`) and shared by every account. The
//! factory pins its address at build time.
#![no_std]

use soroban_sdk::{contract, contractimpl, xdr::FromXdr, Bytes, BytesN, Env, Vec};
use stellar_accounts::verifiers::{
    utils::extract_from_bytes,
    webauthn::{self, WebAuthnSigData},
    Verifier,
};

#[contract]
pub struct PerchWebAuthnVerifier;

#[contractimpl]
impl Verifier for PerchWebAuthnVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    /// Whether `sig_data` (XDR `WebAuthnSigData`) is a valid assertion over
    /// `signature_payload` by the key in `key_data`. Malformed data traps
    /// rather than returning `false`, like OZ's verifier does.
    fn verify(e: &Env, signature_payload: Bytes, key_data: Bytes, sig_data: Bytes) -> bool {
        let sig = WebAuthnSigData::from_xdr(e, &sig_data).expect("WebAuthnSigData XDR");
        let key: BytesN<65> = extract_from_bytes(e, &key_data, 0..65).expect("65-byte key");
        webauthn::verify(e, &signature_payload, &key, &sig)
    }

    /// The 65-byte public key, without any credential-id suffix: the
    /// identity OZ uses to detect duplicate signers, and the compiler uses to
    /// fingerprint credentials.
    fn canonicalize_key(e: &Env, key_data: Bytes) -> Bytes {
        webauthn::canonicalize_key(e, &key_data)
    }

    fn batch_canonicalize_key(e: &Env, key_data: Vec<Bytes>) -> Vec<Bytes> {
        webauthn::batch_canonicalize_key(e, &key_data)
    }
}

#[cfg(test)]
mod test;
