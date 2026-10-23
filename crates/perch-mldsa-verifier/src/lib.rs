//! Deployable ML-DSA-65 verifier: the on-chain contract a post-quantum signer
//! names as the `verifier` half of `Signer::External(verifier, key)`.
//!
//! ML-DSA-65 is FIPS 204's lattice signature at NIST security category 3. It
//! is verified here in guest wasm by the `fips204` crate (pure Rust, no
//! allocation), so it needs no host function: the network has no ML-DSA host
//! function yet (CAP-0087).
//!
//! # Encoding
//!
//! - **Key.** A signer's `key` (`key_data`) is `sha256(public_key)`, 32 bytes.
//!   An encoded ML-DSA-65 public key is 1,952 bytes and OZ caps an external
//!   signer's key at 256 (`MAX_EXTERNAL_KEY_SIZE`), so the signer holds a
//!   commitment and every signature carries the key it commits to. The
//!   encoding is a bijection (every 10-bit `t1` coefficient is in range), so
//!   one key has one commitment, which is also its canonical form.
//! - **Signature.** `sig_data` is the XDR of [`MlDsaSigData`]: the encoded
//!   public key and the 3,309-byte signature.
//! - **Message.** The signature is pure `ML-DSA.Sign` (not HashML-DSA) with
//!   the context string [`SIG_CONTEXT`] over the 32-byte digest the account
//!   hands its verifiers as `signature_payload`: OZ's rule-bound digest,
//!   `sha256(payload || xdr(context_rule_ids))`, whose `payload` a perch
//!   account first binds to its own address
//!   (`perch_smart_account::bind_signature_payload_for_account`). Hedged and
//!   deterministic signatures both verify.
//!
//! This is the format of Nido's ML-DSA verifier and its SDK encoder
//! (`@noble/post-quantum` signing), so one key and one signature work under
//! either verifier; the context string names Nido for that reason.
//!
//! Malformed input traps with an [`MlDsaVerifierError`], as OZ's `Verifier`
//! asks; a well-formed signature that does not verify, or a key the
//! commitment does not name, returns `false`. Undecodable `sig_data` XDR
//! traps in the host before the contract sees it, and a `key_data` that is
//! not 32 bytes traps converting the argument. `MlDsaSigData` is not in the
//! contract spec (no entry point takes it as a typed argument), so
//! [`PerchMlDsaVerifier::verify`]'s spec doc spells out its encoding.
//!
//! Constructorless and stateless, with no admin and no upgrade path: every
//! instance of one wasm verifies identically, so it is deployed
//! content-addressed (`deploy_stateless`) and shared by every account. No
//! other contract pins it.
#![no_std]

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier as _};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, xdr::FromXdr, Bytes,
    BytesN, Env, Vec,
};
use stellar_accounts::verifiers::Verifier;

/// Length of an encoded ML-DSA-65 public key.
pub const PUBLIC_KEY_LEN: usize = ml_dsa_65::PK_LEN;
/// Length of an ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = ml_dsa_65::SIG_LEN;
/// Length of the message every signature is over: the account's auth digest.
pub const PAYLOAD_LEN: usize = 32;
/// The FIPS 204 context string every signature binds. It separates these
/// signatures from any other use of the same key; the signer passes it too.
pub const SIG_CONTEXT: &[u8] = b"nido-mldsa-v1";

/// What an ML-DSA signer submits as `sig_data`, XDR-encoded.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlDsaSigData {
    /// The encoded ML-DSA-65 public key (1952 bytes), whose sha256 is the
    /// signer's key.
    pub public_key: Bytes,
    /// The ML-DSA-65 signature (3309 bytes) over the 32-byte auth digest, with
    /// context "nido-mldsa-v1".
    pub signature: Bytes,
}

/// Why `verify` refused its input as malformed.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MlDsaVerifierError {
    /// `signature_payload` is not 32 bytes.
    PayloadLength = 1,
    /// `sig_data` is the XDR of something other than `MlDsaSigData`.
    SigDataEncoding = 2,
    /// The public key in `sig_data` is not 1952 bytes.
    PublicKeyLength = 3,
    /// The signature in `sig_data` is not 3309 bytes.
    SignatureLength = 4,
}

#[contract]
pub struct PerchMlDsaVerifier;

#[contractimpl]
impl Verifier for PerchMlDsaVerifier {
    type KeyData = BytesN<32>;
    type SigData = Bytes;

    /// Whether `sig_data` proves the key `key_data` names signed `signature_payload`.
    ///
    /// `key_data` is the sha256 of an encoded ML-DSA-65 public key. `sig_data` is
    /// the XDR of `MlDsaSigData`, the map { public_key: Bytes (1952),
    /// signature: Bytes (3309) }. True when `public_key` hashes to `key_data`
    /// and `signature` is its FIPS 204 ML-DSA-65 signature (pure, context
    /// "nido-mldsa-v1") over the 32-byte `signature_payload`. Malformed input
    /// traps (`MlDsaVerifierError`).
    fn verify(e: &Env, signature_payload: Bytes, key_data: BytesN<32>, sig_data: Bytes) -> bool {
        if signature_payload.len() as usize != PAYLOAD_LEN {
            panic_with_error!(e, MlDsaVerifierError::PayloadLength);
        }
        let sig = MlDsaSigData::from_xdr(e, &sig_data)
            .unwrap_or_else(|_| panic_with_error!(e, MlDsaVerifierError::SigDataEncoding));
        if sig.public_key.len() as usize != PUBLIC_KEY_LEN {
            panic_with_error!(e, MlDsaVerifierError::PublicKeyLength);
        }
        if sig.signature.len() as usize != SIGNATURE_LEN {
            panic_with_error!(e, MlDsaVerifierError::SignatureLength);
        }
        if key_commitment(e, &sig.public_key) != key_data {
            return false;
        }
        let mut message = [0u8; PAYLOAD_LEN];
        signature_payload.copy_into_slice(&mut message);
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        sig.public_key.copy_into_slice(&mut public_key);
        let mut signature = [0u8; SIGNATURE_LEN];
        sig.signature.copy_into_slice(&mut signature);
        verify_signature(&public_key, &message, SIG_CONTEXT, &signature)
    }

    /// The key's canonical form: the 32-byte commitment itself. One public key
    /// has one encoding and so one commitment; OZ compares these to detect
    /// duplicate signers. A key of any other length traps.
    fn canonicalize_key(_e: &Env, key_data: BytesN<32>) -> Bytes {
        key_data.into()
    }

    /// [`Self::canonicalize_key`] for each key, in input order.
    fn batch_canonicalize_key(e: &Env, keys_data: Vec<BytesN<32>>) -> Vec<Bytes> {
        Vec::from_iter(e, keys_data.iter().map(Bytes::from))
    }
}

/// The signer key (`key_data`) for an encoded ML-DSA-65 public key.
pub fn key_commitment(e: &Env, public_key: &Bytes) -> BytesN<32> {
    e.crypto().sha256(public_key).to_bytes()
}

/// FIPS 204 `ML-DSA.Verify` (pure) of `signature` by `public_key` over
/// `message` with `context`: the check [`PerchMlDsaVerifier::verify`] runs,
/// with [`SIG_CONTEXT`] and the auth digest.
pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    context: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    ml_dsa_65::PublicKey::try_from_bytes(*public_key)
        .is_ok_and(|key| key.verify(message, signature, context))
}

#[cfg(test)]
mod test;
