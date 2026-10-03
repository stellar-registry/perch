//! A software passkey: a secp256r1 key that produces WebAuthn assertions in
//! exactly the shape a browser authenticator does, for tests and testnet
//! exercises of `perch-webauthn-verifier`.
//!
//! Plain bytes in and out (no `Env`), so host tools that build real
//! transactions use it the same way unit tests do.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// The relying party the assertions name. The verifier does not check the
/// origin or the rp id hash: a wallet binds those when it creates the key.
pub const RP_ID: &str = "perch.test";
pub const ORIGIN: &str = "https://perch.test";

/// Authenticator flags: user present and user verified, no backup bits.
pub const FLAGS_UP_UV: u8 = 0x05;

/// One WebAuthn assertion, the three fields of OZ's `WebAuthnSigData`.
#[derive(Clone, Debug)]
pub struct Assertion {
    pub authenticator_data: Vec<u8>,
    pub client_data: Vec<u8>,
    /// `r || s`, low-s normalized (the host refuses high-s signatures).
    pub signature: [u8; 64],
}

pub struct SoftPasskey {
    key: SigningKey,
    /// Opaque client metadata appended to the public key in `key_data`.
    pub credential_id: Vec<u8>,
}

impl SoftPasskey {
    /// A deterministic key from a 32-byte seed (any seed below the curve
    /// order; tests use small constants).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed.into()).expect("seed is a valid P-256 scalar");
        Self {
            key,
            credential_id: seed[..16].to_vec(),
        }
    }

    /// The 65-byte uncompressed SEC1 public key.
    pub fn public_key(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_encoded_point(false);
        point.as_bytes().try_into().expect("uncompressed point")
    }

    /// `key_data` for `Signer::External(webauthn_verifier, key_data)`: the
    /// public key followed by the credential id, as a browser wallet stores
    /// it. The verifier canonicalizes the suffix away.
    pub fn key_data(&self) -> Vec<u8> {
        let mut out = self.public_key().to_vec();
        out.extend_from_slice(&self.credential_id);
        out
    }

    /// Assert over a 32-byte signature payload with the given flags.
    pub fn assert_with_flags(&self, payload: &[u8; 32], flags: u8) -> Assertion {
        let challenge = URL_SAFE_NO_PAD.encode(payload);
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}","crossOrigin":false}}"#
        )
        .into_bytes();
        let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());

        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let prehash = Sha256::digest(&message);
        let sig: Signature = self.key.sign_prehash(&prehash).expect("sign");
        let sig = sig.normalize_s().unwrap_or(sig);
        Assertion {
            authenticator_data,
            client_data,
            signature: sig.to_bytes().into(),
        }
    }

    /// Assert over a 32-byte signature payload as a user-verifying
    /// authenticator does.
    pub fn assert(&self, payload: &[u8; 32]) -> Assertion {
        self.assert_with_flags(payload, FLAGS_UP_UV)
    }
}

/// The assertion as the signature bytes `perch-webauthn-verifier` takes: the
/// XDR of OZ's `WebAuthnSigData`.
pub fn sig_data(env: &soroban_sdk::Env, a: &Assertion) -> soroban_sdk::Bytes {
    use soroban_sdk::xdr::ToXdr as _;
    use soroban_sdk::{Bytes, BytesN};
    stellar_accounts::verifiers::webauthn::WebAuthnSigData {
        signature: BytesN::from_array(env, &a.signature),
        authenticator_data: Bytes::from_slice(env, &a.authenticator_data),
        client_data: Bytes::from_slice(env, &a.client_data),
    }
    .to_xdr(env)
}

/// `sha256(HashIdPreimage::SorobanAuthorization)`: what the host hands an
/// account's `__check_auth` as `signature_payload` for this entry.
pub fn signature_payload(
    env: &soroban_sdk::Env,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: &soroban_sdk::xdr::SorobanAuthorizedInvocation,
) -> [u8; 32] {
    use soroban_sdk::xdr::{
        Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, WriteXdr as _,
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(env.ledger().network_id().to_array()),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    Sha256::digest(preimage.to_xdr(Limits::none()).expect("preimage xdr")).into()
}

/// A perch account's authorization of `invocation` through `rule_id`,
/// signed by `key` as the account's `Signer::External(verifier, key_data)`:
/// the passkey signs OZ's rule-bound digest, exactly as a wallet does.
#[allow(clippy::too_many_arguments)] // the entry's fields, in wire order
pub fn auth_entry(
    env: &soroban_sdk::Env,
    account: &soroban_sdk::Address,
    verifier: &soroban_sdk::Address,
    key: &SoftPasskey,
    rule_id: u32,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: soroban_sdk::xdr::SorobanAuthorizedInvocation,
) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
    use soroban_sdk::xdr::{
        ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanCredentials,
    };
    use soroban_sdk::{map, vec, Bytes, BytesN, IntoVal as _, TryFromVal as _, Val};
    use stellar_accounts::smart_account::{AuthPayload, Signer};

    let payload = signature_payload(env, nonce, signature_expiration_ledger, &invocation);
    let ids = vec![env, rule_id];
    let digest = crate::auth_digest(env, &BytesN::from_array(env, &payload), &ids);
    let signer = Signer::External(verifier.clone(), Bytes::from_slice(env, &key.key_data()));
    let auth = AuthPayload {
        signers: map![env, (signer, sig_data(env, &key.assert(&digest)))],
        context_rule_ids: ids,
    };
    let val: Val = auth.into_val(env);
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account.clone().into(),
            nonce,
            signature_expiration_ledger,
            signature: ScVal::try_from_val(env, &val).expect("AuthPayload ScVal"),
        }),
        root_invocation: invocation,
    }
}
