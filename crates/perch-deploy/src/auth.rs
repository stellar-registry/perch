//! OZ smart-account auth-entry signing: the rule-id-bound digest and the
//! `AuthPayload` ScVal that becomes `credentials.address.signature`. The wire
//! shapes are pinned byte-for-byte against `stellar_accounts` in the tests
//! below — a `#[contracttype]` derive change upstream fails here, not on chain.

use anyhow::{bail, Result};
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, WriteXdr,
};

use crate::keys::SeedKey;
use crate::scv;

pub fn network_id(passphrase: &str) -> [u8; 32] {
    Sha256::digest(passphrase.as_bytes()).into()
}

/// `sha256(signature_payload || ScVec[ScU32(id), …] XDR)`. Rule selection is
/// bound into the signed digest so a relayer cannot downgrade the auth to a
/// weaker rule (OZ storage.rs `do_check_auth`).
pub fn oz_auth_digest(signature_payload: &[u8; 32], rule_ids: &[u32]) -> Result<[u8; 32]> {
    let ids: Vec<ScVal> = rule_ids.iter().map(|id| ScVal::U32(*id)).collect();
    let ids_xdr = scv::vec(ids)?.to_xdr(Limits::none())?;
    let mut preimage = signature_payload.to_vec();
    preimage.extend_from_slice(&ids_xdr);
    Ok(Sha256::digest(&preimage).into())
}

/// The `Signer::External(verifier, key)` ScVal. `key` is raw public-key bytes
/// (32 for ed25519; other verifiers may use longer encodings).
pub fn external_signer(verifier: &str, key: &[u8]) -> Result<ScVal> {
    scv::vec(vec![
        scv::sym("External")?,
        scv::address(verifier)?,
        scv::bytes(key)?,
    ])
}

/// The `ContextRuleType::CallContract(addr)` ScVal — the one rule-context shape
/// this pipeline uses. Shared by the write path (install-rule) and the read
/// path (verify) so both encode the context identically by construction.
pub fn call_contract_context(addr: &str) -> Result<ScVal> {
    scv::vec(vec![scv::sym("CallContract")?, scv::address(addr)?])
}

/// The `Signer::Delegated(addr)` ScVal — an address (G… or C…) the host
/// authenticates via CAP-0071 delegation.
pub fn delegated_signer(addr: &str) -> Result<ScVal> {
    scv::vec(vec![scv::sym("Delegated")?, scv::any_address(addr)?])
}

/// `AuthPayload { signers, context_rule_ids }` as an ScMap. Symbol keys must be
/// ascending ("context_rule_ids" < "signers") to match the contracttype
/// encoding; the golden test pins this against `stellar_accounts`.
pub fn auth_payload_scval(
    verifier: &str,
    pubkey: &[u8; 32],
    sig: &[u8; 64],
    rule_id: u32,
) -> Result<ScVal> {
    let ids = scv::vec(vec![ScVal::U32(rule_id)])?;
    let signers = scv::map(vec![(external_signer(verifier, pubkey)?, scv::bytes(sig)?)])?;
    scv::map(vec![
        (scv::sym("context_rule_ids")?, ids),
        (scv::sym("signers")?, signers),
    ])
}

/// `sha256(HashIdPreimage::SorobanAuthorization)` — the host-side payload the
/// OZ digest wraps.
pub fn signature_payload(
    passphrase: &str,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: &SorobanAuthorizedInvocation,
) -> Result<[u8; 32]> {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id(passphrase)),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    Ok(Sha256::digest(preimage.to_xdr(Limits::none())?).into())
}

/// `sha256(HashIdPreimage::SorobanAuthorizationWithAddress)` — the payload
/// every CAP-0071 delegate signs. Unlike the classic preimage it binds the
/// TOP-LEVEL account's address, so a delegate signature cannot be replayed
/// against a different account's entry.
pub fn signature_payload_with_address(
    passphrase: &str,
    nonce: i64,
    signature_expiration_ledger: u32,
    invocation: &SorobanAuthorizedInvocation,
    address: &ScAddress,
) -> Result<[u8; 32]> {
    let preimage = HashIdPreimage::SorobanAuthorizationWithAddress(
        HashIdPreimageSorobanAuthorizationWithAddress {
            network_id: Hash(network_id(passphrase)),
            nonce,
            signature_expiration_ledger,
            invocation: invocation.clone(),
            address: address.clone(),
        },
    );
    Ok(Sha256::digest(preimage.to_xdr(Limits::none())?).into())
}

/// A classic G-account's signature ScVal: a vec of
/// `AccountEd25519Signature { public_key, signature }` contracttype maps —
/// what the host's builtin account contract expects (soroban-env-host
/// builtin_contracts/account_contract.rs). Single-signer form.
pub fn account_signature_scval(pubkey: &[u8; 32], sig: &[u8; 64]) -> Result<ScVal> {
    scv::vec(vec![scv::map(vec![
        (scv::sym("public_key")?, scv::bytes(pubkey)?),
        (scv::sym("signature")?, scv::bytes(sig)?),
    ])?])
}

/// `AuthPayload` for a delegated signer: names `Signer::Delegated(delegate)`
/// with EMPTY signature bytes (its authentication is the host-forwarded
/// delegation, carried in the entry's delegate list) and selects `rule_id`.
/// No cryptographic material — construction only.
pub fn delegated_auth_payload_scval(delegate: &str, rule_id: u32) -> Result<ScVal> {
    let ids = scv::vec(vec![ScVal::U32(rule_id)])?;
    let signers = scv::map(vec![(delegated_signer(delegate)?, scv::bytes(&[])?)])?;
    scv::map(vec![
        (scv::sym("context_rule_ids")?, ids),
        (scv::sym("signers")?, signers),
    ])
}

/// Rebuild a simulation-supplied `Address` credential entry as CAP-0071
/// `AddressWithDelegates`: the smart account's signature is the (crypto-free)
/// delegated AuthPayload, and the single delegate is `key`'s G-account signing
/// the WithAddress payload with a classic account signature.
pub fn sign_delegated_auth_entry(
    entry: &mut SorobanAuthorizationEntry,
    passphrase: &str,
    signature_expiration_ledger: u32,
    key: &SeedKey,
    rule_id: u32,
) -> Result<()> {
    let invocation = entry.root_invocation.clone();
    let SorobanCredentials::Address(creds) = entry.credentials.clone() else {
        bail!("expected a plain Address credential entry from simulation");
    };
    let delegate_g = key.account();
    let payload = signature_payload_with_address(
        passphrase,
        creds.nonce,
        signature_expiration_ledger,
        &invocation,
        &creds.address,
    )?;
    let sig = key.signing.sign(&payload).to_bytes();
    entry.credentials =
        SorobanCredentials::AddressWithDelegates(SorobanAddressCredentialsWithDelegates {
            address_credentials: SorobanAddressCredentials {
                address: creds.address,
                nonce: creds.nonce,
                signature_expiration_ledger,
                signature: delegated_auth_payload_scval(&delegate_g, rule_id)?,
            },
            delegates: vec![SorobanDelegateSignature {
                address: g_address(&delegate_g)?,
                signature: account_signature_scval(&key.public, &sig)?,
                nested_delegates: Default::default(),
            }]
            .try_into()?,
        });
    Ok(())
}

fn g_address(strkey: &str) -> Result<ScAddress> {
    match scv::any_address(strkey)? {
        ScVal::Address(a) => Ok(a),
        _ => unreachable!("any_address returns an Address"),
    }
}

/// Sign an address-credential auth entry in place: set the expiration (the
/// simulation nonce is kept), compute payload → OZ digest → raw ed25519
/// signature, and install the AuthPayload ScVal as the credential signature.
pub fn sign_auth_entry(
    entry: &mut SorobanAuthorizationEntry,
    passphrase: &str,
    signature_expiration_ledger: u32,
    key: &SeedKey,
    verifier: &str,
    rule_id: u32,
) -> Result<()> {
    let invocation = entry.root_invocation.clone();
    let SorobanCredentials::Address(creds) = &mut entry.credentials else {
        bail!("cannot sign a source-account credential entry");
    };
    creds.signature_expiration_ledger = signature_expiration_ledger;
    let payload = signature_payload(
        passphrase,
        creds.nonce,
        signature_expiration_ledger,
        &invocation,
    )?;
    let digest = oz_auth_digest(&payload, &[rule_id])?;
    let sig = key.signing.sign(&digest).to_bytes();
    creds.signature = auth_payload_scval(verifier, &key.public, &sig, rule_id)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::auth::{Context, ContractContext};
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::xdr::ToXdr;
    use soroban_sdk::{contract, map, vec as svec, Address, Bytes, Env, Map, Symbol};
    use stellar_accounts::smart_account::{
        add_context_rule, do_check_auth, AuthPayload, ContextRuleType, Signer,
    };

    const VERIFIER: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";

    #[contract]
    struct Account;

    /// The real pin: a signature produced by THIS crate's pure-Rust path
    /// (signature payload → `oz_auth_digest` → ed25519) must be accepted by
    /// `stellar_accounts::do_check_auth` running against the real deployable
    /// verifier — not by a local re-statement of the digest formula.
    #[test]
    fn signature_accepted_by_oz_do_check_auth() {
        let env = Env::default();
        env.mock_all_auths();
        let account = env.register(Account, ());
        let verifier = env.register(perch_ed25519_verifier::PerchEd25519Verifier, ());
        let target = Address::generate(&env);

        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let signer = Signer::External(verifier.clone(), Bytes::from_array(&env, &pk));
        let rule = env.as_contract(&account, || {
            add_context_rule(
                &env,
                &ContextRuleType::CallContract(target.clone()),
                &soroban_sdk::String::from_str(&env, "e2e"),
                None,
                &svec![&env, signer.clone()],
                &Map::new(&env),
            )
        });

        // The host-supplied signature payload; compute its raw bytes with sha2
        // so the signing side never touches soroban.
        let payload_bytes: [u8; 32] = Sha256::digest(b"perch e2e digest pin").into();
        let payload_hash = env
            .crypto()
            .sha256(&Bytes::from_array(&env, b"perch e2e digest pin"));
        assert_eq!(payload_hash.to_bytes().to_array(), payload_bytes);

        let digest = oz_auth_digest(&payload_bytes, &[rule.id]).unwrap();
        let sig = sk.sign(&digest).to_bytes();
        let payload = AuthPayload {
            signers: map![&env, (signer, Bytes::from_array(&env, &sig))],
            context_rule_ids: svec![&env, rule.id],
        };
        let ctx = Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: Symbol::new(&env, "any_fn"),
            args: svec![&env],
        });
        env.as_contract(&account, || {
            do_check_auth(&env, &payload_hash, &payload, &svec![&env, ctx.clone()]).unwrap();
        });

        // Negative control: a digest bound to the wrong rule id must be
        // rejected — proves the rule-id binding is live, not vacuous.
        let bad_digest = oz_auth_digest(&payload_bytes, &[rule.id + 1]).unwrap();
        let bad_sig = sk.sign(&bad_digest).to_bytes();
        let bad_payload = AuthPayload {
            signers: map![
                &env,
                (
                    Signer::External(verifier.clone(), Bytes::from_array(&env, &pk)),
                    Bytes::from_array(&env, &bad_sig)
                )
            ],
            context_rule_ids: svec![&env, rule.id],
        };
        let denied = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            env.as_contract(&account, || {
                do_check_auth(&env, &payload_hash, &bad_payload, &svec![&env, ctx]).unwrap();
            });
        }));
        assert!(denied.is_err());
    }

    /// The delegated AuthPayload (empty sig bytes, Signer::Delegated) must
    /// byte-match the OZ contracttype encoding, same as the external form.
    #[test]
    fn delegated_auth_payload_scval_matches_stellar_accounts() {
        let env = Env::default();
        let delegate = Address::from_str(&env, VERIFIER); // any C-address works
        let signer = Signer::Delegated(delegate.clone());
        let signers: Map<Signer, Bytes> = map![&env, (signer, Bytes::new(&env))];
        let oz = AuthPayload {
            signers,
            context_rule_ids: svec![&env, 3u32],
        };
        let oz_bytes: Vec<u8> = oz.to_xdr(&env).iter().collect();

        let ours = WriteXdr::to_xdr(
            &delegated_auth_payload_scval(VERIFIER, 3).unwrap(),
            Limits::none(),
        )
        .unwrap();
        assert_eq!(ours, oz_bytes);
    }

    #[test]
    fn auth_payload_scval_matches_stellar_accounts() {
        let env = Env::default();
        let pubkey = [7u8; 32];
        let sig = [9u8; 64];

        let signer = Signer::External(
            Address::from_str(&env, VERIFIER),
            Bytes::from_array(&env, &pubkey),
        );
        let signers: Map<Signer, Bytes> = map![&env, (signer, Bytes::from_array(&env, &sig))];
        let oz = AuthPayload {
            signers,
            context_rule_ids: svec![&env, 5u32],
        };
        let oz_bytes: Vec<u8> = oz.to_xdr(&env).iter().collect();

        // Fully qualified: soroban's env-based `ToXdr` also matches `.to_xdr`
        // on ScVal under testutils.
        let ours = WriteXdr::to_xdr(
            &auth_payload_scval(VERIFIER, &pubkey, &sig, 5).unwrap(),
            Limits::none(),
        )
        .unwrap();
        assert_eq!(ours, oz_bytes);
    }
}
