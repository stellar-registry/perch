//! The install-time checks the account keeps from OZ's registry: the limits
//! on one rule (signers, policies, name and key length, at least a signer or
//! a policy) and the canonical-duplicate check, each refusing with OZ's code.
//!
//! - The constructor installs signers no compiler has seen, so it runs every
//!   check, the duplicate check through the verifiers' own
//!   `batch_canonicalize_key` as OZ's registry did.
//! - A compiled document never reaches the duplicate check: the compiler
//!   refuses a key that is not its verifier's canonical form
//!   (`KeyNotCanonicalizable`), and the IR refuses two signers with one
//!   verifier and key (`DuplicateSignerKey`, so `DocInvalid`). Two signers of
//!   one rule are then distinct canonical keys, which the verifier cannot
//!   map to one. Its limits are within the account's (`rules.rs` asserts the
//!   compiler's caps at build time; this suite checks the key cap).

use perch_account::PerchAccountClient;
use perch_account_types::Signer;
use perch_doc_compiler::{DocCompilerError, PerchDocCompiler, PerchDocCompilerClient};
use perch_smart_account::{install_admin, MAX_EXTERNAL_KEY_SIZE, MAX_NAME_SIZE, MAX_SIGNERS};
use perch_testkit::passkey::SoftPasskey;
use perch_testkit::FIXTURE_NETWORK;
use perch_webauthn_verifier::PerchWebAuthnVerifier;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{ContractEventBody, ScVal};
use soroban_sdk::{contract, Address, Bytes, Env, Vec};

/// A contract with no entry points: the constructor helper runs as it.
#[contract]
struct Bare;

/// Run the constructor helper for the signers `signers` builds (given the
/// env and a WebAuthn verifier), in a fresh `Env`. `Err` carries the panic.
fn construct(signers: impl FnOnce(&Env, &Address) -> Vec<Signer>) -> Result<(), String> {
    let env = Env::default();
    let verifier = env.register(PerchWebAuthnVerifier, ());
    let account = env.register(Bare, ());
    let signers = signers(&env, &verifier);
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account, || install_admin(&env, &signers))
    }))
    .map_err(|p| {
        p.downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

fn refused_with(out: Result<(), String>, code: u32) {
    let msg = out.expect_err("the constructor refuses");
    assert!(
        msg.contains(&format!("Error(Contract, #{code})")),
        "expected #{code}, got: {msg}"
    );
}

fn delegated(env: &Env, n: usize) -> Vec<Signer> {
    let mut out = Vec::new(env);
    for _ in 0..n {
        out.push_back(Signer::Delegated(Address::generate(env)));
    }
    out
}

fn passkey(env: &Env, verifier: &Address, key: &[u8]) -> Signer {
    Signer::External(verifier.clone(), Bytes::from_slice(env, key))
}

#[test]
fn the_constructor_refuses_no_signer() {
    refused_with(construct(|e, _| Vec::new(e)), 3004);
}

#[test]
fn the_constructor_refuses_more_signers_than_the_limit() {
    refused_with(
        construct(|e, _| delegated(e, MAX_SIGNERS as usize + 1)),
        3010,
    );
}

#[test]
fn the_constructor_refuses_an_oversized_key() {
    refused_with(
        construct(|e, v| {
            let key = std::vec![4u8; MAX_EXTERNAL_KEY_SIZE as usize + 1];
            Vec::from_array(e, [passkey(e, v, &key)])
        }),
        3013,
    );
}

#[test]
fn the_constructor_refuses_one_delegated_signer_twice() {
    refused_with(
        construct(|e, _| {
            let a = Signer::Delegated(Address::generate(e));
            Vec::from_array(e, [a.clone(), a])
        }),
        3007,
    );
}

/// The WebAuthn verifier keeps a key's first 65 bytes, so a key and the same
/// key with a credential-id suffix are one physical key.
#[test]
fn the_constructor_refuses_two_spellings_of_one_key() {
    let pk = SoftPasskey::from_seed([3u8; 32]);
    let (canonical, suffixed) = (pk.public_key(), pk.key_data());
    assert_ne!(canonical.as_slice(), suffixed.as_slice());
    refused_with(
        construct(|e, v| Vec::from_array(e, [passkey(e, v, &canonical), passkey(e, v, &suffixed)])),
        3007,
    );
}

/// The verifier is asked even for a lone key, so one it cannot read fails
/// the constructor.
#[test]
fn the_constructor_refuses_a_key_its_verifier_cannot_read() {
    let out = construct(|e, v| Vec::from_array(e, [passkey(e, v, &[4u8; 10])]));
    assert!(out.is_err(), "a 10-byte WebAuthn key");
}

/// At the limit, the admin rule is installed under id 0 and announced as
/// OZ's registry announces a rule: `context_rule_added`, its signers'
/// positions as their ids.
#[test]
fn the_constructor_installs_up_to_the_limit_and_announces_the_rule() {
    let env = Env::default();
    let signers = delegated(&env, MAX_SIGNERS as usize);
    let account = env.register(perch_account::PerchAccount, (signers.clone(),));
    let events = env.events().all();
    let added: std::vec::Vec<_> = events
        .events()
        .iter()
        .filter_map(|e| {
            let ContractEventBody::V0(body) = &e.body;
            match body.topics.as_slice() {
                [ScVal::Symbol(name), ScVal::U32(id)]
                    if name.to_utf8_string_lossy() == "context_rule_added" =>
                {
                    Some(*id)
                }
                _ => None,
            }
        })
        .collect();
    assert_eq!(added, [0]);
    let client = PerchAccountClient::new(&env, &account);
    let rules = client.installed_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        (rules.get(0).unwrap().id, rules.get(0).unwrap().signers),
        (0, signers.clone())
    );
    assert_eq!(client.get_context_rules_count(), 1);
    let rule = client.get_context_rule(&0);
    let positions: std::vec::Vec<u32> = rule.signer_ids.iter().collect();
    assert_eq!(positions, (0..MAX_SIGNERS).collect::<std::vec::Vec<_>>());
    assert!(rule.policies.is_empty() && rule.policy_ids.is_empty());
}

fn compile_signers(signers: &[(&str, std::string::String)]) -> Result<(), DocCompilerError> {
    let env = Env::default();
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);
    let verifier = env.register(PerchWebAuthnVerifier, ());
    let compiler = env.register(PerchDocCompiler, ());
    let verifier = perch_testkit::delta::strkey(&verifier);
    let decls: std::vec::Vec<std::string::String> = signers
        .iter()
        .map(|(id, key)| format!(r#"{{"id":"{id}","verifier":"{verifier}","key":"{key}"}}"#))
        .collect();
    let ids: std::vec::Vec<std::string::String> =
        signers.iter().map(|(id, _)| format!(r#""{id}""#)).collect();
    let doc = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":[{}]}}}}]}}"#,
        decls.join(","),
        ids.join(",")
    );
    PerchDocCompilerClient::new(&env, &compiler)
        .try_compile_doc(&Bytes::from_slice(&env, doc.as_bytes()))
        .map(|_| ())
        .map_err(|e| e.unwrap())
}

/// The two ways a document could put one physical key twice in a rule are
/// refused by the compiler, so the account need not ask the verifier again.
#[test]
fn a_document_never_reaches_the_duplicate_check() {
    let pk = SoftPasskey::from_seed([3u8; 32]);
    let (canonical, suffixed) = (hex::encode(pk.public_key()), hex::encode(pk.key_data()));
    assert_eq!(compile_signers(&[("a", canonical.clone())]), Ok(()));
    // Two spellings of one key: the suffixed one is not canonical.
    assert_eq!(
        compile_signers(&[("a", canonical.clone()), ("b", suffixed)]),
        Err(DocCompilerError::KeyNotCanonicalizable)
    );
    // One canonical key under two ids.
    assert_eq!(
        compile_signers(&[("a", canonical.clone()), ("b", canonical)]),
        Err(DocCompilerError::DocInvalid)
    );
}

/// A compiled document stays within the limits: the compiler's caps are
/// asserted at build time, and its key cap is the account's.
#[test]
fn a_documents_keys_and_names_are_within_the_limits() {
    assert_eq!(perch_ir::MAX_SIGNER_KEY_LEN as u32, MAX_EXTERNAL_KEY_SIZE);
    assert_eq!(perch_doc_compiler::MAX_RULE_NAME_BYTES, MAX_NAME_SIZE);
    const { assert!(perch_doc_compiler::MAX_DOC_SIGNERS <= MAX_SIGNERS) };
    let long = hex::encode(std::vec![4u8; MAX_EXTERNAL_KEY_SIZE as usize + 1]);
    assert_eq!(
        compile_signers(&[("a", long)]),
        Err(DocCompilerError::DocInvalid)
    );
}
