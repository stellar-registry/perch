//! `apply_doc` end-to-end: the account's whole authorization is replaced from
//! a policy document's JSON bytes in one call — parse, validate, network
//! binding, compile, anti-brick check, atomic swap, canonical `doc_hash`
//! stored. Piecemeal mutation entry points do not exist on the contract.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{
    contract, contractimpl, vec, Address, Bytes, BytesN, Env, String as SString, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::Signer;
use stellar_accounts::verifiers::Verifier;

mod common;
use common::fixture;

/// Stand-in for the fixture's verifier contracts (whose addresses the frozen
/// document pins but which aren't deployed in a unit env): key handling is
/// pass-through so OZ's canonical-duplicate check can run.
#[contract]
struct AnyKeyVerifier;

#[contractimpl]
impl Verifier for AnyKeyVerifier {
    type KeyData = Bytes;
    type SigData = Bytes;

    fn verify(_e: &Env, _signature_payload: Bytes, _key_data: Bytes, _sig_data: Bytes) -> bool {
        true
    }

    fn canonicalize_key(_e: &Env, key_data: Bytes) -> Bytes {
        key_data
    }

    fn batch_canonicalize_key(_e: &Env, keys_data: Vec<Bytes>) -> Vec<Bytes> {
        keys_data
    }
}

/// The fixture's pinned verifier addresses (admin, ci).
const FIXTURE_VERIFIERS: [&str; 2] = [
    "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN",
    "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG",
];

/// The fixture's frozen canonical identity (testdata/ci-publish.doc-hash).
const CI_PUBLISH_DOC_HASH: &str =
    "38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d";

/// The fixture's network passphrase; apply_doc binds documents to the chain.
const FIXTURE_NETWORK: &str = "Test SDF Network ; September 2015";

struct World {
    env: Env,
    account: Address,
    interpreter: Address,
}

fn setup() -> World {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();

    // Bind the test chain to the fixture's network passphrase.
    let net_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net_id);

    let interpreter = env.register(perch_interpreter::PerchInterpreter, ());
    let verifier = env.register(PerchEd25519Verifier, ());
    for addr in FIXTURE_VERIFIERS {
        env.register_at(&Address::from_str(&env, addr), AnyKeyVerifier, ());
    }
    let admin_signers = vec![
        &env,
        Signer::External(verifier, Bytes::from_array(&env, &[9u8; 32])),
    ];
    let account = env.register(PerchAccount, (admin_signers,));
    World {
        env,
        account,
        interpreter,
    }
}

fn apply_fixture(w: &World) -> BytesN<32> {
    let doc = Bytes::from_slice(&w.env, fixture().as_bytes());
    PerchAccountClient::new(&w.env, &w.account).apply_doc(&doc, &w.interpreter)
}

#[test]
fn apply_doc_installs_rules_and_stores_canonical_hash() {
    let w = setup();
    let client = PerchAccountClient::new(&w.env, &w.account);

    let hash = apply_fixture(&w);

    // The stored identity is the CANONICAL doc_hash — the frozen golden
    // vector — even though the submitted bytes are the pretty-printed file.
    let expected = BytesN::from_array(
        &w.env,
        &<[u8; 32]>::try_from(hex::decode(CI_PUBLISH_DOC_HASH).unwrap().as_slice()).unwrap(),
    );
    assert_eq!(hash, expected);
    assert_eq!(client.applied_doc_hash(), Some(expected));

    // Constructor rule 0 is gone; the document's two rules are installed.
    assert_eq!(client.get_context_rules_count(), 2);
    let admin = client.get_context_rule(&1);
    assert_eq!(admin.name, SString::from_str(&w.env, "admin-root"));
    assert_eq!(admin.policies.len(), 0); // policy-free admin path (INV-2)
    let ci = client.get_context_rule(&2);
    assert_eq!(ci.name, SString::from_str(&w.env, "ci-publish"));
    assert_eq!(ci.policies.len(), 1); // the interpreter program is attached
    assert_eq!(ci.policies.get_unchecked(0), w.interpreter);
    // `not-after-ledger: 55000000` (exclusive) lowers to OZ's inclusive
    // last-valid ledger.
    assert_eq!(ci.valid_until, Some(54_999_999));
}

#[test]
fn reapply_replaces_the_whole_rule_set() {
    let w = setup();
    let client = PerchAccountClient::new(&w.env, &w.account);
    let first = apply_fixture(&w);

    // A second document: admin-root only — the ci grant is revoked wholesale.
    let doc2 = format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN", "key": "aa" }}
  ],
  "rules": [
    {{ "name": "admin-root",
      "scope": {{ "type": "self-admin" }},
      "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ]
}}"#
    );
    let second = client.apply_doc(&Bytes::from_slice(&w.env, doc2.as_bytes()), &w.interpreter);

    assert_ne!(first, second);
    assert_eq!(client.applied_doc_hash(), Some(second));
    assert_eq!(client.get_context_rules_count(), 1);
    // The old rules (ids 1 and 2) no longer exist.
    assert!(client.try_get_context_rule(&1).is_err());
    assert!(client.try_get_context_rule(&2).is_err());
    assert_eq!(
        client.get_context_rule(&3).name,
        SString::from_str(&w.env, "admin-root")
    );
}

#[test]
fn piecemeal_mutation_entry_points_do_not_exist() {
    // Doc-only is structural: the account implements OZ's SmartAccount but
    // never exports it, so the mutation functions aren't callable at all —
    // there is nothing to authorize, misuse, or audit. apply_doc is the only
    // write path.
    let w = setup();
    for func in [
        "add_context_rule",
        "remove_context_rule",
        "add_signer",
        "remove_signer",
        "add_policy",
        "remove_policy",
        "update_context_rule_name",
        "update_context_rule_valid_until",
    ] {
        let res = w.env.try_invoke_contract::<Val, soroban_sdk::Error>(
            &w.account,
            &Symbol::new(&w.env, func),
            vec![&w.env],
        );
        assert!(res.is_err(), "{func} should not be an entry point");
    }
}

#[test]
fn doc_without_admin_rule_is_rejected_anti_brick() {
    let w = setup();
    let client = PerchAccountClient::new(&w.env, &w.account);
    // Only a contract-scoped rule — applying this would leave no admin path.
    let doc = format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "ci", "address": "GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA" }}
  ],
  "rules": [
    {{ "name": "ci-publish",
      "scope": {{ "type": "contract", "address": "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL" }},
      "principals": {{ "type": "all", "signers": ["ci"] }},
      "functions": ["publish"] }}
  ]
}}"#
    );
    assert!(client
        .try_apply_doc(&Bytes::from_slice(&w.env, doc.as_bytes()), &w.interpreter)
        .is_err());
    // Nothing changed: the constructor's rule 0 is still the only rule.
    assert_eq!(client.get_context_rules_count(), 1);
    assert_eq!(client.applied_doc_hash(), None);
}

#[test]
fn doc_for_another_network_is_rejected() {
    let w = setup();
    // Rebind the chain to a different network than the document names.
    let other = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(
            &w.env,
            b"Public Global Stellar Network ; September 2015",
        ))
        .to_array();
    w.env.ledger().with_mut(|l| l.network_id = other);

    let client = PerchAccountClient::new(&w.env, &w.account);
    let doc = Bytes::from_slice(&w.env, fixture().as_bytes());
    assert!(client.try_apply_doc(&doc, &w.interpreter).is_err());
    assert_eq!(client.applied_doc_hash(), None);
}

#[test]
fn garbage_and_unknown_fields_are_rejected() {
    let w = setup();
    let client = PerchAccountClient::new(&w.env, &w.account);
    // Not JSON at all.
    assert!(client
        .try_apply_doc(&Bytes::from_slice(&w.env, b"not json"), &w.interpreter)
        .is_err());
    // Unknown field: fail closed, never skipped.
    let doc = fixture().replace("\"version\": 1,", "\"version\": 1, \"surprise\": true,");
    assert!(client
        .try_apply_doc(&Bytes::from_slice(&w.env, doc.as_bytes()), &w.interpreter)
        .is_err());
}
