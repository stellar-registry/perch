//! `apply_doc` end-to-end: the account's whole authorization is replaced from
//! a policy document's JSON bytes in one call — parse, validate, network
//! binding, compile, anti-brick check, atomic swap, canonical `doc_hash`
//! stored. Piecemeal mutation entry points do not exist on the contract.
//!
//! The whole `setup()` this suite used to hand-roll is now one
//! `perch_testkit::Bootstrap::native()` call; the stand-in verifier, the
//! fixture constants and `fixture()` live in the testkit.

use perch_testkit::{fixture, Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{vec, Bytes, BytesN, String as SString, Symbol, Val};

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

fn apply_fixture(w: &World) -> BytesN<32> {
    let doc = Bytes::from_slice(&w.env, fixture().as_bytes());
    w.account_client().apply_doc(&doc)
}

#[test]
fn apply_doc_installs_rules_and_stores_canonical_hash() {
    let w = setup();
    let client = w.account_client();

    let hash = apply_fixture(&w);

    // The stored identity is the CANONICAL doc_hash — the frozen golden
    // vector — even though the submitted bytes are the pretty-printed file.
    let expected = w.ci_publish_doc_hash();
    assert_eq!(hash, expected);
    assert_eq!(client.applied_doc_hash(), Some(expected));

    // Constructor rule 0 is gone; the document's two rules are installed.
    assert_eq!(client.get_context_rules_count(), 2);
    let admin = client.get_context_rule(&1);
    assert_eq!(admin.name, SString::from_str(&w.env, "admin"));
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
    let client = w.account_client();
    let first = apply_fixture(&w);

    // A second document: admin only — the ci grant is revoked wholesale.
    let doc2 = format!(
        r#"{{
  "version": 1,
  "network": "{FIXTURE_NETWORK}",
  "signers": [
    {{ "id": "admin", "verifier": "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN", "key": "aa" }}
  ],
  "rules": [
    {{ "name": "admin",
      "scope": {{ "type": "self-admin" }},
      "principals": {{ "type": "all", "signers": ["admin"] }} }}
  ]
}}"#
    );
    let second = client.apply_doc(&Bytes::from_slice(&w.env, doc2.as_bytes()));

    assert_ne!(first, second);
    assert_eq!(client.applied_doc_hash(), Some(second));
    assert_eq!(client.get_context_rules_count(), 1);
    // The old rules (ids 1 and 2) no longer exist.
    assert!(client.try_get_context_rule(&1).is_err());
    assert!(client.try_get_context_rule(&2).is_err());
    assert_eq!(
        client.get_context_rule(&3).name,
        SString::from_str(&w.env, "admin")
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
    let client = w.account_client();
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
        .try_apply_doc(&Bytes::from_slice(&w.env, doc.as_bytes()))
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
    // Content addresses are network-dependent, so on the rebound network the
    // account resolves the compiler to a new address — put a real compiler there
    // so the rejection is the compiler's own `WrongNetwork`, not a missing infra.
    w.reregister_infra_for_current_network();

    let client = w.account_client();
    let doc = Bytes::from_slice(&w.env, fixture().as_bytes());
    assert!(client.try_apply_doc(&doc).is_err());
    assert_eq!(client.applied_doc_hash(), None);
}

#[test]
fn garbage_and_unknown_fields_are_rejected() {
    let w = setup();
    let client = w.account_client();
    // Not JSON at all.
    assert!(client
        .try_apply_doc(&Bytes::from_slice(&w.env, b"not json"))
        .is_err());
    // Unknown field: fail closed, never skipped.
    let doc = fixture().replace("\"version\": 1,", "\"version\": 1, \"surprise\": true,");
    assert!(client
        .try_apply_doc(&Bytes::from_slice(&w.env, doc.as_bytes()))
        .is_err());
}
