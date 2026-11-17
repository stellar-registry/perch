//! `apply_doc` with a cumulative cap: a capped document — once rejected by the
//! doc-compiler as `CapUnsupported` — now compiles and installs, its cap in
//! the stored rule-eval rule beside a context rule that carries no
//! policy. This proves the wiring; the cap's runtime allow/deny semantics
//! are proven in rule-core's vectors (`perch-rule-eval`'s `vectors.rs`), the
//! document traces (`rule_core_documents.rs`) and `gate.rs`.

use perch_testkit::{Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::{Bytes, BytesN, String as SString};

/// admin verifier / ci verifier the testkit stands up in native mode.
const ADMIN_VERIFIER: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
const CI_VERIFIER: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
/// The token contract the capped rule is scoped to (and metered in).
const TOKEN: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
const ADMIN_KEY: &str = "045e2a7589b73c19d5341cf12ac0c5f6c45c298d4c20002c794daadafdb83f35f5be23963648d7aaccf5e273803f2fec7a8f0eb4d4845c9b89a972b4a09298b17e";
const CI_KEY: &str = "1ce6040b0d03232ac6c911b0c375f1a52ebdefff56fd361d13680e23ca578a17";

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

/// A two-rule document: a policy-free admin survivor + a `transfer` rule on
/// `TOKEN` capped at 10 over a 1000-ledger window (token omitted ⇒ the scope).
fn capped_doc(token_field: &str) -> String {
    format!(
        r#"{{
          "version": 1,
          "network": "{FIXTURE_NETWORK}",
          "signers": [
            {{ "id": "admin", "verifier": "{ADMIN_VERIFIER}", "key": "{ADMIN_KEY}" }},
            {{ "id": "ci", "verifier": "{CI_VERIFIER}", "key": "{CI_KEY}" }}
          ],
          "rules": [
            {{ "name": "admin", "scope": {{ "type": "self-admin" }},
               "principals": {{ "type": "all", "signers": ["admin"] }} }},
            {{ "name": "capped", "scope": {{ "type": "contract", "address": "{TOKEN}" }},
               "principals": {{ "type": "all", "signers": ["ci"] }},
               "functions": ["transfer"],
               "cap": {{ {token_field}"limit": "10", "period-ledgers": 1000 }} }}
          ]
        }}"#
    )
}

#[test]
fn apply_doc_stores_the_cap_in_the_rule_eval_rule() {
    let w = setup();
    let client = w.account_client();

    // Previously `CapUnsupported`; now it compiles and applies.
    let doc = Bytes::from_slice(&w.env, capped_doc("").as_bytes());
    let hash: BytesN<32> = client.apply_doc(&doc, &0, &None);
    assert_eq!(client.applied_doc_hash(), Some(hash));

    assert_eq!(client.get_context_rules_count(), 2);

    // Rule 0: the policy-free admin survivor (INV-2), the constructor's
    // admin rule edited in place by the delta apply.
    let admin = client.get_context_rule(&0);
    assert_eq!(admin.name, SString::from_str(&w.env, "admin"));
    assert_eq!(admin.policies.len(), 0);

    // Rule 1: the record holds the capped rule's contract and signers, no
    // policy;
    // its stored rule allows `transfer` alone, with argument 2 an `i128`,
    // and carries the cap, metered from that argument.
    let capped = client.get_context_rule(&1);
    assert_eq!(capped.name, SString::from_str(&w.env, "capped"));
    assert_eq!(capped.policies.len(), 0);
    let stored = client.rule_set().get_unchecked(1);
    let cap = stored.cap.get(0).expect("a cap");
    assert_eq!((cap.limit, cap.period, cap.amount_arg), (10, 1000, 2));
    assert_eq!(stored.conds.len(), 1);
}

#[test]
fn apply_doc_rejects_a_cap_token_that_is_not_the_scope() {
    let w = setup();
    // An explicit cap token different from the rule's scope is refused at
    // validation (it would silently meter a different contract).
    let mismatched = format!(r#""token": "{CI_VERIFIER}", "#); // any C-addr != TOKEN
    let doc = Bytes::from_slice(&w.env, capped_doc(&mismatched).as_bytes());
    assert!(w.account_client().try_apply_doc(&doc, &0, &None).is_err());
    // Nothing was installed: the account still has only its constructor admin.
    assert_eq!(w.account_client().get_context_rules_count(), 1);
}
