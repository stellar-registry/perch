//! `apply_doc` with a cumulative cap: a capped document — once rejected by the
//! doc-compiler as `CapUnsupported` — now compiles and installs, attaching OZ
//! `spending_limit` beside the interpreter on one context rule. The policy's
//! address is resolved offline (content-addressed), never admin-supplied. This
//! proves the wiring; the cap's runtime allow/deny semantics are proven in
//! `perch-spending-limit`'s own test and `cap_matrix`.

use perch_smart_account::{infra, stateless_registry};
use perch_testkit::{Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::{Address, Bytes, BytesN, String as SString};

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

/// The content-addressed spending-limit address the account resolves in
/// `install_rule` — recomputed here to assert the rule carries exactly it.
fn spending_limit_addr(w: &World) -> Address {
    infra::perch_spending_limit::address(&w.env, &stateless_registry(&w.env))
}

#[test]
fn apply_doc_installs_the_cap_beside_the_interpreter() {
    let w = setup();
    let client = w.account_client();

    // Previously `CapUnsupported`; now it compiles and applies.
    let doc = Bytes::from_slice(&w.env, capped_doc("").as_bytes());
    let hash: BytesN<32> = client.apply_doc(&doc);
    assert_eq!(client.applied_doc_hash(), Some(hash));

    assert_eq!(client.get_context_rules_count(), 2);

    // Rule 1: the policy-free admin survivor (INV-2).
    let admin = client.get_context_rule(&1);
    assert_eq!(admin.name, SString::from_str(&w.env, "admin"));
    assert_eq!(admin.policies.len(), 0);

    // Rule 2: the capped rule carries BOTH policies — the interpreter (per-call
    // program + INV-1 floor) AND spending_limit (the cumulative cap).
    let capped = client.get_context_rule(&2);
    assert_eq!(capped.name, SString::from_str(&w.env, "capped"));
    assert_eq!(capped.policies.len(), 2, "interpreter + spending_limit");
    assert!(capped.policies.contains(&w.interpreter));
    assert!(capped.policies.contains(&spending_limit_addr(&w)));
}

#[test]
fn apply_doc_rejects_a_cap_token_that_is_not_the_scope() {
    let w = setup();
    // An explicit cap token different from the rule's scope is refused at
    // validation (it would silently meter a different contract).
    let mismatched = format!(r#""token": "{CI_VERIFIER}", "#); // any C-addr != TOKEN
    let doc = Bytes::from_slice(&w.env, capped_doc(&mismatched).as_bytes());
    assert!(w.account_client().try_apply_doc(&doc).is_err());
    // Nothing was installed: the account still has only its constructor admin.
    assert_eq!(w.account_client().get_context_rules_count(), 1);
}
