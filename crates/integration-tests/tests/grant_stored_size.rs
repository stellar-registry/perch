//! The compiler's `grant_stored_bytes` is the size of the ledger entry the
//! account stores for a grant document, to the byte, and every grant
//! document the grant caps admit stores within `MAX_GRANT_STORED_BYTES`,
//! the bound the compiler refuses a grant document past
//! (`docs/recovery/budgets.md`, "Grant-document caps"). The documents cover
//! every part the entry holds: delegated and external signers, keys of
//! several lengths, named and unnamed verifiers, every predicate, functions,
//! caps, expiries, and exact roots. A change to the account's record or to
//! rule-core's lowering fails here first.

use perch_doc_compiler::{
    grant_stored_bytes, DocCompilerError, MAX_GRANT_CANONICAL_BYTES, MAX_GRANT_RULES,
    MAX_GRANT_STORED_BYTES,
};
use perch_testkit::delta::strkey;
use perch_testkit::{
    Bootstrap, World, ED25519_VERIFIER_NAME, FIXTURE_NETWORK, FIXTURE_VERIFIER_NAMES,
};
use soroban_sdk::xdr::{LedgerEntryData, LedgerKey, Limits, ScAddress, ScVal, WriteXdr};
use soroban_sdk::{Bytes, BytesN};

const G: &str = "GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH";

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

fn bytes(w: &World, json: &str) -> Bytes {
    Bytes::from_slice(&w.env, json.as_bytes())
}

fn doc(signers: &[String], rules: &[String]) -> String {
    format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        rules.join(",")
    )
}

/// The account's ledger entry whose value is the record of the grant
/// document hashing to `doc_hash` (the tuple a `StoredGrant` is stored as,
/// its second field the hash), in bytes.
fn stored_entry(w: &World, doc_hash: &BytesN<32>) -> usize {
    let me: ScAddress = w.account.clone().into();
    let hash = ScVal::Bytes(doc_hash.to_array().to_vec().try_into().unwrap());
    let snapshot = w.env.to_ledger_snapshot();
    let found: Vec<usize> = snapshot
        .ledger_entries
        .iter()
        .filter_map(|(key, (entry, _))| {
            let (LedgerKey::ContractData(k), LedgerEntryData::ContractData(d)) =
                (&**key, &entry.data)
            else {
                return None;
            };
            let ScVal::Vec(Some(fields)) = &d.val else {
                return None;
            };
            let holds = fields.len() == 6 && fields.get(1) == Some(&hash);
            (k.contract == me && holds).then(|| entry.to_xdr(Limits::none()).unwrap().len())
        })
        .collect();
    assert_eq!(found.len(), 1, "one record holds the document's hash");
    found[0]
}

/// Apply `json` under `grant` and check the estimate against the entry.
fn check(w: &World, grant: u32, json: &str) -> usize {
    let estimate = grant_stored_bytes(&perch_ir::from_json(json).unwrap()) as usize;
    let hash = w.account_client().apply_grant(&grant, &bytes(w, json));
    assert_eq!(stored_entry(w, &hash), estimate, "grant {grant}: {json}");
    estimate
}

#[test]
fn the_estimate_is_the_stored_entry() {
    let w = setup();
    let target = strkey(&w.verifier);
    let ed = strkey(&w.verifier);
    let any = strkey(&w.fixture_verifiers[0]);
    let any_name = FIXTURE_VERIFIER_NAMES[0];
    let signer = |id: &str, verifier: &str, name: Option<&str>, key: &str| {
        let name = name
            .map(|n| format!(r#","verifier-name":"{n}""#))
            .unwrap_or_default();
        format!(r#"{{"id":"{id}","verifier":"{verifier}"{name},"key":"{key}"}}"#)
    };
    let delegated = |id: &str, address: &str| format!(r#"{{"id":"{id}","address":"{address}"}}"#);
    let scope = format!(r#""scope":{{"type":"contract","address":"{target}"}}"#);

    // One delegated account signer, one bare rule: no verifier names.
    check(
        &w,
        1,
        &doc(
            &[delegated("g", G)],
            &[format!(
                r#"{{"name":"r",{scope},"principals":{{"type":"all","signers":["g"]}}}}"#
            )],
        ),
    );

    // Named ed25519 signers, a delegated contract, every predicate, listed
    // functions, an expiry, and a capped rule with an exact root.
    let c = strkey(&w.compiler);
    let keys: Vec<String> = (1..=3u8).map(|i| format!("{i:02x}").repeat(32)).collect();
    check(
        &w,
        2,
        &doc(
            &[
                signer("a", &ed, Some(ED25519_VERIFIER_NAME), &keys[0]),
                signer("bb", &ed, Some(ED25519_VERIFIER_NAME), &keys[1]),
                delegated("ccc", &c),
                signer("dddd", &ed, Some(ED25519_VERIFIER_NAME), &keys[2]),
            ],
            &[
                format!(
                    r#"{{"name":"wide",{scope},"principals":{{"type":"threshold","m":2,"signers":["a","bb","ccc"]}},"functions":["f","bbbbbbbbb"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}},{{"index":1,"pred":{{"type":"address-eq","address":"{G}"}}}},{{"index":2,"pred":{{"type":"u32-eq","value":7}}}},{{"index":3,"pred":{{"type":"string-prefix","prefix":"pre"}}}},{{"index":4,"pred":{{"type":"string-in","values":["x","yy","zzzzz","123456789"]}}}},{{"index":5,"pred":{{"type":"address-eq","address":"{c}"}}}}],"not-after-ledger":4000000}}"#
                ),
                format!(
                    r#"{{"name":"capped-root",{scope},"auth-root":{{"contract":"{target}","function":"play_a_round"}},"principals":{{"type":"all","signers":["bb","dddd"]}},"functions":["transfer"],"args":[{{"index":0,"pred":{{"type":"is-self"}}}}],"cap":{{"limit":"1000","period-ledgers":17280}}}}"#
                ),
            ],
        ),
    );

    // Long keys under a named verifier and an unnamed one (once in the rule),
    // beside a delegated signer: some signers have no verifier name.
    check(
        &w,
        3,
        &doc(
            &[
                signer("k65", &any, Some(any_name), &"ab".repeat(65)),
                signer("k256", &any, Some(any_name), &"cd".repeat(256)),
                signer("raw", &ed, None, &"ef".repeat(32)),
                delegated("g", G),
            ],
            &[format!(
                r#"{{"name":"long",{scope},"principals":{{"type":"threshold","m":1,"signers":["k65","k256","raw","g"]}}}}"#
            )],
        ),
    );
}

/// A grant document of `signer` (a declaration with id `g`) and one rule
/// whose `string-in`s hold `n` one-character values, `VALUES` per argument
/// index: the densest a document stores, per canonical byte.
fn values_doc(w: &World, signer: &str, n: usize) -> String {
    const VALUES: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let target = strkey(&w.verifier);
    let preds: Vec<String> = (0..n.div_ceil(VALUES.len()))
        .map(|i| {
            let values: Vec<String> = (0..VALUES.len().min(n - i * VALUES.len()))
                .map(|v| format!(r#""{}""#, char::from(VALUES[v])))
                .collect();
            format!(
                r#"{{"index":{i},"pred":{{"type":"string-in","values":[{}]}}}}"#,
                values.join(",")
            )
        })
        .collect();
    doc(
        &[signer.to_string()],
        &[format!(
            r#"{{"name":"v","scope":{{"type":"contract","address":"{target}"}},"principals":{{"type":"all","signers":["g"]}},"args":[{}]}}"#,
            preds.join(",")
        )],
    )
}

fn canonical(json: &str) -> usize {
    perch_ir::canonical_json(&perch_ir::from_json(json).unwrap()).len()
}

/// The bound holds every grant document the other caps admit: the densest
/// per canonical byte, one-character `string-in` values filling the byte
/// cap beside a passkey signer and beside a delegated one (whose shorter
/// declaration leaves room for more values), and the most rules, each
/// apply and store exactly their estimate, within the bound. One value
/// more passes the byte cap and is refused, storing nothing.
#[test]
fn every_grant_document_the_caps_admit_stores_within_the_bound() {
    let w = setup();
    let passkey = format!(
        r#"{{"id":"g","verifier":"{}","verifier-name":"{}","key":"{}"}}"#,
        strkey(&w.fixture_verifiers[0]),
        FIXTURE_VERIFIER_NAMES[0],
        "ab".repeat(65)
    );
    let delegated = format!(r#"{{"id":"g","address":"{G}"}}"#);
    let mut largest = 0;
    for (grant, signer) in [(1, &passkey), (2, &delegated)] {
        let most = (1..)
            .take_while(|&n| {
                canonical(&values_doc(&w, signer, n)) <= MAX_GRANT_CANONICAL_BYTES as usize
            })
            .last()
            .unwrap();
        let stored = check(&w, grant, &values_doc(&w, signer, most));
        assert!(stored <= MAX_GRANT_STORED_BYTES as usize);
        largest = largest.max(stored);

        let past = values_doc(&w, signer, most + 1);
        assert!(matches!(
            w.compiler_client().try_compile_doc(&bytes(&w, &past)),
            Err(Ok(DocCompilerError::DocTooLarge))
        ));
        assert!(w
            .account_client()
            .try_apply_grant(&9, &bytes(&w, &past))
            .is_err());
        assert!(w.account_client().grant(&9).is_none(), "nothing stored");
    }

    // The most rules: one delegated signer, every rule bare.
    let target = strkey(&w.verifier);
    let rules: Vec<String> = (0..MAX_GRANT_RULES)
        .map(|k| {
            format!(
                r#"{{"name":"r{k}","scope":{{"type":"contract","address":"{target}"}},"principals":{{"type":"all","signers":["g"]}}}}"#
            )
        })
        .collect();
    largest = largest.max(check(&w, 3, &doc(&[delegated], &rules)));
    println!("the largest entry the grant caps admit: {largest} bytes");
}
