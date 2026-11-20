//! The documents the live perch authors apply to gain `ci-publish-verifiers`
//! (testdata/deploy/perch-author-<network>.json; docs/deploy/README.md, "The
//! perch author's rule on perch/verifiers"). Each must be the document the
//! account applied, the `applied_doc_hash` it reports on chain, plus that one
//! rule, and the rule must be `ci-publish` moved to perch/verifiers with
//! `publish_hash` alone: the same delegate, the same is-self author and the
//! same expiry.

use perch_deploy::compose::{compose, ComposeOutput, RuleEntry};
use perch_rule_eval::{StoredFunctions, StoredRule};
use soroban_sdk::xdr::FromXdr;
use soroban_sdk::{Address, Bytes, Env, Symbol};
use stellar_xdr::{Limits, ReadXdr, ScVal, WriteXdr};

struct Author {
    file: &'static str,
    account: &'static str,
    /// perch/constructorless, which `registry.path` derives on the network.
    registry: &'static str,
    /// perch/verifiers, which `verifiers.path` derives on the network.
    verifiers: &'static str,
    /// The account's `applied_doc_hash` before this document (read on chain
    /// 2026-11-10).
    applied: &'static str,
    /// This document's hash, which the account reports once it is applied.
    reviewed: &'static str,
}

const AUTHORS: [Author; 2] = [
    Author {
        file: "perch-author-testnet.json",
        account: "CAAGHKZBUOQVVDB6LZCMCJHHSLAMBIPUYN3VU57NOLTVNYWMBI3T4KZ4",
        registry: "CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM",
        verifiers: "CCHJ7RWPMO33JB5PS74B64N4LVTWCGLEMH5IAKYCV32X56MXGYLHN5HW",
        applied: "79e90f3a19386d6e94ed130676c7c5005fea3072820814a8d074ebb5ed83419d",
        reviewed: "d9e69c50681dc63c2aab9379903986e8dbd86405306c93d479732ca27ad44c7b",
    },
    Author {
        file: "perch-author-mainnet.json",
        account: "CDZWM45C6N6YBH73KNUDOTOI7P6K5UQDCRMHSQ76YSCERLS66FPZ253O",
        registry: "CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN",
        verifiers: "CCDCKRUV4W4DQYBWFWT4FNQ2QXQPGUQ7EXOZHIHSSLB6YJHMLHPMGDPH",
        applied: "2fb21e99655e3aa627546f00850fab2285eb40c68fe0d45d184b4e17071d9158",
        reviewed: "4bb8f166d79370dae4ad92086de6623633e6aa4098c3a680f27564a878667441",
    },
];

fn read(author: &Author) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/deploy")
        .join(author.file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn hash(doc_json: &str) -> String {
    let doc = perch_ir::from_json(doc_json).expect("the document parses");
    perch_ir::validate(&doc).expect("the document is valid");
    perch_ir::doc_hash_hex(&doc)
}

fn entry<'a>(out: &'a ComposeOutput, name: &str) -> &'a RuleEntry {
    out.apply
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no rule {name}"))
}

fn stored(env: &Env, entry: &RuleEntry) -> StoredRule {
    let scval = ScVal::from_xdr_base64(&entry.rule.scval_base64, Limits::none()).unwrap();
    let xdr = Bytes::from_slice(env, &WriteXdr::to_xdr(&scval, Limits::none()).unwrap());
    StoredRule::from_xdr(env, &xdr).unwrap()
}

#[test]
fn each_is_the_applied_document_plus_ci_publish_verifiers() {
    for author in &AUTHORS {
        let json = read(author);
        assert_eq!(hash(&json), author.reviewed, "{}", author.file);

        let mut doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let rules = doc["rules"].as_array_mut().unwrap();
        let names: Vec<&str> = rules.iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(
            names,
            [
                "admin",
                "ci-publish",
                "admin-registry",
                "ci-publish-verifiers"
            ],
            "{}",
            author.file
        );
        rules.retain(|r| r["name"] != "ci-publish-verifiers");
        assert_eq!(
            hash(&doc.to_string()),
            author.applied,
            "{} without ci-publish-verifiers is the document the account applied",
            author.file
        );
    }
}

#[test]
fn ci_publish_verifiers_is_ci_publish_on_perch_verifiers_with_publish_hash_alone() {
    for author in &AUTHORS {
        let env = Env::default();
        let out = compose(&env, &read(author), author.account).unwrap();
        let ci = entry(&out, "ci-publish");
        let rule = entry(&out, "ci-publish-verifiers");

        assert_eq!(ci.context_type.call_contract, author.registry);
        assert_eq!(rule.context_type.call_contract, author.verifiers);
        assert!(
            ci.valid_until.is_some(),
            "{}: ci-publish expires",
            author.file
        );
        assert_eq!(rule.valid_until, ci.valid_until, "{}", author.file);
        assert_eq!(
            serde_json::to_value(&rule.signers).unwrap(),
            serde_json::to_value(&ci.signers).unwrap(),
            "{}: the same delegate",
            author.file
        );

        // Everything the account decides with is ci-publish's (signers,
        // threshold, the is-self author, expiry) but the contract and the
        // functions.
        let ci_rule = stored(&env, ci);
        let mut expected = ci_rule.clone();
        expected.0 = Address::from_str(&env, author.verifiers);
        expected.1 =
            StoredFunctions::Only(soroban_sdk::vec![&env, Symbol::new(&env, "publish_hash")]);
        assert_eq!(stored(&env, rule), expected, "{}", author.file);
        assert_eq!(
            ci_rule.1,
            StoredFunctions::Only(soroban_sdk::vec![
                &env,
                Symbol::new(&env, "publish"),
                Symbol::new(&env, "publish_hash")
            ]),
            "{}: ci-publish's own functions",
            author.file
        );
    }
}
