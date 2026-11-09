//! SMT-prover checks: curated docs with known answers, the flagship
//! CI-publish intent proof over the real testdata fixture, and the
//! encoding's agreement with `rule_eval::rule_allows` on concrete
//! invocations.
//!
//! Requires `z3` on PATH; skips (loudly) when absent so local dev without z3
//! stays unblocked. CI installs z3, so these always run there.

use perch_analyze::{
    can_call, dead_rules, lowered, narrows, only_calls, run_z3, z3_available, Encoder,
    WideningFinding, Z3Verdict,
};
use perch_ir::PolicyDoc;

fn fixture(name: &str) -> PolicyDoc {
    let path = format!("{}/../../testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture readable");
    let doc = perch_ir::from_json(&text).expect("fixture parses");
    perch_ir::validate(&doc).expect("fixture valid");
    doc
}

fn doc(json: &str) -> PolicyDoc {
    let doc = perch_ir::from_json(json).expect("test doc parses");
    perch_ir::validate(&doc).expect("test doc valid");
    doc
}

const REGISTRY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
const VERIFIER: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";

fn skip() -> bool {
    if z3_available() {
        false
    } else {
        eprintln!("SKIPPED: z3 not on PATH");
        true
    }
}

/// The flagship proof: the shipped ci-publish policy can only ever authorize
/// publish/publish_hash on its registry scope.
#[test]
fn ci_publish_fixture_only_calls_publish() {
    if skip() {
        return;
    }
    let doc = fixture("ci-publish.json");
    // Find the contract scope the fixture publishes to.
    let contract = doc
        .rules
        .iter()
        .find_map(|r| match &r.scope {
            perch_ir::Scope::Contract(c) => Some(c.address.clone()),
            perch_ir::Scope::SelfAdmin(_) => None,
        })
        .expect("fixture has a contract-scoped rule");

    assert!(
        only_calls(&doc, &contract, &["publish".into(), "publish_hash".into()]).is_empty(),
        "the ci-publish policy must be provably restricted to publish/publish_hash"
    );
    // And the restriction is tight: allowing only `publish` is refuted with a
    // publish_hash witness.
    let violations = only_calls(&doc, &contract, &["publish".into()]);
    assert!(
        !violations.is_empty(),
        "publish_hash should escape a publish-only allowlist"
    );
    assert!(matches!(violations[0].verdict, Z3Verdict::Sat(_)));

    // Every rule in the shipped fixture is live.
    for r in dead_rules(&doc) {
        assert!(
            matches!(r.verdict, Z3Verdict::Sat(_)),
            "rule `{}` unexpectedly dead/undecided",
            r.rule
        );
    }

    // can-call agrees in both directions.
    assert!(can_call(&doc, "publish")
        .iter()
        .any(|r| matches!(r.verdict, Z3Verdict::Sat(_))));
    assert!(can_call(&doc, "steal_funds")
        .iter()
        .all(|r| matches!(r.verdict, Z3Verdict::Unsat)));
}

/// A rule whose only string-in candidates are over-long can never authorize:
/// the lowering drops a candidate over 256 bytes, which never matches an
/// argument on chain, so the rule's condition has none left.
#[test]
fn overlong_string_in_rule_is_provably_dead() {
    if skip() {
        return;
    }
    let long = "x".repeat(300);
    let json = format!(
        r#"{{
          "version": 1,
          "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
          "rules": [{{
            "name": "dead",
            "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
            "principals": {{ "type": "all", "signers": ["ci"] }},
            "args": [{{ "index": 0, "pred": {{ "type": "string-in", "values": ["{long}"] }} }}]
          }}]
        }}"#
    );
    let d = doc(&json);
    let liveness = dead_rules(&d);
    assert!(
        matches!(liveness[0].verdict, Z3Verdict::Unsat),
        "over-long-candidates rule must be provably dead, got {:?}",
        liveness[0].verdict
    );
    assert!(
        matches!(&lowered(&d)[0].rule.conds[..], [rule_eval::Cond::ArgIn(0, vs)] if vs.is_empty()),
        "the stored rule's condition has no candidate"
    );
}

/// A `string-prefix` rule authorizes an argument of any length that starts
/// with the prefix (on-chain reads only the first prefix-length bytes), while
/// a `string-in` rule never authorizes an argument over the on-chain cap.
#[test]
fn string_prefix_rule_authorizes_an_argument_of_any_length() {
    if skip() {
        return;
    }
    let rule_with = |pred: &str| {
        doc(&format!(
            r#"{{
              "version": 1,
              "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
              "rules": [{{
                "name": "r",
                "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
                "principals": {{ "type": "all", "signers": ["ci"] }},
                "args": [{{ "index": 0, "pred": {pred} }}]
              }}]
            }}"#
        ))
    };
    // A concrete argument well over the cap that starts with the prefix.
    let long_arg = format!("perch:{}", "a".repeat(300));
    let allows_long_arg = |d: &PolicyDoc| {
        let mut enc = Encoder::new();
        let allow = enc.rule_allows(&lowered(d)[0].rule);
        run_z3(&format!(
            "{}(assert {allow})\n(assert (= arg0_str \"{long_arg}\"))\n(check-sat)\n",
            enc.declarations()
        ))
    };
    let prefix = rule_with(r#"{ "type": "string-prefix", "prefix": "perch:" }"#);
    assert!(
        matches!(allows_long_arg(&prefix), Z3Verdict::Sat(_)),
        "a string-prefix rule must authorize a long argument with the prefix"
    );
    let set = rule_with(r#"{ "type": "string-in", "values": ["perch:"] }"#);
    assert!(
        matches!(allows_long_arg(&set), Z3Verdict::Unsat),
        "a string-in rule must never authorize an over-long argument"
    );
}

/// Narrowing: function-subset narrows; adding a function, loosening an arg
/// bound, or extending expiry all widen. The arg-bound case is invisible to
/// a `(scope, function-set)` comparison.
#[test]
fn narrows_catches_semantic_widening() {
    if skip() {
        return;
    }
    let parent = doc(&format!(
        r#"{{
          "version": 1,
          "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
          "rules": [{{
            "name": "ci",
            "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
            "principals": {{ "type": "all", "signers": ["ci"] }},
            "functions": ["publish", "publish_hash"],
            "args": [{{ "index": 0, "pred": {{ "type": "u32-eq", "value": 7 }} }}],
            "not-after-ledger": 1000
          }}]
        }}"#
    ));

    // Strict narrowing: fewer functions, same everything else, earlier expiry.
    let narrower = doc(&format!(
        r#"{{
          "version": 1,
          "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
          "rules": [{{
            "name": "ci",
            "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
            "principals": {{ "type": "all", "signers": ["ci"] }},
            "functions": ["publish"],
            "args": [{{ "index": 0, "pred": {{ "type": "u32-eq", "value": 7 }} }}],
            "not-after-ledger": 500
          }}]
        }}"#
    ));
    assert!(
        narrows(&parent, &narrower).is_empty(),
        "function-subset + earlier expiry must be a proved narrowing"
    );

    // Arg-level widening: the child DROPS the arg constraint. The coarse
    // (scope, function-set) check cannot see this; the SMT check must.
    let arg_widened = doc(&format!(
        r#"{{
          "version": 1,
          "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
          "rules": [{{
            "name": "ci",
            "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
            "principals": {{ "type": "all", "signers": ["ci"] }},
            "functions": ["publish"],
            "not-after-ledger": 1000
          }}]
        }}"#
    ));
    let findings = narrows(&parent, &arg_widened);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, perch_analyze::WideningFinding::SemanticWidening { .. })),
        "dropping an arg bound must be a semantic widening, got {findings:?}"
    );

    // Expiry extension.
    let expiry_widened = doc(&format!(
        r#"{{
          "version": 1,
          "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
          "rules": [{{
            "name": "ci",
            "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
            "principals": {{ "type": "all", "signers": ["ci"] }},
            "functions": ["publish"],
            "args": [{{ "index": 0, "pred": {{ "type": "u32-eq", "value": 7 }} }}],
            "not-after-ledger": 2000
          }}]
        }}"#
    ));
    assert!(narrows(&parent, &expiry_widened)
        .iter()
        .any(|f| matches!(f, perch_analyze::WideningFinding::ExpiryExtended { .. })));
}

/// A capped rule allows only what the account's rule for it allows: a
/// `transfer` whose argument 2 is an `i128`, whatever else its document
/// lists.
#[test]
fn a_capped_rule_allows_only_a_metered_transfer() {
    if skip() {
        return;
    }
    let capped = |functions: &str| {
        doc(&format!(
            r#"{{
              "version": 1,
              "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "0102" }}],
              "rules": [{{
                "name": "spend",
                "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
                "principals": {{ "type": "all", "signers": ["ci"] }},
                {functions}
                "cap": {{ "token": "{REGISTRY}", "limit": "100", "period-ledgers": 10 }}
              }}]
            }}"#
        ))
    };
    let d = capped(r#""functions": ["transfer", "approve"],"#);
    assert!(only_calls(&d, REGISTRY, &["transfer".into()]).is_empty());
    let mut enc = Encoder::new();
    let allow = enc.rule_allows(&lowered(&d)[0].rule);
    assert!(
        matches!(
            run_z3(&format!(
                "{}(assert {allow})\n(assert (not (= arg2_type 3)))\n(check-sat)\n",
                enc.declarations()
            )),
            Z3Verdict::Unsat
        ),
        "a capped transfer's argument 2 is an i128"
    );
    // A capped rule whose functions do not cover `transfer` allows nothing.
    let d = capped(r#""functions": ["approve"],"#);
    assert!(matches!(dead_rules(&d)[0].verdict, Z3Verdict::Unsat));
}

/// A child rule whose signer is another key widens its parent, even at the
/// same threshold: the child's signer authorizes what the parent's refuses.
#[test]
fn narrows_catches_a_changed_signer() {
    if skip() {
        return;
    }
    let with_key = |key: &str| {
        doc(&format!(
            r#"{{
              "version": 1,
              "signers": [{{ "id": "ci", "verifier": "{VERIFIER}", "key": "{key}" }}],
              "rules": [{{
                "name": "ci",
                "scope": {{ "type": "contract", "address": "{REGISTRY}" }},
                "principals": {{ "type": "all", "signers": ["ci"] }},
                "functions": ["publish"]
              }}]
            }}"#
        ))
    };
    assert!(narrows(&with_key("0102"), &with_key("0102")).is_empty());
    assert!(narrows(&with_key("0102"), &with_key("0304"))
        .iter()
        .any(|f| matches!(f, WideningFinding::SemanticWidening { .. })));
}

#[test]
fn exact_roots_are_conjunctive_and_cannot_be_erased_by_narrowing() {
    if skip() {
        return;
    }
    let exact = fixture("auth-root.json");
    let i = exact
        .rules
        .iter()
        .position(|r| r.auth_root.is_some())
        .unwrap();
    let mut unrestricted = exact.clone();
    unrestricted.rules[i].auth_root = None;
    assert!(narrows(&unrestricted, &exact).is_empty());
    assert!(narrows(&exact, &exact).is_empty());
    for change in [0, 1, 2] {
        let mut child = exact.clone();
        match change {
            0 => child.rules[i].auth_root = None,
            1 => child.rules[i].auth_root.as_mut().unwrap().function = "other".into(),
            _ => child.rules[i].auth_root.as_mut().unwrap().contract = REGISTRY.into(),
        }
        assert!(narrows(&exact, &child)
            .iter()
            .any(|f| matches!(f, WideningFinding::AuthRootChanged { .. })));
    }
    let rule = &lowered(&exact)[i].rule;
    for (root_call, function, accepted) in [
        (true, "guess", true),
        (true, "transfer", false),
        (false, "guess", false),
    ] {
        let mut enc = Encoder::new();
        let predicate = enc.rule_allows_in(rule);
        let script = format!("{}(assert {predicate})\n(assert (= root_call {root_call}))\n(assert (= root_fn \"{function}\"))\n(check-sat)\n", enc.declarations());
        assert_eq!(matches!(run_z3(&script), Z3Verdict::Sat(_)), accepted);
    }
}
