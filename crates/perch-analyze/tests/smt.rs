//! SMT-prover checks: curated docs with known answers, the flagship
//! CI-publish intent proof over the real testdata fixture, and directional
//! agreement with the coarse op-level analyzer (`can_ever_authorize`).
//!
//! Requires `z3` on PATH; skips (loudly) when absent so local dev without z3
//! stays unblocked. CI installs z3, so these always run there.

use perch_analyze::{can_call, dead_rules, narrows, only_calls, z3_available, Z3Verdict};
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
/// provably dead here, invisible to the coarse op-shape analyzer.
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

    // Directional agreement with the coarse analyzer: it reads op shapes only,
    // so it must NOT claim liveness the SMT layer refutes... it may (and does)
    // over-approximate to "not provably dead" — assert only the sound
    // direction: if the coarse analyzer says dead, SMT agrees. (Here coarse
    // says live, SMT proves dead: the SMT layer is strictly sharper.)
    let env = soroban_sdk::Env::default();
    let cfg = perch_compile::CompileConfig {
        interpreter_wasm_hash: soroban_sdk::BytesN::from_array(&env, &[7u8; 32]),
    };
    let plan = perch_compile::compile(&env, &d, &cfg).expect("compiles");
    let install = plan.rules[0]
        .install
        .as_ref()
        .expect("interpreter attached");
    // Coarse analyzer: over-approximates to live; SMT proves dead.
    assert!(perch_compile::can_ever_authorize(&install.program));
}

/// Narrowing: function-subset narrows; adding a function, loosening an arg
/// bound, extending expiry, or dropping a cap all widen. The arg-bound case
/// is invisible to `perch_compile::attenuation::is_narrowing`.
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
