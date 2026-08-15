use super::*;
use perch_program::{rpn, EvalInputs, Verdict};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, IntoVal, Symbol};
use std::fs;
use std::path::PathBuf;

const REGISTRY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

fn fixture() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/ci-publish.json");
    fs::read_to_string(p).expect("read ci-publish.json")
}

fn cfg(env: &Env) -> CompileConfig {
    CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(env, &[0xABu8; 32]),
    }
}

#[test]
fn ci_publish_lowers_to_the_expected_plan() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    perch_ir::validate(&doc).expect("valid");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");

    assert_eq!(plan.rules.len(), 2);

    // admin-root: constraint-free self-admin → policy-free (INV-2).
    let admin = &plan.rules[0];
    assert_eq!(admin.name, "admin-root");
    assert_eq!(admin.scope, ScopeSpec::SelfAdmin);
    assert_eq!(admin.signers.len(), 1);
    assert!(
        admin.install.is_none(),
        "constraint-free rule must lower policy-free"
    );

    // ci-publish: contract-scoped, interpreter-attached, expiry as valid_until.
    let ci = &plan.rules[1];
    assert_eq!(ci.name, "ci-publish");
    assert_eq!(ci.scope, ScopeSpec::Contract(REGISTRY.to_string()));
    // not-after-ledger 55_000_000 ("dead at or after 55_000_000") lowers to the
    // inclusive OZ valid_until one below it.
    assert_eq!(ci.valid_until, Some(54_999_999));
    let install = ci
        .install
        .as_ref()
        .expect("ci-publish attaches the interpreter");
    assert_eq!(
        install.doc_hash,
        BytesN::from_array(&env, &perch_ir::doc_hash(&doc))
    );

    // Program shape: MinSigners(1), FnIn[publish, publish_hash], ArgAddrIsSelf(1), All(3).
    let ops = &install.program.ops;
    assert_eq!(ops.len(), 4);
    assert_eq!(ops.get(0).unwrap(), Op::MinSigners(1));
    assert_eq!(ops.get(2).unwrap(), Op::ArgAddrIsSelf(1));
    assert_eq!(ops.get(3).unwrap(), Op::All(3));

    // Interpreter hash pinned because a rule attaches it.
    assert_eq!(
        plan.interpreter_wasm_hash,
        Some(BytesN::from_array(&env, &[0xABu8; 32]))
    );
}

#[test]
fn inv1_lowered_program_denies_zero_signature() {
    // The compiled ci-publish program must authorize with a signature and deny
    // with none — the signer-sufficiency invariant, checked on the real program.
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let program = &plan.rules[1].install.as_ref().unwrap().program;

    let self_addr = Address::generate(&env);
    let target = Address::generate(&env);
    // ci-publish(arg0, arg1=self); fn = publish_hash.
    let ctx = Context::Contract(ContractContext {
        contract: target,
        fn_name: Symbol::new(&env, "publish_hash"),
        args: vec![&env, 0u32.into_val(&env), self_addr.into_val(&env)],
    });

    let allow = rpn::eval(
        &env,
        program,
        &EvalInputs {
            context: &ctx,
            signer_count: 1,
            self_addr: &self_addr,
        },
    );
    assert_eq!(allow, Verdict::True, "one signature authorizes");

    let deny = rpn::eval(
        &env,
        program,
        &EvalInputs {
            context: &ctx,
            signer_count: 0,
            self_addr: &self_addr,
        },
    );
    assert!(!deny.allows(), "zero signatures must be denied (INV-1)");
}

#[test]
fn self_authenticating_is_a_typed_error() {
    let env = Env::default();
    let mut doc = perch_ir::from_json(&fixture()).expect("parse");
    // Rewrite ci-publish's principals to self-authenticating.
    doc.rules[1].principals =
        perch_ir::Principals::SelfAuthenticating(perch_ir::SelfAuthenticatingPrincipals {
            policy: REGISTRY.to_string(),
            install_param_hex: String::new(),
            ack: perch_ir::ACK_SENTINEL.to_string(),
        });
    match compile(&env, &doc, &cfg(&env)) {
        Err(LowerError::Unsupported { rule, .. }) => assert_eq!(rule, "ci-publish"),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn unknown_signer_ref_is_a_typed_error() {
    let env = Env::default();
    let mut doc = perch_ir::from_json(&fixture()).expect("parse");
    if let perch_ir::Principals::All(all) = &mut doc.rules[1].principals {
        all.signers = vec_std(&["ghost"]);
    }
    match compile(&env, &doc, &cfg(&env)) {
        Err(LowerError::UnknownSignerRef { id, .. }) => assert_eq!(id, "ghost"),
        other => panic!("expected UnknownSignerRef, got {other:?}"),
    }
}

fn vec_std(ids: &[&str]) -> Vec<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[test]
fn expiry_lowers_to_the_inclusive_boundary_minus_one() {
    // "dead at or after X" (perch-ir) must lower to OZ valid_until = X-1, since
    // OZ keeps a rule valid at sequence == valid_until. Fail-closed on the
    // boundary rather than granting one extra ledger.
    let env = Env::default();
    let mut doc = perch_ir::from_json(&fixture()).expect("parse");
    doc.rules[1].not_after_ledger = Some(1);
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    assert_eq!(plan.rules[1].valid_until, Some(0));

    doc.rules[0].not_after_ledger = None;
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    assert_eq!(plan.rules[0].valid_until, None, "no expiry stays no expiry");
}

// --- static analysis (#19 PR4) ---------------------------------------------

fn syms(env: &Env, names: &[&str]) -> Vec<Symbol> {
    names.iter().map(|n| Symbol::new(env, n)).collect()
}

#[test]
fn reachable_calls_reports_scope_and_functions() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let reach = reachable_calls(&plan);
    assert_eq!(reach.len(), 2);

    // admin-root: policy-free self-admin → any function (INV-2).
    assert_eq!(reach[0].rule, "admin-root");
    assert_eq!(reach[0].scope, ScopeSpec::SelfAdmin);
    assert_eq!(reach[0].functions, FnSet::Any);

    // ci-publish: registry-scoped, restricted to exactly publish/publish_hash.
    assert_eq!(reach[1].rule, "ci-publish");
    assert_eq!(reach[1].scope, ScopeSpec::Contract(REGISTRY.to_string()));
    assert_eq!(
        reach[1].functions,
        FnSet::Only(syms(&env, &["publish", "publish_hash"]))
    );
}

#[test]
fn program_bounds_are_derivable_from_ops() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let program = &plan.rules[1].install.as_ref().unwrap().program;
    let b = program_bounds(program);
    // MinSigners, FnIn, ArgAddrIsSelf, All(3).
    assert_eq!(b.ops, 4);
    assert_eq!(b.max_stack_depth, 3);
    assert!(b.fits(perch_program::MAX_PROGRAM_LEN));
    assert!(!b.fits(3));
}

#[test]
fn can_ever_authorize_flags_live_and_dead_programs() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let live = &plan.rules[1].install.as_ref().unwrap().program;
    assert!(can_ever_authorize(live), "ci-publish can authorize");

    // A leaf that is always False (ledger < 0 is impossible) is dead.
    let dead = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&env, Op::LedgerBefore(0)],
    };
    assert!(!can_ever_authorize(&dead));

    // Not of an always-true structural leaf can never be True.
    let dead2 = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&env, Op::MinSigners(0), Op::Not],
    };
    assert!(!can_ever_authorize(&dead2));

    // Sanity: MinSigners(0) alone is live.
    let live2 = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&env, Op::MinSigners(0)],
    };
    assert!(can_ever_authorize(&live2));
}

// --- fail-closed activation (#19 PR5) --------------------------------------

#[test]
fn verify_plan_accepts_a_freshly_compiled_plan() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    assert_eq!(verify_plan_matches_doc(&env, &doc, &plan), Ok(()));
}

#[test]
fn verify_plan_rejects_a_tampered_doc_hash() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let mut plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    // Tamper the ci-publish attachment's doc_hash → activation must refuse.
    let install = plan.rules[1].install.as_mut().expect("ci-publish attaches");
    install.doc_hash = BytesN::from_array(&env, &[0u8; 32]);
    assert_eq!(
        verify_plan_matches_doc(&env, &doc, &plan),
        Err(ActivationError::DocHashMismatch {
            rule: "ci-publish".to_string()
        })
    );
}

#[test]
fn verify_plan_rejects_a_plan_from_a_different_doc() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    // Same plan, but checked against a document whose canonical form differs
    // (renamed rule → different doc_hash) → refuse.
    let mut other = doc.clone();
    other.rules[1].name = "ci-publish-v2".to_string();
    assert!(matches!(
        verify_plan_matches_doc(&env, &other, &plan),
        Err(ActivationError::DocHashMismatch { .. })
    ));
}

// --- cumulative-cap lowering (#19 PR6) -------------------------------------

#[test]
fn cap_lowers_to_a_spending_limit_spec_beside_the_interpreter() {
    let env = Env::default();
    let mut doc = perch_ir::from_json(&fixture()).expect("parse");
    doc.rules[1].cap = Some(perch_ir::CapConstraint {
        token: Some(REGISTRY.to_string()),
        limit: "10000000".to_string(),
        period_ledgers: 17_280,
    });
    perch_ir::validate(&doc).expect("valid");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let ci = &plan.rules[1];
    // Interpreter still attached (per-call constraints) AND the cap spec present.
    assert!(
        ci.install.is_some(),
        "capped rule keeps the interpreter (INV-1)"
    );
    assert_eq!(
        ci.cap,
        Some(CapSpec {
            token: Some(REGISTRY.to_string()),
            limit: 10_000_000,
            period_ledgers: 17_280,
        })
    );
}

#[test]
fn cap_forces_the_interpreter_even_when_otherwise_constraint_free() {
    // A rule with no functions/args but a cap must still attach the interpreter
    // so INV-1's MinSigners(n) floor holds — spending_limit's single-signer
    // floor is not a substitute for the full referenced signer set.
    let env = Env::default();
    let mut doc = perch_ir::from_json(&fixture()).expect("parse");
    doc.rules[1].functions = None;
    doc.rules[1].args = None;
    doc.rules[1].cap = Some(perch_ir::CapConstraint {
        token: None, // denominate in the scope contract
        limit: "5".to_string(),
        period_ledgers: 100,
    });
    perch_ir::validate(&doc).expect("valid");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    let ci = &plan.rules[1];
    assert!(ci.install.is_some(), "cap forces interpreter (INV-1)");
    assert_eq!(ci.cap.as_ref().unwrap().token, None);
    // The interpreter program is the bare signer floor: [MinSigners(1), All(1)].
    let program = &ci.install.as_ref().unwrap().program;
    assert_eq!(program.ops.len(), 2);
    assert_eq!(program.ops.get(0).unwrap(), Op::MinSigners(1));
}

#[test]
fn a_document_without_a_cap_lowers_cap_free() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let plan = compile(&env, &doc, &cfg(&env)).expect("compile");
    assert!(plan.rules.iter().all(|r| r.cap.is_none()));
}

// --- monotone attenuation (#19 PR8) ----------------------------------------

/// The ci-publish functions on rule 1, mutated in place.
fn set_ci_functions(doc: &mut perch_ir::PolicyDoc, functions: Option<&[&str]>) {
    doc.rules[1].functions = functions.map(|f| f.iter().map(|s| s.to_string()).collect());
}

#[test]
fn narrowing_the_function_set_is_accepted_and_links_the_hashes() {
    let env = Env::default();
    let parent = perch_ir::from_json(&fixture()).expect("parse");
    // Child: ci may only `publish`, not `publish_hash`.
    let mut child = parent.clone();
    set_ci_functions(&mut child, Some(&["publish"]));

    let link = attenuate(&env, &parent, &child, &cfg(&env)).expect("child narrows parent");
    assert_eq!(
        link.parent_hash,
        BytesN::from_array(&env, &perch_ir::doc_hash(&parent))
    );
    assert_eq!(
        link.child_hash,
        BytesN::from_array(&env, &perch_ir::doc_hash(&child))
    );
    assert_ne!(
        link.parent_hash, link.child_hash,
        "a narrowing is a new doc"
    );
}

#[test]
fn dropping_a_rule_is_a_narrowing() {
    let env = Env::default();
    let parent = perch_ir::from_json(&fixture()).expect("parse");
    // Child keeps only admin-root (drops the ci-publish authority entirely).
    let mut child = parent.clone();
    child.rules.remove(1);
    assert!(attenuate(&env, &parent, &child, &cfg(&env)).is_ok());
}

#[test]
fn widening_the_function_set_is_rejected() {
    let env = Env::default();
    let parent = perch_ir::from_json(&fixture()).expect("parse");
    // Child adds a function the parent never authorized.
    let mut child = parent.clone();
    set_ci_functions(&mut child, Some(&["publish", "publish_hash", "set_admin"]));
    assert_eq!(
        attenuate(&env, &parent, &child, &cfg(&env)),
        Err(AttenuationError::NotANarrowing {
            rule: "ci-publish".to_string()
        })
    );
}

#[test]
fn widening_a_specific_set_back_to_any_is_rejected() {
    let env = Env::default();
    let parent = perch_ir::from_json(&fixture()).expect("parse");
    // Child removes every per-call constraint on ci-publish → any function
    // (broader than the parent's publish/publish_hash allowlist).
    let mut child = parent.clone();
    set_ci_functions(&mut child, None);
    child.rules[1].args = None;
    assert_eq!(
        attenuate(&env, &parent, &child, &cfg(&env)),
        Err(AttenuationError::NotANarrowing {
            rule: "ci-publish".to_string()
        })
    );
}

#[test]
fn adding_a_new_scope_is_rejected() {
    let env = Env::default();
    let parent = perch_ir::from_json(&fixture()).expect("parse");
    // Child scopes ci-publish to a different contract the parent never allowed.
    let mut child = parent.clone();
    child.rules[1].scope =
        perch_ir::Scope::contract("CAPS4YALJ6I4D3NDMRG5JZGDAAT266PSPLSHIITGUKBXUVAH5SUPZQKE");
    assert_eq!(
        attenuate(&env, &parent, &child, &cfg(&env)),
        Err(AttenuationError::NotANarrowing {
            rule: "ci-publish".to_string()
        })
    );
}

#[test]
fn a_document_narrows_itself() {
    let env = Env::default();
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    let link = attenuate(&env, &doc, &doc, &cfg(&env)).expect("identity is a narrowing");
    assert_eq!(link.parent_hash, link.child_hash);
}
