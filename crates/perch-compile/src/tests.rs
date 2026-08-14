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
