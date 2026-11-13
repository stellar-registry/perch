//! `perch-rule-eval` against Perch's own lowering, structurally: for every
//! document `d`,
//!
//! `rule_eval::lower(doc_of(model_of(d)), me)` equals the denotation
//! (`perch_testkit::denote`) of each rule the doc compiler's real
//! `compile_doc` returns for `d`, installed on `me` with the interpreter
//! program and spending cap Perch's RPN lowering (`perch_compile::compile`)
//! gives it, then rule-eval's recovery rule when `d` configures recovery.
//!
//! The left side is the path an account takes to rule-eval's rules: the
//! document model and its conversion through `soroban-facade`, then rule-eval's
//! proven lowering. The right side reads what the compiler emits and the RPN
//! lowering attaches, as those policies enforce it: the context rule, the
//! interpreter's program and the spending limit's parameters. The compiler's
//! rules must also equal the RPN lowering's (`perch_testkit::rpn::
//! check_compiled`), and each model survives the host's XDR.
//!
//! The documents:
//!
//! - every account document of rule-core's document traces at the rev the
//!   workspace pins: each admin trace's document and each scoped trace's
//!   account document, renamed onto real addresses. For an admin trace the
//!   lowering must also equal the trace's own, which rule-core's Lean model
//!   computed;
//! - the 500 documents of `tests/corpus/rule-eval-baseline.json`, drawn by
//!   that file's seeded generator, which covers every argument predicate;
//! - documents from `perch_testkit::delta::DocModel`, the generator the
//!   `apply_doc` suites use, which reaches the compiler's document caps,
//!   recovery, and the alternative spellings of keys and cap limits.

use std::collections::BTreeMap;

use arbitrary::Unstructured;
use perch_doc_compiler::{CompiledRule, DocCompilerClient, RuleScope};
use perch_ir::{
    AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, CapConstraint, GuardianSet, IsSelfPred,
    PolicyDoc, Principals, RecoveryConfig, RecoveryMode, RecoveryProfile, Rule, Scope, SignerDecl,
    SignerMethod, StringInPred, StringPrefixPred, ThresholdPrincipals, U32EqPred, ZkFactor,
};
use perch_recovery_interface::config::CompiledRecoveryMode;
use perch_rule_eval::convert::address;
use perch_rule_eval::{doc_of, model_of, CompiledModel};
use perch_smart_account::infra;
use perch_testkit::delta::{strkey, DeltaWorld, DocModel};
use perch_testkit::denote::{denote, Installed};
use perch_testkit::rpn::{self, Policies};
use perch_testkit::{verifiers, AnyKeyVerifier, FIXTURE_NETWORK};
use rule_eval::{Cond, Rule as ERule, Signer as ESigner, Val as EVal};
use rule_eval_conformance::documents::{
    self, JsonDoc, JsonPred, JsonPrincipals, JsonScope, Lowered, Trace,
};
use rule_eval_conformance::{decode_hex, decode_rules, rules_eq, JsonSigner};
use serde_json::Value as J;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::{FromXdr, ToXdr};
use soroban_sdk::{Address, Bytes};

const BASELINE: &str = "tests/corpus/rule-eval-baseline.json";
/// How many `DocModel` documents to draw; `PERCH_RULE_EVAL_DOCS` sets more.
const GENERATED: usize = 256;

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

/// `r`, installed on `me` as the account's `document_rule` installs it,
/// with the policies `p` attached.
fn installed(me: &Address, r: &CompiledRule, p: &Policies) -> Installed {
    Installed {
        contract: match &r.scope {
            RuleScope::SelfAdmin => me.clone(),
            RuleScope::Contract(a) => a.clone(),
        },
        signers: r.signers.clone(),
        valid_until: r.valid_until,
        program: p.install.as_ref().map(|i| i.program.clone()),
        cap: p.cap.clone(),
    }
}

/// What one document's lowering held.
#[derive(Default)]
struct Shape {
    rules: usize,
    conds: usize,
    capped: usize,
    recovery: usize,
    zk: usize,
}

/// Checks `d` on the account `me`, and returns rule-eval's lowering of its
/// model.
fn check(
    w: &DeltaWorld,
    me: &Address,
    d: &PolicyDoc,
    shape: &mut Shape,
) -> Result<Vec<ERule>, String> {
    let e = &w.env;
    perch_ir::validate(d).map_err(|x| format!("perch_ir::validate refuses: {x:?}"))?;
    let compiler = DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e));
    let bytes = Bytes::from_slice(e, perch_ir::canonical_json(d).as_bytes());
    let compiled = compiler
        .try_compile_doc(&bytes)
        .map_err(|x| format!("compile_doc refuses: {x:?}"))?
        .map_err(|x| format!("compile_doc returns no CompiledDoc: {x:?}"))?;

    let model = model_of(e, d).map_err(|x| format!("model_of refuses: {x:?}"))?;
    if CompiledModel::from_xdr(e, &model.clone().to_xdr(e)).ok() != Some(model.clone()) {
        return Err("the model's XDR round trip changed it".into());
    }
    let me_x = address(e, me).expect("the account's XDR");
    let lowered = rule_eval::lower(&doc_of(e, &model).ok_or("doc_of refuses")?, &me_x);

    rpn::check_compiled(e, d, &compiled)?;
    let attached = rpn::batch_policies_of(e, d)?;
    let mut denoted = vec![];
    for (i, (r, p)) in compiled.rules.iter().zip(&attached).enumerate() {
        let mut rule =
            denote(e, me, &installed(me, &r, p)).ok_or(format!("denote refuses rule {i}"))?;
        rule.auth_root = rpn::root_of(e, &p.auth_root);
        denoted.push(rule);
    }
    let n = denoted.len();
    let recovery = !compiled.recovery.is_empty();
    if recovery != d.recovery.is_some() {
        return Err("the compiler and the document disagree on recovery".into());
    }
    // The lowering reads only whether there is recovery; the contracts the
    // model names are compared with the compiler's recovery configuration.
    let wanted = compiled.recovery.first().map(|r| {
        let zk = match r.mode {
            CompiledRecoveryMode::GuardianOnly(_) => None,
            CompiledRecoveryMode::ZkOnly(z) | CompiledRecoveryMode::Combined(_, z) => {
                Some((z.adapter, z.pool))
            }
        };
        (r.controller, zk)
    });
    let got = model.recovery.first().map(|r| {
        let zk = r.zk.first().map(|z| (z.adapter, z.pool));
        (r.controller, zk)
    });
    if got != wanted || model.recovery.len() > 1 {
        return Err(format!(
            "the model's recovery {got:?} is not the compiler's {wanted:?}"
        ));
    }
    if lowered.len() != n + usize::from(recovery) {
        return Err(format!(
            "rule-eval lowers {} rules, the compiler {n}{}",
            lowered.len(),
            if recovery { " and recovery" } else { "" }
        ));
    }
    if let Some(i) = (0..n).find(|&i| !rules_eq(&lowered[i..=i], &denoted[i..=i])) {
        return Err(format!(
            "rule {i}: rule-eval's lowering differs from Perch's"
        ));
    }
    if recovery && !rules_eq(&lowered[n..], &[rule_eval::recovery_rule(&me_x)]) {
        return Err("the recovery rule differs".into());
    }
    shape.rules += n;
    shape.conds += lowered.iter().map(|r| r.conds.len()).sum::<usize>();
    shape.capped += lowered.iter().filter(|r| r.cap.is_some()).count();
    shape.recovery += usize::from(recovery);
    shape.zk += usize::from(got.is_some_and(|(_, zk)| zk.is_some()));
    Ok(lowered)
}

// ---------------------------------------------------------------------------
// Trace documents, renamed onto real addresses
// ---------------------------------------------------------------------------

fn unhex(h: &str) -> Vec<u8> {
    decode_hex(h).expect("trace hex")
}

fn utf8(h: &str) -> Result<String, String> {
    String::from_utf8(unhex(h)).map_err(|x| format!("not utf-8: {x}"))
}

/// One trace's renaming: each abstract address onto a real one, injectively,
/// the account onto `me`. Keys keep their bytes, which `AnyKeyVerifier`
/// takes as they are.
struct Names<'w> {
    w: &'w DeltaWorld,
    addr: BTreeMap<Vec<u8>, Address>,
}

impl<'w> Names<'w> {
    /// The renaming for `d` on a trace whose account is `account`: each
    /// verifier `d` declares is an `AnyKeyVerifier` where `perch/verifiers`
    /// deploys one, named ([`verifiers::auto_name`]), as an account document's
    /// must be.
    fn new(w: &'w DeltaWorld, account: &str, d: &JsonDoc) -> Names<'w> {
        let mut addr = BTreeMap::from([(unhex(account), w.delta.clone())]);
        for s in &d.signers {
            if let JsonSigner::External { verifier, .. } = &s.signer {
                addr.entry(unhex(verifier))
                    .or_insert_with(|| verifiers::deploy_auto(&w.env, AnyKeyVerifier));
            }
        }
        Names { w, addr }
    }

    fn address(&mut self, abs: &[u8]) -> Address {
        let e = &self.w.env;
        self.addr
            .entry(abs.to_vec())
            .or_insert_with(|| Address::generate(e))
            .clone()
    }

    fn strkey(&mut self, h: &str) -> String {
        strkey(&self.address(&unhex(h)))
    }

    fn xdr(&mut self, abs: &[u8]) -> Vec<u8> {
        let a = self.address(abs);
        address(&self.w.env, &a).expect("an address's XDR")
    }

    /// `d` as a Perch document: signer ids `s<i>`, rule names `r<i>`, and,
    /// for recovery, the trace's controller (and ZK adapter and pool) with
    /// fixed values for what the trace does not carry.
    fn doc(&mut self, d: &JsonDoc) -> Result<PolicyDoc, String> {
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        let mut signers = vec![];
        for (i, s) in d.signers.iter().enumerate() {
            let id = format!("s{i}");
            ids.insert(s.id.clone(), id.clone());
            let method = match &s.signer {
                JsonSigner::Delegated { address } => SignerMethod::Delegated {
                    address: self.strkey(address),
                },
                JsonSigner::External { verifier, key } => {
                    let v = self.address(&unhex(verifier));
                    SignerMethod::External {
                        verifier: strkey(&v),
                        key: key.clone(),
                        verifier_name: Some(verifiers::auto_name(&v)),
                    }
                }
            };
            signers.push(SignerDecl { id, method });
        }
        let id_of = |x: &String| {
            ids.get(x)
                .cloned()
                .unwrap_or_else(|| format!("undeclared-{x}"))
        };
        let mut rules = vec![];
        for (i, r) in d.rules.iter().enumerate() {
            let args = match &r.args {
                None => None,
                Some(args) => Some(
                    args.iter()
                        .map(|a| {
                            Ok(ArgConstraint {
                                index: a.index,
                                pred: match &a.pred {
                                    JsonPred::IsSelf => ArgPred::IsSelf(IsSelfPred {}),
                                    JsonPred::AddressEq(h) => ArgPred::AddressEq(AddressEqPred {
                                        address: self.strkey(h),
                                    }),
                                    JsonPred::StringIn(vs) => ArgPred::StringIn(StringInPred {
                                        values: vs
                                            .iter()
                                            .map(|v| utf8(v))
                                            .collect::<Result<_, _>>()?,
                                    }),
                                    JsonPred::StringPrefix(p) => {
                                        ArgPred::StringPrefix(StringPrefixPred { prefix: utf8(p)? })
                                    }
                                    JsonPred::U32Eq(v) => ArgPred::U32Eq(U32EqPred { value: *v }),
                                },
                            })
                        })
                        .collect::<Result<_, String>>()?,
                ),
            };
            rules.push(Rule {
                name: format!("r{i}"),
                scope: match &r.scope {
                    JsonScope::SelfAdmin => Scope::self_admin(),
                    JsonScope::Contract(h) => Scope::contract(self.strkey(h)),
                },
                principals: match &r.principals {
                    JsonPrincipals::All(xs) => Principals::All(AllPrincipals {
                        signers: xs.iter().map(id_of).collect(),
                    }),
                    JsonPrincipals::Threshold { ids: xs, m } => {
                        Principals::Threshold(ThresholdPrincipals {
                            signers: xs.iter().map(id_of).collect(),
                            m: *m,
                        })
                    }
                },
                functions: match &r.functions {
                    None => None,
                    Some(fs) => Some(fs.iter().map(|f| utf8(f)).collect::<Result<_, _>>()?),
                },
                args,
                auth_root: r
                    .auth_root
                    .as_ref()
                    .map(|root| {
                        Ok::<_, String>(perch_ir::AuthRoot {
                            contract: self.strkey(&root.contract),
                            function: utf8(&root.function)?,
                        })
                    })
                    .transpose()?,
                not_after_ledger: r.not_after_ledger,
                cap: r.cap.as_ref().map(|c| CapConstraint {
                    token: None,
                    limit: c.limit.clone(),
                    period_ledgers: c.period_ledgers,
                }),
            });
        }
        let recovery = match &d.recovery {
            None => None,
            Some(r) => {
                let mode = match &r.zk {
                    None => RecoveryMode::GuardianOnly(GuardianSet {
                        guardians: (0..2)
                            .map(|_| strkey(&Address::generate(&self.w.env)))
                            .collect(),
                        quorum: 2,
                    }),
                    Some(z) => RecoveryMode::ZkOnly(ZkFactor {
                        adapter: self.strkey(&z.adapter),
                        circuit_id: "c1".repeat(32),
                        pool: self.strkey(&z.pool),
                        enrollment_id: "e2".repeat(32),
                        commitment: format!("{}01", "00".repeat(31)),
                    }),
                };
                Some(RecoveryConfig {
                    profile: RecoveryProfile::Loss,
                    mode,
                    controller: self.strkey(&r.controller),
                    baseline: None,
                    replaceable: vec!["s0".into()],
                    delay_ledgers: 10,
                    expiry_ledgers: 100,
                    max_cancels: 3,
                })
            }
        };
        Ok(PolicyDoc {
            version: 1,
            network: Some(FIXTURE_NETWORK.into()),
            signers,
            rules,
            recovery,
        })
    }

    /// The trace's rule `r` with every abstract address replaced by its
    /// renamed address's XDR.
    fn rule(&mut self, r: ERule) -> ERule {
        let mut val = |v: EVal| match v {
            EVal::Address(abs) => EVal::Address(self.xdr(&abs)),
            v => v,
        };
        let conds = r
            .conds
            .into_iter()
            .map(|c| match c {
                Cond::ArgEq(i, v) => Cond::ArgEq(i, val(v)),
                Cond::ArgIn(i, vs) => Cond::ArgIn(i, vs.into_iter().map(&mut val).collect()),
                c => c,
            })
            .collect();
        let signers = r
            .signers
            .into_iter()
            .map(|s| match s {
                ESigner::Delegated(a) => ESigner::Delegated(self.xdr(&a)),
                ESigner::External(v, k) => ESigner::External(self.xdr(&v), k),
            })
            .collect();
        ERule {
            contract: self.xdr(&r.contract),
            auth_root: r.auth_root.map(|root| rule_eval::AuthRoot {
                contract: self.xdr(&root.contract),
                function: root.function,
            }),
            conds,
            signers,
            ..r
        }
    }
}

/// Every account document a trace holds, with the lowering the trace states
/// for it when it states one.
fn trace_documents(t: &Trace) -> Vec<(&JsonDoc, Option<&Lowered>)> {
    match &t.scoped {
        None => vec![(&t.document, Some(&t.lowered))],
        Some(s) => vec![(&s.admin, None)],
    }
}

/// Checks every account document of `traces`; returns the failures.
fn check_traces(
    w: &DeltaWorld,
    traces: &[(String, Trace)],
    shape: &mut Shape,
) -> (usize, usize, Vec<String>) {
    let (mut documents, mut against_model, mut failures) = (0, 0, vec![]);
    for (name, t) in traces {
        for (d, lowered) in trace_documents(t) {
            documents += 1;
            let mut names = Names::new(w, &t.account, d);
            let outcome = names.doc(d).and_then(|doc| check(w, &w.delta, &doc, shape));
            match (outcome, lowered) {
                (Err(x), _) => failures.push(format!("{name}: {x}")),
                (Ok(got), Some(Lowered::Ok(want))) => {
                    against_model += 1;
                    let want: Vec<ERule> = decode_rules(want)
                        .expect("trace rules")
                        .into_iter()
                        .map(|r| names.rule(r))
                        .collect();
                    if !rules_eq(&got, &want) {
                        failures.push(format!("{name}: the lowering differs from the trace's"));
                    }
                }
                (Ok(_), Some(Lowered::Error(x))) => failures.push(format!(
                    "{name}: an admin trace whose lowering refuses: {x:?}"
                )),
                (Ok(_), None) => {}
            }
        }
    }
    (documents, against_model, failures)
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn every_rule_core_admin_document_lowers_as_perch_installs_it() {
    let w = DeltaWorld::new();
    let traces: Vec<(String, Trace)> =
        documents::load_dir(&rule_eval_conformance::vectors_dir().join("documents"))
            .unwrap_or_else(|x| panic!("{x}"))
            .into_iter()
            .map(|(_, t)| (t.name.clone(), t))
            .collect();
    let scoped = traces.iter().filter(|(_, t)| t.scoped.is_some()).count();
    let mut shape = Shape::default();
    let (documents, against_model, failures) = check_traces(&w, &traces, &mut shape);
    println!(
        "traces: {}, account documents: {documents} (with the trace's lowering: {against_model}), \
         rules: {}, conditions: {}, capped: {}, with recovery: {} (ZK: {}), differences: {}",
        traces.len(),
        shape.rules,
        shape.conds,
        shape.capped,
        shape.recovery,
        shape.zk,
        failures.len()
    );
    assert_eq!(documents, traces.len(), "one account document per trace");
    assert_eq!(against_model, traces.len() - scoped);
    assert!(shape.zk > 0 && shape.capped > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_baseline_document_lowers_as_perch_installs_it() {
    let w = DeltaWorld::new();
    let file: J = serde_json::from_str(&std::fs::read_to_string(BASELINE).expect("the baseline"))
        .expect("baseline json");
    let traces: Vec<(String, Trace)> = file["traces"]
        .as_array()
        .expect("traces")
        .iter()
        .map(|t| {
            let t: Trace = serde_json::from_value(t.clone()).expect("a trace");
            (t.name.clone(), t)
        })
        .collect();
    let mut shape = Shape::default();
    let (documents, against_model, failures) = check_traces(&w, &traces, &mut shape);
    println!(
        "baseline documents: {documents} (with the recorded lowering: {against_model}), rules: \
         {}, conditions: {}, capped: {}, differences: {}",
        shape.rules,
        shape.conds,
        shape.capped,
        failures.len()
    );
    assert_eq!(documents, 500);
    assert_eq!(against_model, 500);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// SplitMix64, for the generator's input bytes.
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[test]
fn every_generated_document_lowers_as_perch_installs_it() {
    let w = DeltaWorld::new();
    let n = std::env::var("PERCH_RULE_EVAL_DOCS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(GENERATED);
    let mut state = 20_261_103u64;
    let mut shape = Shape::default();
    let mut failures = vec![];
    for i in 0..n {
        let len = 64 + (splitmix(&mut state) % 2048) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| splitmix(&mut state) as u8).collect();
        let model = DocModel::generate(&mut Unstructured::new(&bytes)).expect("a document");
        let d = perch_ir::from_json(&model.json(&w)).expect("the generator's JSON parses");
        if let Err(x) = check(&w, &w.delta, &d, &mut shape) {
            failures.push(format!("document {i} ({model:?}): {x}"));
        }
    }
    println!(
        "generated documents: {n}, rules: {}, capped: {}, with recovery: {}, differences: {}",
        shape.rules,
        shape.capped,
        shape.recovery,
        failures.len()
    );
    assert!(shape.recovery > 0 && shape.capped > 0);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
