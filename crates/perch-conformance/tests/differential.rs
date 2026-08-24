//! Differential compile→eval testing (#PLAN phase 0): random *valid* policy
//! documents are lowered by the real `perch-compile`, and the resulting
//! program's verdict under the real `rpn::eval` is compared against an
//! **independent doc-level reference semantics** written directly from
//! `CANONICAL.md` / the `ArgPred` docs — it never looks at `Op` or the
//! compiler, so a lowering bug and a reference bug cannot cancel out.
//!
//! Also asserts the plan-shape invariants on every generated document:
//! INV-1 (an interpreter-attached rule denies zero-signature auth), INV-2
//! (constraint-free + cap-free rules lower policy-free), the
//! `not_after_ledger → valid_until = X-1` boundary, and that the on-chain
//! `doc_hash` (host sha256 over canonical bytes) equals the std-side
//! `perch_ir::doc_hash` (sha2 crate) — two hash paths, one identity.
//!
//! Randomness is fixed-seed splitmix64, per the security-core convention.

use perch_compile::{compile, CompileConfig};
use perch_ir::{
    validate, AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, CapConstraint, PolicyDoc,
    Principals, Rule, Scope, SignerDecl, SignerMethod, StringInPred, StringPrefixPred,
    ThresholdPrincipals, U32EqPred,
};
use perch_program::{rpn, EvalInputs, Verdict};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, BytesN, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec};

// Checksum-valid strkeys (shared with perch-golden / testdata fixtures).
const CONTRACT_C: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
const VERIFIER_A: &str = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
const VERIFIER_B: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
const DELEGATE_G: &str = "GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA";

// --- deterministic PRNG (splitmix64) -----------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n)) as u32
    }
    fn chance(&mut self, one_in: u32) -> bool {
        self.below(one_in) == 0
    }
}

// --- document generator (valid by construction, then validate()-checked) -----

const FN_NAMES: [&str; 4] = ["publish", "publish_hash", "transfer", "set_admin"];
const STRINGS: [&str; 4] = ["alpha", "beta", "release", "r"];

fn gen_arg_pred(rng: &mut Rng) -> ArgPred {
    match rng.below(5) {
        0 => ArgPred::is_self(),
        1 => ArgPred::AddressEq(AddressEqPred {
            address: (if rng.chance(2) {
                VERIFIER_A
            } else {
                VERIFIER_B
            })
            .into(),
        }),
        2 => ArgPred::U32Eq(U32EqPred {
            value: rng.below(3),
        }),
        3 => {
            let mut values: Vec<String> = Vec::new();
            for _ in 0..=rng.below(2) {
                values.push(STRINGS[rng.below(STRINGS.len() as u32) as usize].into());
            }
            if rng.chance(6) {
                values.push("x".repeat(257)); // over-long candidate: skipped at runtime
            }
            values.dedup();
            ArgPred::StringIn(StringInPred { values })
        }
        _ => ArgPred::StringPrefix(StringPrefixPred {
            // Occasionally an over-long prefix: valid per perch-ir (no length
            // limit), lowered verbatim, and must fail closed at eval time —
            // exercises the prefix-side str_bytes failure path in leaf.rs.
            prefix: if rng.chance(6) {
                "x".repeat(257)
            } else {
                STRINGS[rng.below(STRINGS.len() as u32) as usize].into()
            },
        }),
    }
}

fn gen_doc(rng: &mut Rng, doc_idx: u32) -> PolicyDoc {
    let all_signers = [
        SignerDecl {
            id: "admin".into(),
            method: SignerMethod::External {
                verifier: VERIFIER_A.into(),
                key: "0102".into(),
            },
        },
        SignerDecl {
            id: "ci".into(),
            method: SignerMethod::Delegated {
                address: DELEGATE_G.into(),
            },
        },
        SignerDecl {
            id: "backup".into(),
            method: SignerMethod::External {
                verifier: VERIFIER_B.into(),
                key: "aabbcc".into(),
            },
        },
    ];
    let n_signers = 1 + rng.below(3) as usize;
    let signers: Vec<SignerDecl> = all_signers[..n_signers].to_vec();

    let n_rules = 1 + rng.below(3);
    let mut rules = Vec::new();
    for r in 0..n_rules {
        let contract_scope = rng.below(4) != 0;
        let scope = if contract_scope {
            Scope::contract(CONTRACT_C)
        } else {
            Scope::self_admin()
        };

        // A non-empty subset of the declared signers.
        let take = 1 + rng.below(n_signers as u32) as usize;
        let principal_ids: Vec<String> = signers[..take].iter().map(|s| s.id.clone()).collect();

        // Roughly half the time make it an M-of-N quorum (m in 1..=N) rather
        // than N-of-N `all`, so the oracle exercises the threshold arithmetic
        // and the `MinSigners(m)` lowering, not just N-of-N.
        let principals = if rng.chance(2) {
            let m = 1 + rng.below(principal_ids.len() as u32);
            Principals::Threshold(ThresholdPrincipals {
                signers: principal_ids,
                m,
            })
        } else {
            Principals::All(AllPrincipals {
                signers: principal_ids,
            })
        };

        let functions = if rng.chance(3) {
            None
        } else {
            let mut fns: Vec<String> = Vec::new();
            for _ in 0..=rng.below(3) {
                fns.push(FN_NAMES[rng.below(FN_NAMES.len() as u32) as usize].into());
            }
            fns.sort();
            fns.dedup();
            Some(fns)
        };

        let args = if rng.chance(3) {
            None
        } else {
            let mut cs: Vec<ArgConstraint> = Vec::new();
            let n = 1 + rng.below(3);
            let mut used = [false; 6];
            for _ in 0..n {
                let idx = rng.below(6);
                if used[idx as usize] {
                    continue;
                }
                used[idx as usize] = true;
                cs.push(ArgConstraint {
                    index: idx,
                    pred: gen_arg_pred(rng),
                });
            }
            if cs.is_empty() {
                None // empty args list is a validation error; None means unconstrained
            } else {
                Some(cs)
            }
        };

        // A cap is only generated on contract-scoped rules with a token, keeping
        // the document trivially valid; it forces the interpreter on even for a
        // constraint-free rule (INV-2's cap-free proviso).
        let cap = if contract_scope && rng.chance(5) {
            Some(CapConstraint {
                token: Some(VERIFIER_A.into()),
                limit: "1000000".into(),
                period_ledgers: 17280,
            })
        } else {
            None
        };

        rules.push(Rule {
            name: format!("rule-{doc_idx}-{r}"),
            scope,
            principals,
            functions,
            args,
            not_after_ledger: if rng.chance(3) {
                Some(1 + rng.below(1_000_000))
            } else {
                None
            },
            cap,
        });
    }

    PolicyDoc {
        version: 1,
        network: if rng.chance(2) {
            Some("testnet".into())
        } else {
            None
        },
        signers,
        rules,
    }
}

// --- independent reference semantics (doc-level, three-valued) ---------------

/// A generated argument value, kept symbolic so the reference never touches
/// soroban types.
#[derive(Clone, Debug)]
enum GVal {
    U32(u32),
    SelfAddr,
    Addr(&'static str),
    Sym(&'static str),
    Str(String),
    I128(i128),
    Void,
}

#[derive(Clone, Debug)]
struct GInv {
    contract_ctx: bool,
    fn_name: &'static str,
    args: Vec<GVal>,
    signer_count: u32,
}

const MAX_STR: usize = 256;

fn ref_pred(pred: &ArgPred, inv: &GInv, index: u32) -> Verdict {
    if !inv.contract_ctx {
        return Verdict::Unknown;
    }
    let Some(arg) = inv.args.get(index as usize) else {
        return Verdict::Unknown;
    };
    match pred {
        ArgPred::IsSelf(_) => match arg {
            GVal::SelfAddr => Verdict::True,
            GVal::Addr(_) => Verdict::False,
            _ => Verdict::Unknown,
        },
        ArgPred::AddressEq(p) => match arg {
            GVal::Addr(k) => Verdict::from(*k == p.address),
            GVal::SelfAddr => Verdict::False, // the account address is never a fixture strkey
            _ => Verdict::Unknown,
        },
        ArgPred::U32Eq(p) => match arg {
            GVal::U32(x) => Verdict::from(*x == p.value),
            _ => Verdict::Unknown,
        },
        ArgPred::StringIn(p) => match arg {
            GVal::Str(s) => {
                if s.len() > MAX_STR {
                    Verdict::Unknown
                } else {
                    Verdict::from(p.values.iter().any(|c| c.len() <= MAX_STR && c == s))
                }
            }
            _ => Verdict::Unknown,
        },
        ArgPred::StringPrefix(p) => match arg {
            GVal::Str(s) => {
                if s.len() > MAX_STR || p.prefix.len() > MAX_STR {
                    Verdict::Unknown
                } else if p.prefix.len() > s.len() {
                    Verdict::False
                } else {
                    Verdict::from(s.as_bytes()[..p.prefix.len()] == *p.prefix.as_bytes())
                }
            }
            _ => Verdict::Unknown,
        },
    }
}

/// The reference verdict of one *interpreter-attached* rule for one invocation:
/// the Kleene conjunction of the signer floor, the function allowlist, and the
/// argument predicates — the doc-level meaning of the rule's program. Expiry is
/// deliberately absent: `not_after_ledger` lowers to OZ `valid_until`, outside
/// the program.
fn ref_rule(rule: &Rule, inv: &GInv) -> Verdict {
    let n = match &rule.principals {
        Principals::All(all) => all.signers.len().max(1) as u32,
        Principals::Threshold(t) => t.m.max(1),
        Principals::SelfAuthenticating(_) => unreachable!("generator never emits these"),
    };
    let mut v = Verdict::from(inv.signer_count >= n);
    if let Some(fns) = &rule.functions {
        v = v.and(if inv.contract_ctx {
            Verdict::from(fns.iter().any(|f| f == inv.fn_name))
        } else {
            Verdict::Unknown
        });
    }
    if let Some(args) = &rule.args {
        for c in args {
            v = v.and(ref_pred(&c.pred, inv, c.index));
        }
    }
    v
}

// --- invocation generator -----------------------------------------------------

fn gen_val(rng: &mut Rng) -> GVal {
    match rng.below(8) {
        0 => GVal::U32(rng.below(3)),
        1 => GVal::SelfAddr,
        2 => GVal::Addr(if rng.chance(2) {
            VERIFIER_A
        } else {
            VERIFIER_B
        }),
        3 => GVal::Sym("kind"),
        4 => GVal::Str(STRINGS[rng.below(STRINGS.len() as u32) as usize].into()),
        5 => GVal::Str("x".repeat(if rng.chance(2) { 256 } else { 257 })),
        6 => GVal::I128(-7),
        _ => GVal::Void,
    }
}

fn gen_inv(rng: &mut Rng) -> GInv {
    let n_args = rng.below(7);
    GInv {
        contract_ctx: !rng.chance(8),
        fn_name: FN_NAMES[rng.below(FN_NAMES.len() as u32) as usize],
        args: (0..n_args).map(|_| gen_val(rng)).collect(),
        signer_count: rng.below(5),
    }
}

fn soroban_context(env: &Env, inv: &GInv, self_addr: &Address, target: &Address) -> Context {
    if inv.contract_ctx {
        let mut args: SVec<Val> = SVec::new(env);
        for a in &inv.args {
            let v: Val = match a {
                GVal::U32(n) => (*n).into_val(env),
                GVal::SelfAddr => self_addr.clone().into_val(env),
                GVal::Addr(k) => Address::from_str(env, k).into_val(env),
                GVal::Sym(s) => Symbol::new(env, s).into_val(env),
                GVal::Str(s) => SString::from_str(env, s).into_val(env),
                GVal::I128(n) => (*n).into_val(env),
                GVal::Void => ().into_val(env),
            };
            args.push_back(v);
        }
        Context::Contract(ContractContext {
            contract: target.clone(),
            fn_name: Symbol::new(env, inv.fn_name),
            args,
        })
    } else {
        use soroban_sdk::auth::{ContractExecutable, CreateContractHostFnContext};
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(BytesN::from_array(env, &[0u8; 32])),
            salt: BytesN::from_array(env, &[0u8; 32]),
        })
    }
}

// --- the differential property -------------------------------------------------

#[test]
fn compiled_programs_agree_with_the_doc_level_reference() {
    let mut rng = Rng(0xD1FF_0000_C0DE_0001);

    let mut lowered_rules = 0u32;
    for doc_idx in 0..400 {
        // Fresh env per document: the test env meters host work and a single
        // budget cannot carry the whole run.
        let env = Env::default();
        let self_addr = Address::generate(&env);
        let target = Address::from_str(&env, CONTRACT_C);
        let cfg = CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(&env, &[7u8; 32]),
        };
        let doc = gen_doc(&mut rng, doc_idx);
        validate(&doc).expect("generator must produce valid documents");

        let plan = compile(&env, &doc, &cfg).expect("valid documents must lower");
        assert_eq!(plan.rules.len(), doc.rules.len());

        // Two hash paths, one identity: host sha256 (compile) == sha2 (std).
        let std_hash = perch_ir::doc_hash(&doc);

        for (rule, lowered) in doc.rules.iter().zip(plan.rules.iter()) {
            // Expiry boundary: dead at X ⇒ valid through X-1.
            assert_eq!(
                lowered.valid_until,
                rule.not_after_ledger.map(|x| x - 1),
                "rule `{}`: valid_until must be not_after_ledger - 1",
                rule.name
            );

            // INV-2 (+ cap proviso): policy-free iff it is a bare `all` rule —
            // N-of-N, constraint-free, and cap-free. A `threshold` rule always
            // attaches the interpreter so `MinSigners(m)` is the quorum.
            let constraint_free = matches!(rule.principals, Principals::All(_))
                && rule.functions.is_none()
                && rule.args.is_none()
                && rule.cap.is_none();
            assert_eq!(
                lowered.install.is_none(),
                constraint_free,
                "rule `{}`: interpreter attachment disagrees with INV-2",
                rule.name
            );

            let Some(install) = &lowered.install else {
                continue;
            };
            lowered_rules += 1;
            assert_eq!(
                install.doc_hash.to_array(),
                std_hash,
                "on-chain doc_hash diverged from perch_ir::doc_hash"
            );
            rpn::validate(&install.program).expect("compiled programs always validate");

            for _ in 0..16 {
                let inv = gen_inv(&mut rng);
                let ctx = soroban_context(&env, &inv, &self_addr, &target);
                let inputs = EvalInputs {
                    context: &ctx,
                    signer_count: inv.signer_count,
                    self_addr: &self_addr,
                };
                let got = rpn::eval(&env, &install.program, &inputs);
                let want = ref_rule(rule, &inv);
                assert_eq!(
                    got, want,
                    "rule `{}` diverged from the reference on {:?}",
                    rule.name, inv
                );
            }

            // INV-1: zero authenticated signers can never authorize.
            let inv0 = GInv {
                signer_count: 0,
                ..gen_inv(&mut rng)
            };
            let ctx = soroban_context(&env, &inv0, &self_addr, &target);
            let inputs = EvalInputs {
                context: &ctx,
                signer_count: 0,
                self_addr: &self_addr,
            };
            assert_ne!(
                rpn::eval(&env, &install.program, &inputs),
                Verdict::True,
                "rule `{}` authorized a zero-signature invocation (INV-1 violated)",
                rule.name
            );
        }
    }
    assert!(
        lowered_rules > 200,
        "generator must exercise a healthy number of interpreter-attached rules, got {lowered_rules}"
    );
}
