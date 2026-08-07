//! Metered RPN wire-format benchmark, evaluated AS COMPILED WASM.
//!
//! Originally the arena-vs-RPN decision benchmark (issue #2); postfix won
//! and is frozen as perch-program v1 — see crates/perch-program/BENCH.md.
//! The RPN half is kept as an instruction-count canary for the frozen
//! format.
//!
//! Metered costs only accrue to code executing as wasm — native test
//! execution is not metered. So the encoding is wrapped in a tiny bench
//! contract (`perch-bench-rpn`), built for `wasm32v1-none --release`,
//! registered from its wasm bytes, and invoked through the host.
//! `env.cost_estimate().resources()` reports the resources of the *last
//! top-level invocation only* (it resets before every top-level call), so
//! each number below is exactly one `eval` or `validate` call, nothing
//! else.
//!
//! Run via `just bench` (builds the wasm, then runs this with
//! `--ignored --nocapture`).

use perch_program::{rpn, EvalInputs, Op, RpnProgram, PROGRAM_VERSION};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{vec as svec, Address, Env, IntoVal, Symbol, Val, Vec as SVec};

// ------------------------------------------------------------- shared shape

/// Abstract program shape, lowered into the wire encoding. Construction is
/// fully deterministic — no randomness anywhere.
enum Spec {
    All(Vec<Spec>),
    Any(Vec<Spec>),
    Not(Box<Spec>),
    MinSigners(u32),
    FnIn(Vec<&'static str>),
    ArgAddrEq(u32),
    ArgAddrIsSelf(u32),
    ArgSymEq(u32, &'static str),
    ArgU32Eq(u32, u32),
    LedgerBefore(u32),
    LedgerAtOrAfter(u32),
}

impl Spec {
    fn node_count(&self) -> u32 {
        match self {
            Spec::All(kids) | Spec::Any(kids) => 1 + kids.iter().map(Spec::node_count).sum::<u32>(),
            Spec::Not(kid) => 1 + kid.node_count(),
            _ => 1,
        }
    }
}

struct Lowerer<'a> {
    env: &'a Env,
    /// The address embedded in `ArgAddrEq` leaves (deterministic per Env).
    addr: Address,
}

impl Lowerer<'_> {
    fn syms(&self, names: &[&'static str]) -> SVec<Symbol> {
        let mut v = SVec::new(self.env);
        for n in names {
            v.push_back(Symbol::new(self.env, n));
        }
        v
    }

    /// Post-order lowering: children first, then the combining op.
    fn to_rpn(&self, spec: &Spec) -> RpnProgram {
        let mut ops = SVec::new(self.env);
        self.rpn_op(spec, &mut ops);
        RpnProgram {
            version: PROGRAM_VERSION,
            ops,
        }
    }

    fn rpn_op(&self, spec: &Spec, ops: &mut SVec<Op>) {
        match spec {
            Spec::All(kids) => {
                for k in kids {
                    self.rpn_op(k, ops);
                }
                ops.push_back(Op::All(u32::try_from(kids.len()).unwrap()));
            }
            Spec::Any(kids) => {
                for k in kids {
                    self.rpn_op(k, ops);
                }
                ops.push_back(Op::Any(u32::try_from(kids.len()).unwrap()));
            }
            Spec::Not(kid) => {
                self.rpn_op(kid, ops);
                ops.push_back(Op::Not);
            }
            Spec::MinSigners(n) => ops.push_back(Op::MinSigners(*n)),
            Spec::FnIn(names) => ops.push_back(Op::FnIn(self.syms(names))),
            Spec::ArgAddrEq(i) => ops.push_back(Op::ArgAddrEq(*i, self.addr.clone())),
            Spec::ArgAddrIsSelf(i) => ops.push_back(Op::ArgAddrIsSelf(*i)),
            Spec::ArgSymEq(i, s) => ops.push_back(Op::ArgSymEq(*i, Symbol::new(self.env, s))),
            Spec::ArgU32Eq(i, n) => ops.push_back(Op::ArgU32Eq(*i, *n)),
            Spec::LedgerBefore(n) => ops.push_back(Op::LedgerBefore(*n)),
            Spec::LedgerAtOrAfter(n) => ops.push_back(Op::LedgerAtOrAfter(*n)),
        }
    }
}

// ---------------------------------------------------------- benchmark matrix

/// (a) The CI-publish shape — the expected common case.
fn ci_publish_shape() -> Spec {
    Spec::All(vec![
        Spec::MinSigners(1),
        Spec::FnIn(vec!["publish", "yank"]),
        Spec::ArgAddrIsSelf(1),
    ])
}

/// (b) Synthetic mixed-op program with exactly `n` nodes (n >= 8).
///
/// Fixed skeleton (8 nodes): a root `All` over a `Not(LedgerBefore)`
/// subtree and a nested `Any` that itself contains a `Not` — so every size
/// has at least one `Not` and one nested `Any`. The remaining `n - 8`
/// slots are filled with leaves cycling through all leaf kinds so dispatch
/// is realistic. Fully deterministic.
fn synthetic_mixed(n: u32) -> Spec {
    assert!(n >= 8);
    let mut kids = vec![
        Spec::Not(Box::new(Spec::LedgerBefore(1_000_000))),
        Spec::Any(vec![
            Spec::ArgU32Eq(0, 7),
            Spec::ArgSymEq(0, "transfer"),
            Spec::Not(Box::new(Spec::ArgAddrIsSelf(2))),
        ]),
    ];
    for j in 0..(n - 8) {
        kids.push(match j % 8 {
            0 => Spec::MinSigners(1 + j / 8),
            1 => Spec::LedgerBefore(1_000_000 + j),
            2 => Spec::LedgerAtOrAfter(1),
            3 => Spec::ArgU32Eq(0, 42),
            4 => Spec::FnIn(vec!["transfer"]),
            5 => Spec::ArgSymEq(1, "transfer"),
            6 => Spec::ArgAddrIsSelf(2),
            _ => Spec::ArgAddrEq(2),
        });
    }
    let spec = Spec::All(kids);
    assert_eq!(spec.node_count(), n);
    spec
}

// ------------------------------------------------------------------ harness

const WASM_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release"
);

fn load_wasm(name: &str) -> Vec<u8> {
    let path = format!("{WASM_DIR}/{name}");
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "bench wasm not found at {path} ({e}).\n\
             Build it first: `just bench` (or `cargo build -p perch-bench-rpn \
             --target wasm32v1-none --release`)."
        )
    })
}

struct Measurement {
    eval_cpu: i64,
    eval_mem: i64,
    validate_cpu: i64,
    program_bytes: u32,
    verdict: u32,
}

/// Register `wasm` in a fresh Env and meter one `validate` and one `eval`.
/// `build` constructs (program-as-Val, program-xdr-len) for that Env.
fn measure(
    wasm: &[u8],
    build: &dyn Fn(&Env, &Address) -> (Val, u32),
    signer_count: u32,
) -> Measurement {
    let env = Env::default();
    let self_addr = Address::generate(&env);
    let target = Address::generate(&env);
    let id = env.register(wasm, ());

    let (program, program_bytes) = build(&env, &self_addr);
    let context = Context::Contract(ContractContext {
        contract: target,
        fn_name: Symbol::new(&env, "transfer"),
        args: svec![
            &env,
            42u32.into_val(&env),
            Symbol::new(&env, "transfer").into_val(&env),
            self_addr.into_val(&env),
        ],
    });

    let ok: bool = env.invoke_contract(&id, &Symbol::new(&env, "validate"), svec![&env, program]);
    assert!(ok, "benchmark program failed validation");
    let validate_cpu = env.cost_estimate().resources().instructions;

    let verdict: u32 = env.invoke_contract(
        &id,
        &Symbol::new(&env, "eval"),
        svec![
            &env,
            program,
            context.into_val(&env),
            signer_count.into_val(&env),
            self_addr.into_val(&env),
        ],
    );
    let res = env.cost_estimate().resources();

    Measurement {
        eval_cpu: res.instructions,
        eval_mem: res.mem_bytes,
        validate_cpu,
        program_bytes,
        verdict,
    }
}

#[test]
#[ignore = "needs the bench wasm built for wasm32v1-none; run via `just bench`"]
fn metered_wire_format_bench() {
    let rpn_wasm = load_wasm("perch_bench_rpn.wasm");

    println!("\n## Wasm sizes");
    println!("- perch_bench_rpn.wasm: {} bytes", rpn_wasm.len());

    let matrix: Vec<(&str, Spec, u32)> = vec![
        ("ci-publish (4 nodes)", ci_publish_shape(), 1),
        ("mixed-8", synthetic_mixed(8), 2),
        ("mixed-32", synthetic_mixed(32), 2),
        ("mixed-64", synthetic_mixed(64), 2),
    ];

    println!("\n| program | eval cpu | eval mem | validate cpu | program XDR bytes | verdict |");
    println!("|---|---:|---:|---:|---:|---|");
    for (name, spec, signers) in &matrix {
        // Sanity: the lowering validates, and native eval agrees with the
        // metered verdict below.
        let native_verdict = {
            let env = Env::default();
            let self_addr = Address::generate(&env);
            let low = Lowerer {
                env: &env,
                addr: Address::generate(&env),
            };
            let r = low.to_rpn(spec);
            rpn::validate(&r).expect("rpn lowering must validate");
            let ctx = Context::Contract(ContractContext {
                contract: Address::generate(&env),
                fn_name: Symbol::new(&env, "transfer"),
                args: svec![
                    &env,
                    42u32.into_val(&env),
                    Symbol::new(&env, "transfer").into_val(&env),
                    self_addr.into_val(&env),
                ],
            });
            let inputs = EvalInputs {
                context: &ctx,
                signer_count: *signers,
                self_addr: &self_addr,
            };
            match rpn::eval(&env, &r, &inputs) {
                perch_program::Verdict::False => 0u32,
                perch_program::Verdict::Unknown => 1,
                perch_program::Verdict::True => 2,
            }
        };

        let m = measure(
            &rpn_wasm,
            &|env, _self_addr| {
                let low = Lowerer {
                    env,
                    addr: Address::generate(env),
                };
                let p = low.to_rpn(spec);
                let bytes = p.clone().to_xdr(env).len();
                (p.into_val(env), bytes)
            },
            *signers,
        );
        assert_eq!(
            m.verdict, native_verdict,
            "metered verdict disagrees with native eval on {name}"
        );
        println!(
            "| {name} | {} | {} | {} | {} | {} |",
            m.eval_cpu, m.eval_mem, m.validate_cpu, m.program_bytes, m.verdict
        );
    }
}
