//! Per-op tests for the v1 leaf ops added in #5 (string / bytes / i128 / count),
//! each in allow and deny direction plus the fail-closed decode-failure case
//! (asserted in both polarities: bare and under `Not`).

use perch_program::{rpn, EvalInputs, Op, RpnProgram, Verdict, PROGRAM_VERSION};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Bytes, Env, IntoVal, String, Symbol, Val, Vec as SVec};

struct Fixture {
    env: Env,
    self_addr: Address,
    target: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        let self_addr = Address::generate(&env);
        let target = Address::generate(&env);
        Fixture {
            env,
            self_addr,
            target,
        }
    }

    /// A contract-call context with the given argument list.
    fn ctx(&self, args: SVec<Val>) -> Context {
        Context::Contract(ContractContext {
            contract: self.target.clone(),
            fn_name: Symbol::new(&self.env, "run"),
            args,
        })
    }

    fn eval(&self, ops: SVec<Op>, context: &Context) -> Verdict {
        let program = RpnProgram {
            version: PROGRAM_VERSION,
            ops,
        };
        let inputs = EvalInputs {
            context,
            signer_count: 1,
            self_addr: &self.self_addr,
        };
        rpn::eval(&self.env, &program, &inputs)
    }

    /// A single leaf op, evaluated bare (allow position).
    fn leaf(&self, op: Op, context: &Context) -> Verdict {
        self.eval(vec![&self.env, op], context)
    }

    /// The same op under `Not` — a decode failure (Unknown) must still deny.
    fn negated(&self, op: Op, context: &Context) -> Verdict {
        self.eval(vec![&self.env, op, Op::Not], context)
    }
}

fn s(env: &Env, v: &str) -> Val {
    String::from_str(env, v).into_val(env)
}

#[test]
fn arg_str_in_allow_and_deny() {
    let f = Fixture::new();
    let set = vec![
        &f.env,
        String::from_str(&f.env, "alpha"),
        String::from_str(&f.env, "beta"),
    ];
    let op = || Op::ArgStrIn(0, set.clone());
    assert_eq!(
        f.leaf(op(), &f.ctx(vec![&f.env, s(&f.env, "beta")])),
        Verdict::True
    );
    assert_eq!(
        f.leaf(op(), &f.ctx(vec![&f.env, s(&f.env, "gamma")])),
        Verdict::False
    );
}

#[test]
fn arg_str_in_wrong_type_is_unknown_both_polarities() {
    let f = Fixture::new();
    let set = vec![&f.env, String::from_str(&f.env, "beta")];
    // arg 0 is a u32, not a string → decode failure → Unknown.
    let ctx = f.ctx(vec![&f.env, 7u32.into_val(&f.env)]);
    assert_eq!(f.leaf(Op::ArgStrIn(0, set.clone()), &ctx), Verdict::Unknown);
    assert_eq!(f.negated(Op::ArgStrIn(0, set), &ctx), Verdict::Unknown);
}

#[test]
fn arg_str_prefix_allow_deny_and_too_long() {
    let f = Fixture::new();
    let pfx = String::from_str(&f.env, "perch:");
    assert_eq!(
        f.leaf(
            Op::ArgStrPrefix(0, pfx.clone()),
            &f.ctx(vec![&f.env, s(&f.env, "perch:abc")])
        ),
        Verdict::True
    );
    assert_eq!(
        f.leaf(
            Op::ArgStrPrefix(0, pfx.clone()),
            &f.ctx(vec![&f.env, s(&f.env, "other")])
        ),
        Verdict::False
    );
    // prefix longer than the argument → False (definite), not Unknown.
    assert_eq!(
        f.leaf(
            Op::ArgStrPrefix(0, pfx),
            &f.ctx(vec![&f.env, s(&f.env, "p")])
        ),
        Verdict::False
    );
}

#[test]
fn arg_str_prefix_missing_arg_is_unknown() {
    let f = Fixture::new();
    let pfx = String::from_str(&f.env, "x");
    let ctx = f.ctx(vec![&f.env]); // no args
    assert_eq!(
        f.leaf(Op::ArgStrPrefix(0, pfx.clone()), &ctx),
        Verdict::Unknown
    );
    assert_eq!(f.negated(Op::ArgStrPrefix(0, pfx), &ctx), Verdict::Unknown);
}

#[test]
fn arg_bytes_eq_allow_and_deny() {
    let f = Fixture::new();
    let want = Bytes::from_array(&f.env, &[1, 2, 3]);
    let op = || Op::ArgBytesEq(0, want.clone());
    assert_eq!(
        f.leaf(
            op(),
            &f.ctx(vec![
                &f.env,
                Bytes::from_array(&f.env, &[1, 2, 3]).into_val(&f.env)
            ])
        ),
        Verdict::True
    );
    assert_eq!(
        f.leaf(
            op(),
            &f.ctx(vec![
                &f.env,
                Bytes::from_array(&f.env, &[9]).into_val(&f.env)
            ])
        ),
        Verdict::False
    );
}

#[test]
fn arg_i128_eq_allow_deny_and_wrong_type() {
    let f = Fixture::new();
    let op = || Op::ArgI128Eq(0, 1000i128);
    assert_eq!(
        f.leaf(op(), &f.ctx(vec![&f.env, 1000i128.into_val(&f.env)])),
        Verdict::True
    );
    assert_eq!(
        f.leaf(op(), &f.ctx(vec![&f.env, 999i128.into_val(&f.env)])),
        Verdict::False
    );
    // a u32 arg is not an i128 → Unknown.
    let ctx = f.ctx(vec![&f.env, 1000u32.into_val(&f.env)]);
    assert_eq!(f.leaf(Op::ArgI128Eq(0, 1000), &ctx), Verdict::Unknown);
    assert_eq!(f.negated(Op::ArgI128Eq(0, 1000), &ctx), Verdict::Unknown);
}

#[test]
fn arg_count_allow_and_deny() {
    let f = Fixture::new();
    let two = f.ctx(vec![&f.env, 1u32.into_val(&f.env), 2u32.into_val(&f.env)]);
    assert_eq!(f.leaf(Op::ArgCount(2), &two), Verdict::True);
    assert_eq!(f.leaf(Op::ArgCount(3), &two), Verdict::False);
}
