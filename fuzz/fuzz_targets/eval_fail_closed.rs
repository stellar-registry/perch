//! Fuzz the evaluator's fail-closed totality: for ANY op sequence (mostly
//! structurally invalid) and ANY invocation, `rpn::eval` must return a verdict
//! without panicking, deterministically, and `rpn::validate` must never panic.
//! A panic here is a fail-open bug class: on-chain it would trap the account.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use perch_program::{rpn, EvalInputs, Op, RpnProgram};
use soroban_sdk::auth::{Context, ContractContext, ContractExecutable, CreateContractHostFnContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, String as SString, Symbol, Val, Vec as SVec};

const SYMS: [&str; 4] = ["publish", "publish_hash", "transfer", "kind"];

/// Structured op spec. String contents are irrelevant to the machine — only
/// lengths matter (the MAX_STR_ARG_LEN=256 boundary), so strings are drawn as
/// lengths modulo 300 to straddle the cap.
#[derive(Arbitrary, Debug)]
enum AOp {
    All(u8),
    Any(u8),
    Not,
    MinSigners(u32),
    FnIn(Vec<u8>),
    ArgAddrEq(u8, bool),
    ArgAddrIsSelf(u8),
    ArgSymEq(u8, u8),
    ArgStrIn(u8, Vec<u16>),
    ArgStrPrefix(u8, u16),
    ArgBytesEq(u8, Vec<u8>),
    ArgI128Eq(u8, i128),
    ArgU32Eq(u8, u32),
    ArgCount(u32),
    LedgerBefore(u32),
    LedgerAtOrAfter(u32),
}

#[derive(Arbitrary, Debug)]
enum AVal {
    U32(u32),
    I128(i128),
    SelfAddr,
    Other,
    Sym(u8),
    Str(u16),
    Bytes(Vec<u8>),
    Void,
}

#[derive(Arbitrary, Debug)]
struct ACase {
    version: u32,
    ops: Vec<AOp>,
    contract_ctx: bool,
    fn_name: u8,
    args: Vec<AVal>,
    signer_count: u32,
    ledger: u32,
}

fn sym(env: &Env, i: u8) -> Symbol {
    Symbol::new(env, SYMS[i as usize % SYMS.len()])
}

fn strn(env: &Env, n: u16) -> SString {
    SString::from_str(env, &"a".repeat(n as usize % 300))
}

fn op(env: &Env, self_addr: &Address, other: &Address, spec: &AOp) -> Op {
    match spec {
        AOp::All(n) => Op::All(u32::from(*n)),
        AOp::Any(n) => Op::Any(u32::from(*n)),
        AOp::Not => Op::Not,
        AOp::MinSigners(n) => Op::MinSigners(*n),
        AOp::FnIn(fns) => {
            let mut v: SVec<Symbol> = SVec::new(env);
            for f in fns.iter().take(4) {
                v.push_back(sym(env, *f));
            }
            Op::FnIn(v)
        }
        AOp::ArgAddrEq(i, is_self) => Op::ArgAddrEq(
            u32::from(*i),
            if *is_self { self_addr.clone() } else { other.clone() },
        ),
        AOp::ArgAddrIsSelf(i) => Op::ArgAddrIsSelf(u32::from(*i)),
        AOp::ArgSymEq(i, s) => Op::ArgSymEq(u32::from(*i), sym(env, *s)),
        AOp::ArgStrIn(i, lens) => {
            let mut v: SVec<SString> = SVec::new(env);
            for n in lens.iter().take(4) {
                v.push_back(strn(env, *n));
            }
            Op::ArgStrIn(u32::from(*i), v)
        }
        AOp::ArgStrPrefix(i, n) => Op::ArgStrPrefix(u32::from(*i), strn(env, *n)),
        AOp::ArgBytesEq(i, b) => Op::ArgBytesEq(
            u32::from(*i),
            Bytes::from_slice(env, &b[..b.len().min(64)]),
        ),
        AOp::ArgI128Eq(i, v) => Op::ArgI128Eq(u32::from(*i), *v),
        AOp::ArgU32Eq(i, v) => Op::ArgU32Eq(u32::from(*i), *v),
        AOp::ArgCount(n) => Op::ArgCount(*n),
        AOp::LedgerBefore(n) => Op::LedgerBefore(*n),
        AOp::LedgerAtOrAfter(n) => Op::LedgerAtOrAfter(*n),
    }
}

fuzz_target!(|case: ACase| {
    let env = Env::default();
    env.ledger().with_mut(|li| li.sequence_number = case.ledger);
    let self_addr = Address::generate(&env);
    let other = Address::generate(&env);

    let mut ops: SVec<Op> = SVec::new(&env);
    for spec in case.ops.iter().take(300) {
        ops.push_back(op(&env, &self_addr, &other, spec));
    }
    let program = RpnProgram {
        version: case.version,
        ops,
    };

    // validate is total.
    let _ = rpn::validate(&program);

    let ctx = if case.contract_ctx {
        let mut args: SVec<Val> = SVec::new(&env);
        for a in case.args.iter().take(10) {
            let v: Val = match a {
                AVal::U32(n) => (*n).into_val(&env),
                AVal::I128(n) => (*n).into_val(&env),
                AVal::SelfAddr => self_addr.clone().into_val(&env),
                AVal::Other => other.clone().into_val(&env),
                AVal::Sym(s) => sym(&env, *s).into_val(&env),
                AVal::Str(n) => strn(&env, *n).into_val(&env),
                AVal::Bytes(b) => Bytes::from_slice(&env, &b[..b.len().min(64)]).into_val(&env),
                AVal::Void => ().into_val(&env),
            };
            args.push_back(v);
        }
        Context::Contract(ContractContext {
            contract: other.clone(),
            fn_name: sym(&env, case.fn_name),
            args,
        })
    } else {
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(BytesN::from_array(&env, &[0u8; 32])),
            salt: BytesN::from_array(&env, &[0u8; 32]),
        })
    };
    let inputs = EvalInputs {
        context: &ctx,
        signer_count: case.signer_count,
        self_addr: &self_addr,
    };

    // eval is total and deterministic — a panic or divergence is a finding.
    let a = rpn::eval(&env, &program, &inputs);
    let b = rpn::eval(&env, &program, &inputs);
    assert_eq!(a, b, "eval must be deterministic");
});
