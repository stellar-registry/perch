//! Decidable-fragment properties of perch-program v1 (#19, idea 2).
//!
//! The op set is finite, there is no recursion or backward jump, and every leaf
//! predicate is a total function over a finite-comparable domain. These tests
//! pin the consequences the compiler and the static analyzer (#19 PR4) rely on:
//!
//! - **Totality.** `rpn::eval` returns a [`Verdict`] for *any* op sequence and
//!   any inputs — malformed programs fail closed to `Unknown`, never panic.
//! - **Determinism.** Same program + same inputs ⇒ same verdict.
//! - **Validation ⇒ no structural `Unknown`.** A program that passes
//!   `rpn::validate` never trips eval's defensive `Unknown` paths (underflow /
//!   overflow / not-single-result); its verdict is a pure function of its
//!   leaves. This is what makes "can this ever authorize?" decidable statically.
//!
//! Randomness is a fixed-seed splitmix64 so failures reproduce exactly; no rng
//! dependency in this security-core crate.

use perch_program::{
    rpn, EvalInputs, Op, RpnProgram, Verdict, MAX_PROGRAM_LEN, MAX_STACK_DEPTH, PROGRAM_VERSION,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Bytes, Env, IntoVal, String as SString, Symbol, Vec as SVec};

// --- deterministic PRNG (splitmix64) ----------------------------------------

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform-ish in `0..n`; `n` must be non-zero.
    fn below(&mut self, n: u32) -> u32 {
        (self.next() % u64::from(n)) as u32
    }
}

// --- op generators ----------------------------------------------------------

const SYMS: [&str; 5] = ["publish", "publish_hash", "set_admin", "a", "b"];

fn sym(env: &Env, rng: &mut Rng) -> Symbol {
    Symbol::new(env, SYMS[rng.below(SYMS.len() as u32) as usize])
}

fn sstr(env: &Env, rng: &mut Rng) -> SString {
    SString::from_str(env, SYMS[rng.below(SYMS.len() as u32) as usize])
}

/// A random leaf op (pushes exactly one verdict). Covers every v1 leaf variant.
fn any_leaf(env: &Env, rng: &mut Rng) -> Op {
    let i = rng.below(4);
    match rng.below(13) {
        0 => Op::MinSigners(rng.below(5)),
        1 => {
            let mut fns = SVec::new(env);
            for _ in 0..=rng.below(2) {
                fns.push_back(sym(env, rng));
            }
            Op::FnIn(fns)
        }
        2 => Op::ArgAddrEq(i, Address::generate(env)),
        3 => Op::ArgAddrIsSelf(i),
        4 => Op::ArgSymEq(i, sym(env, rng)),
        5 => {
            let mut set = SVec::new(env);
            for _ in 0..=rng.below(2) {
                set.push_back(sstr(env, rng));
            }
            Op::ArgStrIn(i, set)
        }
        6 => Op::ArgStrPrefix(i, sstr(env, rng)),
        7 => Op::ArgBytesEq(i, Bytes::from_array(env, &[rng.below(256) as u8; 4])),
        8 => Op::ArgI128Eq(i, i128::from(rng.next() as i64)),
        9 => Op::ArgU32Eq(i, rng.below(1000)),
        10 => Op::ArgCount(rng.below(5)),
        11 => Op::LedgerBefore(rng.below(1_000_000)),
        _ => Op::LedgerAtOrAfter(rng.below(1_000_000)),
    }
}

/// Build a *valid-by-construction* postfix program into `ops`: leaves push one
/// verdict, `Not` consumes one, `All(k)`/`Any(k)` consume `k`. Because it is
/// well-formed by construction, it always passes `validate`. `allow_not` is off
/// for the monotone all-true/all-false tests (Not would flip the fold).
fn gen_valid(
    env: &Env,
    rng: &mut Rng,
    budget: u32,
    allow_not: bool,
    leaf: fn(&Env, &mut Rng) -> Op,
    ops: &mut SVec<Op>,
) {
    if budget == 0 || rng.below(3) == 0 {
        ops.push_back(leaf(env, rng));
        return;
    }
    let pick = rng.below(if allow_not { 3 } else { 2 });
    match pick {
        0 if allow_not => {
            gen_valid(env, rng, budget - 1, allow_not, leaf, ops);
            ops.push_back(Op::Not);
        }
        p => {
            let k = 1 + rng.below(3);
            for _ in 0..k {
                gen_valid(env, rng, budget - 1, allow_not, leaf, ops);
            }
            // With Not disallowed, `pick` is 0 or 1 → map both onto All/Any.
            if p % 2 == 0 {
                ops.push_back(Op::All(k));
            } else {
                ops.push_back(Op::Any(k));
            }
        }
    }
}

fn program(ops: SVec<Op>) -> RpnProgram {
    RpnProgram {
        version: PROGRAM_VERSION,
        ops,
    }
}

// --- test scaffolding -------------------------------------------------------

/// A concrete evaluation context. Its shape is irrelevant to the structural
/// properties under test (the all-true/all-false leaves ignore it).
fn with_inputs<R>(env: &Env, signer_count: u32, f: impl FnOnce(&EvalInputs) -> R) -> R {
    let contract = Address::generate(env);
    let self_addr = Address::generate(env);
    let ctx = Context::Contract(ContractContext {
        contract,
        fn_name: Symbol::new(env, "publish"),
        args: vec![env, 0u32.into_val(env), self_addr.clone().into_val(env)],
    });
    let inputs = EvalInputs {
        context: &ctx,
        signer_count,
        self_addr: &self_addr,
    };
    f(&inputs)
}

// --- properties -------------------------------------------------------------

#[test]
fn eval_is_total_and_deterministic_on_arbitrary_ops() {
    // Fully arbitrary op sequences — most are structurally invalid. eval must
    // return a verdict (fail closed to Unknown) without ever panicking, and be
    // deterministic. This is the fail-closed totality the interpreter leans on.
    let env = Env::default();
    let mut rng = Rng(0x0DDB_1A5E_1234_5678);
    with_inputs(&env, 1, |inputs| {
        for _ in 0..1000 {
            let mut ops = SVec::new(&env);
            let len = 1 + rng.below(24);
            for _ in 0..len {
                let op = match rng.below(16) {
                    0 => Op::All(rng.below(5)), // arity possibly 0/too-big → invalid
                    1 => Op::Any(rng.below(5)),
                    2 => Op::Not,
                    _ => any_leaf(&env, &mut rng),
                };
                ops.push_back(op);
            }
            let p = program(ops);
            let a = rpn::eval(&env, &p, inputs);
            let b = rpn::eval(&env, &p, inputs);
            assert_eq!(a, b, "eval must be deterministic");
        }
    });
}

#[test]
fn valid_programs_validate_and_stay_within_bounds() {
    let env = Env::default();
    let mut rng = Rng(0xF00D_CAFE_0000_0001);
    for _ in 0..1000 {
        let mut ops = SVec::new(&env);
        gen_valid(&env, &mut rng, 4, true, any_leaf, &mut ops);
        assert!(
            ops.len() <= MAX_PROGRAM_LEN,
            "generator stayed under the op cap"
        );
        let p = program(ops);
        rpn::validate(&p).expect("valid-by-construction program must validate");
    }
    // Sanity: the depth cap is what validate enforces; a program is rejected the
    // instant its simulated stack would exceed it.
    let mut deep = SVec::new(&env);
    for _ in 0..=MAX_STACK_DEPTH {
        deep.push_back(Op::MinSigners(1));
    }
    // MAX_STACK_DEPTH+1 leaves with no fold → depth overflow, then multi-result.
    assert!(rpn::validate(&program(deep)).is_err());
}

#[test]
fn validated_programs_never_return_structural_unknown() {
    // The decidability payoff: a validated program's verdict is a pure function
    // of its leaves — eval never falls into an underflow/overflow/multi-result
    // Unknown. Prove it with monotone trees whose leaves are all-True or
    // all-False; the fold is forced, so any Unknown could only be structural.
    let env = Env::default();
    let mut rng = Rng(0xABCD_0000_FACE_0002);

    // MinSigners(0) is True for any signer_count; MinSigners(u32::MAX) is False
    // for a realistic count. No Not, only All/Any → the fold is monotone.
    fn always_true(_: &Env, _: &mut Rng) -> Op {
        Op::MinSigners(0)
    }
    fn always_false(_: &Env, _: &mut Rng) -> Op {
        Op::MinSigners(u32::MAX)
    }

    with_inputs(&env, 3, |inputs| {
        for _ in 0..500 {
            let mut t = SVec::new(&env);
            gen_valid(&env, &mut rng, 4, false, always_true, &mut t);
            let p = program(t);
            rpn::validate(&p).expect("validates");
            assert_eq!(
                rpn::eval(&env, &p, inputs),
                Verdict::True,
                "all-true monotone tree must fold to True, not a structural Unknown"
            );

            let mut f = SVec::new(&env);
            gen_valid(&env, &mut rng, 4, false, always_false, &mut f);
            let p = program(f);
            rpn::validate(&p).expect("validates");
            assert_eq!(
                rpn::eval(&env, &p, inputs),
                Verdict::False,
                "all-false monotone tree must fold to False, not a structural Unknown"
            );
        }
    });
}

#[test]
fn every_v1_leaf_is_a_total_single_result() {
    // Each leaf variant, alone, is a valid single-result program that evaluates
    // to a definite verdict without panic — the full v1 alphabet is total.
    let env = Env::default();
    let mut rng = Rng(0x5EED_5EED_5EED_0003);
    with_inputs(&env, 1, |inputs| {
        for _ in 0..SYMS.len() * 40 {
            let leaf = any_leaf(&env, &mut rng);
            let p = program({
                let mut o = SVec::new(&env);
                o.push_back(leaf);
                o
            });
            rpn::validate(&p).expect("a single leaf leaves exactly one result");
            // Must not panic; verdict may be any of the three.
            let _ = rpn::eval(&env, &p, inputs);
        }
    });
}
