#![no_std]
//! Komet (K framework) property tests over the frozen RPN evaluator.
//!
//! Each `test_` method is a boolean property Komet drives with either fuzzed
//! (`komet test`) or **symbolic** (`komet prove run`) arguments, executing the
//! evaluator — compiled into this contract's wasm — under Runtime
//! Verification's mechanized Soroban + KWasm semantics. That makes it an
//! independent second opinion on the wasm-artifact behavior whose trusted base
//! is the K semantics, not rustc/LLVM + wasmi (the base of the Rust wasm leg in
//! `crates/perch-conformance/tests/wasm_leg.rs`).
//!
//! The evaluator is called directly (`perch_program::rpn::eval`) rather than
//! through a deployed contract, so no `komet::create_contract` cheatcode or
//! cross-contract client is needed; the property still runs against the
//! compiled bytecode under the K host.
//!
//! `signer_count` is the symbolic knob: `komet prove run` discharges these for
//! *all* `u32` values, which is the all-inputs guarantee the fixed conformance
//! vectors cannot give on their own.

use perch_program::{rpn, EvalInputs, Op, RpnProgram, Verdict, PROGRAM_VERSION};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Val, Vec};

#[contract]
pub struct PerchKometTests;

/// A minimal contract-call context anchored at the account's own address, with
/// no arguments. `MinSigners` ignores the context; the fail-closed test relies
/// on the empty argument list.
fn ctx(env: &Env, self_addr: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: self_addr.clone(),
        fn_name: symbol_short!("f"),
        args: Vec::<Val>::new(env),
    })
}

#[contractimpl]
impl PerchKometTests {
    /// INV-1 at the bytecode level: the program `[MinSigners(1)]` authorizes
    /// exactly the invocations with at least one authenticated signer, for
    /// every `signer_count`. `komet prove run` proves it for all `u32`.
    pub fn test_min_signers_floor(env: Env, signer_count: u32) -> bool {
        let self_addr = env.current_contract_address();
        let ctx = ctx(&env, &self_addr);
        let program = RpnProgram {
            version: PROGRAM_VERSION,
            ops: Vec::from_array(&env, [Op::MinSigners(1)]),
        };
        let inputs = EvalInputs {
            context: &ctx,
            signer_count,
            self_addr: &self_addr,
        };
        let verdict = rpn::eval(&env, &program, &inputs);
        let expected = if signer_count >= 1 {
            Verdict::True
        } else {
            Verdict::False
        };
        verdict == expected
    }

    /// Composite folding: `All(MinSigners(1), MinSigners(3))` is the Kleene
    /// conjunction (minimum) — definitely `True` iff both floors are met, i.e.
    /// `signer_count >= 3`. Distinguishes correct `All` folding from taking the
    /// first or last leaf.
    pub fn test_all_is_conjunction(env: Env, signer_count: u32) -> bool {
        let self_addr = env.current_contract_address();
        let ctx = ctx(&env, &self_addr);
        let program = RpnProgram {
            version: PROGRAM_VERSION,
            ops: Vec::from_array(
                &env,
                [Op::MinSigners(1), Op::MinSigners(3), Op::All(2)],
            ),
        };
        let inputs = EvalInputs {
            context: &ctx,
            signer_count,
            self_addr: &self_addr,
        };
        let allows = rpn::eval(&env, &program, &inputs).allows();
        allows == (signer_count >= 3)
    }

    /// Fail-closed decode under the wasm host: a leaf reading a missing
    /// argument yields `Unknown`, and `All(_, Unknown)` can never be `True`, so
    /// this program never authorizes — for any `signer_count`. Proving this
    /// symbolically is the strongest statement of the fail-open trap the design
    /// exists to close.
    pub fn test_missing_arg_denies(env: Env, signer_count: u32) -> bool {
        let self_addr = env.current_contract_address();
        let ctx = ctx(&env, &self_addr); // zero args
        let program = RpnProgram {
            version: PROGRAM_VERSION,
            ops: Vec::from_array(
                &env,
                [Op::MinSigners(1), Op::ArgU32Eq(5, 0), Op::All(2)],
            ),
        };
        let inputs = EvalInputs {
            context: &ctx,
            signer_count,
            self_addr: &self_addr,
        };
        // Argument index 5 is absent ⇒ Unknown ⇒ the conjunction never allows.
        !rpn::eval(&env, &program, &inputs).allows()
    }
}
