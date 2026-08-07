#![no_std]
//! Bench-only contract exposing the RPN encoding's validate/eval as
//! metered wasm entry points for the wire-format benchmark
//! (<https://github.com/stellar-registry/perch/issues/2>).
//!
//! One contract per encoding so each wasm's size isolates one encoding's
//! code contribution. Never deployed to a network.

use perch_program::{rpn, EvalInputs, RpnProgram, Verdict};
use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env};

#[contract]
pub struct BenchRpn;

#[contractimpl]
impl BenchRpn {
    /// Validate `program`; returns whether it is well-formed.
    pub fn validate(_env: Env, program: RpnProgram) -> bool {
        rpn::validate(&program).is_ok()
    }

    /// Evaluate `program` against `context`. Returns the verdict as
    /// `0 = False, 1 = Unknown, 2 = True` (Verdict itself is deliberately
    /// not a contracttype).
    pub fn eval(
        env: Env,
        program: RpnProgram,
        context: Context,
        signer_count: u32,
        self_addr: Address,
    ) -> u32 {
        let inputs = EvalInputs {
            context: &context,
            signer_count,
            self_addr: &self_addr,
        };
        match rpn::eval(&env, &program, &inputs) {
            Verdict::False => 0,
            Verdict::Unknown => 1,
            Verdict::True => 2,
        }
    }
}
