#![no_std]
//! SPIKE ONLY. The interpreter's evaluation (`perch_program::rpn::eval`,
//! the exact code `perch-interpreter::enforce` runs) with the program passed
//! by value instead of read from the interpreter's own `(account, rule)`
//! storage. A versioned backend stores each rule's program next to the
//! rule, so no per-rule install/uninstall hook is needed.

use perch_program::{rpn, rpn::RpnProgram, EvalInputs, Verdict};
use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env};

#[contract]
pub struct VEval;

#[contractimpl]
impl VEval {
    pub fn evaluate(
        env: Env,
        program: RpnProgram,
        context: Context,
        signer_count: u32,
        account: Address,
    ) -> bool {
        if signer_count == 0 {
            return false;
        }
        let inputs = EvalInputs {
            context: &context,
            signer_count,
            self_addr: &account,
        };
        rpn::eval(&env, &program, &inputs) == Verdict::True
    }
}
