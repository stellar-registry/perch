#![no_std]
//! The perch interpreter: the single deployable contract implementing
//! OpenZeppelin's `Policy` trait by evaluating a stored constraint program.
//!
//! This is the entire custom on-chain surface of perch — there is no
//! per-policy codegen anywhere. One immutable instance per network; the
//! address is derived from the registry id and this contract's wasm hash.
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/6>

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct PerchInterpreter;

#[contractimpl]
impl PerchInterpreter {
    /// Program wire-format version this interpreter evaluates.
    ///
    /// `0` = pre-release placeholder until the format is frozen by the
    /// arena-vs-postfix benchmark (issue #2). Unknown versions are always
    /// rejected at install time — fail closed.
    pub fn program_version(_env: Env) -> u32 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_version_is_zero() {
        let env = Env::default();
        let id = env.register(PerchInterpreter, ());
        let client = PerchInterpreterClient::new(&env, &id);
        assert_eq!(client.program_version(), 0);
    }
}
