#![no_std]
//! On-chain constraint program encoding and evaluation core.
//!
//! This crate is a plain rlib shared verbatim by the interpreter contract and
//! the compiler — install params are only ever encoded through these types,
//! never hand-built `ScVal`s. It must never become a `#[contract]`.
//!
//! The wire format is FROZEN: postfix (RPN) is perch-program v1, chosen by
//! the metered benchmark in `crates/perch-program/BENCH.md`
//! (<https://github.com/stellar-registry/perch/issues/2>). The op set and
//! evaluation semantics land in
//! <https://github.com/stellar-registry/perch/issues/5>.
//!
//! [`rpn`] encodes programs as postfix ops over a verdict stack, with the
//! leaf semantics and fail-closed rule in `leaf`.

mod leaf;
pub mod rpn;

pub use rpn::{InstallParams, Op, RpnProgram};

use soroban_sdk::{auth::Context, Address};

/// The only program wire-format version accepted today. Unknown versions
/// are rejected at validation time — fail closed.
pub const PROGRAM_VERSION: u32 = 1;

/// Maximum op count a program may contain. Bounds program length so
/// evaluation cost is bounded at install time.
pub const MAX_PROGRAM_LEN: u32 = 256;

/// Maximum RPN value-stack depth.
pub const MAX_STACK_DEPTH: u32 = 128;

/// Why a program failed validation. Validation runs at install time; a
/// program that validates can always be evaluated without tripping the
/// defensive `Unknown` paths in eval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// `program.version` is not [`PROGRAM_VERSION`].
    UnknownVersion,
    /// The program has no ops.
    Empty,
    /// The program exceeds [`MAX_PROGRAM_LEN`].
    TooLarge,
    /// A composite op has an impossible arity (`All`/`Any` of zero operands).
    ArityMismatch,
    /// An op pops more values than the stack holds.
    StackUnderflow,
    /// The simulated stack would exceed [`MAX_STACK_DEPTH`].
    StackOverflow,
    /// The program does not leave exactly one value on the stack.
    NotSingleResult,
}

/// Everything a leaf predicate may inspect, besides the [`soroban_sdk::Env`].
///
/// `context` is the authorization context being screened; only
/// [`Context::Contract`] is decodable — every leaf that looks inside the
/// context yields [`Verdict::Unknown`] for other variants. `signer_count` is
/// the number of *authenticated* signers, computed by the caller.
/// `self_addr` is the address the policy protects (the smart account).
pub struct EvalInputs<'a> {
    pub context: &'a Context,
    pub signer_count: u32,
    pub self_addr: &'a Address,
}

/// Three-valued (Kleene) verdict of evaluating a constraint.
///
/// Every leaf predicate evaluates to one of these; any decode failure (wrong
/// argument type, missing argument, non-contract context) is `Unknown`, never
/// `False`. Only a root verdict of `True` authorizes — `Unknown` denies, which
/// keeps negated guardrails fail-closed: `Not(Unknown) = Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    False,
    Unknown,
    True,
}

impl Verdict {
    /// Conjunction: the minimum under `False < Unknown < True`.
    #[must_use]
    pub fn and(self, other: Verdict) -> Verdict {
        self.min(other)
    }

    /// Disjunction: the maximum under `False < Unknown < True`.
    #[must_use]
    pub fn or(self, other: Verdict) -> Verdict {
        self.max(other)
    }

    /// Whether this verdict authorizes. Only `True` does.
    #[must_use]
    pub fn allows(self) -> bool {
        self == Verdict::True
    }
}

/// A decoded boolean check maps onto the two definite verdicts; `Unknown`
/// only ever arises from decode failure, never from `From<bool>`.
impl From<bool> for Verdict {
    fn from(b: bool) -> Verdict {
        if b {
            Verdict::True
        } else {
            Verdict::False
        }
    }
}

/// Negation: `Unknown` stays `Unknown`.
impl core::ops::Not for Verdict {
    type Output = Verdict;

    fn not(self) -> Verdict {
        match self {
            Verdict::False => Verdict::True,
            Verdict::Unknown => Verdict::Unknown,
            Verdict::True => Verdict::False,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Verdict::{False, True, Unknown};

    #[test]
    fn only_true_allows() {
        assert!(True.allows());
        assert!(!Unknown.allows());
        assert!(!False.allows());
    }

    #[test]
    fn negated_unknown_stays_unknown() {
        // The fail-open trap this design exists to close: a decode failure under
        // Not must deny, not silently pass.
        assert_eq!(!Unknown, Unknown);
        assert!(!(!Unknown).allows());
    }

    #[test]
    fn kleene_truth_tables() {
        let all = [False, Unknown, True];
        for a in all {
            for b in all {
                assert_eq!(a.and(b), b.and(a));
                assert_eq!(a.or(b), b.or(a));
                // De Morgan holds in Kleene logic.
                assert_eq!(!a.and(b), (!a).or(!b));
            }
            assert_eq!(!!a, a);
        }
    }
}
