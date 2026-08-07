#![no_std]
//! On-chain constraint program encoding and evaluation core.
//!
//! This crate is a plain rlib shared verbatim by the interpreter contract and
//! the compiler — install params are only ever encoded through these types,
//! never hand-built `ScVal`s. It must never become a `#[contract]`.
//!
//! The wire format (node arena vs postfix) is frozen by the benchmark in
//! <https://github.com/stellar-registry/perch/issues/2>; the op set and
//! evaluation semantics land in
//! <https://github.com/stellar-registry/perch/issues/5>.

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
