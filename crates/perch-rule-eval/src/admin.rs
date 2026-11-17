//! The account's two rule-set invariants, read on rule-eval's rules.
//!
//! - [`admin_survives`]: the set keeps a rule that lets its signers manage
//!   the account with nothing else asked of them, and that never lapses.
//! - [`guarded`]: a rule asks for at least one signer, so no authorization
//!   with no signer at all satisfies it (Perch's INV-1). The recovery rule is
//!   the one rule that asks for none: its controller decides its calls.

use rule_eval::{Functions, Rule};

/// Whether `r` lets its signers manage the account `me` unconditionally:
/// every function of `me`, no condition, no cap, no last ledger, at least
/// one signer, and all of them required.
fn is_admin(r: &Rule, me: &[u8]) -> bool {
    r.contract == me
        && matches!(&r.functions, Functions::AnyExcept(xs) if xs.is_empty())
        && r.conds.is_empty()
        && r.cap.is_none()
        && r.valid_until.is_none()
        && r.generation.is_none()
        && !r.signers.is_empty()
        && r.threshold as usize == r.signers.len()
}

/// Whether `rules`, on the account `me` (its `ScAddress` XDR), keep a rule
/// that lets its signers manage the account with nothing else asked of them
/// and that never lapses.
///
/// A rule with a last ledger never counts: once that ledger passes, the
/// account could no longer be managed through it.
#[must_use]
pub fn admin_survives(rules: &[Rule], me: &[u8]) -> bool {
    rules.iter().any(|r| is_admin(r, me))
}

/// Whether `r` asks for at least one signer.
#[must_use]
pub fn guarded(r: &Rule) -> bool {
    r.threshold >= 1
}
