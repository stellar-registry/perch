//! The account's two rule-set invariants, read on rule-eval's rules.
//!
//! - [`admin_survives`]: the set keeps a rule that lets its signers manage
//!   the account with nothing else asked of them, and that never lapses.
//! - [`admin_declared`]: the document declares such a rule as a
//!   constraint-free `all` rule, which is what Perch's anti-brick check on a
//!   compiled document (`perch_doc_compiler::admin_survives`) asks; a
//!   `threshold` rule asking all of its signers lowers to the same rule and
//!   does not count.
//! - [`guarded`]: a rule asks for at least one signer, so no authorization
//!   with no signer at all satisfies it (Perch's INV-1). The recovery rule is
//!   the one rule that asks for none: its controller decides its calls.

use rule_eval::{Doc, Functions, Principals, Rule, Scope};

/// Whether `r` lets its signers manage the account `me` unconditionally:
/// every function of `me`, no condition, no cap, no last ledger, at least
/// one signer, and all of them required.
fn is_admin(r: &Rule, me: &[u8]) -> bool {
    r.auth_root.is_none()
        && r.contract == me
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

/// Whether `d` has a self-admin rule with `all` principals naming at least
/// one signer, and no functions, arguments, cap or `not-after-ledger`. A
/// validated document names only declared signers, so such a rule lowers
/// to a rule with signers.
#[must_use]
pub fn admin_declared(d: &Doc) -> bool {
    d.rules.iter().any(|r| {
        r.auth_root.is_none()
            && matches!(r.scope, Scope::SelfAdmin)
            && matches!(&r.principals, Principals::All(ids) if !ids.is_empty())
            && r.functions.is_none()
            && r.args.is_none()
            && r.cap.is_none()
            && r.not_after_ledger.is_none()
    })
}

/// Whether `r` asks for at least one signer.
#[must_use]
pub fn guarded(r: &Rule) -> bool {
    r.threshold >= 1
}
