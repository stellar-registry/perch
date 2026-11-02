//! Monotone attenuation (#19, idea 5 — Macaroons/Biscuit "authority only ever
//! shrinks").
//!
//! A holder of a policy can mint a strictly-narrower one without an issuer
//! round-trip. What makes "narrower" *enforceable* rather than a convention is
//! PR4's [`reachable_calls`]: a child is a valid attenuation of a parent iff
//! every `(scope, function)` the child can authorize is one the parent could
//! already authorize, by a rule that keeps any cap the parent's rule has. The
//! check is fail-closed — anything the analyzer cannot show is within the
//! parent is rejected.
//!
//! Argument predicates are not compared, with one exception: a capped rule
//! (a same-token cap, or a cross-token cap's transfer rule) must keep its
//! cap and its recipient exactly, under the same name and scope. A spend
//! window belongs to its rule, so a renamed or uncapped copy would grant a
//! fresh or unbounded budget, and a changed recipient routes the funds
//! elsewhere. Any change is refused, a tighter limit included: this check
//! does not order caps. `perch-analyze narrows` compares the rest of a
//! program's arguments.
//!
//! [`attenuate`] additionally returns the parent and child `doc_hash`es, the
//! link in the hash chain: given both documents a verifier re-runs the check and
//! confirms the child descends from the parent by narrowing, not by replacement.

use crate::analysis::{reachable_calls, FnSet};
use crate::{compile, CapSpec, CompileConfig, LowerError, LoweredRule, Plan, ScopeSpec};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use perch_ir::PolicyDoc;
use perch_program::Op;
use soroban_sdk::{BytesN, Env};

/// Why an attenuation was refused. Fail closed: on any variant, the child is not
/// a valid narrowing and must not be delegated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttenuationError {
    /// The child can authorize a `(scope, function)` the parent cannot, or
    /// changes or drops a capped rule's cap or recipient — a widening, or a
    /// change this check cannot show is not one.
    NotANarrowing { rule: String },
    /// A document failed to compile.
    Compile(LowerError),
}

/// The verifiable link between a parent policy and its attenuated child: both
/// `doc_hash`es. A verifier holding both documents re-runs [`is_narrowing`] to
/// confirm the relationship.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attenuation {
    pub parent_hash: BytesN<32>,
    pub child_hash: BytesN<32>,
}

/// Whether `child` only narrows `parent`: every call the child can authorize is
/// within the parent's reach, through a rule that keeps the covering parent
/// rule's cap ([`keeps_cap`]). Pure over the compiled plans.
pub fn is_narrowing(parent: &Plan, child: &Plan) -> Result<(), AttenuationError> {
    // `reachable_calls` yields one entry per rule, in plan order.
    let parent_reach = reachable_calls(parent);
    for (cs, crule) in reachable_calls(child).into_iter().zip(&child.rules) {
        let covered = parent_reach.iter().zip(&parent.rules).any(|(ps, prule)| {
            ps.scope == cs.scope
                && fn_covers(&ps.functions, &cs.functions)
                && keeps_cap(prule, crule)
        });
        if !covered {
            return Err(AttenuationError::NotANarrowing { rule: cs.rule });
        }
    }
    Ok(())
}

/// Whether `child` keeps `parent`'s spend cap: always for an uncapped parent
/// rule; otherwise only the same rule (name and scope) with the same cap
/// parameters and the same constraints on the recipient, argument 1.
fn keeps_cap(parent: &LoweredRule, child: &LoweredRule) -> bool {
    let Some(pcap) = &parent.cap else {
        return true;
    };
    let Some(ccap) = &child.cap else {
        return false;
    };
    child.name == parent.name
        && child.scope == parent.scope
        && pcap.limit == ccap.limit
        && pcap.period_ledgers == ccap.period_ledgers
        && cap_token(parent, pcap) == cap_token(child, ccap)
        && same_ops(&recipient_ops(parent), &recipient_ops(child))
}

/// The token a cap meters: its own, else the rule's contract scope.
fn cap_token<'a>(rule: &'a LoweredRule, cap: &'a CapSpec) -> Option<&'a str> {
    cap.token.as_deref().or(match &rule.scope {
        ScopeSpec::Contract(address) => Some(address.as_str()),
        ScopeSpec::SelfAdmin => None,
    })
}

/// The program's constraints on argument 1, a SEP-41 transfer's recipient.
fn recipient_ops(rule: &LoweredRule) -> Vec<Op> {
    rule.install
        .iter()
        .flat_map(|install| install.program.ops.iter())
        .filter(|op| matches!(op, Op::ArgAddrEq(1, _) | Op::ArgAddrIsSelf(1)))
        .collect()
}

/// The same constraints, in any order.
fn same_ops(a: &[Op], b: &[Op]) -> bool {
    a.len() == b.len() && a.iter().all(|op| b.contains(op)) && b.iter().all(|op| a.contains(op))
}

/// Compile both documents, verify `child` only narrows `parent`, and return the
/// hash-chain link. `cfg` only supplies the interpreter wasm hash for
/// compilation; it does not affect the narrowing check.
pub fn attenuate(
    env: &Env,
    parent: &PolicyDoc,
    child: &PolicyDoc,
    cfg: &CompileConfig,
) -> Result<Attenuation, AttenuationError> {
    let parent_plan = compile(env, parent, cfg).map_err(AttenuationError::Compile)?;
    let child_plan = compile(env, child, cfg).map_err(AttenuationError::Compile)?;
    is_narrowing(&parent_plan, &child_plan)?;
    Ok(Attenuation {
        parent_hash: crate::doc_hash_onchain(env, parent),
        child_hash: crate::doc_hash_onchain(env, child),
    })
}

/// Whether the parent's function-set covers the child's on a shared scope.
/// `Any` covers everything; a specific set covers only its subsets; a child that
/// widened back to `Any` under a specific parent is not covered.
fn fn_covers(parent: &FnSet, child: &FnSet) -> bool {
    match (parent, child) {
        (FnSet::Any, _) => true,
        (FnSet::Only(_), FnSet::Any) => false,
        (FnSet::Only(p), FnSet::Only(c)) => c.iter().all(|f| p.contains(f)),
    }
}
