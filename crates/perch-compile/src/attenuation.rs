//! Monotone attenuation (#19, idea 5 — Macaroons/Biscuit "authority only ever
//! shrinks").
//!
//! A holder of a policy can mint a strictly-narrower one without an issuer
//! round-trip. What makes "narrower" *enforceable* rather than a convention is
//! PR4's [`reachable_calls`]: a child is a valid attenuation of a parent iff
//! every `(scope, function)` the child can authorize is one the parent could
//! already authorize. The check is fail-closed — anything the analyzer cannot
//! show is within the parent is rejected.
//!
//! [`attenuate`] additionally returns the parent and child `doc_hash`es, the
//! link in the hash chain: given both documents a verifier re-runs the check and
//! confirms the child descends from the parent by narrowing, not by replacement.

use crate::analysis::{reachable_calls, FnSet};
use crate::{compile, CompileConfig, LowerError, Plan};
use perch_ir::PolicyDoc;
use soroban_sdk::{BytesN, Env};

/// Why an attenuation was refused. Fail closed: on any variant, the child is not
/// a valid narrowing and must not be delegated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttenuationError {
    /// The child can authorize a `(scope, function)` the parent cannot — a
    /// widening, not a narrowing.
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
/// within the parent's reach. Pure over the compiled plans.
pub fn is_narrowing(parent: &Plan, child: &Plan) -> Result<(), AttenuationError> {
    let parent_reach = reachable_calls(parent);
    for cs in reachable_calls(child) {
        let covered = parent_reach
            .iter()
            .any(|ps| ps.scope == cs.scope && fn_covers(&ps.functions, &cs.functions));
        if !covered {
            return Err(AttenuationError::NotANarrowing { rule: cs.rule });
        }
    }
    Ok(())
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
        parent_hash: BytesN::from_array(env, &perch_ir::doc_hash(parent)),
        child_hash: BytesN::from_array(env, &perch_ir::doc_hash(child)),
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
