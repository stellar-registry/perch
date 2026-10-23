//! Fail-closed activation (#19, idea 6 — OPA's "never activate a bundle whose
//! hash doesn't verify").
//!
//! The interpreter stores each program's provenance (its `doc_hash` field,
//! which holds the hash of the rule the program was compiled from,
//! [`perch_ir::rule_hash`]) but cannot recompute it on-chain — it never sees
//! the source [`PolicyDoc`]. So the activation check lives here, at the
//! boundary where the reviewed document exists: before a client attaches a
//! [`Plan`], it MUST confirm every interpreter attachment carries the hash of
//! its own rule in the exact document under review. On mismatch, refuse to
//! attach — the currently-attached policy stays in force, never replaced by an
//! unverified one.
//!
//! This is the host half of perch's fail-closed activation. The on-chain half
//! is the interpreter's own install guards: structural `validate`, refuse-
//! overwrite (`AlreadyInstalled`), and `require_auth`.

use crate::{rule_hash_onchain, Plan};
#[cfg(not(feature = "std"))]
use alloc::string::String;
use perch_ir::PolicyDoc;
use soroban_sdk::Env;

/// Why activation was refused. Fail closed: on any variant, do **not** attach —
/// keep whatever policy is currently in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationError {
    /// An attached program's provenance is not the hash of its rule in the
    /// reviewed document (or the rule is not in it).
    DocHashMismatch { rule: String },
}

/// Verify every interpreter attachment in `plan` carries the hash of its own
/// rule in `doc`. A client MUST call this before submitting the plan's
/// attachments; a plan produced by [`crate::compile`] from `doc` always
/// passes, so a failure means the plan and the document under review have
/// diverged (tampering, a hand-built plan, or a plan compiled from a
/// different document).
pub fn verify_plan_matches_doc(
    env: &Env,
    doc: &PolicyDoc,
    plan: &Plan,
) -> Result<(), ActivationError> {
    for lowered in &plan.rules {
        if let Some(install) = &lowered.install {
            let matches = doc
                .rules
                .iter()
                .find(|r| r.name == lowered.name)
                .is_some_and(|r| rule_hash_onchain(env, r) == install.doc_hash);
            if !matches {
                return Err(ActivationError::DocHashMismatch {
                    rule: lowered.name.clone(),
                });
            }
        }
    }
    Ok(())
}
