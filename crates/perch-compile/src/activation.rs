//! Fail-closed activation (#19, idea 6 — OPA's "never activate a bundle whose
//! hash doesn't verify").
//!
//! The interpreter stores each rule's `doc_hash` but cannot recompute it
//! on-chain — it never sees the source [`PolicyDoc`]. So the activation check
//! lives here, at the boundary where the reviewed document exists: before a
//! client attaches a [`Plan`], it MUST confirm every interpreter attachment
//! carries the `doc_hash` of the exact document under review. On mismatch,
//! refuse to attach — the currently-attached policy stays in force, never
//! replaced by an unverified one.
//!
//! This is the host half of perch's fail-closed activation. The on-chain half
//! is the interpreter's own install guards: structural `validate`, refuse-
//! overwrite (`AlreadyInstalled`), and `require_auth`.

use crate::Plan;
#[cfg(not(feature = "std"))]
use alloc::string::String;
use perch_ir::PolicyDoc;
use soroban_sdk::{Bytes, BytesN, Env};

/// Why activation was refused. Fail closed: on any variant, do **not** attach —
/// keep whatever policy is currently in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationError {
    /// An attached program's `doc_hash` does not match the reviewed document's.
    DocHashMismatch { rule: String },
}

/// Verify every interpreter attachment in `plan` carries the `doc_hash` of
/// `doc`. A client MUST call this before submitting the plan's attachments; a
/// plan produced by [`crate::compile`] from `doc` always passes, so a failure
/// means the plan and the document under review have diverged (tampering, a
/// hand-built plan, or a plan compiled from a different document).
pub fn verify_plan_matches_doc(
    env: &Env,
    doc: &PolicyDoc,
    plan: &Plan,
) -> Result<(), ActivationError> {
    // Recompute the doc_hash on-chain via the host sha256 (a cheap builtin) over
    // the canonical bytes — the same digest as the off-chain `perch_ir::doc_hash`,
    // but no `sha2` software impl (and so no_std-clean).
    let canonical = perch_ir::canonical_json(doc);
    let expected: BytesN<32> = env
        .crypto()
        .sha256(&Bytes::from_slice(env, canonical.as_bytes()))
        .to_bytes();
    for rule in &plan.rules {
        if let Some(install) = &rule.install {
            if install.doc_hash != expected {
                return Err(ActivationError::DocHashMismatch {
                    rule: rule.name.clone(),
                });
            }
        }
    }
    Ok(())
}
