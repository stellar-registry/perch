//! Recovery target derivation (`docs/recovery/spec.md` §7).
//!
//! A recovery never installs a document somebody chose. Its target is
//! derived from a source document and a declared replacement set:
//!
//! - **Lost-key:** the source is the account's applied document.
//! - **Compromise:** the source is the enrolled baseline, whose own
//!   `recovery` member is ignored.
//!
//! Either way the target takes the source's signers and rules, the account's
//! *current* recovery member (with the declared ZK rotation, if any), and
//! nothing else. [`derive_target`] applies rules 1-5 of spec §7.3. The caller
//! then validates, network-binds, compiles, and anti-brick-checks the result
//! (rule 6) and checks it against the account's revoked set (rule 7).

use crate::doc::{PolicyDoc, RecoveryMode, SignerMethod};
use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::string::String;

/// Which recovery the target is derived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveAction {
    /// Replace designated credentials in the applied document. Must replace
    /// at least one signer.
    LostKey,
    /// Restore the baseline, optionally replacing designated credentials.
    Compromise,
}

/// One declared replacement: the target gives `signer_id` this method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    pub signer_id: String,
    pub method: SignerMethod,
}

/// The fresh ZK enrollment a completion installs, as the document spells it
/// (64 lowercase hex characters each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkRotation {
    pub enrollment_id: String,
    pub commitment: String,
}

/// Why a target cannot be derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveError {
    /// The current document has no `recovery` member.
    NotEnrolled,
    /// Replacement signer ids are not strictly ascending by bytes.
    NotCanonical,
    /// A lost-key recovery replaces nothing.
    EmptyReplacements,
    /// The signer id is not in the current configuration's `replaceable`.
    NotReplaceable { id: String },
    /// The signer id is not declared in the source document.
    UndeclaredSigner { id: String },
    /// The replacement is a different kind of credential, or an external
    /// credential with a different verifier, than the one it replaces.
    KindMismatch { id: String },
    /// A ZK rotation was given for a mode without a ZK factor, omitted for a
    /// mode with one, or names the currently enrolled id.
    ZkEnrollmentMismatch,
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeriveError::NotEnrolled => write!(f, "the current document enrolls no recovery"),
            DeriveError::NotCanonical => {
                write!(f, "replacement signer ids are not strictly ascending")
            }
            DeriveError::EmptyReplacements => write!(f, "a lost-key recovery replaces nothing"),
            DeriveError::NotReplaceable { id } => write!(f, "signer `{id}` is not replaceable"),
            DeriveError::UndeclaredSigner { id } => {
                write!(f, "signer `{id}` is not declared in the source")
            }
            DeriveError::KindMismatch { id } => write!(
                f,
                "replacement for `{id}` changes its credential kind or verifier"
            ),
            DeriveError::ZkEnrollmentMismatch => write!(
                f,
                "the ZK rotation does not match the enrolled mode or reuses the enrolled id"
            ),
        }
    }
}

/// Derive a recovery target from `source` (the applied document for
/// lost-key, the baseline for compromise) and `current` (the applied
/// document, whose `recovery` member the target keeps).
///
/// `replacements` must be in strictly ascending signer-id byte order. `zk`
/// must be present exactly when the current mode has a ZK factor, and its
/// enrollment id must differ from the enrolled one.
pub fn derive_target(
    source: &PolicyDoc,
    current: &PolicyDoc,
    action: DeriveAction,
    replacements: &[Replacement],
    zk: Option<&ZkRotation>,
) -> Result<PolicyDoc, DeriveError> {
    let mut recovery = current.recovery.clone().ok_or(DeriveError::NotEnrolled)?;

    if replacements
        .windows(2)
        .any(|w| w[0].signer_id.as_bytes() >= w[1].signer_id.as_bytes())
    {
        return Err(DeriveError::NotCanonical);
    }
    if action == DeriveAction::LostKey && replacements.is_empty() {
        return Err(DeriveError::EmptyReplacements);
    }

    let mut target = PolicyDoc {
        version: source.version,
        network: source.network.clone(),
        signers: source.signers.clone(),
        rules: source.rules.clone(),
        recovery: None,
    };

    for r in replacements {
        if !recovery.replaceable.contains(&r.signer_id) {
            return Err(DeriveError::NotReplaceable {
                id: r.signer_id.clone(),
            });
        }
        let decl = target
            .signers
            .iter_mut()
            .find(|s| s.id == r.signer_id)
            .ok_or_else(|| DeriveError::UndeclaredSigner {
                id: r.signer_id.clone(),
            })?;
        let same_kind = match (&decl.method, &r.method) {
            (
                SignerMethod::External { verifier: a, .. },
                SignerMethod::External { verifier: b, .. },
            ) => a == b,
            (SignerMethod::Delegated { .. }, SignerMethod::Delegated { .. }) => true,
            _ => false,
        };
        if !same_kind {
            return Err(DeriveError::KindMismatch {
                id: r.signer_id.clone(),
            });
        }
        decl.method = r.method.clone();
    }

    let factor = match &mut recovery.mode {
        RecoveryMode::GuardianOnly(_) => None,
        RecoveryMode::ZkOnly(z) | RecoveryMode::Combined(_, z) => Some(z),
    };
    match (factor, zk) {
        (None, None) => {}
        (Some(f), Some(rot)) => {
            if f.enrollment_id == rot.enrollment_id {
                return Err(DeriveError::ZkEnrollmentMismatch);
            }
            f.enrollment_id = rot.enrollment_id.clone();
            f.commitment = rot.commitment.clone();
        }
        _ => return Err(DeriveError::ZkEnrollmentMismatch),
    }

    target.recovery = Some(recovery);
    Ok(target)
}
