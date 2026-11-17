//! Named and unverified verifiers.
//!
//! An external signer names its verifier contract one of two ways:
//!
//! - **By name**, `"verifier-name": "<name>@<version>"` beside its
//!   `"verifier"` address: a verifier published in Perch's managed
//!   `perch/verifiers` registry, whose manager approves each new name. The
//!   doc compiler resolves the name and exact version on-chain
//!   (`fetch_hash`, then the content address the registry deployed that wasm
//!   at) and refuses the document unless it is the signer's `verifier`. A
//!   repointed name never changes an applied account: the account stores the
//!   address, and moves to another verifier only by applying a document.
//! - **By contract id alone**: an *unverified* verifier. Its `verify` decides
//!   whatever the rules holding its signers allow, so the compiler refuses
//!   one in an admin document ([`is_admin_document`]) and lets a scoped
//!   document hold it, at most once per rule ([`unverified_reuse`]), listing
//!   it in the compile result for the wallet's warning.
//!
//! These are the doc compiler's checks, not [`crate::validate`]'s: validation
//! checks only the name's spelling (`InvalidVerifierName`), so a document
//! written either way is a well-formed document.

use crate::doc::{PolicyDoc, Principals, Scope, SignerMethod};
use alloc::vec::Vec;

/// The longest registry name a `verifier-name` may give.
pub const MAX_VERIFIER_NAME_LEN: usize = 64;

/// Split a `verifier-name` into its registry name and exact version, or
/// `None` if it is not spelled `<name>@<MAJOR>.<MINOR>.<PATCH>`:
///
/// - the name is 1 to [`MAX_VERIFIER_NAME_LEN`] bytes of `[a-z0-9-]`,
///   starting with a letter: the registry's normalized form, so one verifier
///   has one spelling;
/// - the version is three decimal numbers without leading zeros, as the
///   registry stores a published version.
#[must_use]
pub fn parse_verifier_name(s: &str) -> Option<(&str, &str)> {
    let (name, version) = s.split_once('@')?;
    let name_ok = (1..=MAX_VERIFIER_NAME_LEN).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let mut parts = 0;
    let version_ok = version.split('.').all(|part| {
        parts += 1;
        !part.is_empty()
            && part.len() <= 10
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0'))
    });
    (name_ok && version_ok && parts == 3).then_some((name, version))
}

/// Whether `doc` is an admin document: it has a `self-admin` rule or a
/// `recovery` member. Every document an account's `apply_doc` applies has
/// one (it must keep an admin rule), and its `apply_scope` refuses both, so
/// this is the document's role read from its text.
#[must_use]
pub fn is_admin_document(doc: &PolicyDoc) -> bool {
    doc.recovery.is_some()
        || doc
            .rules
            .iter()
            .any(|r| matches!(r.scope, Scope::SelfAdmin(_)))
}

/// The address of every verifier `doc` names by contract id alone, once
/// each, in declaration order.
#[must_use]
pub fn unverified_verifiers(doc: &PolicyDoc) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for s in &doc.signers {
        if let SignerMethod::External {
            verifier,
            verifier_name: None,
            ..
        } = &s.method
        {
            if !out.contains(&verifier.as_str()) {
                out.push(verifier);
            }
        }
    }
    out
}

/// The first rule of `doc` with two signers under one unverified verifier,
/// with that verifier: `(rule index, verifier)`. A verifier whose
/// `batch_canonicalize_key` calls every key canonical and whose `verify`
/// accepts one signature for several of them would count each toward the
/// rule's threshold, so a rule may hold one signer per unverified verifier.
#[must_use]
pub fn unverified_reuse(doc: &PolicyDoc) -> Option<(usize, &str)> {
    for (i, rule) in doc.rules.iter().enumerate() {
        let ids = match &rule.principals {
            Principals::All(p) => &p.signers,
            Principals::Threshold(p) => &p.signers,
            Principals::SelfAuthenticating(_) => continue,
        };
        let mut seen: Vec<&str> = Vec::new();
        for id in ids {
            let Some(decl) = doc.signers.iter().find(|s| &s.id == id) else {
                continue;
            };
            if let SignerMethod::External {
                verifier,
                verifier_name: None,
                ..
            } = &decl.method
            {
                if seen.contains(&verifier.as_str()) {
                    return Some((i, verifier));
                }
                seen.push(verifier);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::parse_verifier_name;

    #[test]
    fn a_verifier_name_is_a_registry_name_and_an_exact_version() {
        for (s, want) in [
            (
                "perch-webauthn-verifier@0.1.0",
                Some(("perch-webauthn-verifier", "0.1.0")),
            ),
            ("mldsa65@10.20.300", Some(("mldsa65", "10.20.300"))),
            ("a@0.0.0", Some(("a", "0.0.0"))),
        ] {
            assert_eq!(parse_verifier_name(s), want, "{s}");
        }
        let long = "a".repeat(65);
        let bad_name = format!("{long}@1.0.0");
        for s in [
            "perch-webauthn-verifier",
            "@0.1.0",
            "Perch@0.1.0",
            "perch_webauthn@0.1.0",
            "1perch@0.1.0",
            "-perch@0.1.0",
            bad_name.as_str(),
            "perch@0.1",
            "perch@0.1.0.0",
            "perch@01.0.0",
            "perch@0.1.0-beta",
            "perch@0.1.x",
            "perch@0..0",
            "perch@0.1.0@1.0.0",
            "perch@12345678901.0.0",
        ] {
            assert_eq!(parse_verifier_name(s), None, "{s}");
        }
    }
}
