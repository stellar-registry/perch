//! Hashes over fragments of a CANON v1 document (`CANONICAL.md`, "Fragment
//! hashes"): the bytes one member contributes to the document's canonical
//! serialization, under a domain tag of its own.
//!
//! - [`rule_hash`]: one element of the `rules` array. It is the provenance
//!   an interpreter program carries, and what a delta `apply_doc` compares
//!   to tell which rules changed.
//! - [`crate::config::config_hash`]: the `recovery` member (configuration
//!   identity, spec §3.2).
//!
//! `doc_hash` itself stays `SHA-256(canonical bytes)` with no tag. Every
//! tag here is ASCII starting with `perch/`, and no tag is a prefix of
//! another. A canonical document starts with `{`, so no fragment preimage
//! equals a document preimage, and no two fragment kinds share a preimage.

use soroban_sdk::{Bytes, BytesN, Env};

/// Domain tag for [`rule_hash`].
pub const RULE_DOMAIN: &[u8; 10] = b"perch/rule";

/// `SHA-256("perch/rule" || R)`, where `R` is exactly the bytes one rule
/// contributes to its document's canonical serialization: one element of
/// the top-level `rules` array, without the separating commas.
///
/// It identifies the rule's text, signer *ids* included. It does not cover
/// the signers' credentials, which live in the document's `signers` member,
/// so the same rule text in two documents has the same `rule_hash`. Only
/// `doc_hash` identifies a whole document.
pub fn rule_hash(e: &Env, canonical_rule_json: &Bytes) -> BytesN<32> {
    let mut preimage = Bytes::from_slice(e, RULE_DOMAIN);
    preimage.append(canonical_rule_json);
    e.crypto().sha256(&preimage).to_bytes()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::{config_hash, CONFIG_DOMAIN};

    #[test]
    fn rule_hash_is_domain_separated_from_doc_and_config_hashes() {
        let e = Env::default();
        let json = Bytes::from_slice(&e, br#"{"name":"admin"}"#);
        let mut preimage = Bytes::from_slice(&e, b"perch/rule");
        preimage.append(&json);
        let h = rule_hash(&e, &json);
        assert_eq!(h, e.crypto().sha256(&preimage).to_bytes());
        assert_ne!(h, e.crypto().sha256(&json).to_bytes(), "not a doc_hash");
        assert_ne!(h, config_hash(&e, &json), "not a config_hash");
    }

    #[test]
    fn fragment_tags_are_prefix_free_and_never_start_a_document() {
        let tags: [&[u8]; 2] = [RULE_DOMAIN, CONFIG_DOMAIN];
        for (i, a) in tags.iter().enumerate() {
            assert_ne!(a[0], b'{');
            for (j, b) in tags.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{:?} prefixes {:?}", a, b);
                }
            }
        }
    }
}
