//! The perch policy document model.
//!
//! A `PolicyDoc` is the reviewable artifact at the center of perch: a canonical,
//! serializable description of a smart account's signers, rules, scopes, and
//! constraints. Canonical JSON (JCS) gives every document a stable
//! `doc_hash = sha256(canonical bytes)`; validation is fail-closed
//! (unknown fields and unknown versions are rejected).
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/4>
