#![cfg_attr(not(feature = "std"), no_std)]
//! The perch policy document model.
//!
//! A [`PolicyDoc`] is the reviewable artifact at the center of perch: a
//! canonical, serializable description of a smart account's signers, rules,
//! scopes, and constraints. This crate builds both for `std` (off-chain review
//! tooling) and for `no_std + alloc` (on-chain, via soroban's bump allocator),
//! and is the trust root of the review workflow: what a reviewer
//! approves is `doc_hash = sha256(canonical bytes)` of a document, so parsing,
//! canonicalization, and validation here must be strict and deterministic.
//!
//! # Fail-closed philosophy
//!
//! Anything this model does not understand is an error, never a silent skip.
//! [`from_json`] parses by walking a float-free [`hifijson`] value tree by hand
//! (serde cannot ride the on-chain wasm — see [`parse`]), enforcing at every
//! level:
//!
//! - **Unknown fields** anywhere in the tree are rejected — including beside an
//!   internally-tagged variant's `type` (so the payload-less `self-admin` /
//!   `is-self` shapes accept no stray siblings).
//! - **Unknown enum tags** (`type` values) are rejected.
//! - **Duplicate object keys** at any nesting level are rejected (a
//!   content-aliasing vector — see [`parse`]).
//! - **`version != 1`** is rejected by [`from_json`] with a distinct error
//!   before anything else is examined, so future formats fail loudly and
//!   precisely.
//! - **Semantic validation** ([`validate()`]) collects every violation —
//!   duplicate ids/names, dangling signer references, malformed keys and
//!   addresses, ambiguous empty lists, dead expiries — rather than stopping
//!   at the first, and each error names the offending signer or rule.
//! - Removing all signature checks from a rule requires writing out the
//!   [`ACK_SENTINEL`] acknowledgement string verbatim.
//!
//! # Canonical form
//!
//! [`canonical_json`] implements RFC 8785 (JCS) for the subset of JSON this
//! model can produce (integers only, ASCII keys, no nulls — see [`canon`] for
//! the precise restrictions), and [`doc_hash`] / [`doc_hash_hex`] hash those
//! bytes with SHA-256. Two structurally equal documents hash identically no
//! matter how they were written down.
//!
//! # Authorization semantics
//!
//! Function and argument predicates inspect the selected call. An optional
//! [`AuthRoot`] additionally constrains this account's authorization-entry
//! root; a cap is cumulative state maintained by the account evaluator.
//! All conditions are conjunctive. The legacy RPN compiler supports local
//! predicates only and refuses root-bearing documents. See `docs/auth-root.md`
//! for the host boundary and compatibility rules.

extern crate alloc;

pub mod canon;
pub mod doc;
pub mod normal;
pub mod parse;
pub mod recovery;
pub mod validate;
pub mod verifier;

pub use canon::{
    canonical_json, recovery_canonical_json, rule_canonical_json, CANON_VERSION, RULE_HASH_DOMAIN,
};
#[cfg(feature = "std")]
pub use canon::{doc_hash, doc_hash_hex, rule_hash};
pub use doc::{
    AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, AuthRoot, BaselineCommitment,
    CapConstraint, ContractScope, GuardianSet, IsSelfPred, PolicyDoc, Principals, RecoveryConfig,
    RecoveryMode, RecoveryProfile, Rule, Scope, SelfAdminScope, SelfAuthenticatingPrincipals,
    SignerDecl, SignerMethod, StringInPred, StringPrefixPred, ThresholdPrincipals, U32EqPred,
    ZkFactor,
};
pub use normal::{normal_form, NotNormal};
pub use parse::{from_json, JsonError, ParseError};
pub use validate::{
    is_address_shape, is_contract_address_shape, validate, ValidationError, ACK_SENTINEL,
    MAX_SIGNER_KEY_LEN, MAX_STRING_PRED_LEN,
};
pub use verifier::{
    is_admin_document, parse_verifier_name, unverified_reuse, unverified_verifiers,
    MAX_VERIFIER_NAME_LEN,
};
