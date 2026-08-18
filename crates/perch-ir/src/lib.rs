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
//! Anything this model does not understand is an error, never a silent skip:
//!
//! - **Unknown fields** anywhere in the tree are rejected
//!   (`deny_unknown_fields` on every struct; enum variants wrap payload
//!   structs so the guarantee holds inside tagged enums too — including the
//!   payload-less `self-admin` / `is-self` variants, which use empty structs
//!   because serde's internally-tagged unit variants silently accept extra
//!   fields).
//! - **Unknown enum tags** are rejected by serde's tagged-enum handling.
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
//! # Stateless, per-invocation semantics
//!
//! Every constraint a [`PolicyDoc`] can express is a **pure predicate over a
//! single invocation** — this call's function name and this call's arguments.
//! Perch has no op that reads or writes state, so it cannot express a
//! *cumulative* constraint: "at most N calls per day", "at most X total
//! transferred this month". An [`ArgPred`] bound on a numeric argument limits
//! *one* call's value, never a running total.
//!
//! This matters for spend limits specifically: a per-invocation bound is **not**
//! a spend cap. An authorized signer simply issues the call repeatedly, each
//! within the per-call bound, and drains any intended total — the exact drain
//! passkey-kit documents for a per-transfer limit without a cumulative one. A
//! cumulative cap requires a *stateful* sibling policy — e.g. OpenZeppelin's
//! `spending_limit` — attached to the same OZ context rule alongside perch's
//! interpreter, where OZ enforces every attached policy (AND). Perch stays the
//! stateless "what may be called" layer; cumulative accounting lives in a
//! purpose-built stateful contract, never here.
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/4>

extern crate alloc;

pub mod canon;
pub mod doc;
pub mod parse;
pub mod validate;

pub use canon::{canonical_json, doc_hash, doc_hash_hex, CANON_VERSION};
pub use doc::{
    AddressEqPred, AllPrincipals, ArgConstraint, ArgPred, CapConstraint, ContractScope, IsSelfPred,
    PolicyDoc, Principals, Rule, Scope, SelfAdminScope, SelfAuthenticatingPrincipals, SignerDecl,
    StringInPred, StringPrefixPred, U32EqPred,
};
pub use parse::{from_json, ParseError};
pub use validate::{
    is_address_shape, is_contract_address_shape, validate, ValidationError, ACK_SENTINEL,
    MAX_SIGNER_KEY_LEN,
};
