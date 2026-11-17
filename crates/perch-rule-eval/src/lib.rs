//! Perch's rules as rule-core's evaluator (`rule-eval`) reads them.
//!
//! - [`convert`]: host values as rule-eval's plain data, read through
//!   `soroban-facade` (an address as its `ScAddress` XDR, a signer, an
//!   argument value, `__check_auth`'s contexts), and back to host values
//!   where storage needs them.
//! - [`StoredRule`] and [`StoredRecord`]: `#[contracttype]` mirrors of
//!   `rule_eval::Rule` and `rule_eval::SpendRecord`, for an account's
//!   storage, a stored one read back from its XDR ([`mirror`]).
//! - [`CompiledModel`]: a `#[contracttype]` mirror of `rule_eval::Doc`, the
//!   part of a policy document rule-eval's lowering reads. [`doc_of`] reads
//!   it as a `Doc`; with the `ir` feature, [`model_of`] builds it from a
//!   validated `perch_ir::PolicyDoc`.
//! - [`denote`]: the `rule_eval::Rule` an installed Perch rule enforces (an
//!   OpenZeppelin context rule, the interpreter's program and the spending
//!   limit's parameters).
//! - [`admin_survives`] and [`guarded`]: the account's anti-brick check and
//!   its signer-sufficiency invariant, on rule-eval's rules.
//!
//! Its tests check the mirrors round-trip and, in `perch-integration-tests`
//! (`tests/perch_rule_eval.rs`), that `rule_eval::lower(doc_of(model_of(d)))`
//! equals the denotation of `perch_compile::compile(d)`. `tests/vectors.rs`
//! checks that the pinned `rule-eval` and `soroban-facade` reproduce every
//! conformance vector of the same rev.
#![no_std]

extern crate alloc;

mod admin;
pub mod convert;
mod denote;
pub mod mirror;
mod model;
mod stored;

pub use admin::{admin_survives, guarded};
pub use denote::{denote, Installed};
pub use model::{
    doc_of, doc_of_in, CompiledModel, ModelArg, ModelCap, ModelPred, ModelPrincipals,
    ModelRecovery, ModelRule, ModelScope, ModelSigner, ModelZk,
};
#[cfg(feature = "ir")]
pub use model::{model_of, ModelError};
pub use stored::{
    StoredCap, StoredCond, StoredEntry, StoredFunctions, StoredRecord, StoredRule, StoredVal,
};
