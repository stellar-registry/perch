//! Lowering from `perch_ir::PolicyDoc` to an executable `Plan` — an ordered,
//! transaction-grouped sequence of OZ smart-account calls (deploys,
//! `add_context_rule`, policy installs).
//!
//! Two invariants are the security core of this crate:
//!
//! - **Signer sufficiency**: in OZ, attaching any policy to a rule defers
//!   signer-sufficiency checking entirely to the policies. Every lowered rule
//!   must fail a zero-signature authorization unless explicitly declared
//!   self-authenticating.
//! - **Atomic mutation**: plan steps carry a `tx_group`; sequences that would
//!   transiently brick the account are grouped into one transaction or
//!   rejected.
//!
//! Tracking issue: <https://github.com/stellar-registry/perch/issues/7>
