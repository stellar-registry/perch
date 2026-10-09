//! `perch-recovery`: the one recovery controller of perch's recovery stack —
//! guardian, ZK, and combined recovery under the `Loss` and `Protected`
//! profiles, implementing `docs/recovery/spec.md`.
//!
//! The controller is a constructorless, immutable deployable. An account
//! adopts an instance by naming it in its document's `recovery.controller`.
//! The account reaches it only through the hooks in
//! [`perch_recovery_interface::controller`] (`RecoveryHooksClient`), whose
//! client lives in the interface crate, so account Wasm links none of this
//! crate.
//!
//! - [`contract`]: the controller contract (state machine, hooks, views).
//! - [`types`]: attempt and evidence records.
#![no_std]

pub mod contract;
mod storage;
pub mod types;

pub use contract::{
    AttemptAuthorized, AttemptBegun, AttemptCancelled, ChangeEvidenceRecorded, EpochAdvanced,
    PerchRecovery, PerchRecoveryClient, RecoveryCompleted,
};
pub use perch_recovery_interface::controller::{RecoveryError, SyncOutcome, UpgradeStep};
pub use types::{ActivityGate, Attempt, AttemptState, ChangeApproval, EvidenceDomain};
