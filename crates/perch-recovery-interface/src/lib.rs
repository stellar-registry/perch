//! `perch-recovery-interface`: the **one recovery statement** that every
//! piece of perch's recovery stack binds evidence to, its canonical byte
//! encoding, and the cross-contract interfaces between the recovery
//! controller, the ZK adapter, the proof verifier, and the membership pool.
//!
//! The authoritative behaviour (states, transitions, who may authorize what,
//! which document changes a recovery may make) is `docs/recovery/spec.md`.
//! This crate is the code half of that spec's "Recovery statement" and
//! "ZK adapter boundary" sections, and the byte layout in
//! `docs/recovery/statement.md`. It holds no state and exports no contract
//! entry point, so the controller, the adapter, the pool, and the account can
//! all link it without linking each other (no circular build-time pins).
//!
//! - [`statement`]: [`RecoveryStatement`], its action domains, its canonical
//!   encoding and SHA-256 digest. Guardian signatures and ZK proofs bind the
//!   same digest.
//! - [`credential`]: canonical credential fingerprints (what revocation
//!   compares) and the replacement set a recovery attempt declares.
//! - [`zk`]: the structured adapter boundary ([`zk::ZkAdapterInterface`]),
//!   the evidence/binding types, the projection of a statement onto circuit
//!   field elements, and the circuit domain tags.
//! - [`account`]: account-side constants the spec fixes (the upgrade delay,
//!   the invoker-only function names).
#![no_std]

mod encode;

pub mod account;
pub mod credential;
pub mod statement;
pub mod zk;

pub use encode::{address_payload, AddressKind};
pub use statement::{
    AttemptSubject, CancelSubject, ConfigBinding, ConfigChange, RecoveryAction, RecoveryEvidence,
    RecoveryStatement, StatementError, StatementSubject, StatementTiming, UpgradeSubject,
};
