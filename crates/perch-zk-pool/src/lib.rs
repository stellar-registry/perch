//! `perch-zk-pool`: the membership pool ZK recovery proves against
//! (`docs/recovery/spec.md` §14).
//!
//! An account inserts a commitment `inner = H(DOM_LEAF, secret)` together
//! with the enrollment id its recovery configuration names, from its own
//! `apply_doc` (`rcv_insert` is invoker-only, spec §15). The pool wraps it into
//! a leaf bound to both (`H(DOM_BIND, account, enrollment_id, inner)`, see
//! `perch-zk-primitives`), appends the leaf to the active tree, and records
//! the new root. A recovery proof later shows knowledge of a secret whose leaf
//! is under one of the pool's roots, without revealing which leaf.
//!
//! - Every root a tree has ever had stays acceptable. Trees are append-only,
//!   so a historical root is as sound as the latest one, and a recent-roots
//!   window would let anyone who inserts fast enough push a victim's root out
//!   before their proof lands.
//! - A full tree is sealed by the insertion that fills it, and the next
//!   insertion opens a new tree: a full tree never blocks enrollment.
//! - Each `(account, enrollment_id)` is inserted at most once. The account
//!   enforces this too (spec §3.4); the pool refuses a repeat regardless, so a
//!   second secret can never be added under an id a configuration names.
//!
//! The deployable is constructorless and has no admin, owner, upgrade, pause,
//! or factory authority: every instance of one wasm behaves identically, and
//! its only per-instance state is the trees accounts have filled. See
//! `docs/zk/pool.md`.

#![no_std]

use soroban_sdk::{contracttype, BytesN};
use soroban_sdk_tools::scerr;

/// Wire version of this pool's interface and semantics. Bumped on any change
/// a client or verifier could observe; a new version is always a new wasm and
/// therefore a new address.
pub const VERSION: u32 = 1;

/// Tree depth. Each tree holds `2^TREE_DEPTH` leaves before the pool rolls
/// over to the next one. Must equal the adapter's `tree_depth()`.
#[cfg(not(feature = "tree-depth-24"))]
pub const TREE_DEPTH: u32 = 32;
#[cfg(feature = "tree-depth-24")]
pub const TREE_DEPTH: u32 = 24;

/// Upper bound on `leaves`/`renew_leaves` page sizes, so one call stays well
/// inside a transaction's ledger-entry footprint limits.
pub const MAX_PAGE: u32 = 64;

/// Everything the pool can refuse.
#[scerr]
pub enum PoolError {
    /// The commitment is not a canonical BN254 field element (`>= r`).
    NonCanonicalCommitment,
    /// The inserting address is not a contract. Leaves bind a contract id.
    AccountNotContract,
    /// This account already inserted a leaf under this enrollment id.
    EnrollmentIdTaken,
    /// No tree with this id has been opened.
    UnknownTree,
    /// A page request exceeds `MAX_PAGE`.
    PageTooLarge,
    /// The tree id counter would overflow (2^32 full trees).
    TreeIdOverflow,
}

/// Where an insertion landed. `(tree_id, index)` is the leaf's permanent
/// position; `root` is the tree's root right after the insertion.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Insertion {
    pub tree_id: u32,
    pub index: u64,
    pub leaf: BytesN<32>,
    pub root: BytesN<32>,
}

/// A leaf's permanent position.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafPosition {
    pub tree_id: u32,
    pub index: u64,
}

/// A tree's public summary.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeInfo {
    pub tree_id: u32,
    /// Leaves inserted so far.
    pub size: u64,
    pub capacity: u64,
    /// The latest root (the empty-tree root before any insertion).
    pub root: BytesN<32>,
    /// Full, and never written again.
    pub sealed: bool,
}

// The adapter and the controller reach the pool through
// `perch-recovery-interface`'s `MembershipPoolInterface` (`is_known_root`,
// `depth`), which `PerchZkPool` implements.

mod contract;
pub(crate) mod merkle;

pub use contract::{LeafInserted, PerchZkPool, PerchZkPoolClient};
/// The pool's storage layout is part of its public interface: a witness
/// builder can read `Leaf` entries straight from the ledger.
pub use merkle::{PoolKey, TreeState};

#[cfg(test)]
mod test;
