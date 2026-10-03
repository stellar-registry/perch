//! Typed storage handles (`soroban-sdk-tools`' `#[contractstorage]`). Every
//! entry is per account, per attempt, per nullifier, or per statement
//! digest: the controller has no global configuration (spec §16).
//!
//! Persistent entries are extended to the network maximum whenever written
//! (and by the permissionless `renew`), and an archived persistent entry is
//! unavailable rather than absent, so no counter or configuration can
//! silently reset (spec §3.6). Collecting attempts and completion markers
//! are temporary: losing a collecting attempt to expiry is the same as its
//! evidence window ending.

use crate::types::{Attempt, ChangeApproval, CompletionMarker};
use perch_recovery_interface::config::CompiledRecoveryConfig;
use soroban_sdk::{Address, Bytes, BytesN};
use soroban_sdk_tools::{contractstorage, PersistentMap, TemporaryMap};

#[contractstorage]
#[allow(dead_code)] // the field names only derive storage keys + accessors
pub struct RecoveryStorage {
    /// The account's configuration at this controller. Written only by
    /// `rcv_sync`.
    pub config: PersistentMap<Address, CompiledRecoveryConfig>,
    /// The account's configuration epoch (spec §3.3). Never reset.
    pub epoch: PersistentMap<Address, u64>,
    /// The next attempt id. Never reused.
    pub next_attempt: PersistentMap<Address, u64>,
    /// Collecting attempts with a smaller id were invalidated by a
    /// sibling's authorization (spec T4).
    pub invalidate_below: PersistentMap<Address, u64>,
    /// The id of the authorized attempt, while one may be live.
    pub authorized: PersistentMap<Address, u64>,
    /// Evidence-based cancellations of authorized attempts (spec T6).
    pub cancels: PersistentMap<Address, u32>,
    /// Attempts that were ever authorized.
    pub attempt: PersistentMap<(Address, u64), Attempt>,
    /// Attempts that never left `Collecting` (or were cancelled there).
    pub collecting: TemporaryMap<(Address, u64), Attempt>,
    /// The completing invocation's marker (spec T5).
    pub completing: TemporaryMap<Address, CompletionMarker>,
    /// Spent nullifiers and the account that spent each (spec §11).
    pub nullifier: PersistentMap<BytesN<32>, Address>,
    /// Recorded `Reconfigure`/`Upgrade` evidence, by statement digest.
    pub approval: PersistentMap<(Address, BytesN<32>), ChangeApproval>,
    /// Published baseline documents' canonical bytes, by hash (spec §3.5).
    pub baseline: PersistentMap<(Address, BytesN<32>), Bytes>,
}
