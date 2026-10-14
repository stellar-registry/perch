//! # perch-admin-timelock
//!
//! An owner-gated timelock for administrative calls. The **owner** —
//! canonically the perch admin multisig, a 2-of-3 perch smart account — queues
//! an arbitrary cross-contract call with a visible delay; after the delay
//! elapses the owner executes it, or cancels it beforehand. Nothing else can
//! queue, execute, or cancel.
//!
//! This is the external-call generalization of the perch account's own
//! `schedule_upgrade` → `execute_upgrade` / `cancel_upgrade` trio
//! (`crates/perch-smart-account/src/lib.rs`): the same ledger-sequence delay and
//! the same owner authorization on every step, but targeting any contract
//! rather than only a self-upgrade.
//!
//! ## Why it exists
//!
//! The one mutable admin surface in the perch stack is the stateless registry's
//! `upgrade` / `set_admin` / `set_manager` / `remove_manager`
//! (`crates/perch-stateless-registry`), every one of which takes effect the
//! instant the admin authorizes it. Pointing the registry's admin at a timelock
//! — `registry.set_admin(timelock)` — turns each of those into a **delayed,
//! cancelable multisig action**: the multisig queues it, the delay is public
//! (the [`Queued`] event carries the eta), and anyone watching sees the change
//! coming before it can land. A mistaken or coerced admin action can be
//! cancelled inside the window.
//!
//! ## How a contract can be an admin
//!
//! The registry gates its admin entry points with `admin.require_auth()`
//! (admin-sep's `Administratable`). Soroban satisfies `require_auth` for a
//! *contract* address by **invoker authorization**: when this timelock calls
//! `registry.upgrade(..)` directly, the registry's `require_auth` of the
//! timelock passes because the timelock is the direct caller — no `__check_auth`
//! and no registry code change required. The `owner_invoker_auth_reaches_admin`
//! test proves exactly this with `mock_auths` scoped to the owner alone.
//!
//! ## Delay
//!
//! The delay is a fixed number of ledgers set at construction and enforced in
//! ledgers, exactly like the account's upgrade delay
//! (`perch_recovery_interface::account::ACCOUNT_UPGRADE_DELAY_LEDGERS`). 17 280
//! ledgers is ~24h at the nominal 5-second close; a few ledgers is seconds (for
//! testnet rehearsals). It is enforced in ledgers regardless of the actual
//! close time, so nothing here converts a human-supplied duration in seconds.
#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, Address, Env, Symbol, Val, Vec,
};
use soroban_sdk_tools::{contractstorage, scerr, InstanceItem, PersistentMap};

/// Everything the timelock can refuse. Codes are assigned in declaration order
/// (scerr); append new variants at the end so existing codes never move.
#[scerr]
pub enum TimelockError {
    /// A queued eta overflowed `u32` (the current ledger plus the delay).
    TimingOverflow,
    /// No operation with that id was ever queued.
    UnknownOperation,
    /// The operation is not `Queued` — it was already executed or cancelled.
    NotQueued,
    /// `execute` was called before the operation's eta ledger.
    TooEarly,
}

/// Where a queued operation is in its lifecycle. An operation only ever moves
/// `Queued` → `Executed` or `Queued` → `Cancelled`; both are terminal.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpStatus {
    Queued,
    Executed,
    Cancelled,
}

/// One queued administrative call.
#[contracttype]
#[derive(Clone, Debug)]
pub struct Operation {
    /// The contract this call targets (e.g. a stateless registry).
    pub target: Address,
    /// The function to invoke on `target` (e.g. `upgrade`, `set_admin`).
    pub function: Symbol,
    /// The arguments, replayed verbatim to the invocation at execute time.
    pub args: Vec<Val>,
    /// The first ledger sequence at which `execute` is allowed.
    pub eta: u32,
    /// Where the operation is in its lifecycle.
    pub status: OpStatus,
}

/// Emitted when the owner queues an operation. `eta` is public so watchers see
/// the change coming before it can execute.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Queued {
    #[topic]
    pub id: u64,
    pub target: Address,
    pub function: Symbol,
    pub eta: u32,
}

/// Emitted when a queued operation executes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Executed {
    #[topic]
    pub id: u64,
}

/// Emitted when a queued operation is cancelled.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cancelled {
    #[topic]
    pub id: u64,
}

#[contractstorage]
#[allow(dead_code)] // field names only derive storage keys + typed accessors
struct Store {
    /// The sole authorizer of queue/execute/cancel — the admin multisig. Fixed
    /// at construction: the multisig account's address is permanent, and it
    /// rotates its own signers via `apply_doc`, so this never needs to change.
    owner: InstanceItem<Address>,
    /// Delay in ledgers between queue and the earliest execute.
    delay: InstanceItem<u32>,
    /// The next operation id. Monotonic, never reused.
    next_id: InstanceItem<u64>,
    /// Every operation ever queued, by id. Persistent: an operation must
    /// outlive its delay (a 24h delay is well inside the default persistent
    /// TTL).
    op: PersistentMap<u64, Operation>,
}

#[contract]
pub struct AdminTimelock;

#[contractimpl]
impl AdminTimelock {
    /// Construct with the `owner` that may queue/execute/cancel and the
    /// `delay_ledgers` every queued operation waits before it can execute.
    pub fn __constructor(e: &Env, owner: Address, delay_ledgers: u32) {
        Store::set_owner(e, &owner);
        Store::set_delay(e, &delay_ledgers);
        Store::set_next_id(e, &0);
    }

    /// The multisig that authorizes every action.
    pub fn owner(e: &Env) -> Address {
        Store::get_owner(e).unwrap()
    }

    /// The configured delay in ledgers.
    pub fn delay(e: &Env) -> u32 {
        Store::get_delay(e).unwrap()
    }

    /// The operation with `id`, if it was ever queued.
    pub fn get(e: &Env, id: u64) -> Option<Operation> {
        Store::get_op(e, &id)
    }

    /// Queue `function(args)` against `target`, executable after `delay`
    /// ledgers. Owner authorization. Returns the new operation id.
    pub fn queue(
        e: &Env,
        target: Address,
        function: Symbol,
        args: Vec<Val>,
    ) -> Result<u64, TimelockError> {
        Self::owner(e).require_auth();
        let id = Store::get_next_id(e).unwrap_or(0);
        let eta = e
            .ledger()
            .sequence()
            .checked_add(Store::get_delay(e).unwrap())
            .ok_or(TimelockError::TimingOverflow)?;
        Store::set_op(
            e,
            &id,
            &Operation {
                target: target.clone(),
                function: function.clone(),
                args,
                eta,
                status: OpStatus::Queued,
            },
        );
        Store::set_next_id(e, &(id + 1));
        Queued {
            id,
            target,
            function,
            eta,
        }
        .publish(e);
        Ok(id)
    }

    /// Execute operation `id` once its delay has elapsed. Owner authorization.
    ///
    /// Invokes `target.function(args)` with the timelock as the direct caller,
    /// so a target that `require_auth`s this timelock (e.g. a registry whose
    /// admin is this timelock) is authorized by invoker auth. Returns whatever
    /// the target returns.
    ///
    /// The operation is marked `Executed` before the invocation, so a target
    /// cannot re-enter and run it twice; a trapping invocation rolls back the
    /// whole call, including that mark, leaving the operation `Queued` to retry.
    pub fn execute(e: &Env, id: u64) -> Result<Val, TimelockError> {
        Self::owner(e).require_auth();
        let mut op = Store::get_op(e, &id).ok_or(TimelockError::UnknownOperation)?;
        if op.status != OpStatus::Queued {
            return Err(TimelockError::NotQueued);
        }
        if e.ledger().sequence() < op.eta {
            return Err(TimelockError::TooEarly);
        }
        op.status = OpStatus::Executed;
        Store::set_op(e, &id, &op);
        let result = e.invoke_contract::<Val>(&op.target, &op.function, op.args);
        Executed { id }.publish(e);
        Ok(result)
    }

    /// Cancel a still-queued operation `id`. Owner authorization.
    pub fn cancel(e: &Env, id: u64) -> Result<(), TimelockError> {
        Self::owner(e).require_auth();
        let mut op = Store::get_op(e, &id).ok_or(TimelockError::UnknownOperation)?;
        if op.status != OpStatus::Queued {
            return Err(TimelockError::NotQueued);
        }
        op.status = OpStatus::Cancelled;
        Store::set_op(e, &id, &op);
        Cancelled { id }.publish(e);
        Ok(())
    }
}

#[cfg(test)]
mod test;
