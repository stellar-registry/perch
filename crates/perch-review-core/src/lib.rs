//! A Perch account's verdict on an authorization entry, from a ledger
//! snapshot, with no host: what a wallet shows before the user signs.
//!
//! [`review_entry`] takes the account's `SorobanAuthorizationEntry`, the
//! account's ledger entries as `getLedgerEntries` returns them, and the
//! ledger sequence the transaction is expected to execute at, and runs the
//! account's own `__check_auth` checks ([`gate`]) with rule-core's
//! `rule_eval::check_auth` over them. It returns the verdict, the error the
//! account would fail with, the spending records it would store, and what
//! each chosen capped rule has left ([`remaining`]).
//!
//! **What the verdict is.** For the ledger entries given and the ledger
//! sequence given, assuming each payload signer the request does not mark
//! unverified authenticates, the verdict equals what the account's
//! `__check_auth` (fork `dev`, `perch_smart_account::check_auth`) returns on
//! that state at that ledger. Signatures are not verified here, and nothing
//! is known about another ledger or about state the snapshot does not hold:
//! other spends, an apply or a recovery completion between review and
//! inclusion all change the answer. A recovery completion is decided by the
//! recovery controller, which the core names rather than runs
//! ([`Outcome::Controller`]). `perch-integration-tests`
//! (`review_core_differential.rs`) checks this statement against the
//! account on rule-core's conformance traces and Perch's own gate cases.
//!
//! [`replay_witness`] re-checks an attenuation chain: a child rule set with
//! the steps that derive it from its parent. [`abi`] (feature `abi`) is the
//! browser build's interface.
#![no_std]
#![cfg_attr(not(feature = "abi"), forbid(unsafe_code))]

extern crate alloc;

#[cfg(feature = "abi")]
mod abi;
mod budget;
pub mod envelope;
pub mod gate;
pub mod json;
mod snapshot;
pub mod stored;
pub mod witness;
pub mod xdr;

use alloc::vec::Vec;

use soroban_facade::Val;

pub use budget::{remaining, Blocked, Remaining};
pub use gate::{
    review, Budget, Check, Chosen, Claimed, Error, EvalReason, Outcome, Refusal, Request, Review,
    Verified,
};
pub use snapshot::{Freeze, Snapshot, Unreadable};
pub use witness::{replay, replay_witness, Step, WitnessError};

/// The entry's `AuthPayload`: its rule ids, and its signers in map order.
pub(crate) fn payload(v: &Val) -> Option<(Vec<u32>, Vec<rule_eval::Signer>)> {
    let [ids, signers] = stored::fields(v, [b"context_rule_ids", b"signers"])?;
    let ids = stored::each(ids, stored::u32_of)?;
    let Val::Map(entries) = signers else {
        return None;
    };
    let mut signers = Vec::with_capacity(entries.len());
    for (k, sig) in entries {
        if !matches!(sig, Val::Bytes(_)) {
            return None;
        }
        signers.push(stored::signer(k)?);
    }
    Some((ids, signers))
}

/// The account's verdict on its authorization entry `entry`, over its
/// ledger entries `ledger_entries` at ledger `ledger` (crate docs).
/// `verified` holds one flag per payload signer, in the payload's order, or
/// is empty to assume every signature verifies.
///
/// # Errors
///
/// An [`Unreadable`] naming the input the core cannot read: no verdict is
/// given for it.
pub fn review_entry<'a>(
    entry: &[u8],
    ledger_entries: impl IntoIterator<Item = &'a [u8]>,
    ledger: u32,
    verified: &[Verified],
) -> Result<(Vec<u8>, Review), Unreadable> {
    let e = xdr::entry(entry).ok_or(Unreadable::Entry)?;
    let (rule_ids, signers) = payload(&e.payload).ok_or(Unreadable::Payload)?;
    if !verified.is_empty() && verified.len() != signers.len() {
        return Err(Unreadable::Verified);
    }
    let snapshot = Snapshot::from_ledger_entries(&e.account, ledger_entries)?;
    let request = Request {
        account: e.account.clone(),
        contexts: e.contexts,
        rule_ids,
        signers: signers
            .into_iter()
            .enumerate()
            .map(|(i, signer)| Claimed {
                signer,
                verified: verified.get(i).copied().unwrap_or(Verified::Assumed),
            })
            .collect(),
        delegates: e.delegates,
        ledger,
    };
    Ok((e.account, review(&snapshot, &request)?))
}
