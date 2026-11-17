//! The core's byte interface: a small binary envelope in, JSON out
//! ([`crate::json`]). The browser build exports exactly these functions
//! (`abi`); natively they are what the tests and fixtures run, so the wasm
//! and native builds answer the same bytes.
//!
//! Every length and integer is a big-endian `u32`; byte strings are a
//! length followed by the bytes, unpadded.
//!
//! - [`review`]: `1`, the ledger sequence, the `SorobanAuthorizationEntry`
//!   XDR, the number of ledger entries and each `LedgerEntryData` XDR, then
//!   the number of verified flags and one byte each (`0` does not verify,
//!   `1` verifies, `2` assumed; none assumes every signature verifies).
//! - [`witness`]: `1`, then three `ScVal` XDRs: the parent rules and the
//!   child rules (each a vector of `StoredRule`) around the steps (a vector
//!   of [`crate::witness::step`] values): parent, steps, child.
//! - [`budget`]: `1`, a `StoredRecord` `ScVal`, a `StoredCap` `ScVal`, the
//!   ledger sequence.
//! - [`chosen`]: `1` and a `SorobanAuthorizationEntry` XDR: the account and
//!   the rule ids its payload chooses, which name the ledger entries to
//!   fetch (`Snapshot::keys`).

use alloc::vec::Vec;

use soroban_facade::xdr::decode;

use crate::snapshot::Unreadable;
use crate::stored::{each, fields, i128_of, u32_of};
use crate::xdr::R;
use crate::{json, Verified};

fn bytes<'a>(r: &mut R<'a>) -> Option<&'a [u8]> {
    let n = usize::try_from(r.u32()?).ok()?;
    r.take(n)
}

fn version(r: &mut R<'_>) -> Option<()> {
    (r.u32()? == 1).then_some(())
}

/// A review envelope's fields.
struct ReviewInput<'a> {
    ledger: u32,
    entry: &'a [u8],
    entries: Vec<&'a [u8]>,
    verified: Vec<Verified>,
}

/// The review of one envelope, as JSON.
#[must_use]
pub fn review(input: &[u8]) -> Vec<u8> {
    let parse = || -> Option<ReviewInput<'_>> {
        let mut r = R::new(input);
        version(&mut r)?;
        let ledger = r.u32()?;
        let entry = bytes(&mut r)?;
        let n = r.u32()?;
        let mut entries = Vec::new();
        for _ in 0..n {
            entries.push(bytes(&mut r)?);
        }
        let m = r.u32()?;
        let mut verified = Vec::new();
        for _ in 0..m {
            verified.push(match r.take(1)?[0] {
                0 => Verified::No,
                1 => Verified::Yes,
                2 => Verified::Assumed,
                _ => return None,
            });
        }
        r.done().then_some(ReviewInput {
            ledger,
            entry,
            entries,
            verified,
        })
    };
    let Some(input) = parse() else {
        return json::unreadable(Unreadable::Input);
    };
    match crate::review_entry(input.entry, input.entries, input.ledger, &input.verified) {
        Ok((account, review)) => json::review(&account, input.ledger, &review),
        Err(u) => json::unreadable(u),
    }
}

/// The witness check of one envelope, as JSON.
#[must_use]
pub fn witness(input: &[u8]) -> Vec<u8> {
    let parse = || {
        let mut r = R::new(input);
        version(&mut r)?;
        let rules = |b: &[u8]| each(&decode(b)?, crate::stored::rule);
        let parent = rules(bytes(&mut r)?)?;
        let steps = each(&decode(bytes(&mut r)?)?, crate::witness::step)?;
        let child = rules(bytes(&mut r)?)?;
        r.done().then_some((parent, steps, child))
    };
    match parse() {
        Some((parent, steps, child)) => {
            json::witness(&crate::witness::replay_witness(parent, &steps, &child))
        }
        None => json::unreadable(Unreadable::Input),
    }
}

/// The budget of one envelope, as JSON.
#[must_use]
pub fn budget(input: &[u8]) -> Vec<u8> {
    let parse = || {
        let mut r = R::new(input);
        version(&mut r)?;
        let record = crate::stored::record(&decode(bytes(&mut r)?)?)?;
        let cap = decode(bytes(&mut r)?)?;
        let [_amount_arg, limit, period] = fields(&cap, [b"amount_arg", b"limit", b"period"])?;
        let (limit, period) = (i128_of(limit)?, u32_of(period)?);
        let now = r.u32()?;
        r.done().then_some((record, limit, period, now))
    };
    match parse() {
        Some((record, limit, period, now)) => {
            json::budget(&crate::remaining(&record, limit, period, now))
        }
        None => json::unreadable(Unreadable::Input),
    }
}

/// The account and chosen rule ids of one authorization entry, as JSON:
/// `{"v":1,"account":<hex>,"rule_ids":[..]}`.
#[must_use]
pub fn chosen(input: &[u8]) -> Vec<u8> {
    let parse = || {
        let mut r = R::new(input);
        version(&mut r)?;
        let entry = bytes(&mut r)?;
        r.done().then_some(entry)
    };
    let Some(entry) = parse() else {
        return json::unreadable(Unreadable::Input);
    };
    let Some(e) = crate::xdr::entry(entry) else {
        return json::unreadable(Unreadable::Entry);
    };
    match crate::payload(&e.payload) {
        Some((ids, _)) => json::chosen(&e.account, &ids),
        None => json::unreadable(Unreadable::Payload),
    }
}
