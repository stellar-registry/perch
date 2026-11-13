//! What a capped rule has left to spend: [`remaining`], stated through
//! rule-eval's `check_spend`, the check the account's `__check_auth` makes
//! for every charge.
//!
//! For every record `r`, cap `(limit, period)`, ledger `now` and amount
//! `a >= 0`:
//!
//! ```text
//! check_spend(r, limit, period, now, a).is_ok()  <=>  a <= remaining(r, limit, period, now).amount
//! ```
//!
//! `check_spend` accepts a zero amount always, and a positive one when the
//! record is not ahead of `now`, the eviction and the totals stay within
//! `i128`, the history left after eviction is not full, and the total within
//! the window plus the amount is at most `limit`. So `remaining` is `0`
//! when the record is ahead of `now`, an eviction sum overflows or the
//! history is full ([`Blocked`] says which), and otherwise `limit` less the
//! total within the window, at least `0` and at most `i128::MAX`.
//! `tests/remaining.rs` checks the equivalence on the window's edges and on
//! a sweep of records, caps, ledgers and amounts.

use rule_eval::{SpendEntry, SpendRecord, MAX_HISTORY_ENTRIES};

/// Why no positive amount fits, whatever the limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    /// `now` is before the newest recorded spend (`LedgerBeforeNewest`).
    LedgerBeforeNewest,
    /// The amounts leaving the window, or the total less them, do not fit in
    /// an `i128` (`Overflow`).
    Overflow,
    /// The history left in the window already holds `MAX_HISTORY_ENTRIES`
    /// spends (`HistoryFull`).
    HistoryFull,
}

/// A capped rule's budget at one ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Remaining {
    /// The largest amount a spend at this ledger may have.
    pub amount: i128,
    /// What the record holds within the window: its total less the spends
    /// the window has left. `0` when [`Remaining::blocked`] is
    /// `LedgerBeforeNewest` or `Overflow`.
    pub spent: i128,
    /// The first ledger at which a spend now in the window leaves it, if
    /// any: the oldest kept spend's ledger plus `period`.
    pub next_release: Option<u32>,
    /// Why no positive amount fits, when none does for a reason other than
    /// the limit.
    pub blocked: Option<Blocked>,
}

/// What a spend under the cap `(limit, period)` may still be at ledger
/// `now`, given what `record` has spent (module docs).
#[must_use]
pub fn remaining(record: &SpendRecord, limit: i128, period: u32, now: u32) -> Remaining {
    let none = |spent, next_release, blocked| Remaining {
        amount: 0,
        spent,
        next_release,
        blocked: Some(blocked),
    };
    let history: &[SpendEntry] = &record.history;
    if history.last().is_some_and(|e| now < e.ledger) {
        return none(0, None, Blocked::LedgerBeforeNewest);
    }
    // `check_spend` evicts the front entries at or before this ledger.
    let cutoff = now.saturating_sub(period);
    let mut removed: i128 = 0;
    let mut kept_from = history.len();
    for (i, e) in history.iter().enumerate() {
        if e.ledger > cutoff {
            kept_from = i;
            break;
        }
        removed = match removed.checked_add(e.amount) {
            Some(x) => x,
            None => return none(0, None, Blocked::Overflow),
        };
    }
    let next_release = history
        .get(kept_from)
        .and_then(|e| e.ledger.checked_add(period));
    let Some(spent) = record.total.checked_sub(removed) else {
        return none(0, next_release, Blocked::Overflow);
    };
    if history.len() - kept_from >= MAX_HISTORY_ENTRIES {
        return none(spent, next_release, Blocked::HistoryFull);
    }
    Remaining {
        amount: limit.saturating_sub(spent).max(0),
        spent,
        next_release,
        blocked: None,
    }
}
