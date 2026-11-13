//! `remaining` against rule-eval's `check_spend`: for every record, cap,
//! ledger and amount `a >= 0`, `check_spend` accepts `a` exactly when
//! `a <= remaining(..).amount` (`src/budget.rs`).
//!
//! The window's edges are checked by name: a spend at ledger `L` under a
//! period `P` counts through ledger `L + P - 1` and leaves the window at
//! `L + P`; a spend at ledger 0 is always out of the window, since
//! `check_spend` evicts every entry at or before `now.saturating_sub(P)`.
//! Then a sweep over records, caps, ledgers and amounts near every boundary
//! checks the equivalence itself.

use perch_review_core::{remaining, Blocked};
use rule_eval::{check_spend, SpendEntry, SpendRecord, MAX_HISTORY_ENTRIES};

fn record(spends: &[(u32, i128)]) -> SpendRecord {
    SpendRecord {
        history: spends
            .iter()
            .map(|&(ledger, amount)| SpendEntry { ledger, amount })
            .collect(),
        // Wrapping, so a record whose total overflowed can be built too.
        total: spends.iter().fold(0i128, |t, s| t.wrapping_add(s.1)),
    }
}

/// Every amount worth trying against `left`: the boundary and its
/// neighbours, zero and the extremes.
fn amounts(left: i128) -> Vec<i128> {
    let mut out = vec![0, 1, 2, i128::MAX, i128::MAX - 1, 1 << 64];
    for d in [-2i128, -1, 0, 1, 2] {
        if let Some(a) = left.checked_add(d) {
            if a >= 0 {
                out.push(a);
            }
        }
    }
    out
}

/// The equivalence for one record, cap and ledger, over [`amounts`].
fn agrees(r: &SpendRecord, limit: i128, period: u32, now: u32) -> Result<(), String> {
    let left = remaining(r, limit, period, now);
    if left.amount < 0 {
        return Err(format!("negative remaining {}", left.amount));
    }
    for a in amounts(left.amount) {
        let ok = check_spend(r, limit, period, now, a).is_ok();
        if ok != (a <= left.amount) {
            return Err(format!(
                "limit {limit} period {period} now {now} amount {a}: check_spend {} but remaining {}",
                if ok { "accepts" } else { "refuses" },
                left.amount
            ));
        }
    }
    Ok(())
}

#[test]
fn a_spend_counts_through_the_last_ledger_of_its_window() {
    let r = record(&[(1000, 40)]);
    // Period 100: the spend at 1000 counts at 1000..=1099.
    for now in [1000, 1050, 1099] {
        let left = remaining(&r, 100, 100, now);
        assert_eq!((left.amount, left.spent), (60, 40), "at {now}");
        assert_eq!(left.next_release, Some(1100));
        agrees(&r, 100, 100, now).unwrap();
    }
    // ...and leaves it at 1100.
    for now in [1100, 1101, u32::MAX] {
        let left = remaining(&r, 100, 100, now);
        assert_eq!((left.amount, left.spent), (100, 0), "at {now}");
        assert_eq!(left.next_release, None);
        agrees(&r, 100, 100, now).unwrap();
    }
}

#[test]
fn spends_leave_the_window_one_at_a_time() {
    let r = record(&[(10, 5), (20, 7), (30, 11)]);
    let at = |now| {
        let left = remaining(&r, 30, 15, now);
        (left.amount, left.next_release)
    };
    // At 30 the cutoff is 15: the spend at 10 has left, 7 + 11 remain.
    // Before the newest spend's ledger nothing fits.
    assert_eq!(at(29), (0, None));
    assert_eq!(at(30), (12, Some(35)));
    assert_eq!(at(34), (12, Some(35)));
    assert_eq!(at(35), (19, Some(45)));
    assert_eq!(at(44), (19, Some(45)));
    assert_eq!(at(45), (30, None));
    assert_eq!(at(1000), (30, None));
    for now in 29..=60 {
        agrees(&r, 30, 15, now).unwrap();
    }
}

#[test]
fn a_spend_at_ledger_zero_is_never_in_the_window() {
    let r = record(&[(0, 9)]);
    for now in [0, 1, 50, 99, 100] {
        assert_eq!(remaining(&r, 10, 100, now).amount, 10, "at {now}");
        agrees(&r, 10, 100, now).unwrap();
    }
    // Before the period has run once, the cutoff saturates at 0: a spend
    // at ledger 1 still counts.
    let r = record(&[(1, 9)]);
    assert_eq!(remaining(&r, 10, 100, 99).amount, 1);
    agrees(&r, 10, 100, 99).unwrap();
}

#[test]
fn nothing_fits_while_the_record_is_ahead_of_the_ledger() {
    let r = record(&[(500, 1)]);
    let left = remaining(&r, 100, 10, 499);
    assert_eq!(left.amount, 0);
    assert_eq!(left.blocked, Some(Blocked::LedgerBeforeNewest));
    agrees(&r, 100, 10, 499).unwrap();
    // Zero always passes.
    assert!(check_spend(&r, 100, 10, 499, 0).is_ok());
}

#[test]
fn nothing_fits_once_the_window_holds_a_full_history() {
    let spends: Vec<(u32, i128)> = (0..MAX_HISTORY_ENTRIES as u32)
        .map(|i| (10 + i, 1))
        .collect();
    let r = record(&spends);
    let now = 10 + MAX_HISTORY_ENTRIES as u32;
    let left = remaining(&r, i128::MAX, 5000, now);
    assert_eq!((left.amount, left.blocked), (0, Some(Blocked::HistoryFull)));
    agrees(&r, i128::MAX, 5000, now).unwrap();
    // One spend leaving the window frees a slot.
    let left = remaining(&r, i128::MAX, 1000, now);
    assert_eq!(left.blocked, None);
    agrees(&r, i128::MAX, 1000, now).unwrap();
}

#[test]
fn overflowing_records_and_extreme_caps_agree() {
    let huge = record(&[(1, i128::MAX), (2, i128::MAX)]);
    // The record's own total wrapped: whatever it holds, the two agree.
    for (r, label) in [
        (huge, "two maximal spends"),
        (
            SpendRecord {
                history: vec![SpendEntry {
                    ledger: 3,
                    amount: i128::MIN,
                }],
                total: i128::MAX,
            },
            "a negative spend",
        ),
        (
            SpendRecord {
                history: vec![],
                total: i128::MIN,
            },
            "a minimal total",
        ),
    ] {
        for limit in [i128::MIN, -1, 0, 1, i128::MAX] {
            for period in [0, 1, 2, u32::MAX] {
                for now in [0, 1, 2, 3, 4, u32::MAX] {
                    agrees(&r, limit, period, now).unwrap_or_else(|e| panic!("{label}: {e}"));
                }
            }
        }
    }
}

#[test]
fn the_sweep_agrees_everywhere() {
    // A small deterministic generator (SplitMix64), so the sweep is the
    // same on every run.
    let mut state = 0x5eed_u64;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let mut checked = 0;
    for _ in 0..4000 {
        let n = (next() % 6) as usize;
        let mut ledger = (next() % 200) as u32;
        let mut spends = vec![];
        for _ in 0..n {
            ledger += (next() % 40) as u32;
            spends.push((ledger, (next() % 50) as i128));
        }
        let r = record(&spends);
        let limit = [1, 10, 50, 100, 1000][(next() % 5) as usize];
        let period = [1, 7, 30, 100][(next() % 4) as usize];
        let newest = spends.last().map_or(0, |s| s.0);
        for now in [
            newest.saturating_sub(1),
            newest,
            newest + 1,
            newest + period - 1,
            newest + period,
            newest + 2 * period,
        ] {
            agrees(&r, limit, period, now).unwrap();
            checked += 1;
        }
    }
    assert_eq!(checked, 24000);
}
