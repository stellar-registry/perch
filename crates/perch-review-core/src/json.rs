//! The core's answers as JSON text, for the browser build and the npm
//! wrapper (`npm/src/index.ts` reads exactly these shapes).
//!
//! Integers that may exceed 2^53 (`i128` amounts) are decimal strings;
//! addresses are their `SCAddress` XDR in lowercase hex, which the wrapper
//! turns into strkeys. Written without `core::fmt`, which would cost the
//! wasm several kilobytes.

use alloc::vec::Vec;

use rule_eval::SpendRecord;

use crate::budget::{Blocked, Remaining};
use crate::gate::{Check, Error, Outcome, Review};
use crate::snapshot::Unreadable;
use crate::witness::{error_name, WitnessError};

/// A JSON text being written.
pub struct Out(Vec<u8>);

impl Out {
    fn new() -> Out {
        Out(Vec::new())
    }

    fn raw(&mut self, s: &str) -> &mut Out {
        self.0.extend_from_slice(s.as_bytes());
        self
    }

    /// A string of characters that need no escaping.
    fn str(&mut self, s: &str) -> &mut Out {
        self.0.push(b'"');
        self.raw(s);
        self.0.push(b'"');
        self
    }

    fn key(&mut self, k: &str) -> &mut Out {
        if !matches!(self.0.last(), Some(b'{')) {
            self.0.push(b',');
        }
        self.str(k);
        self.0.push(b':');
        self
    }

    /// `n` in decimal, by long division over 32-bit limbs, so the wasm
    /// carries no 128-bit division.
    fn u128(&mut self, n: u128) -> &mut Out {
        let mut limbs = [
            (n >> 96) as u32,
            (n >> 64) as u32,
            (n >> 32) as u32,
            n as u32,
        ];
        let mut digits = [0u8; 40];
        let mut i = digits.len();
        loop {
            let mut rem = 0u64;
            for limb in &mut limbs {
                let cur = (rem << 32) | u64::from(*limb);
                *limb = (cur / 10) as u32;
                rem = cur % 10;
            }
            i -= 1;
            digits[i] = b'0' + rem as u8;
            if limbs == [0; 4] {
                break;
            }
        }
        self.0.extend_from_slice(&digits[i..]);
        self
    }

    fn num(&mut self, n: u64) -> &mut Out {
        self.u128(u128::from(n))
    }

    /// An `i128` as a decimal string.
    fn big(&mut self, n: i128) -> &mut Out {
        self.0.push(b'"');
        if n < 0 {
            self.0.push(b'-');
        }
        self.u128(n.unsigned_abs());
        self.0.push(b'"');
        self
    }

    fn opt_num(&mut self, n: Option<u64>) -> &mut Out {
        match n {
            Some(n) => self.num(n),
            None => self.raw("null"),
        }
    }

    fn hex(&mut self, b: &[u8]) -> &mut Out {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        self.0.push(b'"');
        for x in b {
            self.0.push(DIGITS[usize::from(x >> 4)]);
            self.0.push(DIGITS[usize::from(x & 15)]);
        }
        self.0.push(b'"');
        self
    }

    fn remaining(&mut self, r: &Remaining) -> &mut Out {
        self.raw("{").key("remaining").big(r.amount);
        self.key("spent").big(r.spent);
        self.key("next_release")
            .opt_num(r.next_release.map(u64::from));
        self.key("blocked");
        match r.blocked {
            None => self.raw("null"),
            Some(Blocked::LedgerBeforeNewest) => self.str("LedgerBeforeNewest"),
            Some(Blocked::Overflow) => self.str("Overflow"),
            Some(Blocked::HistoryFull) => self.str("HistoryFull"),
        };
        self.raw("}")
    }

    fn record(&mut self, id: u32, r: &SpendRecord) -> &mut Out {
        self.raw("{").key("rule").num(u64::from(id));
        self.key("history").raw("[");
        for (i, e) in r.history.iter().enumerate() {
            if i > 0 {
                self.raw(",");
            }
            self.raw("[")
                .num(u64::from(e.ledger))
                .raw(",")
                .big(e.amount)
                .raw("]");
        }
        self.raw("]").key("total").big(r.total).raw("}")
    }

    fn done(self) -> Vec<u8> {
        self.0
    }
}

/// The name of an [`Unreadable`].
#[must_use]
pub fn unreadable_name(u: Unreadable) -> &'static str {
    match u {
        Unreadable::Input => "input",
        Unreadable::Entry => "entry",
        Unreadable::Payload => "payload",
        Unreadable::LedgerEntry => "ledger-entry",
        Unreadable::NoInstance => "no-instance",
        Unreadable::StoredValue => "stored-value",
        Unreadable::Verified => "verified",
    }
}

/// `{"v":1,"status":"unreadable","input":...}`.
#[must_use]
pub fn unreadable(u: Unreadable) -> Vec<u8> {
    let mut o = Out::new();
    o.raw("{").key("v").num(1).key("status").str("unreadable");
    o.key("input").str(unreadable_name(u)).raw("}");
    o.done()
}

/// A review as JSON: `status` is `accepted`, `refused` or `controller`.
#[must_use]
pub fn review(account: &[u8], ledger: u32, r: &Review) -> Vec<u8> {
    let mut o = Out::new();
    o.raw("{").key("v").num(1).key("status");
    o.str(match &r.outcome {
        Outcome::Accepted => "accepted",
        Outcome::Refused(_) => "refused",
        Outcome::Controller { .. } => "controller",
    });
    o.key("account").hex(account);
    o.key("ledger").num(u64::from(ledger));
    o.key("assumed").raw("[");
    for (i, k) in r.assumed.iter().enumerate() {
        if i > 0 {
            o.raw(",");
        }
        o.num(u64::from(*k));
    }
    o.raw("]").key("refusal");
    match &r.outcome {
        Outcome::Refused(f) => {
            o.raw("{").key("check").str(f.check.name());
            o.key("code");
            match f.error() {
                Error::Contract(c) => o.num(u64::from(c)),
                Error::Host | Error::Signer => o.raw("null"),
            };
            o.key("error").str(f.error_name());
            o.key("detail");
            match f.check {
                Check::RuleEval(e) => o.str(e.name()),
                _ => o.raw("null"),
            };
            o.key("context").opt_num(f.context.map(u64::from));
            o.key("rule").opt_num(f.rule.map(u64::from));
            o.key("signer").opt_num(f.signer.map(u64::from));
            o.raw("}");
        }
        _ => {
            o.raw("null");
        }
    }
    o.key("controller");
    match &r.outcome {
        Outcome::Controller { rule, policies } => {
            o.raw("{")
                .key("rule")
                .num(u64::from(*rule))
                .key("policies")
                .raw("[");
            for (i, p) in policies.iter().enumerate() {
                if i > 0 {
                    o.raw(",");
                }
                o.hex(p);
            }
            o.raw("]}");
        }
        _ => {
            o.raw("null");
        }
    }
    o.key("rules").raw("[");
    for (i, c) in r.rules.iter().enumerate() {
        if i > 0 {
            o.raw(",");
        }
        o.raw("{").key("id").num(u64::from(c.id));
        o.key("grant").opt_num(c.grant.map(u64::from));
        o.key("capped").raw(if c.capped { "true" } else { "false" });
        o.key("contract").hex(&c.contract);
        o.key("name");
        match &c.name {
            Some(n) => o.hex(n),
            None => o.raw("null"),
        };
        o.raw("}");
    }
    o.raw("]").key("budgets").raw("[");
    for (i, b) in r.budgets.iter().enumerate() {
        if i > 0 {
            o.raw(",");
        }
        o.raw("{").key("rule").num(u64::from(b.rule));
        o.key("grant").opt_num(b.grant.map(u64::from));
        o.key("limit").big(b.limit);
        o.key("period").num(u64::from(b.period));
        o.key("requested");
        match b.requested {
            Some(n) => o.big(n),
            None => o.raw("null"),
        };
        o.key("before").remaining(&b.before);
        o.key("after");
        match &b.after {
            Some(a) => o.remaining(a),
            None => o.raw("null"),
        };
        o.raw("}");
    }
    o.raw("]").key("records").raw("[");
    for (i, (id, rec)) in r.records.iter().enumerate() {
        if i > 0 {
            o.raw(",");
        }
        o.record(*id, rec);
    }
    o.raw("]}");
    o.done()
}

/// A witness check as JSON: `status` is `narrower`, `refused` (with the
/// step and its error) or `differs`.
#[must_use]
pub fn witness(r: &Result<(), WitnessError>) -> Vec<u8> {
    let mut o = Out::new();
    o.raw("{").key("v").num(1).key("status");
    match r {
        Ok(()) => {
            o.str("narrower");
        }
        Err(WitnessError::Step(k, e)) => {
            o.str("refused").key("step").num(*k as u64);
            o.key("error").str(error_name(e));
        }
        Err(WitnessError::Differs) => {
            o.str("differs");
        }
    }
    o.raw("}");
    o.done()
}

/// A budget as JSON.
#[must_use]
pub fn budget(r: &Remaining) -> Vec<u8> {
    let mut o = Out::new();
    o.remaining(r);
    o.done()
}

/// An entry's account and chosen rule ids as JSON.
#[must_use]
pub fn chosen(account: &[u8], ids: &[u32]) -> Vec<u8> {
    let mut o = Out::new();
    o.raw("{").key("v").num(1).key("account").hex(account);
    o.key("rule_ids").raw("[");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            o.raw(",");
        }
        o.num(u64::from(*id));
    }
    o.raw("]}");
    o.done()
}
