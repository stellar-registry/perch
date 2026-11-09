//! The `rule_eval::Rule` a Perch rule enforces when installed with the
//! interpreter and the spending limit.
//!
//! Accounts installed a Perch rule, before rule-eval decided their
//! authorizations, as an OpenZeppelin context rule on one contract, with its
//! signers and last ledger, and up to two policies: the interpreter running
//! the rule's program, and OpenZeppelin's spending-limit policy with the
//! rule's cap; an account upgraded from that code keeps them until its first
//! `apply_doc`. What the three enforce together:
//!
//! - **No policy.** OpenZeppelin requires every signer of the rule, so the
//!   threshold is the signer count.
//! - **Any policy.** OpenZeppelin leaves the signer requirement to the
//!   policies, and each refuses an empty set of authenticated rule signers,
//!   so the threshold is at least 1.
//! - **The interpreter.** It refuses unless the program's verdict is true.
//!   `MinSigners(n)` sets the threshold to `n` (at least 1), `FnIn` lists the
//!   functions, and each argument leaf is one condition. A leaf that cannot
//!   read its argument gives `Unknown`, which fails the conjunction as
//!   `false` does, as a rule-eval condition is false on a missing argument
//!   or one of another type. Strings compare up to 256 bytes: a `string-in`
//!   candidate longer than that never matches, and a longer prefix never
//!   holds.
//! - **The spending limit.** It refuses every call but a `transfer` whose
//!   argument 2 is an `i128`, and charges that amount to the cap. So the
//!   functions are `transfer` when the program's cover it and none
//!   otherwise, and the rule gets the condition `ArgI128AtMost(2,
//!   i128::MAX)`, which every `i128` meets.
//!
//! [`denote`] reads exactly the programs Perch's lowering emits: argument
//! leaves, at most one `MinSigners` and one `FnIn`, then one `All` over all of
//! them. It refuses any other program.

use std::vec::Vec;

use perch_program::{Op, RpnProgram};
use soroban_sdk::{Address, Env, Vec as SVec};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;
use stellar_accounts::smart_account::Signer;

use perch_rule_eval::convert::{address, signers, string_bytes, symbol_bytes};

/// One installed rule: the context rule's contract, signers and last ledger,
/// the interpreter's program if it is attached, and the spending limit's
/// parameters if it is attached.
#[derive(Clone, Debug)]
pub struct Installed {
    pub contract: Address,
    pub signers: SVec<Signer>,
    pub valid_until: Option<u32>,
    pub program: Option<RpnProgram>,
    pub cap: Option<SpendingLimitAccountParams>,
}

/// What a program says, read leaf by leaf.
struct Reading {
    min_signers: Option<u32>,
    functions: Option<Vec<Vec<u8>>>,
    conds: Vec<rule_eval::Cond>,
}

/// The program's leaves, or `None` for a program outside the fragment
/// Perch's lowering emits.
fn read(e: &Env, me: &[u8], program: &RpnProgram) -> Option<Reading> {
    let ops = &program.ops;
    let leaves = ops.len().checked_sub(1)?;
    if leaves == 0 || ops.last()? != Op::All(leaves) {
        return None;
    }
    let mut out = Reading {
        min_signers: None,
        functions: None,
        conds: Vec::new(),
    };
    for op in ops.iter().take(leaves as usize) {
        match op {
            Op::MinSigners(n) if out.min_signers.is_none() => out.min_signers = Some(n),
            Op::FnIn(fs) if out.functions.is_none() => {
                out.functions = Some(
                    fs.iter()
                        .map(|f| symbol_bytes(e, &f))
                        .collect::<Option<_>>()?,
                );
            }
            Op::ArgAddrIsSelf(i) => out.conds.push(rule_eval::Cond::ArgEq(
                i,
                rule_eval::Val::Address(me.to_vec()),
            )),
            Op::ArgAddrEq(i, a) => out.conds.push(rule_eval::Cond::ArgEq(
                i,
                rule_eval::Val::Address(address(e, &a)?),
            )),
            Op::ArgU32Eq(i, v) => out.conds.push(rule_eval::Cond::ArgEq(
                i,
                rule_eval::Val::Other(rule_eval::u32_xdr(v)),
            )),
            Op::ArgStrIn(i, set) => out.conds.push(rule_eval::Cond::ArgIn(
                i,
                set.iter()
                    .map(|s| string_bytes(&s))
                    .filter(|s| s.len() <= rule_eval::MAX_STRING_LEN)
                    .map(rule_eval::Val::String)
                    .collect(),
            )),
            Op::ArgStrPrefix(i, p) => {
                let p = string_bytes(&p);
                out.conds.push(if p.len() <= rule_eval::MAX_STRING_LEN {
                    rule_eval::Cond::ArgStrPrefix(i, p)
                } else {
                    rule_eval::Cond::ArgIn(i, Vec::new())
                });
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The `rule_eval::Rule` that `rule`, installed on the account `me`,
/// enforces, or `None` when its program is outside the fragment Perch's
/// lowering emits or one of its addresses has no rule-eval form. The rule
/// carries no generation: no installed Perch rule has one.
#[must_use]
pub fn denote(e: &Env, me: &Address, rule: &Installed) -> Option<rule_eval::Rule> {
    let me = address(e, me)?;
    let rule_signers = signers(e, &rule.signers)?;
    let reading = match &rule.program {
        Some(p) => read(e, &me, p)?,
        None => Reading {
            min_signers: None,
            functions: None,
            conds: Vec::new(),
        },
    };
    let mut conds = reading.conds;
    let threshold = if rule.program.is_none() && rule.cap.is_none() {
        rule.signers.len()
    } else {
        reading.min_signers.unwrap_or(0).max(1)
    };
    let functions = match (&rule.cap, reading.functions) {
        (Some(_), fs) => {
            let transfer = b"transfer".to_vec();
            let covers = fs.is_none_or(|fs| fs.contains(&transfer));
            rule_eval::Functions::Only(if covers {
                std::vec![transfer]
            } else {
                Vec::new()
            })
        }
        (None, Some(fs)) => rule_eval::Functions::Only(fs),
        (None, None) => rule_eval::Functions::AnyExcept(Vec::new()),
    };
    let cap = rule.cap.as_ref().map(|c| {
        conds.push(rule_eval::Cond::ArgI128AtMost(
            rule_eval::AMOUNT_ARG,
            i128::MAX,
        ));
        rule_eval::Cap {
            limit: c.spending_limit,
            period: c.period_ledgers,
            amount_arg: rule_eval::AMOUNT_ARG,
        }
    });
    Some(rule_eval::Rule {
        contract: address(e, &rule.contract)?,
        functions,
        conds,
        signers: rule_signers,
        threshold,
        cap,
        valid_until: rule.valid_until,
        generation: None,
    })
}
