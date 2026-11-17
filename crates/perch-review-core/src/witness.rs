//! Attenuation witnesses: a child rule set carried with the steps that
//! derive it from its parent, re-checked by replaying them.
//!
//! The steps are rule-core's ten attenuation steps (`rule_eval::drop_rule`
//! to `rule_eval::lower_valid_until`), applied in order with rule-eval's own
//! functions. rule-core proves each step narrows: the rule set it returns
//! allows no context, under any signers, that its input does not, and
//! accepts no run of authorizations from empty records that its input does
//! not (`attenuate_narrower`, `Derives.narrower` in rule-core's `formal/`).
//! [`replay_witness`] accepts a child exactly when the steps replay from the
//! parent and give the child, rule for rule, so an accepted child is narrower
//! by that proof. It decides nothing about a child and parent related by no
//! steps: whether two arbitrary rule sets are ordered is not what the
//! witness shows.

use alloc::vec::Vec;

use rule_eval::{
    add_cap, add_cond, drop_rule, lengthen_cap_period, lower_cap_limit, lower_valid_until,
    raise_threshold, remove_functions, remove_signers, restrict_functions, val_eq,
    AttenuationError, AuthRoot, Cap, Cond, Functions, Rule, Signer,
};
use soroban_facade::Val;

use crate::stored::{cond, each, i128_of, signer, u32_of, variant};

/// One attenuation step, on the rule at its index.
pub enum Step {
    DropRule(u32),
    AddCond(u32, Cond),
    RemoveFunctions(u32, Vec<Vec<u8>>),
    RestrictFunctions(u32, Vec<Vec<u8>>),
    RemoveSigners(u32, Vec<Signer>),
    RaiseThreshold(u32, u32),
    AddCap(u32, Cap),
    LowerCapLimit(u32, i128),
    LengthenCapPeriod(u32, u32),
    LowerValidUntil(u32, u32),
}

/// Why a witness was not accepted.
pub enum WitnessError {
    /// The step at this position was refused.
    Step(usize, AttenuationError),
    /// The steps replay, to another rule set than the child.
    Differs,
}

/// `parent` after every step of `steps`, in order.
///
/// # Errors
///
/// The position and error of the first refused step.
pub fn replay(parent: Vec<Rule>, steps: &[Step]) -> Result<Vec<Rule>, (usize, AttenuationError)> {
    let mut rules = parent;
    for (k, step) in steps.iter().enumerate() {
        let next = match step {
            Step::DropRule(i) => drop_rule(&rules, *i),
            Step::AddCond(i, c) => add_cond(&rules, *i, c),
            Step::RemoveFunctions(i, fs) => remove_functions(&rules, *i, fs),
            Step::RestrictFunctions(i, fs) => restrict_functions(&rules, *i, fs),
            Step::RemoveSigners(i, ss) => remove_signers(&rules, *i, ss),
            Step::RaiseThreshold(i, t) => raise_threshold(&rules, *i, *t),
            Step::AddCap(i, c) => add_cap(&rules, *i, c),
            Step::LowerCapLimit(i, l) => lower_cap_limit(&rules, *i, *l),
            Step::LengthenCapPeriod(i, p) => lengthen_cap_period(&rules, *i, *p),
            Step::LowerValidUntil(i, v) => lower_valid_until(&rules, *i, *v),
        };
        rules = next.map_err(|e| (k, e))?;
    }
    Ok(rules)
}

/// Whether `steps` replay from `parent` to exactly `child` (module docs).
///
/// # Errors
///
/// [`WitnessError::Step`] for a refused step, [`WitnessError::Differs`]
/// when the replay gives another rule set.
pub fn replay_witness(
    parent: Vec<Rule>,
    steps: &[Step],
    child: &[Rule],
) -> Result<(), WitnessError> {
    let got = replay(parent, steps).map_err(|(k, e)| WitnessError::Step(k, e))?;
    if rules_eq(&got, child) {
        Ok(())
    } else {
        Err(WitnessError::Differs)
    }
}

/// Structural equality of rule sets: every field of every rule, in order,
/// the exact root included.
#[must_use]
pub fn rules_eq(xs: &[Rule], ys: &[Rule]) -> bool {
    xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| rule_eq(x, y))
}

/// Structural equality of two rules ([`rules_eq`]).
#[must_use]
pub fn rule_eq(x: &Rule, y: &Rule) -> bool {
    x.contract == y.contract
        && functions_eq(&x.functions, &y.functions)
        && x.conds.len() == y.conds.len()
        && x.conds.iter().zip(&y.conds).all(|(p, q)| cond_eq(p, q))
        && x.signers.len() == y.signers.len()
        && x.signers
            .iter()
            .zip(&y.signers)
            .all(|(p, q)| rule_eval::signer_eq(p, q))
        && x.threshold == y.threshold
        && cap_eq(x.cap.as_ref(), y.cap.as_ref())
        && x.valid_until == y.valid_until
        && x.generation == y.generation
        && root_eq(x.auth_root.as_ref(), y.auth_root.as_ref())
}

fn functions_eq(p: &Functions, q: &Functions) -> bool {
    match (p, q) {
        (Functions::Only(x), Functions::Only(y))
        | (Functions::AnyExcept(x), Functions::AnyExcept(y)) => x == y,
        _ => false,
    }
}

fn cond_eq(p: &Cond, q: &Cond) -> bool {
    match (p, q) {
        (Cond::ArgEq(i, v), Cond::ArgEq(j, w)) => i == j && val_eq(v, w),
        (Cond::ArgI128AtMost(i, n), Cond::ArgI128AtMost(j, m)) => i == j && n == m,
        (Cond::ArgIn(i, vs), Cond::ArgIn(j, ws)) => {
            i == j && vs.len() == ws.len() && vs.iter().zip(ws).all(|(v, w)| val_eq(v, w))
        }
        (Cond::ArgStrPrefix(i, p), Cond::ArgStrPrefix(j, q)) => i == j && p == q,
        _ => false,
    }
}

fn cap_eq(p: Option<&Cap>, q: Option<&Cap>) -> bool {
    match (p, q) {
        (None, None) => true,
        (Some(p), Some(q)) => {
            p.limit == q.limit && p.period == q.period && p.amount_arg == q.amount_arg
        }
        _ => false,
    }
}

fn root_eq(p: Option<&AuthRoot>, q: Option<&AuthRoot>) -> bool {
    match (p, q) {
        (None, None) => true,
        (Some(p), Some(q)) => p.contract == q.contract && p.function == q.function,
        _ => false,
    }
}

/// A step from its `contracttype`-style value: a vector of the step's name,
/// the rule index, and its argument in the stored shapes (`StoredCond`,
/// `Signer`, `StoredCap`, symbols, integers):
///
/// | Step | Value |
/// |---|---|
/// | `DropRule` | `["DropRule", u32]` |
/// | `AddCond` | `["AddCond", u32, StoredCond]` |
/// | `RemoveFunctions`, `RestrictFunctions` | `[name, u32, Vec<Symbol>]` |
/// | `RemoveSigners` | `["RemoveSigners", u32, Vec<Signer>]` |
/// | `RaiseThreshold`, `LengthenCapPeriod`, `LowerValidUntil` | `[name, u32, u32]` |
/// | `AddCap` | `["AddCap", u32, StoredCap]` |
/// | `LowerCapLimit` | `["LowerCapLimit", u32, i128]` |
#[must_use]
pub fn step(v: &Val) -> Option<Step> {
    let (name, rest) = variant(v)?;
    let (i, arg) = match rest {
        [i] => (u32_of(i)?, None),
        [i, x] => (u32_of(i)?, Some(x)),
        _ => return None,
    };
    let symbols = |x: &Val| -> Option<Vec<Vec<u8>>> {
        each(x, |s| match s {
            Val::Symbol(b) => Some(b.clone()),
            _ => None,
        })
    };
    Some(match (name, arg) {
        (b"DropRule", None) => Step::DropRule(i),
        (b"AddCond", Some(x)) => Step::AddCond(i, cond(x)?),
        (b"RemoveFunctions", Some(x)) => Step::RemoveFunctions(i, symbols(x)?),
        (b"RestrictFunctions", Some(x)) => Step::RestrictFunctions(i, symbols(x)?),
        (b"RemoveSigners", Some(x)) => Step::RemoveSigners(i, each(x, signer)?),
        (b"RaiseThreshold", Some(x)) => Step::RaiseThreshold(i, u32_of(x)?),
        (b"AddCap", Some(x)) => {
            let [amount_arg, limit, period] =
                crate::stored::fields(x, [b"amount_arg", b"limit", b"period"])?;
            Step::AddCap(
                i,
                Cap {
                    limit: i128_of(limit)?,
                    period: u32_of(period)?,
                    amount_arg: u32_of(amount_arg)?,
                },
            )
        }
        (b"LowerCapLimit", Some(x)) => Step::LowerCapLimit(i, i128_of(x)?),
        (b"LengthenCapPeriod", Some(x)) => Step::LengthenCapPeriod(i, u32_of(x)?),
        (b"LowerValidUntil", Some(x)) => Step::LowerValidUntil(i, u32_of(x)?),
        _ => return None,
    })
}

/// The name of an attenuation error, as rule-core's conformance vectors
/// spell it.
#[must_use]
pub fn error_name(e: &AttenuationError) -> &'static str {
    match e {
        AttenuationError::NoSuchRule => "no_such_rule",
        AttenuationError::ThresholdLowered => "threshold_lowered",
        AttenuationError::CapPresent => "cap_present",
        AttenuationError::NoCap => "no_cap",
        AttenuationError::InvalidCap => "invalid_cap",
        AttenuationError::LimitRaised => "limit_raised",
        AttenuationError::PeriodShortened => "period_shortened",
        AttenuationError::ValidUntilRaised => "valid_until_raised",
    }
}
