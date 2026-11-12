//! Perch's stored rules and spending records, read from facade values as the
//! account reads them.
//!
//! [`rule`] and [`record`] are `perch_rule_eval::mirror::rule` and
//! `mirror::record` (`crates/perch-rule-eval/src/mirror.rs`) over a value
//! the facade decoded instead of over the host's XDR: the same layouts (a
//! rule the tuple of its nine fields, its signers positions in its record's
//! signer table), the same refusals. A stored value's constructor is told by its
//! field's type, and by its name only between the two that hold bytes, as
//! `mirror` reads it. The account never reads its stored values any other
//! way, so a stored value both readings accept means the same rule to both;
//! `perch-integration-tests` (`review_core_reader.rs`) checks the two
//! readings agree.

use alloc::vec::Vec;

use rule_eval::{AuthRoot, Cap, Cond, Functions, Rule, Signer, SpendEntry, SpendRecord};
use soroban_facade::{xdr::address_xdr, Val};

/// Whether `v` is the symbol `name`.
pub(crate) fn is_sym(v: &Val, name: &[u8]) -> bool {
    matches!(v, Val::Symbol(s) if s.as_slice() == name)
}

/// The values of a map whose keys are exactly the symbols `keys`, in order.
pub(crate) fn fields<'a, const N: usize>(v: &'a Val, keys: [&[u8]; N]) -> Option<[&'a Val; N]> {
    let Val::Map(entries) = v else { return None };
    if entries.len() != N {
        return None;
    }
    let mut out = [&Val::Void; N];
    for (i, key) in keys.iter().enumerate() {
        let (k, x) = &entries[i];
        if !is_sym(k, key) {
            return None;
        }
        out[i] = x;
    }
    Some(out)
}

/// An enum constructor's name and fields: a vector whose first item is a
/// symbol.
pub(crate) fn variant(v: &Val) -> Option<(&[u8], &[Val])> {
    let Val::Vec(items) = v else { return None };
    let (head, rest) = items.split_first()?;
    let Val::Symbol(name) = head else { return None };
    Some((name.as_slice(), rest))
}

pub(crate) fn u32_of(v: &Val) -> Option<u32> {
    match v {
        Val::U32(x) => Some(*x),
        _ => None,
    }
}

pub(crate) fn u64_of(v: &Val) -> Option<u64> {
    match v {
        Val::U64(x) => Some(*x),
        _ => None,
    }
}

pub(crate) fn i128_of(v: &Val) -> Option<i128> {
    match v {
        Val::I128(x) => Some(*x),
        _ => None,
    }
}

pub(crate) fn vec_of(v: &Val) -> Option<&[Val]> {
    match v {
        Val::Vec(x) => Some(x),
        _ => None,
    }
}

/// An address, as its `SCAddress` XDR.
pub(crate) fn address(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Address(a) => Some(address_xdr(a)),
        _ => None,
    }
}

fn symbol(v: &Val) -> Option<Vec<u8>> {
    match v {
        Val::Symbol(s) => Some(s.clone()),
        _ => None,
    }
}

/// An `Option<u32>` field: `Void` for `None`.
fn opt_u32(v: &Val) -> Option<Option<u32>> {
    match v {
        Val::Void => Some(None),
        Val::U32(x) => Some(Some(*x)),
        _ => None,
    }
}

/// An `Option<u64>` field: `Void` for `None`.
fn opt_u64(v: &Val) -> Option<Option<u64>> {
    match v {
        Val::Void => Some(None),
        Val::U64(x) => Some(Some(*x)),
        _ => None,
    }
}

/// Every item of a vector, read with `f`.
pub(crate) fn each<T>(v: &Val, f: impl Fn(&Val) -> Option<T>) -> Option<Vec<T>> {
    let items = vec_of(v)?;
    let mut out = Vec::with_capacity(items.len());
    for x in items {
        out.push(f(x)?);
    }
    Some(out)
}

/// A `StoredRule` (`mirror::rule`), its signers read from `table`, the
/// signer table of the record holding it: `None` for any other value, one
/// holding more than one cap, or one naming a position past the table.
#[must_use]
pub fn rule(v: &Val, table: &[Signer]) -> Option<Rule> {
    let [contract, functions_v, conds, signers, threshold, caps, valid_until, generation, root] =
        vec_of(v)?
    else {
        return None;
    };
    let cap = match vec_of(caps)? {
        [] => None,
        [c] => Some(cap(c)?),
        _ => return None,
    };
    Some(Rule {
        contract: address(contract)?,
        functions: functions(functions_v)?,
        conds: each(conds, cond)?,
        signers: each(signers, |p| {
            let at = usize::try_from(u32_of(p)?).ok()?;
            Some(match table.get(at)? {
                Signer::Delegated(a) => Signer::Delegated(a.clone()),
                Signer::External(v, k) => Signer::External(v.clone(), k.clone()),
            })
        })?,
        threshold: u32_of(threshold)?,
        cap,
        valid_until: opt_u32(valid_until)?,
        generation: opt_u64(generation)?,
        auth_root: stored_root(root)?,
    })
}

/// A rule's `auth_root`: `Void`, or a vector of one map of the root's
/// contract (a contract address) and function (a symbol of 1 to 32 bytes).
fn stored_root(v: &Val) -> Option<Option<AuthRoot>> {
    if matches!(v, Val::Void) {
        return Some(None);
    }
    let [root] = vec_of(v)? else { return None };
    let [contract, function] = fields(root, [b"contract", b"function"])?;
    let contract = address(contract)?;
    // Only contract addresses can be an invocation root.
    if contract.get(..4)? != [0, 0, 0, 1] {
        return None;
    }
    let function = symbol(function)?;
    if function.is_empty() || function.len() > 32 {
        return None;
    }
    Some(Some(AuthRoot { contract, function }))
}

/// A `StoredCap`: the tuple of its limit, period and amount argument.
pub(crate) fn cap(v: &Val) -> Option<Cap> {
    let [limit, period, amount_arg] = vec_of(v)? else {
        return None;
    };
    Some(Cap {
        limit: i128_of(limit)?,
        period: u32_of(period)?,
        amount_arg: u32_of(amount_arg)?,
    })
}

/// A `StoredFunctions`.
fn functions(v: &Val) -> Option<Functions> {
    let (name, [list]) = variant(v)? else {
        return None;
    };
    let names = each(list, symbol)?;
    match name {
        b"AnyExcept" => Some(Functions::AnyExcept(names)),
        b"Only" => Some(Functions::Only(names)),
        _ => None,
    }
}

/// A `StoredCond`.
pub(crate) fn cond(v: &Val) -> Option<Cond> {
    let (name, [i, x]) = variant(v)? else {
        return None;
    };
    let i = u32_of(i)?;
    Some(match name {
        b"ArgEq" => Cond::ArgEq(i, val(x)?),
        b"ArgI128AtMost" => Cond::ArgI128AtMost(i, i128_of(x)?),
        b"ArgIn" => Cond::ArgIn(
            i,
            each(x, |s| match s {
                Val::String(s) => Some(rule_eval::Val::String(s.clone())),
                _ => None,
            })?,
        ),
        b"ArgStrPrefix" => match x {
            Val::String(p) => Cond::ArgStrPrefix(i, p.clone()),
            _ => return None,
        },
        _ => return None,
    })
}

/// A `StoredVal`: its one field read by its type, which names the
/// constructor; the name tells `Bytes` and `Other`, which both hold bytes,
/// apart.
fn val(v: &Val) -> Option<rule_eval::Val> {
    let (name, [x]) = variant(v)? else {
        return None;
    };
    Some(match x {
        Val::I128(n) => rule_eval::Val::I128(*n),
        Val::U64(n) => rule_eval::Val::U64(*n),
        Val::Bool(b) => rule_eval::Val::Bool(*b),
        Val::Address(a) => rule_eval::Val::Address(address_xdr(a)),
        Val::Bytes(b) if name == b"Other" => rule_eval::Val::Other(b.clone()),
        Val::Bytes(b) => rule_eval::Val::Bytes(b.clone()),
        Val::Symbol(s) => rule_eval::Val::Symbol(s.clone()),
        Val::String(s) => rule_eval::Val::String(s.clone()),
        _ => return None,
    })
}

/// Stored rules with their signer table: the tuple of the table and a
/// vector of `StoredRule`, each read with the table.
pub(crate) fn rules(v: &Val) -> Option<Vec<Rule>> {
    let [table_v, rules] = vec_of(v)? else {
        return None;
    };
    let table = table(table_v)?;
    each(rules, |r| rule(r, &table))
}

/// A signer table: every `perch_account_types::Signer` of a vector, in
/// order (`None` when one has no rule-eval form, as `convert::signers`
/// refuses it).
#[must_use]
pub fn table(v: &Val) -> Option<Vec<Signer>> {
    each(v, signer)
}

/// A `perch_account_types::Signer`.
pub(crate) fn signer(v: &Val) -> Option<Signer> {
    match variant(v)? {
        (b"Delegated", [a]) => Some(Signer::Delegated(address(a)?)),
        (b"External", [verifier, Val::Bytes(key)]) => {
            Some(Signer::External(address(verifier)?, key.clone()))
        }
        _ => None,
    }
}

/// A `StoredRecord` (`mirror::record`).
#[must_use]
pub fn record(v: &Val) -> Option<SpendRecord> {
    let [history, total] = fields(v, [b"history", b"total"])?;
    let history = each(history, |e| {
        let [amount, ledger] = fields(e, [b"amount", b"ledger"])?;
        Some(SpendEntry {
            ledger: u32_of(ledger)?,
            amount: i128_of(amount)?,
        })
    })?;
    Some(SpendRecord {
        history,
        total: i128_of(total)?,
    })
}
