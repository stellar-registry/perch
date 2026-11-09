//! `#[contracttype]` mirrors of `rule_eval::Rule` and `rule_eval::SpendRecord`,
//! so an account can keep rule-eval's rules and spending records in its own
//! storage.
//!
//! Each mirror has one constructor or field per constructor or field of the
//! type it mirrors, with every identifier in its host form: an address as an
//! `Address`, a function name as a `Symbol`, a string as a `String`. A
//! conversion refuses (returns `None`) only a value with no exact host form,
//! so converting a rule to its mirror and back gives the same rule.

use soroban_sdk::{contracttype, Address, Bytes, Env, String, Symbol, Vec};
use stellar_accounts::smart_account::Signer;

use crate::convert::{
    address, bytes, host_address, host_signer, host_symbol, signers, string_bytes, symbol_bytes,
};

/// `rule_eval::Val`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredVal {
    I128(i128),
    U64(u64),
    Bool(bool),
    Bytes(Bytes),
    Address(Address),
    Symbol(Symbol),
    String(String),
    /// Any other argument, as its full `ScVal` XDR.
    Other(Bytes),
}

/// `rule_eval::Functions`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredFunctions {
    AnyExcept(Vec<Symbol>),
    Only(Vec<Symbol>),
}

/// `rule_eval::Cond`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredCond {
    ArgEq(u32, StoredVal),
    ArgI128AtMost(u32, i128),
    ArgIn(u32, Vec<StoredVal>),
    ArgStrPrefix(u32, String),
}

/// `rule_eval::Cap`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCap {
    pub limit: i128,
    pub period: u32,
    pub amount_arg: u32,
}

/// `rule_eval::Rule`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRule {
    pub contract: Address,
    pub functions: StoredFunctions,
    pub conds: Vec<StoredCond>,
    pub signers: Vec<Signer>,
    pub threshold: u32,
    /// Zero or one entries: `#[contracttype]` has no `Option` of a
    /// `#[contracttype]` struct.
    pub cap: Vec<StoredCap>,
    pub valid_until: Option<u32>,
    pub generation: Option<u64>,
}

/// `rule_eval::SpendEntry`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEntry {
    pub ledger: u32,
    pub amount: i128,
}

/// `rule_eval::SpendRecord`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecord {
    pub history: Vec<StoredEntry>,
    pub total: i128,
}

impl StoredVal {
    /// The mirror of `v`, or `None` for an address or symbol with no host
    /// form.
    #[must_use]
    pub fn from_val(e: &Env, v: &rule_eval::Val) -> Option<StoredVal> {
        Some(match v {
            rule_eval::Val::I128(x) => StoredVal::I128(*x),
            rule_eval::Val::U64(x) => StoredVal::U64(*x),
            rule_eval::Val::Bool(x) => StoredVal::Bool(*x),
            rule_eval::Val::Bytes(x) => StoredVal::Bytes(Bytes::from_slice(e, x)),
            rule_eval::Val::Address(x) => StoredVal::Address(host_address(e, x)?),
            rule_eval::Val::Symbol(x) => StoredVal::Symbol(host_symbol(e, x)?),
            rule_eval::Val::String(x) => StoredVal::String(String::from_bytes(e, x)),
            rule_eval::Val::Other(x) => StoredVal::Other(Bytes::from_slice(e, x)),
        })
    }

    /// The value this mirrors.
    #[must_use]
    pub fn to_val(&self, e: &Env) -> Option<rule_eval::Val> {
        Some(match self {
            StoredVal::I128(x) => rule_eval::Val::I128(*x),
            StoredVal::U64(x) => rule_eval::Val::U64(*x),
            StoredVal::Bool(x) => rule_eval::Val::Bool(*x),
            StoredVal::Bytes(x) => rule_eval::Val::Bytes(bytes(x)),
            StoredVal::Address(x) => rule_eval::Val::Address(address(e, x)?),
            StoredVal::Symbol(x) => rule_eval::Val::Symbol(symbol_bytes(e, x)?),
            StoredVal::String(x) => rule_eval::Val::String(string_bytes(x)),
            StoredVal::Other(x) => rule_eval::Val::Other(bytes(x)),
        })
    }
}

fn host_symbols(e: &Env, names: &[alloc::vec::Vec<u8>]) -> Option<Vec<Symbol>> {
    let mut out = Vec::new(e);
    for n in names {
        out.push_back(host_symbol(e, n)?);
    }
    Some(out)
}

fn names(e: &Env, symbols: &Vec<Symbol>) -> Option<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    symbols.iter().map(|s| symbol_bytes(e, &s)).collect()
}

fn host_vals(e: &Env, vs: &[rule_eval::Val]) -> Option<Vec<StoredVal>> {
    let mut out = Vec::new(e);
    for v in vs {
        out.push_back(StoredVal::from_val(e, v)?);
    }
    Some(out)
}

impl StoredFunctions {
    #[must_use]
    pub fn from_functions(e: &Env, f: &rule_eval::Functions) -> Option<StoredFunctions> {
        Some(match f {
            rule_eval::Functions::AnyExcept(xs) => StoredFunctions::AnyExcept(host_symbols(e, xs)?),
            rule_eval::Functions::Only(xs) => StoredFunctions::Only(host_symbols(e, xs)?),
        })
    }

    #[must_use]
    pub fn to_functions(&self, e: &Env) -> Option<rule_eval::Functions> {
        Some(match self {
            StoredFunctions::AnyExcept(xs) => rule_eval::Functions::AnyExcept(names(e, xs)?),
            StoredFunctions::Only(xs) => rule_eval::Functions::Only(names(e, xs)?),
        })
    }
}

impl StoredCond {
    #[must_use]
    pub fn from_cond(e: &Env, c: &rule_eval::Cond) -> Option<StoredCond> {
        Some(match c {
            rule_eval::Cond::ArgEq(i, v) => StoredCond::ArgEq(*i, StoredVal::from_val(e, v)?),
            rule_eval::Cond::ArgI128AtMost(i, bound) => StoredCond::ArgI128AtMost(*i, *bound),
            rule_eval::Cond::ArgIn(i, vs) => StoredCond::ArgIn(*i, host_vals(e, vs)?),
            rule_eval::Cond::ArgStrPrefix(i, p) => {
                StoredCond::ArgStrPrefix(*i, String::from_bytes(e, p))
            }
        })
    }

    #[must_use]
    pub fn to_cond(&self, e: &Env) -> Option<rule_eval::Cond> {
        Some(match self {
            StoredCond::ArgEq(i, v) => rule_eval::Cond::ArgEq(*i, v.to_val(e)?),
            StoredCond::ArgI128AtMost(i, bound) => rule_eval::Cond::ArgI128AtMost(*i, *bound),
            StoredCond::ArgIn(i, vs) => {
                rule_eval::Cond::ArgIn(*i, vs.iter().map(|v| v.to_val(e)).collect::<Option<_>>()?)
            }
            StoredCond::ArgStrPrefix(i, p) => rule_eval::Cond::ArgStrPrefix(*i, string_bytes(p)),
        })
    }
}

impl StoredRule {
    /// The mirror of `r`, or `None` when one of its addresses or symbols has
    /// no host form.
    #[must_use]
    pub fn from_rule(e: &Env, r: &rule_eval::Rule) -> Option<StoredRule> {
        let mut conds = Vec::new(e);
        for c in &r.conds {
            conds.push_back(StoredCond::from_cond(e, c)?);
        }
        let mut rule_signers = Vec::new(e);
        for s in &r.signers {
            rule_signers.push_back(host_signer(e, s)?);
        }
        let mut cap = Vec::new(e);
        if let Some(c) = &r.cap {
            cap.push_back(StoredCap {
                limit: c.limit,
                period: c.period,
                amount_arg: c.amount_arg,
            });
        }
        Some(StoredRule {
            contract: host_address(e, &r.contract)?,
            functions: StoredFunctions::from_functions(e, &r.functions)?,
            conds,
            signers: rule_signers,
            threshold: r.threshold,
            cap,
            valid_until: r.valid_until,
            generation: r.generation,
        })
    }

    /// The rule this mirrors, or `None` when it holds more than one cap or an
    /// address the facade refuses.
    #[must_use]
    pub fn to_rule(&self, e: &Env) -> Option<rule_eval::Rule> {
        if self.cap.len() > 1 {
            return None;
        }
        Some(rule_eval::Rule {
            contract: address(e, &self.contract)?,
            functions: self.functions.to_functions(e)?,
            conds: self
                .conds
                .iter()
                .map(|c| c.to_cond(e))
                .collect::<Option<_>>()?,
            signers: signers(e, &self.signers)?,
            threshold: self.threshold,
            cap: self.cap.first().map(|c| rule_eval::Cap {
                limit: c.limit,
                period: c.period,
                amount_arg: c.amount_arg,
            }),
            valid_until: self.valid_until,
            generation: self.generation,
        })
    }
}

impl StoredRecord {
    #[must_use]
    pub fn from_record(e: &Env, r: &rule_eval::SpendRecord) -> StoredRecord {
        let mut history = Vec::new(e);
        for x in &r.history {
            history.push_back(StoredEntry {
                ledger: x.ledger,
                amount: x.amount,
            });
        }
        StoredRecord {
            history,
            total: r.total,
        }
    }

    #[must_use]
    pub fn to_record(&self) -> rule_eval::SpendRecord {
        rule_eval::SpendRecord {
            history: self
                .history
                .iter()
                .map(|x| rule_eval::SpendEntry {
                    ledger: x.ledger,
                    amount: x.amount,
                })
                .collect(),
            total: self.total,
        }
    }
}
