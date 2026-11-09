//! `#[contracttype]` mirrors of `rule_eval::Rule` and `rule_eval::SpendRecord`,
//! so an account can keep rule-eval's rules and spending records in its own
//! storage.
//!
//! Each mirror has one constructor or field per constructor or field of the
//! type it mirrors, with every identifier in its host form: an address as an
//! `Address`, a function name as a `Symbol`, a string as a `String`. A
//! conversion refuses (returns `None`) only a value with no exact host form,
//! so converting a rule to its mirror and back gives the same rule.

use perch_account_types::Signer;
use soroban_sdk::{
    contracttype, Address, Bytes, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

use crate::convert::{host_symbol, Decoded, HostForms};

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
        Self::from_val_in(e, v, &Decoded)
    }

    /// [`Self::from_val`], with addresses' host forms from `forms`.
    pub fn from_val_in(e: &Env, v: &rule_eval::Val, forms: &impl HostForms) -> Option<StoredVal> {
        Some(match v {
            rule_eval::Val::I128(x) => StoredVal::I128(*x),
            rule_eval::Val::U64(x) => StoredVal::U64(*x),
            rule_eval::Val::Bool(x) => StoredVal::Bool(*x),
            rule_eval::Val::Bytes(x) => StoredVal::Bytes(Bytes::from_slice(e, x)),
            rule_eval::Val::Address(x) => StoredVal::Address(forms.address(e, x)?),
            rule_eval::Val::Symbol(x) => StoredVal::Symbol(host_symbol(e, x)?),
            rule_eval::Val::String(x) => StoredVal::String(String::from_bytes(e, x)),
            rule_eval::Val::Other(x) => StoredVal::Other(Bytes::from_slice(e, x)),
        })
    }
}

/// The host vector of `xs`, each converted by `f`.
fn host_vec<T, U: IntoVal<Env, Val> + TryFromVal<Env, Val>>(
    e: &Env,
    xs: &[T],
    mut f: impl FnMut(&T) -> Option<U>,
) -> Option<Vec<U>> {
    let mut out = Vec::new(e);
    for x in xs {
        out.push_back(f(x)?);
    }
    Some(out)
}

impl StoredFunctions {
    #[must_use]
    pub fn from_functions(e: &Env, f: &rule_eval::Functions) -> Option<StoredFunctions> {
        let symbols = |xs: &[alloc::vec::Vec<u8>]| host_vec(e, xs, |x| host_symbol(e, x));
        Some(match f {
            rule_eval::Functions::AnyExcept(xs) => StoredFunctions::AnyExcept(symbols(xs)?),
            rule_eval::Functions::Only(xs) => StoredFunctions::Only(symbols(xs)?),
        })
    }
}

impl StoredCond {
    #[must_use]
    pub fn from_cond(e: &Env, c: &rule_eval::Cond) -> Option<StoredCond> {
        Self::from_cond_in(e, c, &Decoded)
    }

    /// [`Self::from_cond`], with addresses' host forms from `forms`.
    pub fn from_cond_in(
        e: &Env,
        c: &rule_eval::Cond,
        forms: &impl HostForms,
    ) -> Option<StoredCond> {
        Some(match c {
            rule_eval::Cond::ArgEq(i, v) => {
                StoredCond::ArgEq(*i, StoredVal::from_val_in(e, v, forms)?)
            }
            rule_eval::Cond::ArgI128AtMost(i, bound) => StoredCond::ArgI128AtMost(*i, *bound),
            rule_eval::Cond::ArgIn(i, vs) => StoredCond::ArgIn(
                *i,
                host_vec(e, vs, |v| StoredVal::from_val_in(e, v, forms))?,
            ),
            rule_eval::Cond::ArgStrPrefix(i, p) => {
                StoredCond::ArgStrPrefix(*i, String::from_bytes(e, p))
            }
        })
    }
}

impl StoredRule {
    /// The mirror of `r`, or `None` when one of its addresses or symbols has
    /// no host form.
    #[must_use]
    pub fn from_rule(e: &Env, r: &rule_eval::Rule) -> Option<StoredRule> {
        Self::from_rule_in(e, r, &Decoded)
    }

    /// [`Self::from_rule`], with addresses' and signers' host forms from
    /// `forms`: the [`Addresses`](crate::convert::Addresses) the rule's
    /// document was read with convert a lowered rule with no XDR decoding.
    pub fn from_rule_in(
        e: &Env,
        r: &rule_eval::Rule,
        forms: &impl HostForms,
    ) -> Option<StoredRule> {
        let mut cap = Vec::new(e);
        if let Some(c) = &r.cap {
            cap.push_back(StoredCap {
                limit: c.limit,
                period: c.period,
                amount_arg: c.amount_arg,
            });
        }
        Some(StoredRule {
            contract: forms.address(e, &r.contract)?,
            functions: StoredFunctions::from_functions(e, &r.functions)?,
            conds: host_vec(e, &r.conds, |c| StoredCond::from_cond_in(e, c, forms))?,
            signers: host_vec(e, &r.signers, |s| forms.signer(e, s))?,
            threshold: r.threshold,
            cap,
            valid_until: r.valid_until,
            generation: r.generation,
        })
    }

    /// The rule this mirrors, or `None` when it holds more than one cap
    /// ([`crate::mirror::rule`] of its host value).
    #[must_use]
    pub fn to_rule(&self, e: &Env) -> Option<rule_eval::Rule> {
        crate::mirror::rule(e, self.clone().into_val(e))
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
