//! `#[contracttype]` mirrors of `rule_eval::Rule` and `rule_eval::SpendRecord`,
//! so an account can keep rule-eval's rules and spending records in its own
//! storage.
//!
//! Each mirror has one constructor or field per constructor or field of the
//! type it mirrors, with every identifier in its host form: an address as an
//! `Address`, a function name as a `Symbol`, a string as a `String`. A
//! conversion refuses (returns `None`) only a value with no exact host form,
//! or a set condition (`ArgIn`) holding a value that is not a string, which
//! no document lowers to (only `string-in` does), so converting a rule to
//! its mirror and back gives the same rule.
//!
//! A stored rule is laid out compactly, as the account keeps every rule of a
//! document in one ledger entry: a tuple rather than a map of named fields
//! ([`StoredRule`], [`StoredCap`]), a `string-in`'s values as strings
//! ([`StoredCond::ArgIn`]), and its signers as positions in a signer table
//! the record holding the rule keeps once for all its rules.

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

/// `rule_eval::Cond`. An `ArgIn` holds its values as strings, the one form
/// a document's `string-in` lowers to: [`StoredCond::from_cond`] refuses an
/// `ArgIn` of any other value.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredCond {
    ArgEq(u32, StoredVal),
    ArgI128AtMost(u32, i128),
    ArgIn(u32, Vec<String>),
    ArgStrPrefix(u32, String),
}

/// `rule_eval::Cap`: its limit, its period in ledgers, and the argument
/// holding the amount.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCap(pub i128, pub u32, pub u32);

/// Exact authorization-entry root in host form.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAuthRoot {
    pub contract: Address,
    pub function: Symbol,
}

/// `rule_eval::Rule`, as a tuple of its fields in this order: its contract,
/// functions, conditions, signers, threshold, cap (zero or one: a
/// `#[contracttype]` has no `Option` of a `#[contracttype]` struct), last
/// ledger, grant generation, and exact root (a singleton when it has one).
/// Its signers are positions in the signer table of the record that holds
/// it ([`StoredRule::from_rule`], [`StoredRule::to_rule`]). The accessors
/// name the fields.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRule(
    pub Address,
    pub StoredFunctions,
    pub Vec<StoredCond>,
    pub Vec<u32>,
    pub u32,
    pub Vec<StoredCap>,
    pub Option<u32>,
    pub Option<u64>,
    pub Option<Vec<StoredAuthRoot>>,
);

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
                host_vec(e, vs, |v| match v {
                    rule_eval::Val::String(x) => Some(String::from_bytes(e, x)),
                    _ => None,
                })?,
            ),
            rule_eval::Cond::ArgStrPrefix(i, p) => {
                StoredCond::ArgStrPrefix(*i, String::from_bytes(e, p))
            }
        })
    }
}

impl StoredRule {
    /// The mirror of `r`, its signers as positions in `signers`, the signer
    /// table of the record that will hold it, which gains any signer it
    /// lacks; or `None` when one of `r`'s addresses or symbols has no host
    /// form, or an `ArgIn` holds a value other than a string.
    #[must_use]
    pub fn from_rule(
        e: &Env,
        r: &rule_eval::Rule,
        signers: &mut Vec<Signer>,
    ) -> Option<StoredRule> {
        Self::from_rule_in(e, r, &Decoded, signers)
    }

    /// [`Self::from_rule`], with addresses' and signers' host forms from
    /// `forms`: the [`Addresses`](crate::convert::Addresses) the rule's
    /// document was read with convert a lowered rule with no XDR decoding.
    pub fn from_rule_in(
        e: &Env,
        r: &rule_eval::Rule,
        forms: &impl HostForms,
        signers: &mut Vec<Signer>,
    ) -> Option<StoredRule> {
        if r.auth_root.as_ref().is_some_and(|root| {
            root.contract.get(..4) != Some(&[0, 0, 0, 1]) || root.function.is_empty()
        }) {
            return None;
        }
        let mut cap = Vec::new(e);
        if let Some(c) = &r.cap {
            cap.push_back(StoredCap(c.limit, c.period, c.amount_arg));
        }
        let mut positions = Vec::new(e);
        for s in &r.signers {
            let signer = forms.signer(e, s)?;
            let at = match signers.first_index_of(&signer) {
                Some(at) => at,
                None => {
                    signers.push_back(signer);
                    signers.len() - 1
                }
            };
            positions.push_back(at);
        }
        Some(StoredRule(
            forms.address(e, &r.contract)?,
            StoredFunctions::from_functions(e, &r.functions)?,
            host_vec(e, &r.conds, |c| StoredCond::from_cond_in(e, c, forms))?,
            positions,
            r.threshold,
            cap,
            r.valid_until,
            r.generation,
            match &r.auth_root {
                Some(root) => Some(Vec::from_array(
                    e,
                    [StoredAuthRoot {
                        contract: forms.address(e, &root.contract)?,
                        function: host_symbol(e, &root.function)?,
                    }],
                )),
                None => None,
            },
        ))
    }

    /// The rule this mirrors, its signers read from `signers`, the signer
    /// table of the record that holds it; or `None` when it holds more than
    /// one cap or a position past the table ([`crate::mirror::rule`] of its
    /// host value).
    #[must_use]
    pub fn to_rule(&self, e: &Env, signers: &Vec<Signer>) -> Option<rule_eval::Rule> {
        let table = crate::convert::signers(e, signers)?;
        crate::mirror::rule(e, self.clone().into_val(e), &table)
    }

    /// The contract the rule authorizes calls to.
    #[must_use]
    pub fn contract(&self) -> Address {
        self.0.clone()
    }

    /// Its signers: positions in its record's signer table.
    #[must_use]
    pub fn signers(&self) -> Vec<u32> {
        self.3.clone()
    }

    /// Its cap: zero or one.
    #[must_use]
    pub fn cap(&self) -> Vec<StoredCap> {
        self.5.clone()
    }

    /// The inclusive last ledger it authorizes, if bounded.
    #[must_use]
    pub fn valid_until(&self) -> Option<u32> {
        self.6
    }

    /// Its exact root, a singleton when it has one.
    #[must_use]
    pub fn auth_root(&self) -> Option<Vec<StoredAuthRoot>> {
        self.8.clone()
    }

    /// The signers of `table` at its positions, in order; `None` when a
    /// position is past the table.
    #[must_use]
    pub fn signers_in(&self, e: &Env, table: &Vec<Signer>) -> Option<Vec<Signer>> {
        let mut out = Vec::new(e);
        for at in self.3.iter() {
            out.push_back(table.get(at)?);
        }
        Some(out)
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
