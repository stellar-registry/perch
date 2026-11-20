//! `CompiledModel`, a `#[contracttype]` mirror of `rule_eval::Doc`: the part
//! of a policy document rule-eval's lowering reads, in host types. Strkeys
//! become `Address`es, hex keys `Bytes`, decimal limits `i128`, function
//! names `Symbol`s, and signer ids and strings `String`s.
//!
//! [`doc_of`] reads a model as a `rule_eval::Doc`. With the `ir` feature,
//! [`model_of`] builds one from a validated `perch_ir::PolicyDoc`.

use perch_account_types::Signer;
use soroban_sdk::{contracttype, Address, Env, String, Symbol, Vec};

use crate::convert::{signer_in, string_bytes, symbol_bytes, Addresses};
use crate::StoredAuthRoot;

/// `rule_eval::Scope`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelScope {
    Contract(Address),
    SelfAdmin,
}

/// `rule_eval::Principals`: signer ids.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelPrincipals {
    All(Vec<String>),
    Threshold(Vec<String>, u32),
}

/// `rule_eval::Pred`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelPred {
    IsSelf,
    AddressEq(Address),
    StringIn(Vec<String>),
    StringPrefix(String),
    U32Eq(u32),
}

/// `rule_eval::ArgConstraint`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelArg {
    pub index: u32,
    pub pred: ModelPred,
}

/// `rule_eval::DocCap`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCap {
    pub limit: i128,
    pub period_ledgers: u32,
}

/// `rule_eval::DocRule`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRule {
    pub scope: ModelScope,
    pub principals: ModelPrincipals,
    pub functions: Option<Vec<Symbol>>,
    pub args: Option<Vec<ModelArg>>,
    pub not_after_ledger: Option<u32>,
    /// Zero or one entries: `#[contracttype]` has no `Option` of a
    /// `#[contracttype]` struct.
    pub cap: Vec<ModelCap>,
    /// Exact authorization-entry root (contract, function), or unrestricted.
    pub auth_root: Option<Vec<StoredAuthRoot>>,
}

/// `rule_eval::SignerDecl`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelSigner {
    pub id: String,
    pub signer: Signer,
}

/// `rule_eval::ZkFactor`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelZk {
    pub adapter: Address,
    pub pool: Address,
}

/// `rule_eval::Recovery`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelRecovery {
    pub controller: Address,
    /// Zero or one entries.
    pub zk: Vec<ModelZk>,
}

/// `rule_eval::Doc`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledModel {
    pub signers: Vec<ModelSigner>,
    pub rules: Vec<ModelRule>,
    /// Zero or one entries.
    pub recovery: Vec<ModelRecovery>,
}

fn strings(list: &Vec<String>) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    list.iter().map(|s| string_bytes(&s)).collect()
}

fn pred(e: &Env, p: &ModelPred, known: &mut Addresses) -> Option<rule_eval::Pred> {
    Some(match p {
        ModelPred::IsSelf => rule_eval::Pred::IsSelf,
        ModelPred::AddressEq(a) => rule_eval::Pred::AddressEq(known.read(e, a)?),
        ModelPred::StringIn(vs) => rule_eval::Pred::StringIn(strings(vs)),
        ModelPred::StringPrefix(p) => rule_eval::Pred::StringPrefix(string_bytes(p)),
        ModelPred::U32Eq(v) => rule_eval::Pred::U32Eq(*v),
    })
}

fn rule(e: &Env, r: &ModelRule, known: &mut Addresses) -> Option<rule_eval::DocRule> {
    if r.cap.len() > 1 || (r.auth_root.is_some() && matches!(r.scope, ModelScope::SelfAdmin)) {
        return None;
    }
    let functions = match &r.functions {
        Some(fs) => {
            let mut names = alloc::vec::Vec::new();
            for f in fs.iter() {
                names.push(symbol_bytes(e, &f)?);
            }
            Some(names)
        }
        None => None,
    };
    let args = match &r.args {
        Some(list) => {
            let mut args = alloc::vec::Vec::new();
            for a in list.iter() {
                args.push(rule_eval::ArgConstraint {
                    index: a.index,
                    pred: pred(e, &a.pred, known)?,
                });
            }
            Some(args)
        }
        None => None,
    };
    Some(rule_eval::DocRule {
        scope: match &r.scope {
            ModelScope::Contract(a) => rule_eval::Scope::Contract(known.read(e, a)?),
            ModelScope::SelfAdmin => rule_eval::Scope::SelfAdmin,
        },
        principals: match &r.principals {
            ModelPrincipals::All(ids) => rule_eval::Principals::All(strings(ids)),
            ModelPrincipals::Threshold(ids, m) => {
                rule_eval::Principals::Threshold(strings(ids), *m)
            }
        },
        functions,
        args,
        auth_root: match &r.auth_root {
            Some(roots) => {
                if roots.len() != 1 {
                    return None;
                }
                let root = roots.get_unchecked(0);
                let contract = known.read(e, &root.contract)?;
                let function = symbol_bytes(e, &root.function)?;
                if contract.get(..4)? != [0, 0, 0, 1] || function.is_empty() {
                    return None;
                }
                Some(rule_eval::AuthRoot { contract, function })
            }
            None => None,
        },
        not_after_ledger: r.not_after_ledger,
        cap: r.cap.first().map(|c| rule_eval::DocCap {
            limit: c.limit,
            period_ledgers: c.period_ledgers,
        }),
    })
}

fn recovery(e: &Env, r: &ModelRecovery, known: &mut Addresses) -> Option<rule_eval::Recovery> {
    if r.zk.len() > 1 {
        return None;
    }
    let zk = match r.zk.first() {
        Some(z) => Some(rule_eval::ZkFactor {
            adapter: known.read(e, &z.adapter)?,
            pool: known.read(e, &z.pool)?,
        }),
        None => None,
    };
    Some(rule_eval::Recovery {
        controller: known.read(e, &r.controller)?,
        zk,
    })
}

/// The document `m` mirrors, or `None` when it holds more than one cap,
/// zero-knowledge factor or recovery configuration where one is the most,
/// or an address the facade refuses.
#[must_use]
pub fn doc_of(e: &Env, m: &CompiledModel) -> Option<rule_eval::Doc> {
    doc_of_in(e, m, &mut Addresses::default())
}

/// [`doc_of`], recording every address it reads in `known`, so the rules
/// rule-eval lowers the document to convert back to host values by lookup
/// (`StoredRule::from_rule_by`).
pub fn doc_of_in(e: &Env, m: &CompiledModel, known: &mut Addresses) -> Option<rule_eval::Doc> {
    if m.recovery.len() > 1 {
        return None;
    }
    let recovery = match m.recovery.first() {
        Some(r) => Some(recovery(e, &r, known)?),
        None => None,
    };
    let mut signers = alloc::vec::Vec::new();
    for d in m.signers.iter() {
        signers.push(rule_eval::SignerDecl {
            id: string_bytes(&d.id),
            signer: signer_in(e, &d.signer, known)?,
        });
    }
    let mut rules = alloc::vec::Vec::new();
    for r in m.rules.iter() {
        rules.push(rule(e, &r, known)?);
    }
    Some(rule_eval::Doc {
        signers,
        rules,
        recovery,
    })
}

#[cfg(feature = "ir")]
pub use from_ir::{model_of, ModelError};

#[cfg(feature = "ir")]
mod from_ir {
    use crate::StoredAuthRoot;
    use perch_account_types::Signer;
    use perch_ir::{ArgPred, PolicyDoc, Principals, RecoveryMode, Scope, SignerMethod};
    use soroban_sdk::{Address, Bytes, Env, String, Symbol, Vec};

    use super::{
        CompiledModel, ModelArg, ModelCap, ModelPred, ModelPrincipals, ModelRecovery, ModelRule,
        ModelScope, ModelSigner, ModelZk,
    };

    /// Why a validated document has no model.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ModelError {
        /// A rule with self-authenticating principals, which rule-eval's
        /// document has no form for (Perch's lowering refuses it too).
        SelfAuthenticating,
        /// A signer's `key` is not hex.
        KeyHex,
        /// A cap's `limit` does not parse as an `i128`.
        CapLimit,
        /// Self-admin rules cannot carry an authorization-root restriction.
        AuthRootOnSelfAdmin,
    }

    fn strings(e: &Env, list: &[alloc::string::String]) -> Vec<String> {
        let mut out = Vec::new(e);
        for s in list {
            out.push_back(String::from_str(e, s));
        }
        out
    }

    fn pred(e: &Env, p: &ArgPred) -> ModelPred {
        match p {
            ArgPred::IsSelf(_) => ModelPred::IsSelf,
            ArgPred::AddressEq(p) => ModelPred::AddressEq(Address::from_str(e, &p.address)),
            ArgPred::StringIn(p) => ModelPred::StringIn(strings(e, &p.values)),
            ArgPred::StringPrefix(p) => ModelPred::StringPrefix(String::from_str(e, &p.prefix)),
            ArgPred::U32Eq(p) => ModelPred::U32Eq(p.value),
        }
    }

    /// The model of `d`, read as the doc compiler reads a document: strkeys
    /// with `Address::from_str`, keys as hex of either case, function names
    /// with `Symbol::new`, and a cap's limit with `i128`'s `parse`, which
    /// takes a sign and leading zeros.
    ///
    /// Precondition: `perch_ir::validate(d).is_ok()`, which makes every
    /// strkey and function name one the host takes.
    ///
    /// # Errors
    ///
    /// [`ModelError`]: what validation leaves for the lowering to refuse.
    pub fn model_of(e: &Env, d: &PolicyDoc) -> Result<CompiledModel, ModelError> {
        let mut signers = Vec::new(e);
        for s in &d.signers {
            let signer = match &s.method {
                SignerMethod::Delegated { address } => {
                    Signer::Delegated(Address::from_str(e, address))
                }
                SignerMethod::External { verifier, key, .. } => Signer::External(
                    Address::from_str(e, verifier),
                    Bytes::from_slice(e, &hex::decode(key).map_err(|_| ModelError::KeyHex)?),
                ),
            };
            signers.push_back(ModelSigner {
                id: String::from_str(e, &s.id),
                signer,
            });
        }
        let mut rules = Vec::new(e);
        for r in &d.rules {
            if r.auth_root.is_some() && matches!(r.scope, Scope::SelfAdmin(_)) {
                return Err(ModelError::AuthRootOnSelfAdmin);
            }
            let principals = match &r.principals {
                Principals::All(p) => ModelPrincipals::All(strings(e, &p.signers)),
                Principals::Threshold(p) => ModelPrincipals::Threshold(strings(e, &p.signers), p.m),
                Principals::SelfAuthenticating(_) => return Err(ModelError::SelfAuthenticating),
            };
            let mut cap = Vec::new(e);
            if let Some(c) = &r.cap {
                cap.push_back(ModelCap {
                    limit: c.limit.parse().map_err(|_| ModelError::CapLimit)?,
                    period_ledgers: c.period_ledgers,
                });
            }
            rules.push_back(ModelRule {
                scope: match &r.scope {
                    Scope::Contract(c) => ModelScope::Contract(Address::from_str(e, &c.address)),
                    Scope::SelfAdmin(_) => ModelScope::SelfAdmin,
                },
                principals,
                functions: r.functions.as_ref().map(|fs| {
                    let mut out = Vec::new(e);
                    for f in fs {
                        out.push_back(Symbol::new(e, f));
                    }
                    out
                }),
                args: r.args.as_ref().map(|args| {
                    let mut out = Vec::new(e);
                    for a in args {
                        out.push_back(ModelArg {
                            index: a.index,
                            pred: pred(e, &a.pred),
                        });
                    }
                    out
                }),
                auth_root: r.auth_root.as_ref().map(|root| {
                    Vec::from_array(
                        e,
                        [StoredAuthRoot {
                            contract: Address::from_str(e, &root.contract),
                            function: Symbol::new(e, &root.function),
                        }],
                    )
                }),
                not_after_ledger: r.not_after_ledger,
                cap,
            });
        }
        let mut recovery = Vec::new(e);
        if let Some(r) = &d.recovery {
            let mut zk = Vec::new(e);
            if let RecoveryMode::ZkOnly(z) | RecoveryMode::Combined(_, z) = &r.mode {
                zk.push_back(ModelZk {
                    adapter: Address::from_str(e, &z.adapter),
                    pool: Address::from_str(e, &z.pool),
                });
            }
            recovery.push_back(ModelRecovery {
                controller: Address::from_str(e, &r.controller),
                zk,
            });
        }
        Ok(CompiledModel {
            signers,
            rules,
            recovery,
        })
    }
}
