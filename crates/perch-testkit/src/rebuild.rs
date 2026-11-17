//! A grant document's canonical text, rebuilt from what the account keeps
//! for it: each rule's name and stored rule-eval rule (`grant`,
//! `grant_rule_set`), the document's signer ids (`grant_signer_ids`), and
//! each signer's `verifier-name` (`grant_verifier_names`), trusted only once
//! its sha256 is the grant's stored `doc_hash`.
//!
//! The rebuild inverts rule-core's lowering on the normal form
//! (`perch_ir::normal_form`, and the account's own checks in `apply_grant`),
//! the one document of the many that store the same rules which the
//! account accepts as a grant document:
//!
//! - the signers, in declaration order, are the distinct stored signers in
//!   the order the rules first name them, each under the next stored id: a
//!   key in lowercase hex, and the next stored `verifier-name` where it is
//!   not empty;
//! - each rule's scope is its stored contract, its principals `all` when it
//!   asks every signer it names and `threshold` otherwise, and its
//!   `not-after-ledger` one past its last ledger;
//! - a capped rule's functions are `["transfer"]`, its cap a plain decimal
//!   limit with no token, and the condition the cap adds on argument 2 is
//!   dropped; an uncapped rule lists its functions, or none for every one;
//! - each condition is the predicate that lowers to it: `is-self` for the
//!   account's own address, `address-eq` for another, `u32-eq`,
//!   `string-in` and `string-prefix`.
//!
//! `perch-js`'s `rebuildScopeDoc` is the same function, pinned against the
//! vectors `crates/integration-tests/tests/grant_rebuild.rs` writes from it.
//! [`normal`] gives the grant document in normal form that stores the same
//! rules as a given one, for suites that apply documents written otherwise.

use crate::delta::strkey;
use perch_account::PerchAccountClient;
use perch_account_types::Signer;
use perch_ir::{
    AddressEqPred, ArgConstraint, ArgPred, CapConstraint, IsSelfPred, PolicyDoc, Principals, Rule,
    Scope, SignerDecl, SignerMethod, StringInPred, StringPrefixPred, U32EqPred,
    MAX_STRING_PRED_LEN,
};
use perch_rule_eval::convert::{string_bytes, symbol_bytes};
use perch_rule_eval::{StoredCond, StoredFunctions, StoredRule, StoredVal};
use sha2::{Digest, Sha256};
use soroban_sdk::{Address, Bytes, Env};
use std::format;
use std::string::{String, ToString};
use std::vec::Vec;

/// The network passphrases a reader knows: the document's `network` is the
/// one whose sha256 is the ledger's network id (the compiler refuses any
/// other).
pub const NETWORKS: [&str; 3] = [
    "Test SDF Network ; September 2015",
    "Public Global Stellar Network ; September 2015",
    "Standalone Network ; February 2017",
];

/// What an account keeps for one grant document.
#[derive(Clone, Debug)]
pub struct StoredDoc {
    pub account: Address,
    /// The passphrase of the network the account is on.
    pub network: String,
    pub doc_hash: [u8; 32],
    pub signer_ids: Vec<String>,
    /// Each signer's `verifier-name`, aligned with `signer_ids` (empty where
    /// it has none), or no entries when no signer has one.
    pub verifier_names: Vec<String>,
    /// Each rule's name and stored rule, in the record's order.
    pub rules: Vec<(String, StoredRule)>,
}

/// The known passphrase whose sha256 is `e`'s network id.
pub fn network(e: &Env) -> Option<String> {
    let id = e.ledger().network_id().to_array();
    NETWORKS
        .iter()
        .find(|n| <[u8; 32]>::from(Sha256::digest(n.as_bytes())) == id)
        .map(|n| n.to_string())
}

fn utf8(b: Vec<u8>) -> Result<String, String> {
    String::from_utf8(b).map_err(|x| format!("not UTF-8: {x}"))
}

/// What `account` keeps for its grant document under `grant`, read through
/// its views; `None` when it has none.
pub fn read(e: &Env, account: &Address, grant: u32) -> Result<Option<StoredDoc>, String> {
    let c = PerchAccountClient::new(e, account);
    let Some(record) = c.grant(&grant) else {
        return Ok(None);
    };
    let rules = c.grant_rule_set(&grant);
    if rules.len() != record.rules.len() {
        return Err(format!(
            "grant {grant}: {} records and {} stored rules",
            record.rules.len(),
            rules.len()
        ));
    }
    let signer_ids = c
        .grant_signer_ids(&grant)
        .ok_or(format!("grant {grant}: a record and no signer ids"))?;
    let verifier_names = c
        .grant_verifier_names(&grant)
        .ok_or(format!("grant {grant}: a record and no verifier names"))?;
    Ok(Some(StoredDoc {
        account: account.clone(),
        network: network(e).ok_or("a network no known passphrase hashes to")?,
        doc_hash: record.doc_hash.to_array(),
        signer_ids: signer_ids
            .iter()
            .map(|s| utf8(string_bytes(&s)))
            .collect::<Result<_, _>>()?,
        verifier_names: verifier_names
            .iter()
            .map(|s| utf8(string_bytes(&s)))
            .collect::<Result<_, _>>()?,
        rules: record
            .rules
            .iter()
            .zip(rules.iter())
            .map(|(r, s)| Ok((utf8(string_bytes(&r.name))?, s)))
            .collect::<Result<_, String>>()?,
    }))
}

fn bytes_vec(b: &Bytes) -> Vec<u8> {
    let mut out = std::vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut out);
    out
}

/// The stored signers in the order the rules first name them.
fn first_appearance(st: &StoredDoc) -> Vec<Signer> {
    let mut out: Vec<Signer> = Vec::new();
    for (_, r) in &st.rules {
        for s in r.signers.iter() {
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

fn declaration(id: &str, s: &Signer, verifier_name: Option<&String>) -> SignerDecl {
    SignerDecl {
        id: id.to_string(),
        method: match s {
            Signer::Delegated(a) => SignerMethod::Delegated { address: strkey(a) },
            Signer::External(v, k) => SignerMethod::External {
                verifier: strkey(v),
                key: hex::encode(bytes_vec(k)),
                verifier_name: verifier_name.filter(|n| !n.is_empty()).cloned(),
            },
        },
    }
}

fn symbol(e: &Env, s: &soroban_sdk::Symbol) -> Result<String, String> {
    utf8(symbol_bytes(e, s).ok_or("a symbol with no bytes")?)
}

/// The argument constraint condition `c` is the lowering of.
fn arg(st: &StoredDoc, c: &StoredCond) -> Result<ArgConstraint, String> {
    let (index, pred) = match c {
        StoredCond::ArgEq(i, StoredVal::Address(a)) if *a == st.account => {
            (*i, ArgPred::IsSelf(IsSelfPred {}))
        }
        StoredCond::ArgEq(i, StoredVal::Address(a)) => {
            (*i, ArgPred::AddressEq(AddressEqPred { address: strkey(a) }))
        }
        StoredCond::ArgEq(i, StoredVal::Other(x)) => {
            let x = bytes_vec(x);
            let [0, 0, 0, 3, a, b, c, d] = x[..] else {
                return Err(format!("an equality on a value that is no u32: {x:?}"));
            };
            (
                *i,
                ArgPred::U32Eq(U32EqPred {
                    value: u32::from_be_bytes([a, b, c, d]),
                }),
            )
        }
        StoredCond::ArgIn(i, vs) => {
            let mut values = Vec::new();
            for v in vs.iter() {
                let StoredVal::String(s) = v else {
                    return Err(format!("a set holding a non-string {v:?}"));
                };
                values.push(utf8(string_bytes(&s))?);
            }
            (*i, ArgPred::StringIn(StringInPred { values }))
        }
        StoredCond::ArgStrPrefix(i, p) => (
            *i,
            ArgPred::StringPrefix(StringPrefixPred {
                prefix: utf8(string_bytes(p))?,
            }),
        ),
        other => return Err(format!("a condition no predicate lowers to: {other:?}")),
    };
    Ok(ArgConstraint { index, pred })
}

/// The document rule `rule`, named `name`, is the lowering of, its signers
/// declared as `decls`.
fn rule(
    e: &Env,
    st: &StoredDoc,
    name: &str,
    rule: &StoredRule,
    decls: &[(SignerDecl, Signer)],
) -> Result<Rule, String> {
    let mut ids = Vec::new();
    for s in rule.signers.iter() {
        let (d, _) = decls
            .iter()
            .find(|(_, x)| *x == s)
            .ok_or("a stored signer with no id")?;
        ids.push(d.id.clone());
    }
    let principals = if rule.threshold as usize == ids.len() {
        Principals::all(ids)
    } else {
        Principals::threshold(ids, rule.threshold)
    };
    let mut conds: Vec<StoredCond> = rule.conds.iter().collect();
    let (functions, cap) = match rule.cap.len() {
        0 => (
            match &rule.functions {
                StoredFunctions::AnyExcept(fs) if fs.is_empty() => None,
                StoredFunctions::Only(fs) => {
                    Some(fs.iter().map(|f| symbol(e, &f)).collect::<Result<_, _>>()?)
                }
                other => return Err(format!("functions no document lowers to: {other:?}")),
            },
            None,
        ),
        1 => {
            let c = rule.cap.get_unchecked(0);
            match conds.pop() {
                Some(StoredCond::ArgI128AtMost(2, i128::MAX)) if c.amount_arg == 2 => {}
                other => {
                    return Err(format!(
                        "a cap on argument {}, last {other:?}",
                        c.amount_arg
                    ))
                }
            }
            match &rule.functions {
                StoredFunctions::Only(fs)
                    if fs.len() == 1 && symbol(e, &fs.get_unchecked(0))? == "transfer" => {}
                other => return Err(format!("a capped rule allowing {other:?}")),
            }
            (
                Some(std::vec!["transfer".to_string()]),
                Some(CapConstraint {
                    token: None,
                    limit: c.limit.to_string(),
                    period_ledgers: c.period,
                }),
            )
        }
        n => return Err(format!("{n} caps")),
    };
    let args = if conds.is_empty() {
        None
    } else {
        Some(conds.iter().map(|c| arg(st, c)).collect::<Result<_, _>>()?)
    };
    Ok(Rule {
        auth_root: match &rule.auth_root {
            Some(roots) => {
                if roots.len() != 1 {
                    return Err("malformed auth-root".into());
                }
                let root = roots.get_unchecked(0);
                Some(perch_ir::AuthRoot {
                    contract: strkey(&root.contract),
                    function: utf8(symbol_bytes(e, &root.function).ok_or("invalid root symbol")?)?,
                })
            }
            None => None,
        },
        name: name.to_string(),
        scope: Scope::contract(strkey(&rule.contract)),
        principals,
        functions,
        args,
        not_after_ledger: match rule.valid_until {
            Some(v) => Some(v.checked_add(1).ok_or("a last ledger of u32::MAX")?),
            None => None,
        },
        cap,
    })
}

/// The normal-form document `st` is the lowering of.
pub fn rebuild(e: &Env, st: &StoredDoc) -> Result<PolicyDoc, String> {
    let signers = first_appearance(st);
    if signers.len() != st.signer_ids.len() {
        return Err(format!(
            "{} signer ids for {} stored signers",
            st.signer_ids.len(),
            signers.len()
        ));
    }
    if !st.verifier_names.is_empty() && st.verifier_names.len() != st.signer_ids.len() {
        return Err(format!(
            "{} verifier names for {} signer ids",
            st.verifier_names.len(),
            st.signer_ids.len()
        ));
    }
    let decls: Vec<(SignerDecl, Signer)> = st
        .signer_ids
        .iter()
        .zip(signers)
        .enumerate()
        .map(|(i, (id, s))| (declaration(id, &s, st.verifier_names.get(i)), s))
        .collect();
    let rules = st
        .rules
        .iter()
        .map(|(name, r)| rule(e, st, name, r, &decls))
        .collect::<Result<_, _>>()?;
    Ok(PolicyDoc {
        version: 1,
        network: Some(st.network.clone()),
        signers: decls.into_iter().map(|(d, _)| d).collect(),
        rules,
        recovery: None,
    })
}

/// The canonical text of `st`'s document: its rebuild, refused unless its
/// sha256 is the stored `doc_hash`.
pub fn text(e: &Env, st: &StoredDoc) -> Result<String, String> {
    let text = perch_ir::canonical_json(&rebuild(e, st)?);
    if <[u8; 32]>::from(Sha256::digest(text.as_bytes())) != st.doc_hash {
        return Err(format!(
            "the rebuilt text does not hash to doc_hash: {text}"
        ));
    }
    Ok(text)
}

/// The canonical text of `account`'s grant document under `grant`, rebuilt
/// from storage and checked against its `doc_hash`.
pub fn grant_text(e: &Env, account: &Address, grant: u32) -> Result<String, String> {
    let st = read(e, account, grant)?.ok_or(format!("no grant {grant}"))?;
    text(e, &st)
}

/// The ids `p` names, in order.
fn principal_ids(p: &Principals) -> &[String] {
    match p {
        Principals::All(a) => &a.signers,
        Principals::Threshold(t) => &t.signers,
        Principals::SelfAuthenticating(_) => &[],
    }
}

/// The grant document in normal form that stores the same rules as `doc`
/// on the account `account` (its strkey) at ledger `ledger`: rules already
/// expired dropped, `all` for a threshold asking every signer it names, a
/// capped rule's functions `["transfer"]` when they cover it, its limit a
/// plain decimal and no token, `is-self` for an `address-eq` naming the
/// account, no `string-in` value too long to match, and the signers the
/// rules name declared in the order they first name them, keys in
/// lowercase hex. A capped rule whose functions do not cover `transfer`
/// allows nothing, and keeps them: no document in normal form stores it.
pub fn normal(doc: &PolicyDoc, account: &str, ledger: u32) -> PolicyDoc {
    let mut d = doc.clone();
    d.rules
        .retain(|r| r.not_after_ledger.is_none_or(|n| n > ledger));
    for r in &mut d.rules {
        if let Principals::Threshold(t) = &r.principals {
            if t.m as usize == t.signers.len() {
                r.principals = Principals::all(t.signers.clone());
            }
        }
        if let Some(cap) = &mut r.cap {
            cap.token = None;
            if let Ok(limit) = cap.limit.parse::<i128>() {
                cap.limit = limit.to_string();
            }
            if r.functions
                .as_ref()
                .is_none_or(|fs| fs.iter().any(|f| f == "transfer"))
            {
                r.functions = Some(std::vec!["transfer".to_string()]);
            }
        }
        for a in r.args.iter_mut().flatten() {
            if matches!(&a.pred, ArgPred::AddressEq(p) if p.address == account) {
                a.pred = ArgPred::IsSelf(IsSelfPred {});
            }
            if let ArgPred::StringIn(p) = &mut a.pred {
                p.values.retain(|v| v.len() <= MAX_STRING_PRED_LEN);
            }
        }
    }
    let mut order: Vec<String> = Vec::new();
    for r in &d.rules {
        for id in principal_ids(&r.principals) {
            if !order.contains(id) {
                order.push(id.clone());
            }
        }
    }
    d.signers = order
        .iter()
        .filter_map(|id| doc.signers.iter().find(|s| &s.id == id).cloned())
        .map(|mut s| {
            if let SignerMethod::External { key, .. } = &mut s.method {
                *key = key.to_lowercase();
            }
            s
        })
        .collect();
    d
}
