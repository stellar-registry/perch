//! Rule-set reconciliation for `apply_doc` (`docs/recovery/spec.md` §7.5).
//!
//! The account records every context rule it installs ([`InstalledRule`]).
//! `apply_doc` matches the compiled document's rules against those records
//! (document rules by name and scope, the recovery rule by role) and changes
//! only what differs:
//!
//! - a rule present in both, with the same signers, policy parameters, and
//!   expiry, is not touched at all: no OZ call, no storage access, no event;
//! - a rule present in both that differs is edited in place with OZ's
//!   per-signer, per-policy, and expiry updates, keeping its id;
//! - a rule only in the record is removed; a rule only in the document is
//!   added.
//!
//! A rule is replaced whole (removed and added under a new id) only when an
//! in-place edit cannot keep it valid at every step: its scope changed, or
//! nothing on it survives and the edit would otherwise pass through an
//! empty rule or exceed OZ's per-rule limits.
//!
//! The authorization the result grants is exactly what a full replace of
//! every rule would grant. Two things differ, deliberately: a kept rule keeps
//! its id, and its policies keep their state (a spending cap's window is not
//! reset by re-applying the document that set it). Everything runs in the
//! one `apply_doc` invocation, so a failure anywhere reverts every edit.

use crate::infra;
use perch_doc_compiler::{CompiledDoc, CompiledRule, RuleScope};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, Address, BytesN, Env, IntoVal, Map, String, Val, Vec};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;
use stellar_accounts::smart_account::{self, ContextRuleType, Signer, MAX_POLICIES, MAX_SIGNERS};

/// One policy attached to an installed rule.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledPolicy {
    pub policy: Address,
    /// `sha256` of the install parameters' XDR. A policy whose parameters
    /// change is uninstalled and installed again; one whose parameters are
    /// unchanged is left alone.
    pub params: BytesN<32>,
}

/// One context rule as the account installed it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRule {
    /// The OZ context-rule id.
    pub id: u32,
    /// The zero-signer recovery rule. Document rules are matched by name;
    /// the recovery rule by this flag, so a document rule that happens to be
    /// named `recovery` is never confused with it.
    pub recovery: bool,
    pub name: String,
    pub context_type: ContextRuleType,
    pub valid_until: Option<u32>,
    pub signers: Vec<Signer>,
    pub policies: Vec<InstalledPolicy>,
}

impl InstalledRule {
    /// Whether `other` is the same rule slot: an in-place edit can turn one
    /// into the other.
    fn same_slot(&self, other: &InstalledRule) -> bool {
        self.recovery == other.recovery
            && (self.recovery || self.name == other.name)
            && self.context_type == other.context_type
    }

    fn with_id(&self, id: u32) -> InstalledRule {
        let mut rule = self.clone();
        rule.id = id;
        rule
    }
}

/// The constructor's admin rule, as recorded.
pub(crate) fn admin_rule(e: &Env, id: u32, signers: &Vec<Signer>) -> InstalledRule {
    InstalledRule {
        id,
        recovery: false,
        name: String::from_str(e, "admin"),
        context_type: ContextRuleType::CallContract(e.current_contract_address()),
        valid_until: None,
        signers: signers.clone(),
        policies: Vec::new(e),
    }
}

/// The rules `compiled` asks for, with each policy's install parameters
/// (aligned with `rule.policies`). Ids are unset.
pub(crate) fn desired(e: &Env, compiled: &CompiledDoc) -> (Vec<InstalledRule>, Vec<Vec<Val>>) {
    let mut rules = Vec::new(e);
    let mut params = Vec::new(e);
    for rule in compiled.rules.iter() {
        let (r, p) = document_rule(e, &rule);
        rules.push_back(r);
        params.push_back(p);
    }
    if let Some(recovery) = compiled.recovery.first() {
        let mut p: Vec<Val> = Vec::new(e);
        p.push_back(recovery.config_hash.clone().into_val(e));
        rules.push_back(InstalledRule {
            id: 0,
            recovery: true,
            name: String::from_str(e, "recovery"),
            context_type: ContextRuleType::CallContract(e.current_contract_address()),
            valid_until: None,
            signers: Vec::new(e),
            policies: Vec::from_array(
                e,
                [InstalledPolicy {
                    policy: recovery.controller.clone(),
                    params: digest(e, recovery.config_hash.clone().to_xdr(e)),
                }],
            ),
        });
        params.push_back(p);
    }
    (rules, params)
}

/// A compiled document rule: its scope, signers, and the interpreter and
/// spending-limit policies its program and cap need.
fn document_rule(e: &Env, rule: &CompiledRule) -> (InstalledRule, Vec<Val>) {
    let context_type = match &rule.scope {
        RuleScope::SelfAdmin => ContextRuleType::CallContract(e.current_contract_address()),
        RuleScope::Contract(addr) => ContextRuleType::CallContract(addr.clone()),
    };
    let mut policies = Vec::new(e);
    let mut params = Vec::new(e);
    if let Some(install) = rule.install.first() {
        policies.push_back(InstalledPolicy {
            policy: infra::perch_interpreter::address(e),
            params: digest(e, install.clone().to_xdr(e)),
        });
        params.push_back(install.into_val(e));
    }
    // A capped rule also attaches OZ `spending_limit` (the stateful cumulative
    // cap the interpreter cannot express), keyed by its content-addressed
    // address — resolved offline like the interpreter, never admin-supplied. OZ
    // enforces every attached policy (AND): the interpreter's per-call program
    // AND the rolling cap must pass. The metered token is this rule's
    // `CallContract` scope (validation pins `token == scope`).
    if let Some(cap) = rule.cap.first() {
        let cap = SpendingLimitAccountParams {
            spending_limit: cap.spending_limit,
            period_ledgers: cap.period_ledgers,
        };
        policies.push_back(InstalledPolicy {
            policy: infra::perch_spending_limit::address(e),
            params: digest(e, cap.clone().to_xdr(e)),
        });
        params.push_back(cap.into_val(e));
    }
    let installed = InstalledRule {
        id: 0,
        recovery: false,
        name: rule.name.clone(),
        context_type,
        valid_until: rule.valid_until,
        signers: rule.signers.clone(),
        policies,
    };
    (installed, params)
}

fn digest(e: &Env, xdr: soroban_sdk::Bytes) -> BytesN<32> {
    e.crypto().sha256(&xdr).to_bytes()
}

/// Bring the installed rules from `current` to `desired`, touching only what
/// differs. Returns the new records, in `desired` order.
pub(crate) fn reconcile(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
) -> Vec<InstalledRule> {
    // Rules with no counterpart go first, releasing their signer and policy
    // registrations before anything is added.
    for c in current.iter() {
        if !desired.iter().any(|d| c.same_slot(&d)) {
            smart_account::remove_context_rule(e, c.id);
        }
    }
    let mut next = Vec::new(e);
    for (i, d) in desired.iter().enumerate() {
        let p = params.get_unchecked(i as u32);
        next.push_back(match current.iter().find(|c| c.same_slot(&d)) {
            Some(c) => update(e, &c, &d, &p),
            None => add(e, &d, &p),
        });
    }
    next
}

/// The pre-delta behaviour: remove every installed rule, then add every
/// desired one. Kept only as the oracle the delta is tested against.
#[cfg(feature = "testutils")]
pub(crate) fn replace_all(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
) -> Vec<InstalledRule> {
    for c in current.iter() {
        smart_account::remove_context_rule(e, c.id);
    }
    let mut next = Vec::new(e);
    for (i, d) in desired.iter().enumerate() {
        next.push_back(add(e, &d, &params.get_unchecked(i as u32)));
    }
    next
}

fn add(e: &Env, d: &InstalledRule, params: &Vec<Val>) -> InstalledRule {
    let mut policies: Map<Address, Val> = Map::new(e);
    for (i, p) in d.policies.iter().enumerate() {
        policies.set(p.policy, params.get_unchecked(i as u32));
    }
    let rule = smart_account::add_context_rule(
        e,
        &d.context_type,
        &d.name,
        d.valid_until,
        &d.signers,
        &policies,
    );
    d.with_id(rule.id)
}

/// Edit rule `c` in place into `d`, or replace it whole when no in-place
/// order keeps it valid at every step.
fn update(e: &Env, c: &InstalledRule, d: &InstalledRule, params: &Vec<Val>) -> InstalledRule {
    let add_signers = missing(e, &d.signers, &c.signers);
    let remove_signers = missing(e, &c.signers, &d.signers);
    // A policy whose parameters change is removed and added back.
    let mut remove_policies: Vec<InstalledPolicy> = Vec::new(e);
    for p in c.policies.iter() {
        if !d.policies.contains(&p) {
            remove_policies.push_back(p);
        }
    }
    let mut add_policies: Vec<(InstalledPolicy, Val)> = Vec::new(e);
    for (i, p) in d.policies.iter().enumerate() {
        if !c.policies.contains(&p) {
            add_policies.push_back((p, params.get_unchecked(i as u32)));
        }
    }

    let edits = !(add_signers.is_empty()
        && remove_signers.is_empty()
        && add_policies.is_empty()
        && remove_policies.is_empty());
    if edits {
        let kept =
            (c.signers.len() - remove_signers.len()) + (c.policies.len() - remove_policies.len());
        // Additions under addresses the rule does not have yet can go before
        // the removals; a changed policy keeps its address, so it can only be
        // added back after its old parameters are removed.
        let fresh: Vec<(InstalledPolicy, Val)> = {
            let mut v = Vec::new(e);
            for (p, val) in add_policies.iter() {
                if !c.policies.iter().any(|q| q.policy == p.policy) {
                    v.push_back((p, val));
                }
            }
            v
        };
        let rule = smart_account::get_context_rule(e, c.id);
        if kept > 0 {
            // Something survives, so removing first never empties the rule,
            // and the counts only shrink before they grow to the target.
            remove(e, &rule, &remove_signers, &remove_policies);
            for s in add_signers.iter() {
                smart_account::add_signer(e, c.id, &s);
            }
            for (p, val) in add_policies.iter() {
                smart_account::add_policy(e, c.id, &p.policy, val);
            }
        } else if (!add_signers.is_empty() || !fresh.is_empty())
            && c.signers.len() + add_signers.len() <= MAX_SIGNERS
            && c.policies.len() + fresh.len() <= MAX_POLICIES
        {
            // Nothing survives: add first so the rule is never empty, then
            // remove the old, then re-add changed policies.
            for s in add_signers.iter() {
                smart_account::add_signer(e, c.id, &s);
            }
            for (p, val) in fresh.iter() {
                smart_account::add_policy(e, c.id, &p.policy, val);
            }
            remove(e, &rule, &remove_signers, &remove_policies);
            for (p, val) in add_policies.iter() {
                if !fresh.iter().any(|(q, _)| q.policy == p.policy) {
                    smart_account::add_policy(e, c.id, &p.policy, val);
                }
            }
        } else {
            smart_account::remove_context_rule(e, c.id);
            return add(e, d, params);
        }
    }
    if c.valid_until != d.valid_until {
        smart_account::update_context_rule_valid_until(e, c.id, d.valid_until);
    }
    d.with_id(c.id)
}

/// Remove signers and policies from `rule`, using the OZ ids read from it
/// before any edit.
fn remove(
    e: &Env,
    rule: &smart_account::ContextRule,
    signers: &Vec<Signer>,
    policies: &Vec<InstalledPolicy>,
) {
    for s in signers.iter() {
        if let Some(pos) = rule.signers.first_index_of(&s) {
            smart_account::remove_signer(e, rule.id, rule.signer_ids.get_unchecked(pos));
        }
    }
    for p in policies.iter() {
        if let Some(pos) = rule.policies.first_index_of(&p.policy) {
            smart_account::remove_policy(e, rule.id, rule.policy_ids.get_unchecked(pos));
        }
    }
}

/// The elements of `from` that `other` lacks.
fn missing(e: &Env, from: &Vec<Signer>, other: &Vec<Signer>) -> Vec<Signer> {
    let mut out = Vec::new(e);
    for s in from.iter() {
        if !other.contains(&s) {
            out.push_back(s);
        }
    }
    out
}
