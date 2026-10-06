//! Rule-set reconciliation for `apply_doc` (`docs/recovery/spec.md` §7.5).
//!
//! The account records every context rule it installs ([`InstalledRule`]).
//! `apply_doc` matches the compiled document's rules against those records
//! (document rules by name and scope, the recovery rule by role) and changes
//! only what differs:
//!
//! - a rule present in both, with the same signers, policy parameters, and
//!   expiry, is not touched at all: no OZ call, no storage access, no event;
//! - a rule present in both that differs is either edited in place with
//!   OZ's per-signer, per-policy, and expiry updates, keeping its id, or
//!   replaced whole under a new id, whichever [`Cost`] prices lower;
//! - a rule only in the record is removed; a rule only in the document is
//!   added.
//!
//! The cost model prices the exact operation sequence each path would run
//! (the same code drives the pricing and the operations): contract event
//! bytes first, then ledger writes. An in-place edit costs per changed
//! signer and policy; a replacement costs a rule removal and addition plus
//! re-registering and reinstalling everything the rule keeps. Replacement is
//! also the only path when no in-place order keeps the rule valid at every
//! step (nothing on it survives and adding first would exceed OZ's per-rule
//! limits or is impossible). Choosing the cheaper path per rule keeps every
//! apply at or below the cost of replacing every rule.
//!
//! The authorization the result grants is exactly what a full replace of
//! every rule would grant. Two things differ, deliberately: a rule edited in
//! place keeps its id, and its kept policies keep their state (a spending
//! cap's window is not reset by a signer change). Everything runs in the one
//! `apply_doc` invocation, so a failure anywhere reverts every edit.

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

/// How `apply_doc` reconciles a rule that the records and the document both
/// have but that differs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Whichever of an in-place edit and a whole replacement [`Cost`] prices
    /// lower, the in-place edit on a tie. `apply_doc`'s only mode.
    Cheapest,
    /// Every changed rule edited in place where an in-place order exists
    /// (test-only: prices that path on its own).
    #[cfg(feature = "testutils")]
    InPlace,
    /// Every changed rule replaced whole (test-only).
    #[cfg(feature = "testutils")]
    Replace,
    /// Every installed rule removed and every document rule added: the
    /// behaviour before the delta apply, kept as the test oracle.
    #[cfg(feature = "testutils")]
    FullReplace,
}

/// The cost model's price of reconciling one rule: bytes of contract events
/// (the account's and its policies'), then ledger entries written, compared
/// in that order. Events come first because they are what grows fastest per
/// changed signer and what the network caps per transaction.
#[contracttype]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd, Ord)]
pub struct Cost {
    pub events: u32,
    pub writes: u32,
}

/// What reconciliation does to one rule slot.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Identical in the records and the document: not touched.
    Keep,
    /// Only in the records.
    Remove,
    /// Only in the document.
    Add,
    InPlace,
    Replace,
}

/// One slot's step and price. A changed rule ([`Step::InPlace`] or
/// [`Step::Replace`]) also carries both prices the choice compared.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedRule {
    pub name: String,
    pub recovery: bool,
    pub context_type: ContextRuleType,
    pub step: Step,
    pub cost: Cost,
    /// Whether some in-place order keeps the rule valid; `in_place` is
    /// meaningful only then.
    pub editable: bool,
    pub in_place: Cost,
    pub replace: Cost,
}

// Contract event sizes, in bytes of `ContractEvent` XDR: the measure the
// network's per-transaction events limit and fee apply to. Each is 52 bytes
// of envelope (extension, contract id, type, body tag, topic count), its
// topics (the event-name symbol, then a `u32` id or the account's address),
// and its data map. `apply_delta.rs` checks every apply's total against the
// host's.
const SIGNER_ADDED: u32 = 120;
const SIGNER_REMOVED: u32 = 124;
/// Plus the signer's XDR.
const SIGNER_REGISTERED: u32 = 116;
const SIGNER_DEREGISTERED: u32 = 100;
const POLICY_ADDED: u32 = 120;
const POLICY_REMOVED: u32 = 124;
const POLICY_REGISTERED: u32 = 156;
const POLICY_DEREGISTERED: u32 = 100;
/// Plus the context type's and name's XDR, 8 per signer and policy id, and
/// the expiry ([`expiry`]).
const RULE_ADDED: u32 = 216;
const RULE_REMOVED: u32 = 100;
/// Plus the name's XDR and the expiry.
const RULE_META_UPDATED: u32 = 140;
const SPENDING_LIMIT_INSTALLED: u32 = 244;
const SPENDING_LIMIT_UNINSTALLED: u32 = 172;

/// An `Option<u32>` expiry's XDR: a `u32`, or void.
fn expiry(valid_until: Option<u32>) -> u32 {
    if valid_until.is_some() {
        8
    } else {
        4
    }
}

/// Bring the installed rules from `current` to `desired`, touching only what
/// differs. Returns the new records, in `desired` order.
pub(crate) fn reconcile(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
    mode: Mode,
) -> Vec<InstalledRule> {
    #[cfg(feature = "testutils")]
    if mode == Mode::FullReplace {
        return replace_all(e, current, desired, params);
    }
    run(e, current, desired, params, mode, None)
}

/// What [`reconcile`] would do to each slot, without doing it.
#[cfg(feature = "testutils")]
pub(crate) fn plan(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
    mode: Mode,
) -> Vec<PlannedRule> {
    let mut planned = Vec::new(e);
    run(e, current, desired, params, mode, Some(&mut planned));
    planned
}

/// Reconcile, or with `dry_run` only record each slot's step and price.
///
/// Unmatched records are removed first, so their signers and policies leave
/// the registries before anything is added. Each changed rule is then priced
/// both ways against the registry reference counts at that point (a
/// registration or deregistration is an event of its own) and reconciled the
/// cheaper way. Taking the minimum per rule keeps the whole apply at or below
/// a full replace: that replaces every rule, and deregisters and registers
/// every signer and policy on the way.
fn run(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
    mode: Mode,
    mut dry_run: Option<&mut Vec<PlannedRule>>,
) -> Vec<InstalledRule> {
    let hooks = Hooks {
        interpreter: infra::perch_interpreter::address(e),
        spending_limit: infra::perch_spending_limit::address(e),
    };
    let mut refs = Refs::of(e, current);
    let live = dry_run.is_none();
    let mut apply = Apply { e, rule: None };
    let mut record =
        |r: &InstalledRule, step: Step, cost: Cost, in_place: Option<Cost>, replace: Cost| {
            if let Some(planned) = dry_run.as_deref_mut() {
                planned.push_back(PlannedRule {
                    name: r.name.clone(),
                    recovery: r.recovery,
                    context_type: r.context_type.clone(),
                    step,
                    cost,
                    editable: in_place.is_some(),
                    in_place: in_place.unwrap_or_default(),
                    replace,
                });
            }
        };

    for c in current.iter() {
        if !desired.iter().any(|d| c.same_slot(&d)) {
            let mut m = Meter::new(e, &hooks, &refs);
            m.remove_rule(&c);
            refs = m.refs;
            record(&c, Step::Remove, m.cost, None, Cost::default());
            if live {
                apply.remove_rule(&c);
            }
        }
    }
    let mut next = Vec::new(e);
    for (i, d) in desired.iter().enumerate() {
        let p = params.get_unchecked(i as u32);
        let Some(c) = current.iter().find(|c| c.same_slot(&d)) else {
            let mut m = Meter::new(e, &hooks, &refs);
            m.add_rule(&d, &p);
            refs = m.refs;
            record(&d, Step::Add, m.cost, None, Cost::default());
            let id = if live { apply.add_rule(&d, &p) } else { 0 };
            next.push_back(d.with_id(id));
            continue;
        };
        if unchanged(e, &c, &d) {
            record(&d, Step::Keep, Cost::default(), None, Cost::default());
            next.push_back(d.with_id(c.id));
            continue;
        }
        let mut edited = Meter::new(e, &hooks, &refs);
        let editable = edit(e, &mut edited, &c, &d, &p);
        let mut replaced = Meter::new(e, &hooks, &refs);
        replace(&mut replaced, &c, &d, &p);
        let in_place = editable
            && match mode {
                Mode::Cheapest => edited.cost <= replaced.cost,
                #[cfg(feature = "testutils")]
                Mode::InPlace => true,
                #[cfg(feature = "testutils")]
                Mode::Replace | Mode::FullReplace => false,
            };
        let offered = editable.then_some(edited.cost);
        if in_place {
            refs = edited.refs;
            record(&d, Step::InPlace, edited.cost, offered, replaced.cost);
            if live {
                edit(e, &mut apply, &c, &d, &p);
            }
            next.push_back(d.with_id(c.id));
        } else {
            refs = replaced.refs;
            record(&d, Step::Replace, replaced.cost, offered, replaced.cost);
            let id = if live {
                replace(&mut apply, &c, &d, &p)
            } else {
                0
            };
            next.push_back(d.with_id(id));
        }
    }
    next
}

/// The policies whose own `install` and `uninstall` cost something: the
/// interpreter writes its program, the spending limit writes its window and
/// emits an event. The recovery controller's hooks write and emit nothing.
struct Hooks {
    interpreter: Address,
    spending_limit: Address,
}

/// The signer and policy registries' reference counts: how many installed
/// rules name each. Derived from the records, which are every rule the
/// account has.
#[derive(Clone)]
struct Refs {
    signers: Map<Signer, u32>,
    policies: Map<Address, u32>,
}

impl Refs {
    fn of(e: &Env, rules: &Vec<InstalledRule>) -> Refs {
        let mut refs = Refs {
            signers: Map::new(e),
            policies: Map::new(e),
        };
        for r in rules.iter() {
            for s in r.signers.iter() {
                let n = refs.signers.get(s.clone()).unwrap_or(0);
                refs.signers.set(s, n + 1);
            }
            for p in r.policies.iter() {
                let n = refs.policies.get(p.policy.clone()).unwrap_or(0);
                refs.policies.set(p.policy, n + 1);
            }
        }
        refs
    }
}

/// The OZ operations reconciliation is made of. [`Apply`] performs them and
/// [`Meter`] prices them; [`edit`] and [`replace`] drive both through the
/// same sequence, so the model prices exactly what runs.
trait Effects {
    fn add_signer(&mut self, rule: &InstalledRule, signer: &Signer);
    fn remove_signer(&mut self, rule: &InstalledRule, signer: &Signer);
    fn add_policy(&mut self, rule: &InstalledRule, policy: &Address, param: &Val);
    fn remove_policy(&mut self, rule: &InstalledRule, policy: &Address);
    fn set_valid_until(&mut self, rule: &InstalledRule, valid_until: Option<u32>);
    fn remove_rule(&mut self, rule: &InstalledRule);
    /// The new rule's id.
    fn add_rule(&mut self, rule: &InstalledRule, params: &Vec<Val>) -> u32;
}

/// Prices operations against simulated registry counts.
struct Meter<'a> {
    e: &'a Env,
    hooks: &'a Hooks,
    refs: Refs,
    cost: Cost,
    /// An in-place edit rewrites the rule's own entry once, however many
    /// operations it takes.
    rule_written: bool,
}

impl<'a> Meter<'a> {
    fn new(e: &'a Env, hooks: &'a Hooks, refs: &Refs) -> Meter<'a> {
        Meter {
            e,
            hooks,
            refs: refs.clone(),
            cost: Cost::default(),
            rule_written: false,
        }
    }

    fn touch_rule(&mut self) {
        if !self.rule_written {
            self.rule_written = true;
            self.cost.writes += 1;
        }
    }

    /// The registry entry's count changes; the first reference also writes
    /// its lookup entry and emits the registration.
    fn register_signer(&mut self, signer: &Signer) {
        let n = self.refs.signers.get(signer.clone()).unwrap_or(0);
        self.cost.writes += 1;
        if n == 0 {
            self.cost.events += SIGNER_REGISTERED + signer.clone().to_xdr(self.e).len();
            self.cost.writes += 1;
        }
        self.refs.signers.set(signer.clone(), n + 1);
    }

    fn deregister_signer(&mut self, signer: &Signer) {
        let n = self.refs.signers.get(signer.clone()).unwrap_or(0);
        self.cost.writes += 1;
        if n <= 1 {
            self.cost.events += SIGNER_DEREGISTERED;
            self.cost.writes += 1;
            self.refs.signers.remove(signer.clone());
        } else {
            self.refs.signers.set(signer.clone(), n - 1);
        }
    }

    fn register_policy(&mut self, policy: &Address) {
        let n = self.refs.policies.get(policy.clone()).unwrap_or(0);
        self.cost.writes += 1;
        if n == 0 {
            self.cost.events += POLICY_REGISTERED;
            self.cost.writes += 1;
        }
        self.refs.policies.set(policy.clone(), n + 1);
    }

    fn deregister_policy(&mut self, policy: &Address) {
        let n = self.refs.policies.get(policy.clone()).unwrap_or(0);
        self.cost.writes += 1;
        if n <= 1 {
            self.cost.events += POLICY_DEREGISTERED;
            self.cost.writes += 1;
            self.refs.policies.remove(policy.clone());
        } else {
            self.refs.policies.set(policy.clone(), n - 1);
        }
    }

    /// A policy's own `install` (or `uninstall`).
    fn hook(&mut self, policy: &Address, install: bool) {
        if *policy == self.hooks.spending_limit {
            self.cost.events += if install {
                SPENDING_LIMIT_INSTALLED
            } else {
                SPENDING_LIMIT_UNINSTALLED
            };
            self.cost.writes += 1;
        } else if *policy == self.hooks.interpreter {
            self.cost.writes += 1;
        }
    }
}

impl Effects for Meter<'_> {
    fn add_signer(&mut self, _: &InstalledRule, signer: &Signer) {
        self.touch_rule();
        self.register_signer(signer);
        self.cost.events += SIGNER_ADDED;
    }

    fn remove_signer(&mut self, _: &InstalledRule, signer: &Signer) {
        self.touch_rule();
        self.deregister_signer(signer);
        self.cost.events += SIGNER_REMOVED;
    }

    fn add_policy(&mut self, _: &InstalledRule, policy: &Address, _: &Val) {
        self.touch_rule();
        self.register_policy(policy);
        self.hook(policy, true);
        self.cost.events += POLICY_ADDED;
    }

    fn remove_policy(&mut self, _: &InstalledRule, policy: &Address) {
        self.touch_rule();
        self.hook(policy, false);
        self.deregister_policy(policy);
        self.cost.events += POLICY_REMOVED;
    }

    fn set_valid_until(&mut self, rule: &InstalledRule, valid_until: Option<u32>) {
        self.touch_rule();
        self.cost.events +=
            RULE_META_UPDATED + rule.name.clone().to_xdr(self.e).len() + expiry(valid_until);
    }

    fn remove_rule(&mut self, rule: &InstalledRule) {
        for p in rule.policies.iter() {
            self.hook(&p.policy, false);
            self.deregister_policy(&p.policy);
        }
        for s in rule.signers.iter() {
            self.deregister_signer(&s);
        }
        self.cost.events += RULE_REMOVED;
        self.cost.writes += 1;
    }

    fn add_rule(&mut self, rule: &InstalledRule, _: &Vec<Val>) -> u32 {
        for s in rule.signers.iter() {
            self.register_signer(&s);
        }
        for p in rule.policies.iter() {
            self.register_policy(&p.policy);
            self.hook(&p.policy, true);
        }
        self.cost.events += RULE_ADDED
            + rule.context_type.clone().to_xdr(self.e).len()
            + rule.name.clone().to_xdr(self.e).len()
            + 8 * (rule.signers.len() + rule.policies.len())
            + expiry(rule.valid_until);
        self.cost.writes += 1;
        0
    }
}

/// Performs operations through OZ.
struct Apply<'a> {
    e: &'a Env,
    /// The rule being edited, read before its first removal: removals need
    /// OZ's registry ids, which no addition in the same edit changes.
    rule: Option<smart_account::ContextRule>,
}

impl Apply<'_> {
    fn oz(&mut self, id: u32) -> &smart_account::ContextRule {
        if self.rule.as_ref().map(|r| r.id) != Some(id) {
            self.rule = Some(smart_account::get_context_rule(self.e, id));
        }
        self.rule.as_ref().unwrap()
    }
}

impl Effects for Apply<'_> {
    fn add_signer(&mut self, rule: &InstalledRule, signer: &Signer) {
        smart_account::add_signer(self.e, rule.id, signer);
    }

    fn remove_signer(&mut self, rule: &InstalledRule, signer: &Signer) {
        let oz = self.oz(rule.id);
        let id = oz
            .signer_ids
            .get_unchecked(oz.signers.first_index_of(signer).unwrap());
        smart_account::remove_signer(self.e, rule.id, id);
    }

    fn add_policy(&mut self, rule: &InstalledRule, policy: &Address, param: &Val) {
        smart_account::add_policy(self.e, rule.id, policy, *param);
    }

    fn remove_policy(&mut self, rule: &InstalledRule, policy: &Address) {
        let oz = self.oz(rule.id);
        let id = oz
            .policy_ids
            .get_unchecked(oz.policies.first_index_of(policy).unwrap());
        smart_account::remove_policy(self.e, rule.id, id);
    }

    fn set_valid_until(&mut self, rule: &InstalledRule, valid_until: Option<u32>) {
        smart_account::update_context_rule_valid_until(self.e, rule.id, valid_until);
    }

    fn remove_rule(&mut self, rule: &InstalledRule) {
        smart_account::remove_context_rule(self.e, rule.id);
    }

    fn add_rule(&mut self, rule: &InstalledRule, params: &Vec<Val>) -> u32 {
        let mut policies: Map<Address, Val> = Map::new(self.e);
        for (i, p) in rule.policies.iter().enumerate() {
            policies.set(p.policy, params.get_unchecked(i as u32));
        }
        smart_account::add_context_rule(
            self.e,
            &rule.context_type,
            &rule.name,
            rule.valid_until,
            &rule.signers,
            &policies,
        )
        .id
    }
}

/// Whether `c` and `d` install the same rule: the same slot, signers,
/// policies with their parameters, and expiry.
fn unchanged(e: &Env, c: &InstalledRule, d: &InstalledRule) -> bool {
    missing(e, &c.signers, &d.signers).is_empty()
        && missing(e, &d.signers, &c.signers).is_empty()
        && c.policies.iter().all(|p| d.policies.contains(&p))
        && d.policies.iter().all(|p| c.policies.contains(&p))
        && c.valid_until == d.valid_until
}

/// Edit rule `c` into `d` under its id, or return false, doing nothing, when
/// no in-place order keeps it valid at every step.
fn edit(
    e: &Env,
    fx: &mut impl Effects,
    c: &InstalledRule,
    d: &InstalledRule,
    params: &Vec<Val>,
) -> bool {
    let add_signers = missing(e, &d.signers, &c.signers);
    let remove_signers = missing(e, &c.signers, &d.signers);
    // A policy whose parameters change is removed and added back.
    let mut remove_policies: Vec<Address> = Vec::new(e);
    for p in c.policies.iter() {
        if !d.policies.contains(&p) {
            remove_policies.push_back(p.policy);
        }
    }
    let mut add_policies: Vec<(Address, Val)> = Vec::new(e);
    for (i, p) in d.policies.iter().enumerate() {
        if !c.policies.contains(&p) {
            add_policies.push_back((p.policy, params.get_unchecked(i as u32)));
        }
    }
    // Additions under addresses the rule does not have yet can go before the
    // removals; a changed policy keeps its address, so it can only be added
    // back after its old parameters are removed.
    let mut fresh: Vec<(Address, Val)> = Vec::new(e);
    for (p, val) in add_policies.iter() {
        if !c.policies.iter().any(|q| q.policy == p) {
            fresh.push_back((p, val));
        }
    }
    let kept =
        (c.signers.len() - remove_signers.len()) + (c.policies.len() - remove_policies.len());
    if kept > 0 {
        // Something survives, so removing first never empties the rule, and
        // the counts only shrink before they grow to the target.
        for s in remove_signers.iter() {
            fx.remove_signer(c, &s);
        }
        for p in remove_policies.iter() {
            fx.remove_policy(c, &p);
        }
        for s in add_signers.iter() {
            fx.add_signer(c, &s);
        }
        for (p, val) in add_policies.iter() {
            fx.add_policy(c, &p, &val);
        }
    } else if (!add_signers.is_empty() || !fresh.is_empty())
        && c.signers.len() + add_signers.len() <= MAX_SIGNERS
        && c.policies.len() + fresh.len() <= MAX_POLICIES
    {
        // Nothing survives: add first so the rule is never empty, then remove
        // the old, then re-add changed policies.
        for s in add_signers.iter() {
            fx.add_signer(c, &s);
        }
        for (p, val) in fresh.iter() {
            fx.add_policy(c, &p, &val);
        }
        for s in remove_signers.iter() {
            fx.remove_signer(c, &s);
        }
        for p in remove_policies.iter() {
            fx.remove_policy(c, &p);
        }
        for (p, val) in add_policies.iter() {
            if !fresh.iter().any(|(q, _)| q == p) {
                fx.add_policy(c, &p, &val);
            }
        }
    } else {
        return false;
    }
    if c.valid_until != d.valid_until {
        fx.set_valid_until(c, d.valid_until);
    }
    true
}

/// Replace rule `c` with `d` under a new id, which it returns.
fn replace(fx: &mut impl Effects, c: &InstalledRule, d: &InstalledRule, params: &Vec<Val>) -> u32 {
    fx.remove_rule(c);
    fx.add_rule(d, params)
}

/// The pre-delta behaviour: remove every installed rule, then add every
/// desired one. Kept only as the oracle the delta is tested against.
#[cfg(feature = "testutils")]
fn replace_all(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
) -> Vec<InstalledRule> {
    let mut apply = Apply { e, rule: None };
    for c in current.iter() {
        apply.remove_rule(&c);
    }
    let mut next = Vec::new(e);
    for (i, d) in desired.iter().enumerate() {
        let id = apply.add_rule(&d, &params.get_unchecked(i as u32));
        next.push_back(d.with_id(id));
    }
    next
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
