//! Rule-set reconciliation for `apply_doc` and `apply_scope`
//! (`docs/recovery/spec.md` §7.5).
//!
//! The account's own records are its rule registry: every context rule it
//! installs is an [`InstalledRule`], in `installed_rules` for the admin
//! document and in its scope's record for a scoped document, under an id the
//! account's counter allocates and never reuses ([`allocate`]). What a
//! document rule allows is the stored rule-eval rule beside its record
//! (`rule_set`). The recovery rule carries the adopted controller as its one
//! policy. `apply_doc` matches the compiled document's rules against those
//! records (document rules by name and scope, the recovery rule by role) and
//! changes only what differs:
//!
//! - a rule present in both, with the same signers, policies, and expiry,
//!   keeps its record and id;
//! - a rule present in both that differs is edited in place, keeping its id,
//!   except a recovery rule whose controller stays and whose configuration
//!   changes, which is installed again under a new id ([`keeps_id`]);
//! - a rule only in the records is removed; a rule only in the document is
//!   added under a new id.
//!
//! These are the ids OpenZeppelin's context-rule registry gives the same
//! documents, so the ids wallets select are unchanged; `keeps_id` says why
//! the recovery rule is the exception.
//!
//! Every rule added or edited is held to OZ's install-time limits
//! ([`check`]), which a compiled document always meets. The recovery rule's
//! controller is asked to install it, as OZ asks a rule's policies; a
//! completion reads the rule from its record (`auth::authorize_completion`).
//!
//! The authorization the result grants is exactly what a full replace of
//! every rule would grant. One thing differs, deliberately: a rule edited in
//! place keeps its id, and with it its spending record when its cap is
//! unchanged (`gate::drop_records`). Everything runs in the one `apply_doc`
//! invocation, so a failure anywhere reverts every edit.

use crate::auth;
use crate::PerchStorage;
use perch_account_types::{ContextRule, ContextRuleType, Signer};
use perch_doc_compiler::{CompiledDoc, CompiledRule, RuleScope};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, Address, BytesN, Env, IntoVal, String, Val, Vec};

/// OZ's install-time limits, which the account keeps: signers and policies
/// per rule, rule-name bytes, and external key bytes.
pub const MAX_SIGNERS: u32 = 15;
/// See [`MAX_SIGNERS`].
pub const MAX_POLICIES: u32 = 5;
/// See [`MAX_SIGNERS`].
pub const MAX_NAME_SIZE: u32 = 20;
/// See [`MAX_SIGNERS`].
pub const MAX_EXTERNAL_KEY_SIZE: u32 = 256;

// The compiler refuses what these limits would, so a document that compiles
// also installs: a rule name within the name limit, a rule naming every
// declared signer within the signer limit, and keys within the key limit.
const _: () = assert!(perch_doc_compiler::MAX_RULE_NAME_BYTES == MAX_NAME_SIZE);
const _: () = assert!(perch_doc_compiler::MAX_DOC_SIGNERS <= MAX_SIGNERS);

/// OZ's codes for the install-time refusals (`stellar-accounts`'
/// `SmartAccountError`), raised unchanged.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum InstallError {
    NoSignersAndPolicies = 3004,
    DuplicateSigner = 3007,
    TooManySigners = 3010,
    TooManyPolicies = 3011,
    MathOverflow = 3012,
    KeyDataTooLarge = 3013,
    NameTooLong = 3015,
}

/// Fail the invocation with `error`'s code.
pub(crate) fn refuse(e: &Env, error: InstallError) -> ! {
    soroban_sdk::panic_with_error!(e, soroban_sdk::Error::from_contract_error(error as u32))
}

/// One policy attached to an installed rule.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledPolicy {
    /// The policy contract.
    pub policy: Address,
    /// `sha256` of the install parameters' XDR.
    // docs/account-interface.md, "Types".
    pub params: BytesN<32>,
}

/// What an `apply_doc` changed in the rule set, counted as it is done.
/// Rule changes publish no event of their own, so this, carried by
/// `DocApplied`, is the one record of the change an indexer gets (with the
/// applied document itself, `applied_doc`). A rule installed again under a
/// new id counts as removed and added; signers and policies count only for
/// rules edited in place.
#[contracttype]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DeltaSummary {
    pub rules_added: u32,
    pub rules_removed: u32,
    pub rules_edited: u32,
    pub signers_added: u32,
    pub signers_removed: u32,
    pub policies_added: u32,
    pub policies_removed: u32,
}

/// One context rule as the account installed it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledRule {
    /// The rule id.
    pub id: u32,
    /// Whether this is the zero-signer recovery rule.
    // docs/account-interface.md, "Types".
    pub recovery: bool,
    /// The rule's name.
    // The document rule's, `admin` for the constructor's, `recovery` for the
    // recovery rule.
    pub name: String,
    /// The contract the rule authorizes calls to.
    pub context_type: ContextRuleType,
    /// The inclusive last valid ledger, if bounded.
    pub valid_until: Option<u32>,
    /// The rule's signers.
    pub signers: Vec<Signer>,
    /// The policies attached to the rule.
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

    /// The rule as the `ContextRule` OZ's views and policy hooks name: its
    /// signers and policies with their positions as their ids.
    pub(crate) fn context_rule(&self, e: &Env) -> ContextRule {
        let mut policies = Vec::new(e);
        for p in self.policies.iter() {
            policies.push_back(p.policy);
        }
        ContextRule {
            id: self.id,
            context_type: self.context_type.clone(),
            name: self.name.clone(),
            signers: self.signers.clone(),
            signer_ids: positions(e, self.signers.len()),
            policy_ids: positions(e, policies.len()),
            policies,
            valid_until: self.valid_until,
        }
    }
}

/// `[0, 1, …, n - 1]`.
pub(crate) fn positions(e: &Env, n: u32) -> Vec<u32> {
    let mut out = Vec::new(e);
    for i in 0..n {
        out.push_back(i);
    }
    out
}

/// A new rule id: the account's counter, which never reuses one, so spending
/// records and scope tags keyed by id never outlive their rule into another.
pub(crate) fn allocate(e: &Env) -> u32 {
    let id = PerchStorage::get_next_rule_id(e).unwrap_or(0);
    let next = id
        .checked_add(1)
        .unwrap_or_else(|| refuse(e, InstallError::MathOverflow));
    PerchStorage::set_next_rule_id(e, &next);
    id
}

/// OZ's install-time limits on one rule: its name, every external key, its
/// signers and policies, and at least one of either.
pub(crate) fn check(e: &Env, rule: &InstalledRule) {
    if rule.name.len() > MAX_NAME_SIZE {
        refuse(e, InstallError::NameTooLong);
    }
    for s in rule.signers.iter() {
        if let Signer::External(_, key) = s {
            if key.len() > MAX_EXTERNAL_KEY_SIZE {
                refuse(e, InstallError::KeyDataTooLarge);
            }
        }
    }
    if rule.signers.len() > MAX_SIGNERS {
        refuse(e, InstallError::TooManySigners);
    }
    if rule.policies.len() > MAX_POLICIES {
        refuse(e, InstallError::TooManyPolicies);
    }
    if rule.signers.is_empty() && rule.policies.is_empty() {
        refuse(e, InstallError::NoSignersAndPolicies);
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

/// Whether a rule's lowered `valid_until` is already past at the current
/// ledger (`valid_until < sequence`). Such a rule is dead — it authorizes
/// nothing — so it is dropped at install, keeping the "a document that
/// compiles also installs" invariant (`perch-doc-compiler`): a recovery
/// target stays installable even when one of its bounded rules expired
/// between publish and completion. The anti-brick check (`admin_survives`)
/// refuses any document whose only admin rule is bounded, so this drop can
/// never remove the account's sole admin rule.
pub(crate) fn expired(e: &Env, valid_until: Option<u32>) -> bool {
    valid_until.is_some_and(|v| v < e.ledger().sequence())
}

/// The rules `compiled` asks for, with each policy's install parameters
/// (aligned with `rule.policies`). Ids are unset. A document rule whose
/// `not-after-ledger` has already passed ([`expired`]) is dropped.
pub(crate) fn desired(e: &Env, compiled: &CompiledDoc) -> (Vec<InstalledRule>, Vec<Vec<Val>>) {
    let mut rules = Vec::new(e);
    let mut params = Vec::new(e);
    for rule in compiled.rules.iter() {
        if expired(e, rule.valid_until) {
            continue;
        }
        rules.push_back(document_rule(e, &rule));
        params.push_back(Vec::new(e));
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

/// A compiled document rule as recorded: its scope, signers and last
/// ledger, and no policy. Its program and cap are the stored rule-eval
/// rule's (`rule_set`).
fn document_rule(e: &Env, rule: &CompiledRule) -> InstalledRule {
    let context_type = match &rule.scope {
        RuleScope::SelfAdmin => ContextRuleType::CallContract(e.current_contract_address()),
        RuleScope::Contract(addr) => ContextRuleType::CallContract(addr.clone()),
    };
    InstalledRule {
        id: 0,
        recovery: false,
        name: rule.name.clone(),
        context_type,
        valid_until: rule.valid_until,
        signers: rule.signers.clone(),
        policies: Vec::new(e),
    }
}

fn digest(e: &Env, xdr: soroban_sdk::Bytes) -> BytesN<32> {
    e.crypto().sha256(&xdr).to_bytes()
}

/// How `apply_doc` reconciles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Only what differs ([`keeps_id`]): `apply_doc`'s only mode.
    Delta,
    /// Every installed rule removed and every document rule added under a
    /// new id: kept as the test oracle.
    #[cfg(feature = "testutils")]
    FullReplace,
}

/// Bring the installed rules from `current` to `desired`, touching only what
/// differs. Returns the new records, in `desired` order.
pub(crate) fn reconcile(
    e: &Env,
    current: &Vec<InstalledRule>,
    desired: &Vec<InstalledRule>,
    params: &Vec<Vec<Val>>,
    mode: Mode,
) -> (Vec<InstalledRule>, DeltaSummary) {
    let delta = mode == Mode::Delta;
    let mut sum = DeltaSummary::default();
    for c in current.iter() {
        if !(delta && desired.iter().any(|d| c.same_slot(&d))) {
            sum.rules_removed += 1;
        }
    }
    let mut next = Vec::new(e);
    for (i, d) in desired.iter().enumerate() {
        let p = params.get_unchecked(i as u32);
        let matched = current.iter().find(|c| delta && c.same_slot(&d));
        let id = match matched {
            None => add(e, &d, &p, &mut sum),
            Some(c) if unchanged(&c, &d) => c.id,
            Some(c) if keeps_id(&c, &d) => {
                edit(e, &c, &d.with_id(c.id), &p, &mut sum);
                c.id
            }
            Some(_) => {
                sum.rules_removed += 1;
                add(e, &d, &p, &mut sum)
            }
        };
        next.push_back(d.with_id(id));
    }
    (next, sum)
}

/// Whether `c` and `d` install the same rule: the same slot, signers in the
/// same order, policies with their parameters, and expiry. A rule keeps its
/// signers in the order its document gives, so a document that only
/// reorders a rule's signers is a change, as a full replace would make it.
fn unchanged(c: &InstalledRule, d: &InstalledRule) -> bool {
    c.signers == d.signers
        && c.policies.iter().all(|p| d.policies.contains(&p))
        && d.policies.iter().all(|p| c.policies.contains(&p))
        && c.valid_until == d.valid_until
}

/// Whether changed rule `c` keeps its id as `d`. Every changed rule does
/// except a recovery rule that names no controller `c` lacks: one keeping
/// its controller under a new configuration. OZ's registry could not edit
/// that rule in place, since it would pass through a rule with no signer
/// and no policy or hold the controller twice, so it was installed again
/// under a new id; keeping that rule keeps every id as OZ gave it.
fn keeps_id(c: &InstalledRule, d: &InstalledRule) -> bool {
    !c.recovery
        || d.policies
            .iter()
            .any(|p| !c.policies.iter().any(|q| q.policy == p.policy))
}

/// Add `rule` under a new id, which it returns.
fn add(e: &Env, rule: &InstalledRule, params: &Vec<Val>, sum: &mut DeltaSummary) -> u32 {
    let rule = rule.with_id(allocate(e));
    check(e, &rule);
    if rule.recovery {
        install(e, &rule, params);
    }
    sum.rules_added += 1;
    rule.id
}

/// Edit `c` into `d` (which carries `c`'s id).
fn edit(e: &Env, c: &InstalledRule, d: &InstalledRule, params: &Vec<Val>, sum: &mut DeltaSummary) {
    check(e, d);
    sum.rules_edited += 1;
    sum.signers_added += missing(e, &d.signers, &c.signers).len();
    sum.signers_removed += missing(e, &c.signers, &d.signers).len();
    let mut added = false;
    for p in d.policies.iter() {
        if !c.policies.contains(&p) {
            sum.policies_added += 1;
            added = true;
        }
    }
    for p in c.policies.iter() {
        if !d.policies.contains(&p) {
            sum.policies_removed += 1;
        }
    }
    if d.recovery && added {
        install(e, d, params);
    }
}

/// Install recovery rule `rule` (with its id): its controller's `install`
/// checks the rule's shape and that it is installed for the configuration
/// `rcv_sync` stored.
fn install(e: &Env, rule: &InstalledRule, params: &Vec<Val>) {
    auth::PolicyClient::new(e, &rule.policies.get_unchecked(0).policy).install(
        &params.get_unchecked(0),
        &rule.context_rule(e),
        &e.current_contract_address(),
    );
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

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn rule(e: &Env, recovery: bool, controller: &Address, config: u8) -> InstalledRule {
        InstalledRule {
            id: 7,
            recovery,
            name: String::from_str(e, "r1"),
            context_type: ContextRuleType::CallContract(Address::generate(e)),
            valid_until: None,
            signers: Vec::new(e),
            policies: Vec::from_array(
                e,
                [InstalledPolicy {
                    policy: controller.clone(),
                    params: BytesN::from_array(e, &[config; 32]),
                }],
            ),
        }
    }

    /// A recovery rule keeps its id across a controller switch and takes a
    /// new one for a new configuration under the same controller; any other
    /// changed rule keeps its id.
    #[test]
    fn only_a_recovery_rule_reconfigured_at_its_controller_takes_a_new_id() {
        let e = Env::default();
        let (a, b) = (Address::generate(&e), Address::generate(&e));
        assert!(keeps_id(&rule(&e, true, &a, 0), &rule(&e, true, &b, 0)));
        assert!(keeps_id(&rule(&e, true, &a, 0), &rule(&e, true, &b, 1)));
        assert!(!keeps_id(&rule(&e, true, &a, 0), &rule(&e, true, &a, 1)));
        assert!(keeps_id(&rule(&e, false, &a, 0), &rule(&e, false, &a, 1)));
    }
}
