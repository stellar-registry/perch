//! The account's `__check_auth`, as one pure function of a ledger snapshot
//! and an authorization entry: [`review`].
//!
//! [`review`] makes the reads and checks `perch_smart_account::check_auth`
//! (`crates/perch-smart-account/src/lib.rs:1116`) makes, in its order, over
//! the [`Snapshot`] instead of the ledger, and returns the error it would
//! fail with, the records it would store, and what the chosen capped rules
//! have left. Each step names the lines it ports (`README.md`, "Checks",
//! has the table). Two steps are not decided here:
//!
//! - **Signatures.** The account authenticates each payload signer after
//!   rule-eval accepts (`gate.rs:133-135`, `auth.rs:47-60`): an `External`
//!   signer through its verifier contract, a `Delegated` one through the
//!   host's CAP-0071 delegate check. The core does not verify signatures. A
//!   signer is taken as verified unless the request says it is not
//!   ([`Verified::No`]); a `Delegated` signer the entry carries no delegate
//!   for fails, since the host's delegate check finds none.
//! - **Recovery completion.** The account checks a completion against its own
//!   record of the recovery rule (`auth.rs:110-137`), which the core ports,
//!   and then asks the recovery controller's `rcv_complete`, whose verdict
//!   depends on the controller's storage. The core returns
//!   [`Outcome::Controller`] with the controllers to ask.
//!
//! So the verdict is the account's for the snapshot's ledger entries and the
//! request's ledger sequence, assuming every signer not marked unverified
//! authenticates; it says nothing about another ledger or other state.

use alloc::vec::Vec;

use rule_eval::{CapError, Refusal as EvalRefusal, Signer, SpendRecord};
use soroban_facade::{val_to_rule_eval, Val};

use crate::budget::{remaining, Remaining};
use crate::snapshot::{Rules, Snapshot, Unreadable};
use crate::stored::{self, fields, u32_of, vec_of};
use crate::xdr::Ctx;

/// `perch_recovery_interface::account::RESERVED_INVOKER_ONLY_FNS`
/// (`crates/perch-recovery-interface/src/account.rs:119`).
pub const RESERVED_INVOKER_ONLY_FNS: [&str; 10] = [
    "install",
    "uninstall",
    "enforce",
    "rcv_sync",
    "rcv_cancel",
    "rcv_upgrade",
    "rcv_install",
    "rcv_complete",
    "rcv_insert",
    "rcv_gate",
];

/// `perch_recovery_interface::account::GUARDIAN_APPROVAL_FNS` (`account.rs:155`).
pub const GUARDIAN_APPROVAL_FNS: [&str; 2] = ["submit_guardian", "approve_change"];

/// `perch_smart_account::TOKEN_ADMIN_FNS` (`lib.rs:1397`).
pub const TOKEN_ADMIN_FNS: [&str; 4] = ["mint", "clawback", "set_admin", "set_authorized"];

/// `perch_smart_account::OWNER_FNS` (`lib.rs:1412`).
pub const OWNER_FNS: [&str; 5] = ["transfer", "transfer_from", "approve", "burn", "burn_from"];

/// Whether a signer's signature verifies, as far as the caller knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verified {
    /// Not known: taken to verify. A verdict that depends on this says so.
    Assumed,
    /// Checked by the caller.
    Yes,
    /// Checked by the caller and does not verify.
    No,
}

/// One signer the payload names.
pub struct Claimed {
    pub signer: Signer,
    pub verified: Verified,
}

/// An authorization of the account, as `__check_auth` receives it.
pub struct Request {
    /// The account, as its `SCAddress` XDR.
    pub account: Vec<u8>,
    /// The contexts, root first, in preorder.
    pub contexts: Vec<Ctx>,
    /// The payload's `context_rule_ids`.
    pub rule_ids: Vec<u32>,
    /// The payload's signers, in the payload map's order.
    pub signers: Vec<Claimed>,
    /// The delegates the entry's credentials carry, as `SCAddress` XDR;
    /// `None` without delegate credentials.
    pub delegates: Option<Vec<Vec<u8>>>,
    /// The ledger sequence the authorization is checked at.
    pub ledger: u32,
}

/// The account's own refusal reasons, in the order `__check_auth` checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// A context names an invoker-only hook (`lib.rs:1122-1128`).
    ReservedFunction,
    /// The `Protected` freeze is in force (`lib.rs:1131-1135`).
    Frozen,
    /// A grant rule is chosen for the excluded set, a guardian approval or a
    /// token-admin function (`lib.rs:1142-1162`).
    GrantEscalation,
    /// A completion's ids and contexts differ in length (`auth.rs:117-119`).
    CompletionLength,
    /// A completion chooses an id other than the stored recovery rule
    /// (`auth.rs:123-126`).
    CompletionRuleNotFound,
    /// A completion's context is not on the account, or the recovery rule
    /// expired or is not on the account (`auth.rs:127-133`).
    CompletionUnvalidated,
    /// A completion's payload names a signer (`auth.rs:135-137`).
    CompletionSigner,
    /// The account stores no rule set (`lib.rs:1166`).
    NoRuleSet,
    /// The recovery rule is chosen outside a completion (`gate.rs:85-87`).
    RecoveryRuleChosen,
    /// A chosen id names no installed rule (`gate.rs:91`).
    RuleNotFound,
    /// A chosen rule's stored value does not read (`gate.rs:92`).
    UnreadableRule,
    /// A chosen capped rule's stored record does not read (`gate.rs:93-97`).
    UnreadableRecord,
    /// The batch holds a creation, or an argument the account cannot read
    /// (`gate.rs:105`).
    UnreadableContexts,
    /// A capped rule, or a grant rule for an owner function, is chosen for a
    /// call whose argument 0 is not the account (`gate.rs:107-113`).
    NotOwnFunds,
    /// rule-eval refuses a chosen grant rule of another grant generation
    /// (`gate.rs:115-125`).
    StaleGrant,
    /// rule-eval refuses otherwise (`gate.rs:115-126`).
    RuleEval(EvalReason),
    /// A signer does not authenticate (`gate.rs:133-135`): the account's
    /// error is then the signer's ([`Refusal::error`]).
    Signature,
}

/// rule-eval's refusal (`rule_eval::Refusal`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvalReason {
    ChoicesMismatch,
    RecordsMismatch,
    NoSuchRule,
    Expired,
    StaleGeneration,
    NotAllowed,
    UnauthorizedSigner,
    NoAmount,
    CapNegativeAmount,
    CapLedgerBeforeNewest,
    CapOverflow,
    CapLimitExceeded,
    CapHistoryFull,
}

impl EvalReason {
    fn of(r: &EvalRefusal) -> EvalReason {
        match r {
            EvalRefusal::ChoicesMismatch => EvalReason::ChoicesMismatch,
            EvalRefusal::RecordsMismatch => EvalReason::RecordsMismatch,
            EvalRefusal::NoSuchRule => EvalReason::NoSuchRule,
            EvalRefusal::Expired => EvalReason::Expired,
            EvalRefusal::StaleGeneration => EvalReason::StaleGeneration,
            EvalRefusal::NotAllowed => EvalReason::NotAllowed,
            EvalRefusal::UnauthorizedSigner => EvalReason::UnauthorizedSigner,
            EvalRefusal::NoAmount => EvalReason::NoAmount,
            EvalRefusal::Cap(c) => match c {
                CapError::NegativeAmount => EvalReason::CapNegativeAmount,
                CapError::LedgerBeforeNewest => EvalReason::CapLedgerBeforeNewest,
                CapError::Overflow => EvalReason::CapOverflow,
                CapError::LimitExceeded => EvalReason::CapLimitExceeded,
                CapError::HistoryFull => EvalReason::CapHistoryFull,
            },
        }
    }

    /// The reason's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            EvalReason::ChoicesMismatch => "ChoicesMismatch",
            EvalReason::RecordsMismatch => "RecordsMismatch",
            EvalReason::NoSuchRule => "NoSuchRule",
            EvalReason::Expired => "Expired",
            EvalReason::StaleGeneration => "StaleGeneration",
            EvalReason::NotAllowed => "NotAllowed",
            EvalReason::UnauthorizedSigner => "UnauthorizedSigner",
            EvalReason::NoAmount => "NoAmount",
            EvalReason::CapNegativeAmount => "Cap.NegativeAmount",
            EvalReason::CapLedgerBeforeNewest => "Cap.LedgerBeforeNewest",
            EvalReason::CapOverflow => "Cap.Overflow",
            EvalReason::CapLimitExceeded => "Cap.LimitExceeded",
            EvalReason::CapHistoryFull => "Cap.HistoryFull",
        }
    }
}

/// How the invocation fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A contract error the account raises: `PerchAuthError` (`1..=5`) or
    /// `SmartAccountError` (`3000..`).
    Contract(u32),
    /// A host error: the host's CAP-0071 delegate check finds no delegate
    /// for a `Delegated` signer.
    Host,
    /// A signer's own refusal: `ExternalVerificationFailed` (3003) when an
    /// `External` signer's verifier returns `false`, otherwise the error
    /// its verifier, or a `Delegated` signer's own authorization, fails
    /// with (an ed25519 verifier traps on a bad signature, for one). The
    /// refusal is certain; its code depends on that contract.
    Signer,
}

impl Check {
    /// The error the account's `__check_auth` fails with.
    #[must_use]
    pub fn error(self) -> Error {
        Error::Contract(match self {
            Check::ReservedFunction => 1,
            Check::Frozen => 2,
            Check::StaleGrant => 3,
            Check::GrantEscalation => 4,
            Check::NoRuleSet
            | Check::RecoveryRuleChosen
            | Check::UnreadableRule
            | Check::UnreadableRecord
            | Check::UnreadableContexts
            | Check::NotOwnFunds
            | Check::RuleEval(_) => 5,
            Check::CompletionRuleNotFound | Check::RuleNotFound => 3000,
            Check::CompletionUnvalidated => 3002,
            Check::Signature => 3003,
            Check::CompletionLength => 3014,
            Check::CompletionSigner => 3016,
        })
    }

    /// The name of the error the account fails with.
    #[must_use]
    pub fn error_name(self) -> &'static str {
        match self.error() {
            Error::Contract(1) => "ReservedFunction",
            Error::Contract(2) => "AccountFrozen",
            Error::Contract(3) => "StaleGrant",
            Error::Contract(4) => "GrantEscalation",
            Error::Contract(5) => "RuleEvalRefused",
            Error::Contract(3000) => "ContextRuleNotFound",
            Error::Contract(3002) => "UnvalidatedContext",
            Error::Contract(3003) => "ExternalVerificationFailed",
            Error::Contract(3014) => "ContextRuleIdsLengthMismatch",
            Error::Contract(3016) => "UnauthorizedSigner",
            _ => "HostError",
        }
    }

    /// A short name for the check.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Check::ReservedFunction => "reserved-function",
            Check::Frozen => "frozen",
            Check::GrantEscalation => "grant-escalation",
            Check::CompletionLength => "completion-length",
            Check::CompletionRuleNotFound => "completion-rule-not-found",
            Check::CompletionUnvalidated => "completion-unvalidated",
            Check::CompletionSigner => "completion-signer",
            Check::NoRuleSet => "no-rule-set",
            Check::RecoveryRuleChosen => "recovery-rule-chosen",
            Check::RuleNotFound => "rule-not-found",
            Check::UnreadableRule => "unreadable-rule",
            Check::UnreadableRecord => "unreadable-record",
            Check::UnreadableContexts => "unreadable-contexts",
            Check::NotOwnFunds => "not-own-funds",
            Check::StaleGrant => "stale-grant",
            Check::RuleEval(_) => "rule-eval",
            Check::Signature => "signature",
        }
    }
}

/// A refusal: the check, and the context and rule it concerns, when one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub check: Check,
    pub context: Option<u32>,
    pub rule: Option<u32>,
    /// For [`Check::Signature`]: the signer's position in the payload.
    pub signer: Option<u32>,
    /// For [`Check::Signature`]: whether the signer is a `Delegated` one the
    /// entry carries no delegate for, which the host's delegate check
    /// refuses, rather than one marked unverified.
    pub missing_delegate: bool,
}

impl Refusal {
    /// The error the account's `__check_auth` fails with.
    #[must_use]
    pub fn error(&self) -> Error {
        match self.check {
            Check::Signature if self.missing_delegate => Error::Host,
            Check::Signature => Error::Signer,
            c => c.error(),
        }
    }

    /// The name of the error the account fails with.
    #[must_use]
    pub fn error_name(&self) -> &'static str {
        match self.error() {
            Error::Host => "HostError",
            Error::Signer => "SignerRefused",
            Error::Contract(_) => self.check.error_name(),
        }
    }
}

/// The account's verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// `__check_auth` returns `Ok`.
    Accepted,
    /// `__check_auth` fails.
    Refused(Refusal),
    /// A recovery completion the account's own checks accept, which the
    /// controllers named here then decide (`rcv_complete`, each as its
    /// `SCAddress` XDR); an empty list cannot occur, since the account
    /// accepts a completion of a rule with no policy outright.
    Controller { rule: u32, policies: Vec<Vec<u8>> },
}

/// One chosen capped rule's budget.
pub struct Budget {
    pub rule: u32,
    pub grant: Option<u32>,
    pub limit: i128,
    pub period: u32,
    /// Before this authorization's charges.
    pub before: Remaining,
    /// The sum of the amounts this authorization charges to the rule, when
    /// every context choosing it has an `I128` amount and the sum fits.
    pub requested: Option<i128>,
    /// After its charges, when the account accepts.
    pub after: Option<Remaining>,
}

/// One distinct chosen rule, as the account found it.
pub struct Chosen {
    pub id: u32,
    pub grant: Option<u32>,
    pub capped: bool,
    /// The rule's contract, as its `SCAddress` XDR: for a capped rule, the
    /// token its cap counts.
    pub contract: Vec<u8>,
    /// The record's `name`, as stored (a Soroban string's bytes).
    pub name: Option<Vec<u8>>,
}

/// The core's answer for one authorization entry.
pub struct Review {
    pub outcome: Outcome,
    /// Every signer's position in the payload whose verdict was assumed.
    pub assumed: Vec<u32>,
    pub rules: Vec<Chosen>,
    pub budgets: Vec<Budget>,
    /// The spending records the account stores when it accepts: each
    /// chosen capped rule whose record the charges changed, by rule id.
    pub records: Vec<(u32, SpendRecord)>,
}

fn named(f: &[u8], list: &[&str]) -> bool {
    list.iter().any(|n| f == n.as_bytes())
}

/// Whether the payload and contexts are one `apply_doc` on the account
/// choosing the recovery rule (`is_completion`, `lib.rs:1176-1193`).
fn is_completion(recovery: Option<u32>, r: &Request) -> bool {
    let Some(rule) = recovery else { return false };
    if r.contexts.len() != 1 || r.rule_ids != [rule] {
        return false;
    }
    matches!(&r.contexts[0], Ctx::Call { contract, function, .. }
        if *contract == r.account && function.as_slice() == b"apply_doc")
}

/// `rule_of` (`gate.rs`): the stored rule (fourth field) of the first
/// record (the tuple of its id, name, policies and stored rule) whose id is
/// `id`. A record that is not a vector, or has no `u32` id first, ends the
/// search with nothing, as the account's read does.
fn rule_of(records: &[Val], id: u32) -> Option<(&Val, &Val)> {
    for v in records {
        let items = vec_of(v)?;
        if u32_of(items.first()?)? == id {
            return items.get(3).map(|rule| (rule, v));
        }
    }
    None
}

/// A stored rule as `stored_rule` finds it: its grant, its stored value, its
/// record, and the signer table its records keep.
struct Found<'a> {
    grant: Option<u32>,
    rule: &'a Val,
    record: &'a Val,
    table: &'a Val,
}

/// The stored rule `id` names and its grant (`stored_rule`, `gate.rs:173-182`).
fn stored_rule<'a>(
    s: &'a Snapshot,
    admin: Rules<'a>,
    id: u32,
) -> Result<Option<Found<'a>>, Unreadable> {
    let (grant, rules) = match s.grant_tag(id)? {
        Some(grant) => match s.grant_rules(grant)? {
            Some(rules) => (Some(grant), rules),
            None => return Ok(None),
        },
        None => (None, admin),
    };
    Ok(rule_of(rules.records, id).map(|(rule, record)| Found {
        grant,
        rule,
        record,
        table: rules.table,
    }))
}

/// The amount `ctx` charges under a cap reading argument `arg`.
fn amount(ctx: &rule_eval::Context, arg: u32) -> Option<i128> {
    match ctx {
        rule_eval::Context::Call { args, .. } => match args.get(arg as usize) {
            Some(rule_eval::Val::I128(n)) => Some(*n),
            _ => None,
        },
        rule_eval::Context::Create { .. } => None,
    }
}

impl Review {
    fn refused(mut self, check: Check, context: Option<usize>, rule: Option<u32>) -> Review {
        self.outcome = Outcome::Refused(Refusal {
            check,
            context: context.map(|c| c as u32),
            rule,
            signer: None,
            missing_delegate: false,
        });
        self
    }
}

/// The account's verdict on `r` over the storage `s` (module docs).
///
/// # Errors
///
/// [`Unreadable::StoredValue`] when a stored value the account reads with a
/// type is of another type, which no state the account writes holds.
pub fn review(s: &Snapshot, r: &Request) -> Result<Review, Unreadable> {
    let assumed = r
        .signers
        .iter()
        .enumerate()
        .filter(|(_, c)| c.verified == Verified::Assumed)
        .map(|(i, _)| i as u32)
        .collect();
    let out = Review {
        outcome: Outcome::Accepted,
        assumed,
        rules: Vec::new(),
        budgets: Vec::new(),
        records: Vec::new(),
    };
    // 1. lib.rs:1122-1128: no context may name an invoker-only hook.
    for (i, c) in r.contexts.iter().enumerate() {
        if let Ctx::Call { function, .. } = c {
            if named(function, &RESERVED_INVOKER_ONLY_FNS) {
                return Ok(out.refused(Check::ReservedFunction, Some(i), None));
            }
        }
    }
    // lib.rs:1129-1130.
    let recovery = s.recovery_rule()?;
    let completion = is_completion(recovery, r);
    // 2. lib.rs:1131-1135: under the freeze, only a completion.
    if let Some(gate) = s.gate()? {
        // `perch_recovery_interface::account::is_frozen` (`account.rs:167`).
        if r.ledger < gate.until && !completion {
            return Ok(out.refused(Check::Frozen, None, None));
        }
    }
    // 3. lib.rs:1142-1162: a grant rule never reaches the excluded set, a
    // guardian approval or a token-admin function.
    let excluded = s.excluded()?;
    for (i, id) in r.rule_ids.iter().enumerate() {
        // `has_grant_tags`: the tag's presence, not its value.
        if s.has_grant_tag(*id) {
            if let Some(Ctx::Call {
                contract, function, ..
            }) = r.contexts.get(i)
            {
                if excluded.contains(contract)
                    || named(function, &GUARDIAN_APPROVAL_FNS)
                    || named(function, &TOKEN_ADMIN_FNS)
                {
                    return Ok(out.refused(Check::GrantEscalation, Some(i), Some(*id)));
                }
            }
        }
    }
    // 4. lib.rs:1163-1165: a completion goes to the controller.
    if let (Some(id), true) = (recovery, completion) {
        return completion_review(s, r, id, out);
    }
    // lib.rs:1166: no rule set, nothing but a completion.
    let Some(admin) = s.rule_set()? else {
        return Ok(out.refused(Check::NoRuleSet, None, None));
    };
    review_rules(s, r, admin, recovery, out)
}

/// `authorize_completion` (`auth.rs:110-144`), up to the controller's call.
fn completion_review(
    s: &Snapshot,
    r: &Request,
    recovery: u32,
    out: Review,
) -> Result<Review, Unreadable> {
    if r.rule_ids.len() != r.contexts.len() {
        return Ok(out.refused(Check::CompletionLength, None, None));
    }
    // `record` (`auth.rs:151-158`): the rule set's record of the recovery
    // rule, read with its type.
    let mut rule = None;
    if let Some(rules) = s.rule_set()? {
        for v in rules.records {
            let [id, _name, policies, stored] = vec_of(v).ok_or(Unreadable::StoredValue)? else {
                return Err(Unreadable::StoredValue);
            };
            if u32_of(id).ok_or(Unreadable::StoredValue)? != recovery {
                continue;
            }
            let stored = vec_of(stored).ok_or(Unreadable::StoredValue)?;
            let contract = stored
                .first()
                .and_then(stored::address)
                .ok_or(Unreadable::StoredValue)?;
            let valid_until = match stored.get(6) {
                Some(Val::Void) => None,
                Some(Val::U32(v)) => Some(*v),
                _ => return Err(Unreadable::StoredValue),
            };
            let mut controllers = Vec::new();
            for p in vec_of(policies).ok_or(Unreadable::StoredValue)? {
                let [_params, policy] =
                    fields(p, [b"params", b"policy"]).ok_or(Unreadable::StoredValue)?;
                controllers.push(stored::address(policy).ok_or(Unreadable::StoredValue)?);
            }
            rule = Some((contract, valid_until, controllers));
            break;
        }
    }
    for (i, c) in r.contexts.iter().enumerate() {
        // auth.rs:123-126.
        let Some((contract, valid_until, _)) = rule.as_ref().filter(|_| r.rule_ids[i] == recovery)
        else {
            return Ok(out.refused(Check::CompletionRuleNotFound, Some(i), Some(r.rule_ids[i])));
        };
        // auth.rs:127-133.
        let on_me = matches!(c, Ctx::Call { contract: to, .. } if *to == r.account);
        let expired = valid_until.is_some_and(|v| v < r.ledger);
        if expired || !on_me || *contract != r.account {
            return Ok(out.refused(Check::CompletionUnvalidated, Some(i), Some(recovery)));
        }
    }
    // auth.rs:135-137.
    if !r.signers.is_empty() {
        return Ok(out.refused(Check::CompletionSigner, None, Some(recovery)));
    }
    // auth.rs:138-143: each policy's controller decides each context.
    let policies = rule.map(|(_, _, p)| p).unwrap_or_default();
    let mut out = out;
    if !policies.is_empty() {
        out.outcome = Outcome::Controller {
            rule: recovery,
            policies,
        };
    }
    Ok(out)
}

/// `gate::authorize` (`gate.rs:70-145`), its signature checks reduced to the
/// request's `verified` flags.
fn review_rules(
    s: &Snapshot,
    r: &Request,
    admin: Rules,
    recovery: Option<u32>,
    mut out: Review,
) -> Result<Review, Unreadable> {
    let mut rules: Vec<rule_eval::Rule> = Vec::new();
    let mut records: Vec<SpendRecord> = Vec::new();
    let mut choices: Vec<u32> = Vec::new();
    // gate.rs:84-104: each chosen id's stored rule and record, once.
    for id in &r.rule_ids {
        // gate.rs:85-87.
        if recovery == Some(*id) {
            return Ok(out.refused(Check::RecoveryRuleChosen, None, Some(*id)));
        }
        let j = match out.rules.iter().position(|c| c.id == *id) {
            Some(j) => j,
            None => {
                // gate.rs:91.
                let Some(found) = stored_rule(s, admin, *id)? else {
                    return Ok(out.refused(Check::RuleNotFound, None, Some(*id)));
                };
                // gate.rs:92.
                let rule = stored::table(found.table).and_then(|t| stored::rule(found.rule, &t));
                let Some(rule) = rule else {
                    return Ok(out.refused(Check::UnreadableRule, None, Some(*id)));
                };
                // gate.rs:93-97, `record` (gate.rs:198-207): absent is empty.
                let record = match (&rule.cap, s.spend_record(*id)) {
                    (None, _) | (Some(_), None) => Some(rule_eval::empty_record()),
                    (Some(_), Some(v)) => stored::record(v),
                };
                let Some(record) = record else {
                    return Ok(out.refused(Check::UnreadableRecord, None, Some(*id)));
                };
                out.rules.push(Chosen {
                    id: *id,
                    grant: found.grant,
                    capped: rule.cap.is_some(),
                    contract: rule.contract.clone(),
                    name: match vec_of(found.record).and_then(|r| r.get(1)) {
                        Some(Val::String(n)) => Some(n.clone()),
                        _ => None,
                    },
                });
                rules.push(rule);
                records.push(record);
                out.rules.len() - 1
            }
        };
        choices.push(j as u32);
    }
    // gate.rs:105, `convert::calls`: every context a call the account reads.
    let mut contexts = Vec::new();
    let mut readable = true;
    for c in &r.contexts {
        match c {
            Ctx::Call {
                contract,
                function,
                args: Some(args),
            } => contexts.push(rule_eval::Context::Call {
                contract: contract.clone(),
                function: function.clone(),
                args: args.iter().map(val_to_rule_eval).collect(),
            }),
            _ => readable = false,
        }
    }
    let whole = readable && contexts.len() == choices.len();
    budgets(
        &mut out,
        &rules,
        &records,
        whole.then_some(&contexts[..]),
        &choices,
        r.ledger,
    );
    if !readable {
        return Ok(out.refused(Check::UnreadableContexts, None, None));
    }
    // gate.rs:107-113: a capped rule, or a grant rule for an owner
    // function, acts only on the account's own calls.
    for (k, (ctx, j)) in contexts.iter().zip(&choices).enumerate() {
        let rule = &rules[*j as usize];
        let owner =
            matches!(ctx, rule_eval::Context::Call { function, .. } if named(function, &OWNER_FNS));
        let own = rule.cap.is_some() || (rule.generation.is_some() && owner);
        let from_self = matches!(ctx, rule_eval::Context::Call { args, .. }
            if matches!(args.first(), Some(rule_eval::Val::Address(a)) if *a == r.account));
        if own && !from_self {
            let id = out.rules[*j as usize].id;
            return Ok(out.refused(Check::NotOwnFunds, Some(k), Some(id)));
        }
    }
    // gate.rs:114-127.
    let signers: Vec<Signer> = r.signers.iter().map(|c| copy_signer(&c.signer)).collect();
    let after = match rule_eval::check_auth(
        &rules,
        &records,
        &contexts,
        &choices,
        &signers,
        r.ledger,
        s.grant_generation()?,
    ) {
        Ok(after) => after,
        Err(EvalRefusal::StaleGeneration) => return Ok(out.refused(Check::StaleGrant, None, None)),
        Err(e) => return Ok(out.refused(Check::RuleEval(EvalReason::of(&e)), None, None)),
    };
    // gate.rs:133-135: every signer authenticates, in the payload's order:
    // a `Delegated` one through the host's delegate check, which needs a
    // delegate for it in the entry.
    for (k, c) in r.signers.iter().enumerate() {
        let missing_delegate = match &c.signer {
            Signer::Delegated(a) => !r.delegates.as_ref().is_some_and(|ds| ds.contains(a)),
            Signer::External(..) => false,
        };
        if missing_delegate || c.verified == Verified::No {
            out.outcome = Outcome::Refused(Refusal {
                check: Check::Signature,
                context: None,
                rule: None,
                signer: Some(k as u32),
                missing_delegate,
            });
            return Ok(out);
        }
    }
    // gate.rs:136-143: the records the charges changed are stored.
    for (j, rule) in rules.iter().enumerate() {
        if let Some(cap) = &rule.cap {
            if let Some(b) = out.budgets.iter_mut().find(|b| b.rule == out.rules[j].id) {
                b.after = Some(remaining(&after[j], cap.limit, cap.period, r.ledger));
            }
        }
    }
    for (j, (rule, (before, next))) in rules.iter().zip(records.iter().zip(after)).enumerate() {
        if rule.cap.is_some() && !same(before, &next) {
            out.records.push((out.rules[j].id, next));
        }
    }
    Ok(out)
}

/// Each chosen capped rule's budget before the charges, and what the batch
/// asks of it: `contexts` is `None` when the batch does not read as one call
/// per choice, so no request is known.
fn budgets(
    out: &mut Review,
    rules: &[rule_eval::Rule],
    records: &[SpendRecord],
    contexts: Option<&[rule_eval::Context]>,
    choices: &[u32],
    now: u32,
) {
    for (j, (rule, record)) in rules.iter().zip(records).enumerate() {
        let Some(cap) = &rule.cap else { continue };
        let requested = contexts.and_then(|cs| {
            let mut sum = 0i128;
            for (ctx, k) in cs.iter().zip(choices) {
                if *k as usize == j {
                    sum = sum.checked_add(amount(ctx, cap.amount_arg)?)?;
                }
            }
            Some(sum)
        });
        out.budgets.push(Budget {
            rule: out.rules[j].id,
            grant: out.rules[j].grant,
            limit: cap.limit,
            period: cap.period,
            before: remaining(record, cap.limit, cap.period, now),
            requested,
            after: None,
        });
    }
}

fn copy_signer(s: &Signer) -> Signer {
    match s {
        Signer::Delegated(a) => Signer::Delegated(a.clone()),
        Signer::External(v, k) => Signer::External(v.clone(), k.clone()),
    }
}

/// Whether two records hold the same spends and total (`same`, `gate.rs:160`).
fn same(a: &SpendRecord, b: &SpendRecord) -> bool {
    a.total == b.total
        && a.history.len() == b.history.len()
        && a.history
            .iter()
            .zip(&b.history)
            .all(|(x, y)| x.ledger == y.ledger && x.amount == y.amount)
}
