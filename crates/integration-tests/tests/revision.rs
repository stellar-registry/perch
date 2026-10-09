//! The configuration revision and the consumer views (#108), and
//! `apply_doc`'s `expected_revision` (RFC #109 §3c), under ENFORCING
//! authorization: every call below runs the account's real `__check_auth`
//! (`support/mod.rs`).
//!
//! Two guarantees are told apart. G1, a consistent read, is the views': one
//! `configuration()` carries the revision everything in it belongs to. G2,
//! execution only at the revision a transaction was signed for, is provided
//! for `apply_doc` alone, by `expected_revision`. An ordinary transaction
//! signed at one revision still runs at a later one when its selected rule
//! survives, under that rule's new content; it fails closed only when the
//! rule's id is gone. The tests below assert both as current behaviour.

mod support;

use perch_account::PerchAccountError;
use perch_doc_compiler::{
    DocLimits, FlatDocLimits, MAX_DOC_CANONICAL_BYTES, MAX_DOC_RULES, MAX_DOC_SIGNERS,
    MAX_RULE_NAME_BYTES,
};
use perch_recovery::EvidenceDomain::{Cancel, Initiate};
use perch_recovery_interface::account::ACCOUNT_UPGRADE_DELAY_LEDGERS;
use perch_recovery_interface::RecoveryAction;
use perch_testkit::delta::{events, storage_state, History};
use perch_testkit::FIXTURE_NETWORK;
use soroban_sdk::{Address, Bytes, Symbol, TryFromVal, Vec};
use stellar_accounts::smart_account::SmartAccountError;
use support::*;

fn revision(w: &World) -> u64 {
    w.client().revision()
}

/// The revision the last invocation's `DocApplied` carries, if it emitted
/// one.
fn applied_revision(w: &World) -> Option<u64> {
    events(&w.env)
        .into_iter()
        .find(|e| e.name == "doc_applied")
        .map(|e| {
            e.data
                .split(['{', ',', '}'])
                .find_map(|f| f.strip_prefix("revision:"))
                .and_then(|r| r.parse().ok())
                .unwrap_or_else(|| panic!("DocApplied data {}", e.data))
        })
}

/// Apply `bytes` as the owner and check the revision advanced by exactly
/// one, in storage and in `DocApplied`.
fn apply_advances(w: &World, bytes: &Bytes, what: &str) {
    let before = revision(w);
    w.apply_bytes(bytes, 0)
        .unwrap_or_else(|e| panic!("{what}: {e:?}"));
    assert_eq!(applied_revision(w), Some(before + 1), "{what}: DocApplied");
    assert_eq!(revision(w), before + 1, "{what}: revision");
}

/// One rule of a hand-written document: scoped to `scope`, signed by every
/// signer id in `signers`.
struct Rule<'a> {
    name: &'a str,
    scope: &'a Address,
    signers: &'a [&'a str],
    not_after: Option<u32>,
}

/// A document declaring `owner` and `device` (the world's keys), an admin
/// rule for `owner`, and `rules`.
fn doc(w: &World, rules: &[Rule]) -> Bytes {
    let mut out = std::vec![r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#.to_string()];
    for r in rules {
        let signers: std::vec::Vec<String> =
            r.signers.iter().map(|s| format!(r#""{s}""#)).collect();
        let not_after = r
            .not_after
            .map(|l| format!(r#","not-after-ledger":{l}"#))
            .unwrap_or_default();
        out.push(format!(
            r#"{{"name":"{}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":[{}]}}{not_after}}}"#,
            r.name,
            strkey(r.scope),
            signers.join(",")
        ));
    }
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"owner","address":"{}"}},{{"id":"device","address":"{}"}}],"rules":[{}]}}"#,
        strkey(&w.owner),
        strkey(&w.device),
        out.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// The id of the installed rule named `name`, by name in the account's
/// `configuration()`: how a consumer selects a rule.
fn select(w: &World, name: &str) -> Option<u32> {
    let wanted = soroban_sdk::String::from_str(&w.env, name);
    w.client()
        .configuration()
        .rules
        .iter()
        .find(|r| !r.recovery && r.name == wanted)
        .map(|r| r.id)
}

/// `key`'s authorization of `Target::protected` through rule `id`, built
/// now and submitted by [`submit`].
fn sign_activity(w: &World, key: &Address, id: u32) -> soroban_sdk::xdr::SorobanAuthorizationEntry {
    let root = w.invocation(&w.target, "protected", std::vec![w.sc(w.account.clone())]);
    w.delegated_entry(&w.account, key, id, root)
}

fn submit(w: &World, entry: soroban_sdk::xdr::SorobanAuthorizationEntry) -> bool {
    submit_result(w, entry).is_ok()
}

/// The submission's own outcome: the error the host reports for it.
fn submit_result(
    w: &World,
    entry: soroban_sdk::xdr::SorobanAuthorizationEntry,
) -> Result<u32, soroban_sdk::Error> {
    w.env.set_auths(&[entry]);
    let out = TargetClient::new(&w.env, &w.target).try_protected(&w.account);
    w.env.set_auths(&[]);
    match out {
        Ok(Ok(hits)) => Ok(hits),
        Ok(Err(e)) => panic!("unexpected conversion error {e:?}"),
        Err(Ok(e)) => Err(e),
        Err(Err(e)) => panic!("unexpected invoke error {e:?}"),
    }
}

/// The account and the error its `__check_auth` failed with in the last
/// invocation: the host's "failed account authentication" diagnostic.
fn account_auth_failure(w: &World) -> Option<(Address, soroban_sdk::Error)> {
    use soroban_sdk::xdr::{ContractEventBody, ScVal};
    let events = w.env.host().get_events().unwrap();
    events.0.iter().find_map(|e| {
        let ContractEventBody::V0(body) = &e.event.body;
        let ScVal::Vec(Some(data)) = &body.data else {
            return None;
        };
        match data.as_slice() {
            [ScVal::String(msg), ScVal::Address(account), ScVal::Error(err)]
                if msg.to_utf8_string_lossy() == "failed account authentication with error" =>
            {
                Some((
                    Address::try_from_val(&w.env, &ScVal::Address(account.clone())).unwrap(),
                    soroban_sdk::Error::from(err.clone()),
                ))
            }
            _ => None,
        }
    })
}

fn rule_not_found() -> soroban_sdk::Error {
    soroban_sdk::Error::from_contract_error(SmartAccountError::ContextRuleNotFound as u32)
}

/// Whether OZ holds no rule `id`.
fn rule_missing(w: &World, id: u32) -> bool {
    w.env.as_contract(&w.account, || {
        !w.env
            .storage()
            .persistent()
            .has(&stellar_accounts::smart_account::SmartAccountStorageKey::ContextRuleData(id))
    })
}

// ---------------------------------------------------------------------------
// The revision
// ---------------------------------------------------------------------------

#[test]
fn every_apply_doc_path_advances_the_revision_by_exactly_one() {
    let w = world();
    assert_eq!(revision(&w), 0, "after the constructor");

    let plain = w.doc(None).bytes(&w);
    apply_advances(&w, &plain, "owner apply");
    apply_advances(&w, &plain, "re-apply of the same document");

    let loss = w.recovery("loss", Mode::Guardian);
    apply_advances(&w, &w.doc(Some(loss.clone())).bytes(&w), "enrollment");
    let mut quorum3 = loss.clone();
    quorum3.quorum = 3;
    apply_advances(&w, &w.doc(Some(quorum3)).bytes(&w), "reconfiguration");
    let mut switched = loss.clone();
    switched.controller = w.env.register(perch_recovery::PerchRecovery, ());
    apply_advances(&w, &w.doc(Some(switched)).bytes(&w), "controller switch");
    apply_advances(&w, &plain, "removal");
    apply_advances(&w, &w.doc(Some(loss)).bytes(&w), "enrollment again");

    // A completion, submitted through the zero-signer recovery rule.
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, attempt, Initiate);
    w.guardian(1, attempt, Initiate);
    w.advance(DELAY);
    let before = revision(&w);
    w.complete(&target).expect("completion");
    assert_eq!(
        applied_revision(&w),
        Some(before + 1),
        "completion: DocApplied"
    );
    assert_eq!(revision(&w), before + 1, "completion");
    assert_eq!(revision(&w), 8);
}

#[test]
fn an_executed_upgrade_advances_the_revision_and_scheduling_does_not() {
    let w = world();
    w.enroll(&w.doc(None));
    let wasm = w.env.deployer().upload_contract_wasm(Bytes::from_slice(
        &w.env,
        include_bytes!("../../perch-smart-account/wasm/perch-spending-limit.wasm"),
    ));
    let call = |name: &str, args: std::vec::Vec<soroban_sdk::xdr::ScVal>| {
        w.env
            .set_auths(&[w.owner_entry("admin", w.invocation(&w.account, name, args))]);
    };

    call(
        "schedule_upgrade",
        std::vec![w.sc(wasm.clone()), w.sc(0u32)],
    );
    w.client().schedule_upgrade(&wasm, &0);
    call("cancel_upgrade", std::vec![]);
    w.client().cancel_upgrade();
    call(
        "schedule_upgrade",
        std::vec![w.sc(wasm.clone()), w.sc(0u32)],
    );
    let id = w.client().schedule_upgrade(&wasm, &0);
    w.env.set_auths(&[]);
    assert_eq!(
        revision(&w),
        1,
        "scheduling and cancelling change no configuration"
    );

    // A refused execution changes nothing.
    call("execute_upgrade", std::vec![w.sc(id)]);
    assert_eq!(
        err(w.client().try_execute_upgrade(&id)),
        PerchAccountError::UpgradeNotReady
    );
    w.env.set_auths(&[]);
    assert_eq!(revision(&w), 1);

    w.advance(ACCOUNT_UPGRADE_DELAY_LEDGERS);
    call("execute_upgrade", std::vec![w.sc(id)]);
    w.client().execute_upgrade(&id);
    w.env.set_auths(&[]);
    // The account now runs other code, so read the stored revision.
    let state = storage_state(&w.env, &w.account, History::Keep);
    assert_eq!(
        state.get("account/instance/Revision").map(String::as_str),
        Some("2")
    );
}

#[test]
fn attempts_evidence_freezes_and_cancellations_leave_the_revision() {
    // Protected: the authorizing evidence sets the freeze, the cancelling
    // evidence lifts it.
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let r = revision(&w);
    let replacements = w.replacements(&w.new_key(), None);
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    assert_eq!(revision(&w), r, "begin");
    w.guardian(0, attempt, Initiate);
    assert_eq!(revision(&w), r, "evidence");
    w.guardian(1, attempt, Initiate);
    assert!(w.client().recovery_gate().is_some(), "frozen");
    assert_eq!(revision(&w), r, "freeze");
    w.guardian(0, attempt, Cancel);
    w.guardian(1, attempt, Cancel);
    assert!(
        w.client().recovery_gate().is_none(),
        "the cancellation lifted the freeze"
    );
    assert_eq!(revision(&w), r, "cancellation and unfreeze");

    // Loss: the owner cancels.
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let r = revision(&w);
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements_for(&w));
    w.guardian(0, attempt, Initiate);
    w.guardian(1, attempt, Initiate);
    let cancel = w.invocation(&w.account, "cancel_recovery", std::vec![w.sc(attempt)]);
    w.env.set_auths(&[w.owner_entry("admin", cancel)]);
    w.client().cancel_recovery(&attempt);
    w.env.set_auths(&[]);
    assert_eq!(revision(&w), r, "owner cancellation");
}

fn replacements_for(w: &World) -> perch_recovery_interface::credential::ReplacementSet {
    w.replacements(&w.new_key(), None)
}

#[test]
fn a_failed_call_leaves_the_revision() {
    let w = world();
    w.enroll(&w.doc(None));
    assert_eq!(revision(&w), 1);

    // Unauthorized: no entry for the call.
    assert!(w
        .client()
        .try_apply_doc(&w.doc(None).bytes(&w), &0, &None)
        .is_err());
    // Refused by the compiler, by anti-brick, and by the revision check.
    assert!(w.apply_bytes(&Bytes::from_slice(&w.env, b"{}"), 0).is_err());
    let no_admin = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"owner","address":"{}"}}],"rules":[{{"name":"t","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["owner"]}}}}]}}"#,
        strkey(&w.owner),
        strkey(&w.target)
    );
    assert_eq!(
        err(w.apply_bytes(&Bytes::from_slice(&w.env, no_admin.as_bytes()), 0)),
        PerchAccountError::AdminLockout
    );
    assert_eq!(
        err(w.submit_apply(w.apply_entry(&w.owner, &w.doc(None).bytes(&w), 0, Some(0)))),
        PerchAccountError::StaleRevision
    );
    assert_eq!(revision(&w), 1, "no failed call moved it");
}

// ---------------------------------------------------------------------------
// A -> B -> A
// ---------------------------------------------------------------------------

#[test]
fn a_b_a_restores_the_doc_hash_but_not_the_selection() {
    let w = world();
    let app = Rule {
        name: "app",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    let a = doc(&w, &[app]);
    let b = doc(&w, &[]);

    let hash_a = w.apply_bytes(&a, 0).unwrap();
    let r1 = revision(&w);
    let i = select(&w, "app").expect("app at r1");
    // Signed at r1, through the r1 selection.
    let signed_at_r1 = sign_activity(&w, &w.owner, i);

    w.apply_bytes(&b, 0).unwrap();
    let r2 = revision(&w);
    assert_eq!(select(&w, "app"), None, "B removes app");
    let hash_again = w.apply_bytes(&a, 0).unwrap();
    let r3 = revision(&w);
    assert_eq!((r2, r3), (r1 + 1, r1 + 2));

    // Same document identity, different configuration.
    assert_eq!(hash_again, hash_a);
    assert_eq!(w.client().configuration().doc_hash, Some(hash_a));
    let j = select(&w, "app").expect("app at r3");
    assert_ne!(j, i, "OZ never reuses an id");
    assert_ne!(r3, r1, "the revision tells A -> B -> A from A");

    // The r1 selection names an id that no longer exists: the transaction
    // signed with it fails closed.
    assert!(rule_missing(&w, i));
    assert_eq!(
        submit_result(&w, signed_at_r1),
        Err(soroban_sdk::Error::from_type_and_code(
            soroban_sdk::xdr::ScErrorType::Context,
            soroban_sdk::xdr::ScErrorCode::InvalidAction
        )),
        "the stale selection fails closed"
    );
    // The submission's own failure: the account's authentication failed with
    // OZ's `ContextRuleNotFound`, which perch-js maps to `StaleSelection`.
    assert_eq!(
        account_auth_failure(&w),
        Some((w.account.clone(), rule_not_found()))
    );
    // Re-resolved at r3, it works.
    assert!(submit(&w, sign_activity(&w, &w.owner, j)));
}

// ---------------------------------------------------------------------------
// A change between signing and submission
// ---------------------------------------------------------------------------

#[test]
fn a_selected_rule_removed_or_replaced_after_signing_fails_closed() {
    let w = world();
    let other = w.env.register(Target, ());
    let at_target = Rule {
        name: "app",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    let at_other = Rule {
        name: "app",
        scope: &other,
        signers: &["owner"],
        not_after: None,
    };

    // Removed.
    w.apply_bytes(&doc(&w, &[at_target]), 0).unwrap();
    let id = select(&w, "app").unwrap();
    let signed = sign_activity(&w, &w.owner, id);
    w.apply_bytes(&doc(&w, &[]), 0).unwrap();
    assert!(!submit(&w, signed), "removed: fails closed");
    assert_eq!(
        account_auth_failure(&w),
        Some((w.account.clone(), rule_not_found()))
    );

    // Replaced: same name, another scope, so another slot and a new id.
    let at_target = Rule {
        name: "app",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    w.apply_bytes(&doc(&w, &[at_target]), 0).unwrap();
    let id = select(&w, "app").unwrap();
    let signed = sign_activity(&w, &w.owner, id);
    w.apply_bytes(&doc(&w, &[at_other]), 0).unwrap();
    assert_ne!(select(&w, "app"), Some(id), "replaced under a new id");
    assert!(rule_missing(&w, id));
    assert!(!submit(&w, signed), "replaced: fails closed");
    assert_eq!(
        account_auth_failure(&w),
        Some((w.account.clone(), rule_not_found()))
    );
}

/// G2 is not provided for ordinary transactions: a rule edited in place
/// keeps its id, and a transaction signed before the edit is evaluated under
/// the edited rule.
#[test]
fn a_selected_rule_edited_in_place_after_signing_runs_under_the_new_content() {
    let w = world();
    let owner_only = |not_after| Rule {
        name: "app",
        scope: &w.target,
        signers: &["owner"],
        not_after,
    };
    w.apply_bytes(&doc(&w, &[owner_only(None)]), 0).unwrap();
    let id = select(&w, "app").unwrap();
    let r = revision(&w);

    // An edit that still admits the signer: the r-signed transaction runs
    // at r + 1.
    let signed = sign_activity(&w, &w.owner, id);
    w.apply_bytes(&doc(&w, &[owner_only(Some(START + 100_000))]), 0)
        .unwrap();
    assert_eq!(revision(&w), r + 1);
    assert_eq!(select(&w, "app"), Some(id), "edited in place");
    assert!(submit(&w, signed), "executes under r + 1's content");

    // An edit that no longer admits the signer: same id, refused.
    let signed = sign_activity(&w, &w.owner, id);
    let device_only = Rule {
        name: "app",
        scope: &w.target,
        signers: &["device"],
        not_after: None,
    };
    w.apply_bytes(&doc(&w, &[device_only]), 0).unwrap();
    assert_eq!(select(&w, "app"), Some(id), "edited in place");
    assert!(!submit(&w, signed), "evaluated under the new signers");
}

/// RFC #109 §3c: an `apply_doc` naming the revision it was prepared at is
/// refused once another apply lands, so a second admin device cannot
/// silently overwrite the first one's change. Without it, the whole document
/// applies over the newer revision.
#[test]
fn an_apply_doc_signed_at_a_revision_is_refused_once_the_account_moves() {
    let w = world();
    let second = w.env.register(Target, ());
    let one = Rule {
        name: "one",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    w.apply_bytes(&doc(&w, &[one]), 0).unwrap();
    let r = revision(&w);

    // Two devices prepare documents at r; the first lands.
    let one = Rule {
        name: "one",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    let two = Rule {
        name: "two",
        scope: &second,
        signers: &["owner"],
        not_after: None,
    };
    let first = w.apply_entry(&w.owner, &doc(&w, &[one, two]), 0, Some(r));
    let stale = w.apply_entry(&w.owner, &doc(&w, &[]), 0, Some(r));
    let unchecked = w.apply_entry(&w.owner, &doc(&w, &[]), 0, None);
    w.submit_apply(first).expect("at r");
    assert_eq!(revision(&w), r + 1);

    // The second, checked against r, is refused and changes nothing.
    assert_eq!(err(w.submit_apply(stale)), PerchAccountError::StaleRevision);
    assert_eq!(revision(&w), r + 1);
    assert!(
        select(&w, "two").is_some(),
        "the first device's change stands"
    );

    // Unchecked, it applies its whole document over r + 1: the lost update
    // the check exists to prevent.
    w.submit_apply(unchecked).expect("no check");
    assert_eq!(revision(&w), r + 2);
    assert_eq!(select(&w, "two"), None, "overwritten");

    // Checked against the current revision, it applies.
    let current = revision(&w);
    w.submit_apply(w.apply_entry(&w.owner, &w.doc(None).bytes(&w), 0, Some(current)))
        .expect("at the current revision");
    assert_eq!(revision(&w), current + 1);
}

#[test]
fn a_completion_may_name_the_revision_its_target_was_derived_at() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let replacements = w.replacements(&w.new_key(), None);
    let source = w.client().applied_doc().unwrap();
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, attempt, Initiate);
    w.guardian(1, attempt, Initiate);
    w.advance(DELAY);
    let r = revision(&w);
    assert_eq!(
        err(w.complete_at(&target, Some(r + 1))),
        PerchAccountError::StaleRevision
    );
    w.complete_at(&target, Some(r)).expect("completion at r");
    assert_eq!(revision(&w), r + 1);
}

// ---------------------------------------------------------------------------
// The views
// ---------------------------------------------------------------------------

/// `configuration()` is every individual view at one ledger.
fn assert_snapshot_matches_views(w: &World) {
    let c = w.client();
    let config = c.configuration();
    assert_eq!(config.revision, c.revision());
    assert_eq!(config.doc_hash, c.applied_doc_hash());
    assert_eq!(config.rules, c.installed_rules());
    assert_eq!(config.recovery_controller, c.recovery_controller());
    assert_eq!(
        config.gate,
        match c.recovery_gate() {
            Some(g) => Vec::from_array(&w.env, [g]),
            None => Vec::new(&w.env),
        }
    );
    assert_eq!(config.recovery_generation, c.recovery_generation());
    assert_eq!(config.infra, c.infra());
    assert_eq!(
        config.recovery_rule,
        config.rules.iter().find(|r| r.recovery).map(|r| r.id)
    );
    for rule in config.rules.iter() {
        assert_eq!(c.get_context_rule(&rule.id).name, rule.name);
    }
    assert_eq!(c.document(), (config.revision, c.applied_doc()));
}

#[test]
fn the_configuration_snapshot_matches_the_individual_views() {
    let w = world();
    assert_snapshot_matches_views(&w);
    assert_eq!(w.client().document(), (0, None));

    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    assert_snapshot_matches_views(&w);

    // Frozen, with a recovery rule and a gate to report.
    let replacements = w.replacements(&w.new_key(), None);
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    w.guardian(0, attempt, Initiate);
    w.guardian(1, attempt, Initiate);
    assert_eq!(w.client().configuration().gate.len(), 1);
    assert_snapshot_matches_views(&w);
}

#[test]
fn a_read_that_straddles_an_apply_sees_two_revisions() {
    let w = world();
    w.enroll(&w.doc(None));
    let snapshot = w.client().configuration();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (revision, _) = w.client().document();
    assert_ne!(
        revision, snapshot.revision,
        "a second read after the apply reports another revision"
    );
}

#[test]
fn capabilities_and_limits_are_constants_of_the_wasm() {
    let w = world();
    let caps = w.client().capabilities();
    assert_eq!(
        caps.interface_version,
        perch_smart_account::INTERFACE_VERSION
    );
    assert_eq!(caps.snapshot_version, perch_smart_account::SNAPSHOT_VERSION);
    assert_eq!(caps.doc_identity, Symbol::new(&w.env, "canon_v1"));
    assert_eq!(caps.auth_digest, Symbol::new(&w.env, "oz_rule_ids"));
    assert_eq!(
        caps.apply_modes,
        Vec::from_array(&w.env, [Symbol::new(&w.env, "one_tx")])
    );
    w.enroll(&w.doc(None));
    assert_eq!(
        w.client().capabilities(),
        caps,
        "applying a document changes none"
    );

    assert_eq!(
        w.compiler().limits(),
        DocLimits::V1(FlatDocLimits {
            max_signers: MAX_DOC_SIGNERS,
            max_rules: MAX_DOC_RULES,
            max_canonical_bytes: MAX_DOC_CANONICAL_BYTES,
            max_rule_name_bytes: MAX_RULE_NAME_BYTES,
        })
    );
    let compiler = w.compiler().capabilities();
    assert_eq!(compiler.canon_version, perch_ir::CANON_VERSION);
    assert_eq!(
        compiler.rule_hash_tag,
        soroban_sdk::String::from_str(&w.env, perch_ir::RULE_HASH_DOMAIN)
    );
    assert_eq!(
        compiler.config_hash_tag,
        soroban_sdk::String::from_str(&w.env, "perch/recovery/config")
    );
}

// ---------------------------------------------------------------------------
// Diagnostic event vectors for perch-js
// ---------------------------------------------------------------------------

/// The last invocation's error diagnostics, as the `DiagnosticEvent` XDR an
/// RPC returns (simulation `events`, a transaction's
/// `diagnosticEventsXdr`), base64.
fn error_diagnostics(w: &World) -> std::vec::Vec<String> {
    use soroban_sdk::xdr::{ContractEventBody, DiagnosticEvent, Limits, ScVal, WriteXdr};
    let events = w.env.host().get_events().unwrap();
    events
        .0
        .iter()
        .filter(|e| {
            let ContractEventBody::V0(body) = &e.event.body;
            matches!(body.topics.first(), Some(ScVal::Symbol(s)) if s.to_utf8_string_lossy() == "error")
        })
        .map(|e| {
            DiagnosticEvent {
                in_successful_contract_call: !e.failed_call,
                event: e.event.clone(),
            }
            .to_xdr_base64(Limits::none())
            .unwrap()
        })
        .collect()
}

/// `testdata/auth/diagnostic-events.json`: the host's own error events for
/// the three failures perch-js types after submission, decoded and mapped
/// by `packages/perch-js/test/diagnostics.test.ts`. Rewrite with
/// `PERCH_BLESS=1`.
#[test]
fn diagnostic_event_vectors_are_the_hosts_own() {
    let mut cases = std::vec::Vec::new();

    // A selection whose rule is gone: the account's authentication fails
    // with OZ's ContextRuleNotFound.
    let w = world();
    let app = Rule {
        name: "app",
        scope: &w.target,
        signers: &["owner"],
        not_after: None,
    };
    w.apply_bytes(&doc(&w, &[app]), 0).unwrap();
    let signed = sign_activity(&w, &w.owner, select(&w, "app").unwrap());
    w.apply_bytes(&doc(&w, &[]), 0).unwrap();
    assert!(!submit(&w, signed));
    cases.push(serde_json::json!({
        "name": "stale_selection",
        "account": strkey(&w.account),
        "events": error_diagnostics(&w),
    }));

    // An apply_doc checked against a revision the account has left.
    let w = world();
    w.enroll(&w.doc(None));
    assert_eq!(
        err(w.submit_apply(w.apply_entry(&w.owner, &w.doc(None).bytes(&w), 0, Some(0)))),
        PerchAccountError::StaleRevision
    );
    cases.push(serde_json::json!({
        "name": "stale_revision",
        "account": strkey(&w.account),
        "events": error_diagnostics(&w),
    }));

    // Ordinary activity on a frozen account.
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let attempt = w
        .ctl()
        .begin_lost_key(&w.account, &w.replacements(&w.new_key(), None));
    w.guardian(0, attempt, Initiate);
    w.guardian(1, attempt, Initiate);
    assert!(!w.activity());
    cases.push(serde_json::json!({
        "name": "account_frozen",
        "account": strkey(&w.account),
        "events": error_diagnostics(&w),
    }));

    let want = serde_json::to_string_pretty(&serde_json::json!({
        "comment": "Written by crates/integration-tests/tests/revision.rs (PERCH_BLESS=1); read by packages/perch-js/test/diagnostics.test.ts. Each case is the host's error DiagnosticEvents (base64 XDR) for one failed submission.",
        "cases": cases,
    }))
    .unwrap()
        + "\n";
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/auth/diagnostic-events.json");
    if std::env::var("PERCH_BLESS").is_ok() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).expect("PERCH_BLESS=1 writes the vectors");
    assert_eq!(
        have, want,
        "diagnostic-events.json is stale: rerun with PERCH_BLESS=1"
    );
}
