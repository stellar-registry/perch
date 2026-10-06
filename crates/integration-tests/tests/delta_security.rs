//! The delta `apply_doc` against recovery's security properties, and its
//! atomicity, under ENFORCING authorization (`support/mod.rs`).
//!
//! - Revoked credentials cannot come back through an in-place edit.
//! - The `Protected` freeze and the recovery generation behave exactly as
//!   under the full replace: the same recovery runs on a delta account and
//!   on the full-replace oracle, and their complete normalized storage
//!   matches after every step.
//! - Reserved names and the controller-scope rule still hold after in-place
//!   edits; a delta inside an authorized window is refused and changes
//!   nothing.
//! - A failure partway through a delta (a policy install that fails, or the
//!   budget running out) reverts the whole `apply_doc`.

mod support;

use perch_account::PerchAccountError;
use perch_recovery::{EvidenceDomain, RecoveryError};
use perch_recovery_interface::credential::Credential;
use perch_recovery_interface::RecoveryAction;
use perch_testkit::delta::{raw_entries, storage_state, History};
use soroban_sdk::{Address, Bytes, BytesN};
use support::*;

use EvidenceDomain::Initiate;

fn fingerprint(w: &World, key: &Address) -> BytesN<32> {
    Credential::Delegated(key.clone()).fingerprint(&w.env).unwrap()
}

/// A document with `owner` (admin) and `device`, and extra rules
/// `(name, scope, signer ids, capped)`, optionally enrolling `recovery`.
fn json(
    w: &World,
    owner: &Address,
    rules: &[(&str, &Address, &[&str], bool)],
    recovery: Option<&Recovery>,
) -> Bytes {
    let mut out = std::vec![format!(
        r#"{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}}"#
    )];
    for (name, scope, signers, capped) in rules {
        let ids: std::vec::Vec<String> = signers.iter().map(|s| format!(r#""{s}""#)).collect();
        let cap = if *capped {
            r#","cap":{"limit":"1000","period-ledgers":100}"#
        } else {
            ""
        };
        out.push(format!(
            r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":[{}]}}{cap}}}"#,
            strkey(scope),
            ids.join(",")
        ));
    }
    let recovery = recovery
        .map(|r| format!(r#","recovery":{}"#, r.json(w)))
        .unwrap_or_default();
    let doc = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","address":"{}"}},{{"id":"device","address":"{}"}}],"rules":[{}]{recovery}}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(owner),
        strkey(&w.device),
        out.join(",")
    );
    Bytes::from_slice(&w.env, doc.as_bytes())
}

fn authorize_lost_key(w: &World) -> (u64, Address, Bytes) {
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    (id, new_owner, target)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

#[test]
fn a_revoked_credential_cannot_return_through_an_in_place_edit() {
    let w = world();
    let r = w.recovery("loss", Mode::Guardian);
    let other = w.new_key();
    w.apply_bytes(&json(&w, &w.owner, &[("r1", &other, &["device"], false)], Some(&r)), 0)
        .unwrap();
    let (_, new_owner, target) = authorize_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert!(w.client().is_revoked(&fingerprint(&w, &w.owner)));

    // Adding the revoked key to an existing rule would be an in-place
    // `add_signer`; the revocation check runs on the compiled document
    // before any rule is touched.
    let r1_id = w.rule_id(&w.account, "r1");
    let before = raw_entries(&w.env);
    let with_old = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","address":"{}"}},{{"id":"device","address":"{}"}},{{"id":"old","address":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}},{{"name":"r1","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["device","old"]}}}}],"recovery":{}}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(&new_owner),
        strkey(&w.device),
        strkey(&w.owner),
        strkey(&other),
        r.json(&w)
    );
    assert_eq!(
        err(w.apply_as(&new_owner, &Bytes::from_slice(&w.env, with_old.as_bytes()), 0)),
        PerchAccountError::RevokedCredential
    );
    assert_eq!(raw_entries(&w.env), before, "a refused delta changes nothing");
    assert_eq!(w.rule_id(&w.account, "r1"), r1_id);
}

// ---------------------------------------------------------------------------
// The Protected freeze and the recovery generation, delta vs full replace
// ---------------------------------------------------------------------------

/// The same `Protected` recovery on a delta account and on the
/// full-replace oracle: identical complete storage after every step, and
/// identical freeze and generation readings.
#[test]
fn the_freeze_and_the_generation_behave_as_under_the_full_replace() {
    let delta = world();
    let oracle = world_with(Opts {
        oracle: true,
        ..Opts::default()
    });
    let compare = |step: &str| {
        let a = storage_state(&delta.env, &delta.account, History::Keep);
        let b = storage_state(&oracle.env, &oracle.account, History::Keep);
        assert_eq!(a, b, "storage diverged after {step}");
        assert_eq!(
            delta.client().recovery_gate(),
            oracle.client().recovery_gate(),
            "{step}"
        );
        assert_eq!(
            delta.client().recovery_generation(),
            oracle.client().recovery_generation(),
            "{step}"
        );
    };
    let docs = |w: &World| {
        let r = w.recovery("protected", Mode::Guardian);
        let scope = w.target.clone();
        (
            json(w, &w.owner, &[("r1", &scope, &["owner", "device"], false)], Some(&r)),
            json(w, &w.owner, &[("r1", &scope, &["device"], true)], Some(&r)),
        )
    };
    for w in [&delta, &oracle] {
        let (first, _) = docs(w);
        w.apply_bytes(&first, 0).unwrap();
    }
    compare("enrollment");
    for w in [&delta, &oracle] {
        let (_, edited) = docs(w);
        w.apply_bytes(&edited, 0).unwrap();
    }
    compare("an in-place edit (no reconfiguration)");

    let mut targets = std::vec::Vec::new();
    for w in [&delta, &oracle] {
        let (_, new_owner, target) = authorize_lost_key(w);
        assert!(w.client().recovery_gate().is_some());
        assert!(!w.activity(), "frozen");
        let (first, _) = docs(w);
        assert!(w.apply_bytes(&first, 0).is_err(), "frozen");
        targets.push((new_owner, target));
    }
    compare("authorization");
    for (w, (new_owner, target)) in [&delta, &oracle].into_iter().zip(&targets) {
        w.advance(DELAY);
        w.complete(target).unwrap();
        assert_eq!(w.client().recovery_gate(), None);
        assert!(w.client().is_revoked(&fingerprint(w, &w.owner)));
        assert!(!w.client().is_revoked(&fingerprint(w, new_owner)));
    }
    compare("completion");
}

// ---------------------------------------------------------------------------
// Reserved names, controller scope, the authorized window
// ---------------------------------------------------------------------------

#[test]
fn reserved_names_hold_after_a_controller_scoped_rule_is_edited_in_place() {
    let w = world();
    let r = w.recovery("loss", Mode::Guardian);
    let controller = w.controller.clone();
    w.apply_bytes(&json(&w, &w.owner, &[("ctl", &controller, &["owner"], false)], Some(&r)), 0)
        .unwrap();
    let id = w.rule_id(&w.account, "ctl");
    w.apply_bytes(
        &json(&w, &w.owner, &[("ctl", &controller, &["owner", "device"], false)], Some(&r)),
        0,
    )
    .unwrap();
    assert_eq!(w.rule_id(&w.account, "ctl"), id, "edited in place");

    let config = w.ctl().config(&w.account).unwrap();
    let hash = w.client().applied_doc_hash().unwrap();
    let sync = w.invocation(
        &w.controller,
        "rcv_sync",
        std::vec![
            w.sc(w.account.clone()),
            w.sc(hash.clone()),
            w.sc(soroban_sdk::vec![&w.env, config.clone()]),
            w.sc(0u32),
        ],
    );
    w.env.set_auths(&[w.owner_entry("ctl", sync)]);
    assert!(w
        .ctl()
        .try_rcv_sync(&w.account, &hash, &soroban_sdk::vec![&w.env, config], &0)
        .is_err());
    w.env.set_auths(&[]);
}

#[test]
fn a_delta_inside_an_authorized_window_is_refused_and_changes_nothing() {
    let w = world();
    let r = w.recovery("loss", Mode::Guardian);
    let scope = w.target.clone();
    w.apply_bytes(&json(&w, &w.owner, &[("r1", &scope, &["owner"], false)], Some(&r)), 0)
        .unwrap();
    authorize_lost_key(&w);
    let before = raw_entries(&w.env);
    let edited = json(&w, &w.owner, &[("r1", &scope, &["owner", "device"], false)], Some(&r));
    assert_eq!(
        err(w.apply_bytes(&edited, 0)),
        PerchAccountError::Recovery(RecoveryError::AttemptAuthorized)
    );
    assert_eq!(raw_entries(&w.env), before);
}

// ---------------------------------------------------------------------------
// Atomicity
// ---------------------------------------------------------------------------

/// A delta that removes a rule, edits another in place, and then fails on a
/// policy install leaves nothing behind.
#[test]
fn a_policy_install_failing_mid_delta_reverts_every_edit() {
    let w = world_with(Opts {
        failing_spending_limit: true,
        ..Opts::default()
    });
    let (a, b, c) = (w.new_key(), w.new_key(), w.new_key());
    w.apply_bytes(
        &json(&w, &w.owner, &[("r1", &a, &["owner"], false), ("r2", &b, &["owner"], false)], None),
        0,
    )
    .unwrap();
    let before = raw_entries(&w.env);
    let installed = w.client().installed_rules();
    let applied = w.client().applied_doc_hash();

    // r2 goes (removed first), r1 gains a signer (edited in place), then r3's
    // spending-limit install fails.
    let failing = json(
        &w,
        &w.owner,
        &[("r1", &a, &["owner", "device"], false), ("r3", &c, &["owner"], true)],
        None,
    );
    assert!(w.apply_bytes(&failing, 0).is_err());
    assert_eq!(raw_entries(&w.env), before, "every edit reverted");
    assert_eq!(w.client().installed_rules(), installed);
    assert_eq!(w.client().applied_doc_hash(), applied);

    // The account is still usable: the same edits without the cap apply.
    w.apply_bytes(
        &json(
            &w,
            &w.owner,
            &[("r1", &a, &["owner", "device"], false), ("r3", &c, &["owner"], false)],
            None,
        ),
        0,
    )
    .unwrap();
}

/// The budget running out at any point of a delta reverts all of it. The
/// SDK surfaces budget exhaustion as a panic of the call (it is not a
/// recoverable error), raised after the host has unwound the invocation; each
/// fraction gets a fresh world (AGENTS.md: don't chain recovered panics in
/// one `Env`).
#[test]
fn budget_exhaustion_mid_delta_reverts_every_edit() {
    let docs = |w: &World, keys: &[Address; 3]| {
        let [a, b, c] = keys;
        (
            json(w, &w.owner, &[("r1", a, &["owner"], false), ("r2", b, &["owner"], true)], None),
            json(
                w,
                &w.owner,
                &[("r1", a, &["owner", "device"], false), ("r3", c, &["device"], true)],
                None,
            ),
        )
    };
    let setup = || {
        let w = world();
        let keys = [w.new_key(), w.new_key(), w.new_key()];
        let (first, second) = docs(&w, &keys);
        w.apply_bytes(&first, 0).unwrap();
        (w, second)
    };

    // The full cost of the delta.
    let (twin, second) = setup();
    twin.apply_bytes(&second, 0).unwrap();
    let cost = twin.env.cost_estimate().resources().instructions as u64;

    for percent in [20u64, 40, 60, 80, 90, 95, 99] {
        let (w, second) = setup();
        let before = raw_entries(&w.env);
        // Build the authorization first: the limit applies to every host
        // operation, so only the `apply_doc` call itself runs under it.
        let root = w.invocation(
            &w.account,
            "apply_doc",
            std::vec![w.sc(second.clone()), w.sc(0u32)],
        );
        w.env.set_auths(&[w.owner_entry("admin", root)]);
        w.env
            .cost_estimate()
            .budget()
            .reset_limits(cost * percent / 100, 1 << 30);
        let client = w.client();
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.try_apply_doc(&second, &0)
        }));
        w.env.cost_estimate().budget().reset_unlimited();
        w.env.set_auths(&[]);
        assert!(
            out.is_err() || out.as_ref().is_ok_and(|r| r.is_err()),
            "{percent}% of the budget"
        );
        assert_eq!(raw_entries(&w.env), before, "{percent}%: every edit reverted");
        w.apply_bytes(&second, 0)
            .expect("the account still applies the delta with budget to spare");
    }
}
