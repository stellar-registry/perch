//! Scoped documents under ENFORCING authorization (`docs/recovery/spec.md`
//! §7.6): `apply_scope`, `remove_scope`, and `gc_scope`, the guards that
//! keep a scoped document away from the account itself and its recovery,
//! the scope generation gate in `__check_auth`, and the wipe a recovery
//! completion makes. See `support/mod.rs` for the world. Every grant is
//! exercised through the account's real `__check_auth`, never mocked auth.

mod support;

use perch_account::{PerchAccountError, PerchAuthError};
use perch_recovery::{AttemptState, EvidenceDomain, RecoveryError};
use perch_recovery_interface::credential::Credential;
use perch_recovery_interface::RecoveryAction;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::storage::Persistent as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{ContractDataDurability, LedgerKey, ScSymbol, ScVal, ScVec};
use soroban_sdk::{vec, Address, Bytes, BytesN, IntoVal, Map, Symbol, Val, Vec};
use stellar_accounts::smart_account::{
    AuthPayload, SMART_ACCOUNT_EXTEND_AMOUNT, SMART_ACCOUNT_TTL_THRESHOLD,
};
use support::*;

use EvidenceDomain::Initiate;

type CallResult<T> = Result<T, Result<PerchAccountError, soroban_sdk::InvokeError>>;

/// A scoped document: `signers` as delegated keys, and one rule per
/// `(name, contract, signer id)` scoped to that contract and signed by that
/// signer alone.
fn scoped(w: &World, signers: &[(&str, &Address)], rules: &[(&str, &Address, &str)]) -> Bytes {
    let signers: std::vec::Vec<String> = signers
        .iter()
        .map(|(id, a)| format!(r#"{{"id":"{id}","address":"{}"}}"#, strkey(a)))
        .collect();
    let rules: std::vec::Vec<String> = rules
        .iter()
        .map(|(name, contract, signer)| {
            format!(
                r#"{{"name":"{name}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["{signer}"]}}}}"#,
                strkey(contract)
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"network":"{}","signers":[{}],"rules":[{}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        signers.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// A grant: `key` may call [`Target`] as the account, through rule `name`.
fn grant(w: &World, name: &str, key: &Address) -> Bytes {
    scoped(w, &[("k", key)], &[(name, &w.target, "k")])
}

/// `apply_scope(scope, doc)` signed by `key` through the admin rule.
fn apply_scope_as(w: &World, key: &Address, scope: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
    let root = w.invocation(
        &w.account,
        "apply_scope",
        std::vec![w.sc(scope), w.sc(doc.clone())],
    );
    w.env.set_auths(&[w.entry_as(key, "admin", root)]);
    let out = w.client().try_apply_scope(&scope, doc);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

fn apply_scope(w: &World, scope: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
    apply_scope_as(w, &w.owner, scope, doc)
}

fn remove_scope_as(w: &World, key: &Address, scope: u32) -> CallResult<()> {
    let root = w.invocation(&w.account, "remove_scope", std::vec![w.sc(scope)]);
    w.env.set_auths(&[w.entry_as(key, "admin", root)]);
    let out = w.client().try_remove_scope(&scope);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

/// The OZ id of rule `name` in `scope`'s record.
fn scoped_id(w: &World, scope: u32, name: &str) -> u32 {
    let wanted = soroban_sdk::String::from_str(&w.env, name);
    w.client()
        .scope(&scope)
        .expect("the scope has a record")
        .rules
        .iter()
        .find(|r| r.name == wanted)
        .expect("the scope has the rule")
        .id
}

/// `key` calls [`Target`] as the account through rule `rule`.
fn call_via(w: &World, key: &Address, rule: u32) -> bool {
    let root = w.invocation(&w.target, "protected", std::vec![w.sc(w.account.clone())]);
    w.env
        .set_auths(&[w.delegated_entry(&w.account, key, rule, root)]);
    let ok = TargetClient::new(&w.env, &w.target)
        .try_protected(&w.account)
        .is_ok();
    w.env.set_auths(&[]);
    ok
}

/// The account's `__check_auth` of a [`Target`] call selecting `rule`,
/// with no signatures: what it refuses before OZ looks at any signer.
fn check_auth_selecting(w: &World, rule: u32) -> Result<(), soroban_sdk::Error> {
    let context = Context::Contract(ContractContext {
        contract: w.target.clone(),
        fn_name: Symbol::new(&w.env, "protected"),
        args: vec![&w.env, w.account.clone().into_val(&w.env)],
    });
    let payload = AuthPayload {
        signers: Map::new(&w.env),
        context_rule_ids: vec![&w.env, rule],
    };
    w.env
        .try_invoke_contract_check_auth::<soroban_sdk::Error>(
            &w.account,
            &BytesN::from_array(&w.env, &[7; 32]),
            payload.into_val(&w.env),
            &vec![&w.env, context],
        )
        .map_err(|e| match e {
            Ok(e) => e,
            Err(e) => panic!("invoke error {e:?}"),
        })
}

fn stale() -> Result<(), soroban_sdk::Error> {
    Err(PerchAuthError::StaleScope.into())
}

/// The storage key of rule `id`'s scope tag: the account's `scope_tags`
/// map, whose entries `contractstorage` keys `[ScopeTags, id]`.
fn tag_key(w: &World, id: u32) -> Vec<Val> {
    vec![
        &w.env,
        Symbol::new(&w.env, "ScopeTags").into_val(&w.env),
        id.into_val(&w.env),
    ]
}

fn has_tag(w: &World, id: u32) -> bool {
    w.env.as_contract(&w.account, || {
        w.env.storage().persistent().has(&tag_key(w, id))
    })
}

fn tag_ttl(w: &World, id: u32) -> u32 {
    w.env.as_contract(&w.account, || {
        w.env.storage().persistent().get_ttl(&tag_key(w, id))
    })
}

/// Whether rule `id`'s tag entry is archived at the current ledger, read
/// from the raw ledger (`get_ttl` would restore it).
fn tag_archived(w: &World, id: u32) -> bool {
    let account: soroban_sdk::xdr::ScAddress = w.account.clone().into();
    let key = ScVal::Vec(Some(ScVec(
        std::vec![
            ScVal::Symbol(ScSymbol("ScopeTags".try_into().unwrap())),
            ScVal::U32(id)
        ]
        .try_into()
        .unwrap(),
    )));
    let seq = w.ledger();
    w.env
        .to_ledger_snapshot()
        .ledger_entries
        .iter()
        .any(|(k, (_, live_until))| {
            matches!(k.as_ref(), LedgerKey::ContractData(d)
                if d.contract == account
                    && d.durability == ContractDataDurability::Persistent
                    && d.key == key)
                && live_until.is_some_and(|l| l < seq)
        })
}

fn exists(w: &World, rule: u32) -> bool {
    matches!(w.client().try_get_context_rule(&rule), Ok(Ok(_)))
}

fn fingerprint(w: &World, key: &Address) -> BytesN<32> {
    Credential::Delegated(key.clone())
        .fingerprint(&w.env)
        .unwrap()
}

/// Open a lost-key attempt replacing `owner` and have two guardians
/// authorize it. Returns the attempt id, the new owner, and the target.
fn authorized_lost_key(w: &World) -> (u64, Address, Bytes) {
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
// Applying, changing, and removing a scope
// ---------------------------------------------------------------------------

#[test]
fn a_scoped_grant_authorizes_its_contract_until_remove_scope_revokes_it() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    let doc = grant(&w, "game", &app);
    let hash = apply_scope(&w, 4, &doc).expect("owner apply_scope");
    assert_eq!(hash, w.compiler().compile_doc(&doc).doc_hash);

    let record = w.client().scope(&4).unwrap();
    assert_eq!((record.gen, record.doc_hash.clone()), (0, hash.clone()));
    assert_eq!(record.rules.len(), 1);
    assert_eq!(
        w.client().scope_doc(&4),
        Some(w.compiler().compile_doc(&doc).canonical)
    );
    assert_eq!(w.client().scope_count(), 1);
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 4u32]);

    let id = scoped_id(&w, 4, "game");
    assert!(has_tag(&w, id));
    assert!(call_via(&w, &app, id), "the grant authorizes its contract");
    assert!(
        !call_via(&w, &w.new_key(), id),
        "and only for its own signer"
    );

    // Re-applying the same document changes nothing and keeps the id.
    apply_scope(&w, 4, &doc).unwrap();
    assert_eq!(w.client().scope(&4), Some(record));

    remove_scope_as(&w, &w.owner, 4).expect("owner remove_scope");
    assert!(!call_via(&w, &app, id), "revoked");
    assert!(!exists(&w, id) && !has_tag(&w, id));
    assert_eq!(w.client().scope(&4), None);
    assert_eq!(w.client().scope_doc(&4), None);
    assert_eq!(w.client().scope_count(), 0);
    assert_eq!(
        err(remove_scope_as(&w, &w.owner, 4)),
        PerchAccountError::UnknownScope
    );
}

#[test]
fn only_the_owner_changes_a_scope() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    apply_scope(&w, 1, &grant(&w, "game", &app)).unwrap();
    let id = scoped_id(&w, 1, "game");

    // No authorization at all.
    let other = grant(&w, "game", &w.new_key());
    assert!(w.client().try_apply_scope(&1, &other).is_err());
    assert!(w.client().try_remove_scope(&1).is_err());

    // A grant's own key, through its own rule: the rule is scoped to
    // another contract, so OZ refuses a context on the account.
    for (fn_name, args) in [
        ("apply_scope", std::vec![w.sc(1u32), w.sc(other.clone())]),
        ("remove_scope", std::vec![w.sc(1u32)]),
    ] {
        let root = w.invocation(&w.account, fn_name, args);
        w.env
            .set_auths(&[w.delegated_entry(&w.account, &app, id, root)]);
        let refused = if fn_name == "apply_scope" {
            w.client().try_apply_scope(&1, &other).is_err()
        } else {
            w.client().try_remove_scope(&1).is_err()
        };
        w.env.set_auths(&[]);
        assert!(refused, "{fn_name} through a scoped rule");
    }

    // A key that is no admin signer, through the admin rule.
    assert!(apply_scope_as(&w, &app, 1, &other).is_err());
    assert!(remove_scope_as(&w, &w.device, 1).is_err());
    assert!(call_via(&w, &app, id), "nothing changed");
}

#[test]
fn changing_a_scope_reconciles_its_own_rules_only() {
    let w = world();
    w.enroll(&w.doc(None));
    let (a, b) = (w.new_key(), w.new_key());
    // Two scopes with a rule of the same name for the same key.
    apply_scope(&w, 1, &grant(&w, "game", &a)).unwrap();
    apply_scope(&w, 2, &grant(&w, "game", &a)).unwrap();
    let (id1, id2) = (scoped_id(&w, 1, "game"), scoped_id(&w, 2, "game"));
    assert_ne!(id1, id2, "rule names are unique within one scope only");

    // Scope 1's key rotates in place under its id; scope 2 is untouched.
    apply_scope(&w, 1, &grant(&w, "game", &b)).unwrap();
    assert_eq!(scoped_id(&w, 1, "game"), id1, "edited in place");
    assert!(call_via(&w, &b, id1) && !call_via(&w, &a, id1));
    assert!(call_via(&w, &a, id2));

    // A renamed rule replaces the old one; its tag goes with it.
    apply_scope(&w, 1, &grant(&w, "dice", &b)).unwrap();
    let dice = scoped_id(&w, 1, "dice");
    assert!(!exists(&w, id1) && !has_tag(&w, id1));
    assert!(has_tag(&w, dice) && call_via(&w, &b, dice));

    // Removing scope 1 leaves scope 2's rule, which shares the signer.
    remove_scope_as(&w, &w.owner, 1).unwrap();
    assert!(call_via(&w, &a, id2));
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 2u32]);
}

#[test]
fn scopes_and_the_admin_document_share_signers_without_touching_each_other() {
    let w = world();
    w.enroll(&w.doc(None));
    let hash = w.client().applied_doc_hash();
    let revision = w.client().revision();
    let configuration = w.client().configuration();

    // A scope signed by keys the admin document also names.
    let shared = scoped(
        &w,
        &[("o", &w.owner), ("d", &w.device)],
        &[("o", &w.target, "o"), ("d", &w.target, "d")],
    );
    apply_scope(&w, 9, &shared).unwrap();
    assert_eq!(w.client().applied_doc_hash(), hash);
    assert_eq!(w.client().revision(), revision, "a scope is no revision");
    assert_eq!(w.client().configuration(), configuration);
    assert_eq!(w.client().installed_rules(), configuration.rules);

    // The admin document drops `device`: OZ's registry keeps the signer
    // the scope still names, and the scope's rules are not in the admin
    // document's reconcile.
    let mut lean = w.doc(None);
    lean.signers.truncate(1);
    lean.rules.clear();
    w.enroll(&lean);
    assert!(call_via(&w, &w.device, scoped_id(&w, 9, "d")));
    assert!(call_via(&w, &w.owner, scoped_id(&w, 9, "o")));

    // Removing the scope leaves the admin rule, which shares `owner`.
    remove_scope_as(&w, &w.owner, 9).unwrap();
    assert!(
        w.apply(&w.doc(None), 0).is_ok(),
        "the admin rule still works"
    );
}

#[test]
fn the_index_lists_every_scope_through_removals() {
    let w = world();
    w.enroll(&w.doc(None));
    let key = w.new_key();
    for scope in [3u32, 7, 9, 11] {
        apply_scope(&w, scope, &grant(&w, "g", &key)).unwrap();
    }
    assert_eq!(w.client().scope_count(), 4);
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 3u32, 7, 9, 11]);
    assert_eq!(w.client().scopes(&1, &2), vec![&w.env, 7u32, 9]);
    assert_eq!(w.client().scopes(&3, &u32::MAX), vec![&w.env, 11u32]);
    assert_eq!(w.client().scopes(&9, &2), Vec::<u32>::new(&w.env));

    // The last id moves into a freed position.
    remove_scope_as(&w, &w.owner, 3).unwrap();
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 11u32, 7, 9]);
    remove_scope_as(&w, &w.owner, 9).unwrap();
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 11u32, 7]);
    // Re-applying a known scope does not index it twice.
    apply_scope(&w, 7, &grant(&w, "h", &key)).unwrap();
    apply_scope(&w, 3, &grant(&w, "g", &key)).unwrap();
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 11u32, 7, 3]);
    for scope in [11u32, 7, 3] {
        remove_scope_as(&w, &w.owner, scope).unwrap();
    }
    assert_eq!(w.client().scope_count(), 0);
    assert_eq!(w.client().scopes(&0, &10), Vec::<u32>::new(&w.env));
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

#[test]
fn a_scoped_document_cannot_reach_the_account_or_its_recovery() {
    let w = world();
    let r = w.recovery("loss", Mode::Zk);
    w.enroll(&w.doc(Some(r.clone())));
    let k = w.new_key();
    let escalation = |doc: String| {
        let bytes = Bytes::from_slice(&w.env, doc.as_bytes());
        // Each compiles: only the account refuses it.
        assert!(w.compiler().try_compile_doc(&bytes).is_ok(), "{doc}");
        err(apply_scope(&w, 1, &bytes))
    };
    let head = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"k","address":"{}"}}]"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(&k)
    );
    let contract_rule = |a: &Address| {
        format!(
            r#"{{"name":"x","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["k"]}}}}"#,
            strkey(a)
        )
    };

    // A self-admin rule: owner authority.
    assert_eq!(
        escalation(format!(
            r#"{head},"rules":[{{"name":"x","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["k"]}}}}]}}"#
        )),
        PerchAccountError::ScopeEscalation
    );
    // A contract rule naming the account itself: the same authority.
    assert_eq!(
        escalation(format!(
            r#"{head},"rules":[{}]}}"#,
            contract_rule(&w.account)
        )),
        PerchAccountError::ScopeEscalation
    );
    // The applied recovery member's ZK adapter and pool (spec §15 rule 3).
    for zk in [&w.adapter, &w.pool] {
        assert_eq!(
            escalation(format!(r#"{head},"rules":[{}]}}"#, contract_rule(zk))),
            PerchAccountError::ScopeEscalation
        );
    }
    // A recovery member, even next to an ordinary grant.
    let mut member = r.clone();
    member.replaceable = std::vec!["k"];
    assert_eq!(
        escalation(format!(
            r#"{head},"rules":[{}],"recovery":{}}}"#,
            contract_rule(&w.target),
            member.json(&w)
        )),
        PerchAccountError::ScopeEscalation
    );
    // The recovery controller is another contract: a scope may hold the
    // account's guardian approvals there, as the admin document may (§2).
    assert!(apply_scope(
        &w,
        2,
        &Bytes::from_slice(
            &w.env,
            format!(r#"{head},"rules":[{}]}}"#, contract_rule(&w.controller)).as_bytes()
        )
    )
    .is_ok());
    assert_eq!(w.client().scope_count(), 1, "nothing else was applied");
}

#[test]
fn a_scoped_document_naming_a_revoked_credential_is_refused() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert!(w.client().is_revoked(&fingerprint(&w, &w.owner)));
    assert_eq!(
        err(apply_scope_as(
            &w,
            &new_owner,
            1,
            &grant(&w, "game", &w.owner)
        )),
        PerchAccountError::RevokedCredential
    );
}

// ---------------------------------------------------------------------------
// Recovery: the generation wipe, the freeze, the policy block
// ---------------------------------------------------------------------------

#[test]
fn a_completion_wipes_every_scope_and_anyone_collects_them() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (a, b) = (w.new_key(), w.new_key());
    apply_scope(&w, 1, &grant(&w, "game", &a)).unwrap();
    apply_scope(&w, 2, &grant(&w, "dice", &b)).unwrap();
    let (game, dice) = (scoped_id(&w, 1, "game"), scoped_id(&w, 2, "dice"));
    assert_eq!(
        err(w.client().try_gc_scope(&1)),
        PerchAccountError::ScopeLive
    );

    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).expect("completion");
    assert_eq!(w.client().scope_generation(), 1);

    // Every scope stops authorizing, refused by the gate before OZ.
    assert!(!call_via(&w, &a, game) && !call_via(&w, &b, dice));
    assert_eq!(check_auth_selecting(&w, game), stale());
    assert_eq!(check_auth_selecting(&w, dice), stale());
    // The records stay, at their old generation, until collected. The
    // admin rules authorize as before.
    assert_eq!(w.client().scope(&1).unwrap().gen, 0);
    assert!(w.activity_as(&new_owner));

    // Anyone collects a wiped scope, with no authorization.
    w.client().gc_scope(&1);
    assert!(!exists(&w, game) && !has_tag(&w, game));
    assert_eq!(w.client().scope(&1), None);
    assert_eq!(w.client().scopes(&0, &10), vec![&w.env, 2u32]);
    assert_eq!(
        err(w.client().try_gc_scope(&1)),
        PerchAccountError::UnknownScope
    );

    // The new owner re-grants over a wiped scope without collecting it:
    // the same rule is edited in place under its id and tagged anew.
    apply_scope_as(&w, &new_owner, 2, &grant(&w, "dice", &b)).unwrap();
    assert_eq!(scoped_id(&w, 2, "dice"), dice);
    assert_eq!(w.client().scope(&2).unwrap().gen, 1);
    assert!(call_via(&w, &b, dice));
    assert_eq!(
        err(w.client().try_gc_scope(&2)),
        PerchAccountError::ScopeLive
    );
}

#[test]
fn a_compromise_completion_wipes_the_thiefs_scopes() {
    let w = world();
    let baseline = w.doc(None);
    let mut r = w.recovery("protected", Mode::Guardian);
    r.baseline = Some(w.doc_hash(&baseline));
    w.enroll(&w.doc(Some(r)));

    // A thief with the owner key grants itself scopes; no condition is
    // needed for scopes under Protected, as for any non-recovery change.
    let thief = w.new_key();
    for scope in 0..3u32 {
        apply_scope(
            &w,
            scope,
            &scoped(
                &w,
                &[("t", &thief)],
                &[("drain", &w.target, "t"), ("pool", &w.controller, "t")],
            ),
        )
        .unwrap();
    }
    let drain = scoped_id(&w, 2, "drain");
    assert!(call_via(&w, &thief, drain));

    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    w.ctl().publish_baseline(&w.account, &baseline.bytes(&w));
    let id = w.ctl().begin_compromise(&w.account, &replacements);
    let source = w.ctl().baseline(&w.account).unwrap();
    let target = w.target_bytes(RecoveryAction::Compromise, &source, &replacements);
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    assert!(!call_via(&w, &thief, drain), "frozen");
    w.advance(DELAY);
    w.complete(&target).expect("compromise completion");

    assert_eq!(check_auth_selecting(&w, drain), stale());
    assert!(!call_via(&w, &thief, drain));
    assert!(w.activity_as(&new_owner));
    assert_eq!(w.client().scope_count(), 3, "wiped, awaiting collection");
    for scope in 0..3u32 {
        w.client().gc_scope(&scope);
    }
    assert_eq!(w.client().scope_count(), 0);
}

#[test]
fn the_protected_freeze_refuses_scope_changes() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let app = w.new_key();
    apply_scope(&w, 1, &grant(&w, "game", &app)).unwrap();
    let game = scoped_id(&w, 1, "game");
    let (_, new_owner, target) = authorized_lost_key(&w);
    assert!(w.client().recovery_gate().is_some());

    assert!(apply_scope(&w, 2, &grant(&w, "dice", &app)).is_err());
    assert!(remove_scope_as(&w, &w.owner, 1).is_err());
    assert!(!call_via(&w, &app, game), "scoped grants are frozen too");
    assert_eq!(
        check_auth_selecting(&w, game),
        Err(PerchAuthError::AccountFrozen.into())
    );

    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert!(apply_scope_as(&w, &new_owner, 2, &grant(&w, "dice", &app)).is_ok());
}

#[test]
fn under_loss_the_owner_changes_scopes_during_an_authorized_attempt() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    let app = w.new_key();
    apply_scope(&w, 1, &grant(&w, "game", &app)).unwrap();
    let (id, _, _) = authorized_lost_key(&w);

    // The admin document is blocked (spec D3), scopes are not: they are
    // neither the attempt's source nor its target.
    assert_eq!(
        err(w.apply(&doc, 0)),
        PerchAccountError::Recovery(RecoveryError::AttemptAuthorized)
    );
    apply_scope(&w, 2, &grant(&w, "dice", &app)).expect("a scope change");
    remove_scope_as(&w, &w.owner, 1).expect("a revocation");
    assert!(call_via(&w, &app, scoped_id(&w, 2, "dice")));
    assert_eq!(
        w.ctl().attempt(&w.account, &id).unwrap().state,
        AttemptState::Authorized
    );
}

#[test]
fn a_scope_change_never_restarts_a_lost_key_attempt() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);

    // Grant churn while the attempt collects evidence (T4 compares only
    // the admin document's hash).
    let app = w.new_key();
    w.guardian(0, id, Initiate);
    apply_scope(&w, 1, &grant(&w, "game", &app)).unwrap();
    remove_scope_as(&w, &w.owner, 1).unwrap();
    apply_scope(&w, 2, &grant(&w, "game", &app)).unwrap();
    w.guardian(1, id, Initiate);
    assert_eq!(
        w.ctl().attempt(&w.account, &id).unwrap().state,
        AttemptState::Authorized
    );
    w.advance(DELAY);
    w.complete(&target).expect("completion");
    assert!(w.activity_as(&new_owner));
}

// ---------------------------------------------------------------------------
// Tag lifetime
// ---------------------------------------------------------------------------

#[test]
fn a_scoped_authorization_extends_its_tag_like_oz_extends_its_rule() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    apply_scope(&w, 1, &grant(&w, "game", &app)).unwrap();
    let game = scoped_id(&w, 1, "game");
    let written = tag_ttl(&w, game);
    assert_eq!(
        written,
        w.env.as_contract(&w.account, || w.env.storage().max_ttl()),
        "extended to the maximum when written"
    );

    // Well above OZ's threshold: reading changes nothing.
    w.advance(1_000);
    assert!(call_via(&w, &app, game));
    assert_eq!(tag_ttl(&w, game), written - 1_000);

    // Below it: the authorization extends the tag to OZ's amount.
    w.advance(written - SMART_ACCOUNT_TTL_THRESHOLD);
    assert!(tag_ttl(&w, game) < SMART_ACCOUNT_TTL_THRESHOLD);
    assert!(call_via(&w, &app, game));
    assert_eq!(tag_ttl(&w, game), SMART_ACCOUNT_EXTEND_AMOUNT);
}

/// An archived tag is unavailable, never absent: the host restores it on
/// access (the test host emulates protocol 23's automatic restoration), so
/// an archived stale tag still refuses and an archived live one still
/// authorizes. Were it read as absent, a wiped rule would pass the gate as
/// an admin document's rule.
#[test]
fn an_archived_tag_is_restored_never_read_as_absent() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (thief, app) = (w.new_key(), w.new_key());
    apply_scope(&w, 1, &grant(&w, "drain", &thief)).unwrap();
    let drain = scoped_id(&w, 1, "drain");
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    apply_scope_as(&w, &new_owner, 2, &grant(&w, "game", &app)).unwrap();
    let game = scoped_id(&w, 2, "game");

    let max = w.env.as_contract(&w.account, || w.env.storage().max_ttl());
    w.env.ledger().with_mut(|l| l.sequence_number += max + 1);
    assert!(tag_archived(&w, drain) && tag_archived(&w, game));

    assert_eq!(check_auth_selecting(&w, drain), stale());
    assert!(!call_via(&w, &thief, drain));
    assert!(
        call_via(&w, &app, game),
        "a live scope authorizes once restored"
    );
}
