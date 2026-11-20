//! Grant documents under ENFORCING authorization (`docs/recovery/spec.md`
//! §7.6): `apply_grant`, `remove_grant`, and `gc_grant`, the guards that
//! keep a grant document away from the account itself and its recovery,
//! the grant generation gate in `__check_auth`, the wipe a recovery
//! completion makes, and the credential index that keeps a wiped grant's
//! credentials from being named again. See `support/mod.rs` for the world. Every grant is
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

/// A grant document: `signers` as delegated keys, and one rule per
/// `(name, contract, signer id)` scoped to that contract and signed by that
/// signer alone.
fn grant_doc(w: &World, signers: &[(&str, &Address)], rules: &[(&str, &Address, &str)]) -> Bytes {
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
fn target_grant(w: &World, name: &str, key: &Address) -> Bytes {
    grant_doc(w, &[("k", key)], &[(name, &w.target, "k")])
}

/// `apply_grant(grant, doc)` signed by `key` through the admin rule.
fn apply_grant_as(w: &World, key: &Address, grant: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
    let root = w.invocation(
        &w.account,
        "apply_grant",
        std::vec![w.sc(grant), w.sc(doc.clone())],
    );
    w.env.set_auths(&[w.entry_as(key, "admin", root)]);
    let out = w.client().try_apply_grant(&grant, doc);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

fn apply_grant(w: &World, grant: u32, doc: &Bytes) -> CallResult<BytesN<32>> {
    apply_grant_as(w, &w.owner, grant, doc)
}

fn remove_grant_as(w: &World, key: &Address, grant: u32) -> CallResult<()> {
    let root = w.invocation(&w.account, "remove_grant", std::vec![w.sc(grant)]);
    w.env.set_auths(&[w.entry_as(key, "admin", root)]);
    let out = w.client().try_remove_grant(&grant);
    w.env.set_auths(&[]);
    out.map(|r| r.unwrap())
}

/// The id of rule `name` in `grant`'s record.
fn grant_rule_id(w: &World, grant: u32, name: &str) -> u32 {
    let wanted = soroban_sdk::String::from_str(&w.env, name);
    w.client()
        .grant(&grant)
        .expect("the grant has a record")
        .rules
        .iter()
        .find(|r| r.name == wanted)
        .expect("the grant has the rule")
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
    check_auth_on(w, &w.target, rule)
}

/// [`check_auth_selecting`] for a call on `contract`.
fn check_auth_on(w: &World, contract: &Address, rule: u32) -> Result<(), soroban_sdk::Error> {
    let context = Context::Contract(ContractContext {
        contract: contract.clone(),
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
    Err(PerchAuthError::StaleGrant.into())
}

/// The storage key of rule `id`'s grant tag: the account's `grant_tags`
/// map, whose entries `contractstorage` keys `[GrantTags, id]`.
fn tag_key(w: &World, id: u32) -> Vec<Val> {
    vec![
        &w.env,
        Symbol::new(&w.env, "GrantTags").into_val(&w.env),
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
            ScVal::Symbol(ScSymbol("GrantTags".try_into().unwrap())),
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
// Applying, changing, and removing a grant
// ---------------------------------------------------------------------------

#[test]
fn a_grant_authorizes_its_contract_until_remove_grant_revokes_it() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    let doc = target_grant(&w, "game", &app);
    let hash = apply_grant(&w, 4, &doc).expect("owner apply_grant");
    assert_eq!(hash, w.compiler().compile_doc(&doc).doc_hash);

    let record = w.client().grant(&4).unwrap();
    assert_eq!((record.gen, record.doc_hash.clone()), (0, hash.clone()));
    assert_eq!(record.rules.len(), 1);
    // The account keeps the signer ids, not the text, and they give the
    // text back.
    assert_eq!(
        w.client().grant_signer_ids(&4),
        Some(vec![&w.env, soroban_sdk::String::from_str(&w.env, "k")])
    );
    let text = perch_testkit::rebuild::grant_text(&w.env, &w.account, 4).unwrap();
    assert_eq!(
        Bytes::from_slice(&w.env, text.as_bytes()),
        w.compiler().compile_doc(&doc).canonical
    );
    assert_eq!(w.client().grant_count(), 1);
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 4u32]);

    let id = grant_rule_id(&w, 4, "game");
    assert!(has_tag(&w, id));
    assert!(call_via(&w, &app, id), "the grant authorizes its contract");
    assert!(
        !call_via(&w, &w.new_key(), id),
        "and only for its own signer"
    );

    // Re-applying the same document changes nothing and keeps the id.
    apply_grant(&w, 4, &doc).unwrap();
    assert_eq!(w.client().grant(&4), Some(record));

    remove_grant_as(&w, &w.owner, 4).expect("owner remove_grant");
    assert!(!call_via(&w, &app, id), "revoked");
    assert!(!exists(&w, id) && !has_tag(&w, id));
    assert_eq!(w.client().grant(&4), None);
    assert_eq!(w.client().grant_signer_ids(&4), None);
    assert_eq!(w.client().grant_count(), 0);
    assert_eq!(
        err(remove_grant_as(&w, &w.owner, 4)),
        PerchAccountError::UnknownGrant
    );
}

#[test]
fn only_the_owner_changes_a_grant() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    let id = grant_rule_id(&w, 1, "game");

    // No authorization at all.
    let other = target_grant(&w, "game", &w.new_key());
    assert!(w.client().try_apply_grant(&1, &other).is_err());
    assert!(w.client().try_remove_grant(&1).is_err());

    // A grant's own key, through its own rule: the rule is scoped to
    // another contract, so OZ refuses a context on the account.
    for (fn_name, args) in [
        ("apply_grant", std::vec![w.sc(1u32), w.sc(other.clone())]),
        ("remove_grant", std::vec![w.sc(1u32)]),
    ] {
        let root = w.invocation(&w.account, fn_name, args);
        w.env
            .set_auths(&[w.delegated_entry(&w.account, &app, id, root)]);
        let refused = if fn_name == "apply_grant" {
            w.client().try_apply_grant(&1, &other).is_err()
        } else {
            w.client().try_remove_grant(&1).is_err()
        };
        w.env.set_auths(&[]);
        assert!(refused, "{fn_name} through a grant rule");
    }

    // A key that is no admin signer, through the admin rule.
    assert!(apply_grant_as(&w, &app, 1, &other).is_err());
    assert!(remove_grant_as(&w, &w.device, 1).is_err());
    assert!(call_via(&w, &app, id), "nothing changed");
}

/// Rule `k`'s name in [`dense_grant`]: `a`, ..., `z`, `ba`, ....
fn dense_name(k: u32) -> String {
    let letter = |n: u32| char::from(b'a' + n as u8);
    if k < 26 {
        letter(k).to_string()
    } else {
        format!("{}{}", letter(k / 26), letter(k % 26))
    }
}

/// The shortest spelling of a grant document of `rules` rules on the target,
/// each asking the one delegated key `key` (`a`): one-letter ids, rule names
/// [`dense_name`], and `all` principals, so that the most rules fit the byte
/// cap.
fn dense_grant(w: &World, key: &Address, rules: u32) -> Bytes {
    let rules: std::vec::Vec<String> = (0..rules)
        .map(|k| {
            format!(
                r#"{{"name":"{}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["a"]}}}}"#,
                dense_name(k),
                strkey(&w.target)
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"network":"{}","signers":[{{"id":"a","address":"{}"}}],"rules":[{}]}}"#,
        perch_testkit::FIXTURE_NETWORK,
        strkey(key),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// A grant document of `signers` delegated keys and `rules` rules, each
/// scoped to the target and letting any one of every signer call it.
fn wide_grant(w: &World, keys: &[Address], rules: u32) -> Bytes {
    let ids: std::vec::Vec<String> = (0..keys.len()).map(|i| format!(r#""k{i:02}""#)).collect();
    let signers: std::vec::Vec<String> = keys
        .iter()
        .enumerate()
        .map(|(i, a)| format!(r#"{{"id":"k{i:02}","address":"{}"}}"#, strkey(a)))
        .collect();
    let rules: std::vec::Vec<String> = (0..rules)
        .map(|k| {
            format!(
                r#"{{"name":"g{k:02}","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"threshold","m":1,"signers":[{}]}}}}"#,
                strkey(&w.target),
                ids.join(",")
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

/// A grant document at each grant count cap applies and authorizes through
/// its last rule: at the rule cap with one signer, and at the signer cap
/// (OZ's per-rule signer limit) with every rule naming every signer, as many
/// rules as the byte cap holds. One past the rule or the signer cap, within
/// the byte cap, is refused, though an account document's caps are smaller
/// (`docs/recovery/budgets.md`, "Grant-document caps").
#[test]
fn a_grant_document_at_the_grant_caps_applies() {
    use perch_doc_compiler::{
        DocCompilerError, MAX_GRANT_CANONICAL_BYTES, MAX_GRANT_RULES, MAX_GRANT_SIGNERS,
    };
    let w = world();
    w.enroll(&w.doc(None));
    let keys: std::vec::Vec<Address> = (0..=MAX_GRANT_SIGNERS).map(|_| w.new_key()).collect();
    let at_signers = &keys[..MAX_GRANT_SIGNERS as usize];
    let within_bytes = |doc: &Bytes| {
        let json = std::str::from_utf8(&doc.to_alloc_vec())
            .unwrap()
            .to_string();
        perch_ir::canonical_json(&perch_ir::from_json(&json).unwrap()).len()
            <= MAX_GRANT_CANONICAL_BYTES as usize
    };
    let fit = (1..=MAX_GRANT_RULES)
        .take_while(|&r| within_bytes(&wide_grant(&w, at_signers, r)))
        .last()
        .unwrap();

    let at_caps = [
        (
            3,
            &keys[..1],
            MAX_GRANT_RULES,
            dense_grant(&w, &keys[0], MAX_GRANT_RULES),
        ),
        (4, at_signers, fit, wide_grant(&w, at_signers, fit)),
    ];
    for (grant, signers, rules, doc) in at_caps {
        apply_grant(&w, grant, &doc).expect("at a grant cap");
        let record = w.client().grant(&grant).unwrap();
        assert_eq!(record.rules.len(), rules);
        assert!(record
            .rules
            .iter()
            .all(|r| r.signers.len() == signers.len() as u32));
        let last = if grant == 3 {
            dense_name(rules - 1)
        } else {
            format!("g{:02}", rules - 1)
        };
        let last = grant_rule_id(&w, grant, &last);
        assert!(call_via(&w, &signers[signers.len() - 1], last));
    }

    let before = (w.client().grant(&3), w.client().grant(&4));
    for past in [
        dense_grant(&w, &keys[0], MAX_GRANT_RULES + 1),
        wide_grant(&w, &keys, 1),
    ] {
        assert!(within_bytes(&past));
        assert_eq!(
            err(apply_grant(&w, 5, &past)),
            PerchAccountError::Compiler(DocCompilerError::DocTooLarge)
        );
    }
    assert_eq!(
        (w.client().grant(&3), w.client().grant(&4)),
        before,
        "nothing changed"
    );
    assert_eq!(w.client().grant(&5), None);
}

#[test]
fn changing_a_grant_reconciles_its_own_rules_only() {
    let w = world();
    w.enroll(&w.doc(None));
    let (a, b) = (w.new_key(), w.new_key());
    // Two grants with a rule of the same name for the same key.
    apply_grant(&w, 1, &target_grant(&w, "game", &a)).unwrap();
    apply_grant(&w, 2, &target_grant(&w, "game", &a)).unwrap();
    let (id1, id2) = (grant_rule_id(&w, 1, "game"), grant_rule_id(&w, 2, "game"));
    assert_ne!(id1, id2, "rule names are unique within one grant only");

    // Grant 1's key rotates in place under its id; grant 2 is untouched.
    apply_grant(&w, 1, &target_grant(&w, "game", &b)).unwrap();
    assert_eq!(grant_rule_id(&w, 1, "game"), id1, "edited in place");
    assert!(call_via(&w, &b, id1) && !call_via(&w, &a, id1));
    assert!(call_via(&w, &a, id2));

    // A renamed rule replaces the old one; its tag goes with it.
    apply_grant(&w, 1, &target_grant(&w, "dice", &b)).unwrap();
    let dice = grant_rule_id(&w, 1, "dice");
    assert!(!exists(&w, id1) && !has_tag(&w, id1));
    assert!(has_tag(&w, dice) && call_via(&w, &b, dice));

    // Removing grant 1 leaves grant 2's rule, which shares the signer.
    remove_grant_as(&w, &w.owner, 1).unwrap();
    assert!(call_via(&w, &a, id2));
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 2u32]);
}

#[test]
fn grants_and_the_account_document_share_signers_without_touching_each_other() {
    let w = world();
    w.enroll(&w.doc(None));
    let hash = w.client().applied_doc_hash();
    let revision = w.client().revision();
    let configuration = w.client().configuration();

    // A grant signed by keys the account document also names.
    let shared = grant_doc(
        &w,
        &[("o", &w.owner), ("d", &w.device)],
        &[("o", &w.target, "o"), ("d", &w.target, "d")],
    );
    apply_grant(&w, 9, &shared).unwrap();
    assert_eq!(w.client().applied_doc_hash(), hash);
    assert_eq!(w.client().revision(), revision, "a grant is no revision");
    assert_eq!(w.client().configuration(), configuration);
    assert_eq!(w.client().installed_rules(), configuration.rules);

    // The account document drops `device`: the grant's rules still name it,
    // and they are not in the account document's reconcile.
    let mut lean = w.doc(None);
    lean.signers.truncate(1);
    lean.rules.clear();
    w.enroll(&lean);
    assert!(call_via(&w, &w.device, grant_rule_id(&w, 9, "d")));
    assert!(call_via(&w, &w.owner, grant_rule_id(&w, 9, "o")));

    // Removing the grant leaves the admin rule, which shares `owner`.
    remove_grant_as(&w, &w.owner, 9).unwrap();
    assert!(
        w.apply(&w.doc(None), 0).is_ok(),
        "the admin rule still works"
    );
}

#[test]
fn the_index_lists_every_grant_through_removals() {
    let w = world();
    w.enroll(&w.doc(None));
    let key = w.new_key();
    for grant in [3u32, 7, 9, 11] {
        apply_grant(&w, grant, &target_grant(&w, "g", &key)).unwrap();
    }
    assert_eq!(w.client().grant_count(), 4);
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 3u32, 7, 9, 11]);
    assert_eq!(w.client().grants(&1, &2), vec![&w.env, 7u32, 9]);
    assert_eq!(w.client().grants(&3, &u32::MAX), vec![&w.env, 11u32]);
    assert_eq!(w.client().grants(&9, &2), Vec::<u32>::new(&w.env));

    // The last id moves into a freed position.
    remove_grant_as(&w, &w.owner, 3).unwrap();
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 11u32, 7, 9]);
    remove_grant_as(&w, &w.owner, 9).unwrap();
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 11u32, 7]);
    // Re-applying a known grant does not index it twice.
    apply_grant(&w, 7, &target_grant(&w, "h", &key)).unwrap();
    apply_grant(&w, 3, &target_grant(&w, "g", &key)).unwrap();
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 11u32, 7, 3]);
    for grant in [11u32, 7, 3] {
        remove_grant_as(&w, &w.owner, grant).unwrap();
    }
    assert_eq!(w.client().grant_count(), 0);
    assert_eq!(w.client().grants(&0, &10), Vec::<u32>::new(&w.env));
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

#[test]
fn a_grant_document_cannot_reach_the_account_or_its_recovery() {
    let w = world();
    let r = w.recovery("loss", Mode::Zk);
    w.enroll(&w.doc(Some(r.clone())));
    let k = w.new_key();
    let escalation = |doc: String| {
        let bytes = Bytes::from_slice(&w.env, doc.as_bytes());
        // Each compiles: only the account refuses it.
        assert!(w.compiler().try_compile_doc(&bytes).is_ok(), "{doc}");
        err(apply_grant(&w, 1, &bytes))
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
        PerchAccountError::GrantEscalation
    );
    // A contract rule naming the account itself: the same authority.
    assert_eq!(
        escalation(format!(
            r#"{head},"rules":[{}]}}"#,
            contract_rule(&w.account)
        )),
        PerchAccountError::GrantEscalation
    );
    // The applied recovery member's ZK adapter and pool (spec §15 rule 3).
    for zk in [&w.adapter, &w.pool] {
        assert_eq!(
            escalation(format!(r#"{head},"rules":[{}]}}"#, contract_rule(zk))),
            PerchAccountError::GrantEscalation
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
        PerchAccountError::GrantEscalation
    );
    // The recovery controller: a grant rule there could cast this
    // account's guardian approvals for other accounts, which only the
    // account document may hold (§2).
    assert_eq!(
        escalation(format!(
            r#"{head},"rules":[{}]}}"#,
            contract_rule(&w.controller)
        )),
        PerchAccountError::GrantEscalation
    );
    assert_eq!(w.client().grant_count(), 0, "nothing was applied");
}

#[test]
fn a_grant_applied_before_recovery_enrollment_never_authorizes_on_its_controller_adapter_or_pool() {
    let w = world();
    w.enroll(&w.doc(None));
    let k = w.new_key();
    apply_grant(
        &w,
        1,
        &grant_doc(&w, &[("k", &k)], &[("adapter", &w.adapter, "k")]),
    )
    .unwrap();
    apply_grant(
        &w,
        2,
        &grant_doc(&w, &[("k", &k)], &[("pool", &w.pool, "k")]),
    )
    .unwrap();
    apply_grant(
        &w,
        3,
        &grant_doc(&w, &[("k", &k)], &[("controller", &w.controller, "k")]),
    )
    .unwrap();
    let (adapter, pool, controller) = (
        grant_rule_id(&w, 1, "adapter"),
        grant_rule_id(&w, 2, "pool"),
        grant_rule_id(&w, 3, "controller"),
    );
    let escalation = || Err(PerchAuthError::GrantEscalation.into());
    // With no recovery member applied, the gate passes them on to OZ.
    assert_ne!(check_auth_on(&w, &w.adapter, adapter), escalation());
    assert_ne!(check_auth_on(&w, &w.pool, pool), escalation());
    assert_ne!(check_auth_on(&w, &w.controller, controller), escalation());

    w.apply(&w.doc(Some(w.recovery("loss", Mode::Zk))), 0)
        .expect("enroll ZK recovery over the live grants");
    assert_eq!(check_auth_on(&w, &w.adapter, adapter), escalation());
    assert_eq!(check_auth_on(&w, &w.pool, pool), escalation());
    assert_eq!(check_auth_on(&w, &w.controller, controller), escalation());
    assert!(!call_via(&w, &k, controller));
}

#[test]
fn a_grant_document_naming_a_revoked_credential_is_refused() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert!(w.client().is_revoked(&fingerprint(&w, &w.owner)));
    assert_eq!(
        err(apply_grant_as(
            &w,
            &new_owner,
            1,
            &target_grant(&w, "game", &w.owner)
        )),
        PerchAccountError::RevokedCredential
    );
}

// ---------------------------------------------------------------------------
// Recovery: the generation wipe, the freeze, the policy block
// ---------------------------------------------------------------------------

#[test]
fn a_completion_wipes_every_grant_and_anyone_collects_them() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (a, b) = (w.new_key(), w.new_key());
    apply_grant(&w, 1, &target_grant(&w, "game", &a)).unwrap();
    apply_grant(&w, 2, &target_grant(&w, "dice", &b)).unwrap();
    let (game, dice) = (grant_rule_id(&w, 1, "game"), grant_rule_id(&w, 2, "dice"));
    assert_eq!(
        err(w.client().try_gc_grant(&1)),
        PerchAccountError::GrantLive
    );

    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).expect("completion");
    assert_eq!(w.client().grant_generation(), 1);

    // Every grant stops authorizing, refused by the gate before OZ.
    assert!(!call_via(&w, &a, game) && !call_via(&w, &b, dice));
    assert_eq!(check_auth_selecting(&w, game), stale());
    assert_eq!(check_auth_selecting(&w, dice), stale());
    // The records stay, at their old generation, until collected. The
    // admin rules authorize as before.
    assert_eq!(w.client().grant(&1).unwrap().gen, 0);
    assert!(w.activity_as(&new_owner));

    // Anyone collects a wiped grant, with no authorization.
    w.client().gc_grant(&1);
    assert!(!exists(&w, game) && !has_tag(&w, game));
    assert_eq!(w.client().grant(&1), None);
    assert_eq!(w.client().grants(&0, &10), vec![&w.env, 2u32]);
    assert_eq!(
        err(w.client().try_gc_grant(&1)),
        PerchAccountError::UnknownGrant
    );

    // A key the wiped grant named is never granted again. The new owner
    // re-grants over the wiped grant to a fresh key without collecting it:
    // the same rule is edited in place under its id and tagged anew.
    assert_eq!(
        err(apply_grant_as(
            &w,
            &new_owner,
            2,
            &target_grant(&w, "dice", &b)
        )),
        PerchAccountError::WipedCredential
    );
    let c = w.new_key();
    apply_grant_as(&w, &new_owner, 2, &target_grant(&w, "dice", &c)).unwrap();
    assert_eq!(grant_rule_id(&w, 2, "dice"), dice);
    assert_eq!(w.client().grant(&2).unwrap().gen, 1);
    assert!(call_via(&w, &c, dice) && !call_via(&w, &b, dice));
    assert_eq!(
        err(w.client().try_gc_grant(&2)),
        PerchAccountError::GrantLive
    );
}

/// A wiped grant's rule is refused by rule-eval's generation check on its
/// stored rule (`StaleGrant`), after the account's own gate: one selected for
/// a call on a recovery controller adopted after its grant was applied is
/// refused as an escalation first.
#[test]
fn a_wiped_rule_is_refused_by_its_stored_generation_after_the_escalation_gate() {
    let w = world();
    w.enroll(&w.doc(None));
    let k = w.new_key();
    apply_grant(
        &w,
        1,
        &grant_doc(
            &w,
            &[("k", &k)],
            &[("game", &w.target, "k"), ("ctl", &w.controller, "k")],
        ),
    )
    .unwrap();
    let (game, ctl) = (grant_rule_id(&w, 1, "game"), grant_rule_id(&w, 1, "ctl"));
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (_, _, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert_eq!(check_auth_selecting(&w, game), stale());
    assert_eq!(
        check_auth_on(&w, &w.controller, ctl),
        Err(PerchAuthError::GrantEscalation.into())
    );
}

#[test]
fn a_compromise_completion_wipes_the_thiefs_grants() {
    let w = world();
    let baseline = w.doc(None);
    let mut r = w.recovery("protected", Mode::Guardian);
    r.baseline = Some(w.doc_hash(&baseline));
    w.enroll(&w.doc(Some(r)));

    // A thief with the owner key applies grants of its own; no condition is
    // needed for grants under Protected, as for any non-recovery change.
    let thief = w.new_key();
    for grant in 0..3u32 {
        apply_grant(
            &w,
            grant,
            &grant_doc(
                &w,
                &[("t", &thief)],
                &[("drain", &w.target, "t"), ("spend", &w.target, "t")],
            ),
        )
        .unwrap();
    }
    let drain = grant_rule_id(&w, 2, "drain");
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
    assert_eq!(w.client().grant_count(), 3, "wiped, awaiting collection");
    for grant in 0..3u32 {
        w.client().gc_grant(&grant);
    }
    assert_eq!(w.client().grant_count(), 0);
}

#[test]
fn the_protected_freeze_refuses_grant_changes() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("protected", Mode::Guardian))));
    let app = w.new_key();
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    let game = grant_rule_id(&w, 1, "game");
    let (_, new_owner, target) = authorized_lost_key(&w);
    assert!(w.client().recovery_gate().is_some());

    assert!(apply_grant(&w, 2, &target_grant(&w, "dice", &app)).is_err());
    assert!(remove_grant_as(&w, &w.owner, 1).is_err());
    assert!(!call_via(&w, &app, game), "grants are frozen too");
    assert_eq!(
        check_auth_selecting(&w, game),
        Err(PerchAuthError::AccountFrozen.into())
    );

    w.advance(DELAY);
    w.complete(&target).unwrap();
    let fresh = w.new_key();
    assert!(apply_grant_as(&w, &new_owner, 2, &target_grant(&w, "dice", &fresh)).is_ok());
}

#[test]
fn under_loss_the_owner_changes_grants_during_an_authorized_attempt() {
    let w = world();
    let doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    w.enroll(&doc);
    let app = w.new_key();
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    let (id, _, _) = authorized_lost_key(&w);

    // The account document is blocked (spec D3), grants are not: they are
    // neither the attempt's source nor its target.
    assert_eq!(
        err(w.apply(&doc, 0)),
        PerchAccountError::Recovery(RecoveryError::AttemptAuthorized)
    );
    apply_grant(&w, 2, &target_grant(&w, "dice", &app)).expect("a grant change");
    remove_grant_as(&w, &w.owner, 1).expect("a revocation");
    assert!(call_via(&w, &app, grant_rule_id(&w, 2, "dice")));
    assert_eq!(
        w.ctl().attempt(&w.account, &id).unwrap().state,
        AttemptState::Authorized
    );
}

#[test]
fn a_grant_change_never_restarts_a_lost_key_attempt() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let new_owner = w.new_key();
    let replacements = w.replacements(&new_owner, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);

    // Grant churn while the attempt collects evidence (T4 compares only
    // the account document's hash).
    let app = w.new_key();
    w.guardian(0, id, Initiate);
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    remove_grant_as(&w, &w.owner, 1).unwrap();
    apply_grant(&w, 2, &target_grant(&w, "game", &app)).unwrap();
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
// The credential index
// ---------------------------------------------------------------------------

/// The default document with `owner` as `key` and `device` as `device`.
fn admin_doc(w: &World, key: &Address, device: &Address) -> Doc {
    let mut doc = w.doc(Some(w.recovery("loss", Mode::Guardian)));
    doc.signers = std::vec![("owner", key.clone()), ("device", device.clone())];
    doc
}

#[test]
fn a_credential_stays_grantable_until_a_completion() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let app = w.new_key();
    assert_eq!(
        w.client().credential_generation(&fingerprint(&w, &app)),
        None
    );
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    assert_eq!(
        w.client().credential_generation(&fingerprint(&w, &app)),
        Some(0)
    );
    // Removed and named again, by a grant and by the account document,
    // within one grant generation.
    remove_grant_as(&w, &w.owner, 1).unwrap();
    apply_grant(&w, 2, &target_grant(&w, "game", &app)).unwrap();
    w.apply(&admin_doc(&w, &w.owner, &app), 0)
        .expect("the account document names a live grant's credential");
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    assert!(call_via(&w, &app, grant_rule_id(&w, 2, "game")));
}

#[test]
fn a_credential_a_wiped_grant_named_is_never_named_again() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let app = w.new_key();
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    remove_grant_as(&w, &w.owner, 1).unwrap();
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    assert_eq!(w.client().grant_generation(), 1);

    // Removed before the completion still counts: the index outlives the
    // grant. Refused by every grant id and by the account document.
    for grant in [1u32, 2] {
        assert_eq!(
            err(apply_grant_as(
                &w,
                &new_owner,
                grant,
                &target_grant(&w, "game", &app)
            )),
            PerchAccountError::WipedCredential
        );
    }
    assert_eq!(
        err(w.apply_as(&new_owner, &admin_doc(&w, &new_owner, &app).bytes(&w), 0)),
        PerchAccountError::WipedCredential
    );
    assert_eq!(w.client().grant_count(), 0, "nothing was applied");

    // A fresh credential is granted, and recorded under the new generation.
    let fresh = w.new_key();
    apply_grant_as(&w, &new_owner, 2, &target_grant(&w, "game", &fresh)).unwrap();
    assert_eq!(
        w.client().credential_generation(&fingerprint(&w, &fresh)),
        Some(1)
    );
    assert!(call_via(&w, &fresh, grant_rule_id(&w, 2, "game")));
}

/// A credential the account document and a wiped grant both name: the
/// completion that wipes the grant keeps it in its target, and so does a
/// later recovery's target. Neither completion is refused, though no
/// document the owner chooses may name it again.
#[test]
fn a_recovery_completes_over_a_credential_a_wiped_grant_named() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    apply_grant(&w, 1, &target_grant(&w, "game", &w.device)).unwrap();
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target)
        .expect("the first completion keeps device");
    assert_eq!(
        err(w.apply_as(
            &new_owner,
            &admin_doc(&w, &new_owner, &w.device).bytes(&w),
            0
        )),
        PerchAccountError::WipedCredential
    );

    // Lost again: the second target still names device.
    w.advance(EXPIRY);
    let newer = w.new_key();
    let replacements = w.replacements(&newer, None);
    let source = w.client().applied_doc().unwrap();
    let id = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(RecoveryAction::LostKey, &source, &replacements);
    w.guardian(0, id, Initiate);
    w.guardian(1, id, Initiate);
    w.advance(DELAY);
    w.complete(&target)
        .expect("the second completion keeps device too");
    assert_eq!(w.client().grant_generation(), 2);
    assert!(w.activity_as(&newer));

    // The owner rotates device out to apply any other document.
    let rotated = w.new_key();
    w.apply_as(&newer, &admin_doc(&w, &newer, &rotated).bytes(&w), 0)
        .expect("a document without device");
}

// ---------------------------------------------------------------------------
// Tag lifetime
// ---------------------------------------------------------------------------

#[test]
fn a_grant_authorization_extends_its_tag_like_oz_extends_its_rule() {
    let w = world();
    w.enroll(&w.doc(None));
    let app = w.new_key();
    apply_grant(&w, 1, &target_grant(&w, "game", &app)).unwrap();
    let game = grant_rule_id(&w, 1, "game");
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
/// an account document's rule.
#[test]
fn an_archived_tag_is_restored_never_read_as_absent() {
    let w = world();
    w.enroll(&w.doc(Some(w.recovery("loss", Mode::Guardian))));
    let (thief, app) = (w.new_key(), w.new_key());
    apply_grant(&w, 1, &target_grant(&w, "drain", &thief)).unwrap();
    let drain = grant_rule_id(&w, 1, "drain");
    let (_, new_owner, target) = authorized_lost_key(&w);
    w.advance(DELAY);
    w.complete(&target).unwrap();
    apply_grant_as(&w, &new_owner, 2, &target_grant(&w, "game", &app)).unwrap();
    let game = grant_rule_id(&w, 2, "game");

    let max = w.env.as_contract(&w.account, || w.env.storage().max_ttl());
    w.env.ledger().with_mut(|l| l.sequence_number += max + 1);
    assert!(tag_archived(&w, drain) && tag_archived(&w, game));

    assert_eq!(check_auth_selecting(&w, drain), stale());
    assert!(!call_via(&w, &thief, drain));
    assert!(
        call_via(&w, &app, game),
        "a live grant authorizes once restored"
    );
}
