//! Exact-root rules under Soroban 29.0.1 enforcing auth and real Ed25519
//! signatures. No mock auth: even setup uses host authorization entries.
//!
//! Game::guess preserves the relevant behavior of guess-the-number commit
//! df80831ac6bc2a2110cab15654726456b53cc8f3 (guesser.require_auth BEFORE both
//! branches, win paid by the game/invoker, loss paid by the guesser). The
//! fixture fixes the secret at 7 and injects a local SAC, avoiding randomness
//! and network transactions. Other entrypoints are adversarial fixtures.

mod support;

use ed25519_dalek::{Signer as _, SigningKey};
use perch_account_types::{AuthPayload, Signer};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_testkit::{auth_digest, delta::raw_entries, FIXTURE_NETWORK};
use serde_json::{json, Value};
use soroban_sdk::xdr::{
    ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedInvocation,
    SorobanCredentials,
};
use soroban_sdk::{
    contract, contractimpl, symbol_short, token, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol,
    Vec,
};
use std::cell::Cell;
use support::{strkey, world_with, Opts, World};

const UNIT: i128 = 10_000_000;
const SCOPE: u32 = 17;

#[contract]
struct Game;
#[contractimpl]
impl Game {
    pub fn __constructor(e: &Env, token: Address) {
        e.storage().instance().set(&symbol_short!("token"), &token);
    }
    pub fn guess(e: &Env, a_number: u64, guesser: Address) -> bool {
        guesser.require_auth();
        let token: Address = e.storage().instance().get(&symbol_short!("token")).unwrap();
        let t = token::Client::new(e, &token);
        let me = e.current_contract_address();
        if a_number == 7 {
            t.transfer(&me, &guesser, &t.balance(&me));
            true
        } else {
            t.transfer(&guesser, &me, &UNIT);
            false
        }
    }
    pub fn other(e: &Env, a_number: u64, guesser: Address) -> bool {
        Self::guess(e, a_number, guesser)
    }
    pub fn no_auth(e: &Env, a_number: u64, guesser: Address) -> bool {
        let _ = a_number;
        let token: Address = e.storage().instance().get(&symbol_short!("token")).unwrap();
        token::Client::new(e, &token).transfer(&guesser, e.current_contract_address(), &UNIT);
        false
    }
    pub fn many(e: &Env, guesser: Address, count: u32, fail: bool) {
        guesser.require_auth();
        let token: Address = e.storage().instance().get(&symbol_short!("token")).unwrap();
        for _ in 0..count {
            token::Client::new(e, &token).transfer(&guesser, e.current_contract_address(), &UNIT);
        }
        assert!(!fail, "later invocation failure");
    }
}

#[contract]
struct Router;
#[contractimpl]
impl Router {
    pub fn guesses(e: &Env, game: Address, account: Address, count: u32) {
        for _ in 0..count {
            GameClient::new(e, &game).guess(&0, &account);
        }
    }
    pub fn split(e: &Env, game: Address, token: Address, account: Address) {
        GameClient::new(e, &game).guess(&7, &account);
        token::Client::new(e, &token).transfer(&account, &game, &UNIT);
    }
}

struct Lab {
    w: World,
    game: Address,
    other: Address,
    router: Address,
    token: Address,
    key: SigningKey,
    doc: Value,
    nonce: Cell<i64>,
}
impl Lab {
    fn new(root_fn: &str, cap: i128) -> Self {
        let w = world_with(Opts {
            skip_snapshot: true,
            ..Opts::default()
        });
        let e = &w.env;
        let token = e
            .register_stellar_asset_contract_v2(w.owner.clone())
            .address();
        let game = e.register(Game, (&token,));
        let other = e.register(Game, (&token,));
        let router = e.register(Router, ());
        let verifier = e.register(PerchEd25519Verifier, ());
        let key = SigningKey::from_bytes(&[45; 32]);
        let doc = json!({"version":1,"network":FIXTURE_NETWORK,
        "signers":[{"id":"session","verifier":strkey(&verifier),"key":hex::encode(key.verifying_key().as_bytes())}],
        "rules":[
            {"name":"game","scope":{"type":"contract","address":strkey(&game)},"principals":{"type":"all","signers":["session"]}},
            {"name":"other","scope":{"type":"contract","address":strkey(&other)},"principals":{"type":"all","signers":["session"]}},
            {"name":"transfer","scope":{"type":"contract","address":strkey(&token)},"principals":{"type":"all","signers":["session"]},
             "functions":["transfer"],"args":[{"index":0,"pred":{"type":"is-self"}}],
             "auth-root":{"contract":strkey(&game),"function":root_fn},"cap":{"limit":cap.to_string(),"period-ledgers":100},
             "not-after-ledger":w.ledger()+50}
        ]});
        let lab = Self {
            w,
            game,
            other,
            router,
            token,
            key,
            doc,
            nonce: Cell::new(5_000_000),
        };
        lab.apply(&lab.doc);
        lab.mint(&lab.w.account, 10 * UNIT);
        lab.mint(&lab.game, 3 * UNIT);
        lab
    }
    fn nonce(&self) -> i64 {
        let n = self.nonce.get();
        self.nonce.set(n + 1);
        n
    }
    fn apply(&self, doc: &Value) {
        let bytes = Bytes::from_slice(&self.w.env, doc.to_string().as_bytes());
        let root = self.w.invocation(
            &self.w.account,
            "apply_scope",
            vec![self.w.sc(SCOPE), self.w.sc(bytes.clone())],
        );
        self.w.env.set_auths(&[self.w.owner_entry("admin", root)]);
        self.w.client().apply_scope(&SCOPE, &bytes);
        self.w.env.set_auths(&[]);
    }
    fn mint(&self, to: &Address, amount: i128) {
        let root = self.w.invocation(
            &self.token,
            "mint",
            vec![self.w.sc(to.clone()), self.w.sc(amount)],
        );
        self.w.env.set_auths(&[SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: self.w.owner.clone().into(),
                nonce: self.nonce(),
                signature_expiration_ledger: self.w.ledger() + 1000,
                signature: ScVal::Void,
            }),
            root_invocation: root,
        }]);
        token::StellarAssetClient::new(&self.w.env, &self.token).mint(to, &amount);
        self.w.env.set_auths(&[]);
    }
    fn id(&self, name: &str) -> u32 {
        self.w
            .client()
            .scope(&SCOPE)
            .unwrap()
            .rules
            .iter()
            .find(|r| r.name == soroban_sdk::String::from_str(&self.w.env, name))
            .unwrap()
            .id
    }
    fn transfer(&self) -> SorobanAuthorizedInvocation {
        self.transfer_to(&self.game)
    }
    fn transfer_to(&self, to: &Address) -> SorobanAuthorizedInvocation {
        self.w.invocation(
            &self.token,
            "transfer",
            vec![
                self.w.sc(self.w.account.clone()),
                self.w.sc(to.clone()),
                self.w.sc(UNIT),
            ],
        )
    }
    fn guess(&self, game: &Address, method: &str, number: u64) -> SorobanAuthorizedInvocation {
        let mut root = self.w.invocation(
            game,
            method,
            vec![self.w.sc(number), self.w.sc(self.w.account.clone())],
        );
        if number != 7 {
            root.sub_invocations = vec![self.transfer_to(game)].try_into().unwrap();
        }
        root
    }
    fn entry(&self, root: SorobanAuthorizedInvocation, ids: &[u32]) -> SorobanAuthorizationEntry {
        self.signed(root, ids, &self.key)
    }
    fn signed(
        &self,
        root: SorobanAuthorizedInvocation,
        ids: &[u32],
        key: &SigningKey,
    ) -> SorobanAuthorizationEntry {
        let e = &self.w.env;
        let nonce = self.nonce();
        let expiry = self.w.ledger() + 1000;
        let payload = perch_testkit::passkey::signature_payload(e, nonce, expiry, &root);
        let ids = Vec::from_iter(e, ids.iter().copied());
        let digest = auth_digest(e, &self.w.account, &BytesN::from_array(e, &payload), &ids);
        let decl = &self.doc["signers"][0];
        let signer = Signer::External(
            Address::from_str(e, decl["verifier"].as_str().unwrap()),
            Bytes::from_slice(e, self.key.verifying_key().as_bytes()),
        );
        let mut signers = Map::new(e);
        signers.set(signer, Bytes::from_slice(e, &key.sign(&digest).to_bytes()));
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: self.w.account.clone().into(),
                nonce,
                signature_expiration_ledger: expiry,
                signature: self.w.sc(AuthPayload {
                    signers,
                    context_rule_ids: ids,
                }),
            }),
            root_invocation: root,
        }
    }
    fn spent(&self) -> i128 {
        let id = self.id("transfer");
        self.w.env.as_contract(&self.w.account, || {
            perch_smart_account::testutils::spend_record(&self.w.env, id).map_or(0, |r| r.total)
        })
    }
    fn balance(&self) -> i128 {
        token::Client::new(&self.w.env, &self.token).balance(&self.w.account)
    }
    fn call(
        &self,
        target: &Address,
        method: &str,
        number: u64,
        entries: &[SorobanAuthorizationEntry],
    ) -> bool {
        self.w.env.set_auths(entries);
        let result = self.w.env.try_invoke_contract::<bool, soroban_sdk::Error>(
            target,
            &Symbol::new(&self.w.env, method),
            soroban_sdk::vec![
                &self.w.env,
                number.into_val(&self.w.env),
                self.w.account.clone().into_val(&self.w.env)
            ],
        );
        self.w.env.set_auths(&[]);
        result.is_ok()
    }
}

#[test]
fn signed_game_loss_and_win_and_document_round_trip() {
    let l = Lab::new("guess", 2 * UNIT);
    let stored = l.w.client().scope_rule_set(&SCOPE);
    assert!(stored.get_unchecked(2).auth_root.is_some());
    let rebuilt = perch_testkit::rebuild::scope_text(&l.w.env, &l.w.account, SCOPE).unwrap();
    let parsed = perch_ir::from_json(&l.doc.to_string()).unwrap();
    assert_eq!(rebuilt, perch_ir::canonical_json(&parsed));
    assert_eq!(l.w.client().capabilities().snapshot_version, 2);
    perch_testkit::rule_set::check_scope(&l.w.env, &l.w.account, SCOPE).unwrap();
    let entry = l.entry(
        l.guess(&l.game, "guess", 0),
        &[l.id("game"), l.id("transfer")],
    );
    assert!(l.call(&l.game, "guess", 0, &[entry]));
    assert_eq!(l.spent(), UNIT);
    assert_eq!(l.balance(), 9 * UNIT);
    let entry = l.entry(l.guess(&l.game, "guess", 7), &[l.id("game")]);
    assert!(l.call(&l.game, "guess", 7, &[entry]));
    assert_eq!(l.spent(), UNIT);
    assert_eq!(l.balance(), 13 * UNIT);
}

#[test]
fn direct_under_cap_and_fabricated_game_root_are_refused() {
    for fabricated in [false, true] {
        let l = Lab::new("guess", 2 * UNIT);
        let root = if fabricated {
            l.guess(&l.game, "guess", 0)
        } else {
            l.transfer()
        };
        let ids = if fabricated {
            vec![l.id("game"), l.id("transfer")]
        } else {
            vec![l.id("transfer")]
        };
        l.w.env.set_auths(&[l.entry(root, &ids)]);
        let before = raw_entries(&l.w.env);
        assert!(token::Client::new(&l.w.env, &l.token)
            .try_transfer(&l.w.account, &l.game, &UNIT)
            .is_err());
        assert_eq!(raw_entries(&l.w.env), before);
        assert_eq!(l.spent(), 0);
    }
}

#[test]
fn wrong_root_function_contract_omitted_root_auth_and_reordered_tree_are_refused() {
    for case in 0..4 {
        let l = Lab::new("guess", 2 * UNIT);
        let (target, method) = match case {
            0 => (&l.game, "other"),
            1 => (&l.other, "guess"),
            2 => (&l.game, "no_auth"),
            _ => (&l.game, "guess"),
        };
        let mut root = l.guess(target, method, 0);
        let ids = if case == 1 {
            vec![l.id("other"), l.id("transfer")]
        } else if case == 2 {
            root = l.transfer();
            vec![l.id("transfer")]
        } else {
            vec![l.id("game"), l.id("transfer")]
        };
        if case == 3 {
            let mut reordered = l.transfer();
            root.sub_invocations = Default::default();
            reordered.sub_invocations = vec![root].try_into().unwrap();
            root = reordered;
        }
        let entry = l.entry(root, &ids);
        let before = raw_entries(&l.w.env);
        assert!(!l.call(target, method, 0, &[entry]), "case {case}");
        assert_eq!(raw_entries(&l.w.env), before);
    }
}

#[test]
fn missing_and_wrong_signatures_refuse_both_game_branches() {
    for number in [0, 7] {
        for missing in [true, false] {
            let l = Lab::new("guess", 2 * UNIT);
            let ids = if number == 7 {
                vec![l.id("game")]
            } else {
                vec![l.id("game"), l.id("transfer")]
            };
            let entries = if missing {
                vec![]
            } else {
                vec![l.signed(
                    l.guess(&l.game, "guess", number),
                    &ids,
                    &SigningKey::from_bytes(&[99; 32]),
                )]
            };
            let before = raw_entries(&l.w.env);
            assert!(!l.call(&l.game, "guess", number, &entries));
            assert_eq!(raw_entries(&l.w.env), before);
        }
    }
}

#[test]
fn auth_free_router_keeps_entry_roots_and_caps_aggregate_across_entries() {
    for count in [1, 2, 3] {
        let l = Lab::new("guess", 2 * UNIT);
        let entries: std::vec::Vec<_> = (0..count)
            .map(|_| {
                l.entry(
                    l.guess(&l.game, "guess", 0),
                    &[l.id("game"), l.id("transfer")],
                )
            })
            .collect();
        l.w.env.set_auths(&entries);
        let before = raw_entries(&l.w.env);
        let result =
            RouterClient::new(&l.w.env, &l.router).try_guesses(&l.game, &l.w.account, &count);
        if count <= 2 {
            assert!(result.is_ok());
            assert_eq!(l.spent(), i128::from(count) * UNIT);
        } else {
            assert!(result.is_err());
            assert_eq!(raw_entries(&l.w.env), before);
        }
    }
}

#[test]
fn root_in_a_different_entry_cannot_authorize_a_transfer() {
    let l = Lab::new("guess", 2 * UNIT);
    l.w.env.set_auths(&[
        l.entry(l.guess(&l.game, "guess", 7), &[l.id("game")]),
        l.entry(l.transfer(), &[l.id("transfer")]),
    ]);
    let before = raw_entries(&l.w.env);
    assert!(RouterClient::new(&l.w.env, &l.router)
        .try_split(&l.game, &l.token, &l.w.account)
        .is_err());
    assert_eq!(raw_entries(&l.w.env), before);
}

#[test]
fn sibling_charges_and_later_failure_are_atomic() {
    for (cap, count, fail, accept) in [
        (2, 2, false, true),
        (1, 2, false, false),
        (2, 1, true, false),
    ] {
        let l = Lab::new("many", cap * UNIT);
        let mut root = l.w.invocation(
            &l.game,
            "many",
            vec![l.w.sc(l.w.account.clone()), l.w.sc(count), l.w.sc(fail)],
        );
        root.sub_invocations = (0..count)
            .map(|_| l.transfer())
            .collect::<std::vec::Vec<_>>()
            .try_into()
            .unwrap();
        let mut ids = vec![l.id("game")];
        ids.extend((0..count).map(|_| l.id("transfer")));
        l.w.env.set_auths(&[l.entry(root, &ids)]);
        let before = raw_entries(&l.w.env);
        let result = GameClient::new(&l.w.env, &l.game).try_many(&l.w.account, &count, &fail);
        assert_eq!(result.is_ok(), accept);
        if accept {
            assert_eq!(l.spent(), i128::from(count) * UNIT);
        } else {
            assert_eq!(raw_entries(&l.w.env), before);
        }
    }
}

#[test]
fn expiry_and_stale_generation_still_refuse_root_matching_batches() {
    for stale in [false, true] {
        let l = Lab::new("guess", 2 * UNIT);
        if stale {
            let generation = l.w.client().scope(&SCOPE).unwrap().gen + 1;
            l.w.env.as_contract(&l.w.account, || {
                perch_smart_account::testutils::set_scope_generation(&l.w.env, generation)
            });
        } else {
            l.w.advance(51);
        }
        let entry = l.entry(
            l.guess(&l.game, "guess", 0),
            &[l.id("game"), l.id("transfer")],
        );
        let before = raw_entries(&l.w.env);
        assert!(!l.call(&l.game, "guess", 0, &[entry]));
        assert_eq!(raw_entries(&l.w.env), before);
    }
}

#[test]
fn dropping_the_companion_rule_never_erases_the_transfer_root_or_cap_history() {
    let l = Lab::new("guess", 2 * UNIT);
    let id = l.id("transfer");
    let entry = l.entry(l.guess(&l.game, "guess", 0), &[l.id("game"), id]);
    assert!(l.call(&l.game, "guess", 0, &[entry]));
    let mut doc = l.doc.clone();
    doc["rules"] = json!([doc["rules"][2].clone()]);
    l.apply(&doc);
    assert_eq!(l.id("transfer"), id);
    assert_eq!(l.spent(), UNIT);
    assert!(l
        .w
        .client()
        .scope_rule_set(&SCOPE)
        .get_unchecked(0)
        .auth_root
        .is_some());
    l.w.env.set_auths(&[l.entry(l.transfer(), &[id])]);
    let before = raw_entries(&l.w.env);
    assert!(token::Client::new(&l.w.env, &l.token)
        .try_transfer(&l.w.account, &l.game, &UNIT)
        .is_err());
    assert_eq!(raw_entries(&l.w.env), before);
}

#[test]
fn legacy_compiler_and_attenuation_refuse_root_documents_instead_of_dropping_them() {
    let l = Lab::new("guess", 2 * UNIT);
    let child = perch_ir::from_json(&l.doc.to_string()).unwrap();
    let mut parent = child.clone();
    parent.rules[2].auth_root = None;
    let cfg = perch_compile::CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(&l.w.env, &[0; 32]),
    };
    assert!(matches!(
        perch_compile::compile(&l.w.env, &child, &cfg),
        Err(perch_compile::LowerError::Unsupported { .. })
    ));
    assert!(perch_compile::attenuate(&l.w.env, &parent, &child, &cfg).is_err());
    assert!(perch_compile::attenuate(&l.w.env, &child, &parent, &cfg).is_err());
}

#[test]
fn recovery_freeze_and_completion_still_gate_exact_root_grants() {
    let l = Lab::new("guess", 2 * UNIT);
    let w = &l.w;
    w.enroll(&w.doc(Some(w.recovery("protected", support::Mode::Guardian))));
    let source = w.client().applied_doc().unwrap();
    let replacements = w.replacements(&w.new_key(), None);
    let attempt = w.ctl().begin_lost_key(&w.account, &replacements);
    let target = w.target_bytes(
        perch_recovery_interface::RecoveryAction::LostKey,
        &source,
        &replacements,
    );
    // Collecting has no freeze, and the root-matching transfer still works.
    let entry = l.entry(
        l.guess(&l.game, "guess", 0),
        &[l.id("game"), l.id("transfer")],
    );
    assert!(l.call(&l.game, "guess", 0, &[entry]));
    for guardian in [0, 1] {
        w.guardian(guardian, attempt, perch_recovery::EvidenceDomain::Initiate);
    }
    assert!(w.client().recovery_gate().is_some());
    for number in [0, 7] {
        let ids = if number == 7 {
            vec![l.id("game")]
        } else {
            vec![l.id("game"), l.id("transfer")]
        };
        let entry = l.entry(l.guess(&l.game, "guess", number), &ids);
        let before = raw_entries(&w.env);
        assert!(!l.call(&l.game, "guess", number, &[entry]));
        assert_eq!(raw_entries(&w.env), before);
    }
    let old_ids = [l.id("game"), l.id("transfer")];
    w.advance(support::DELAY);
    w.complete(&target)
        .expect("generated recovery rule remains eligible");
    assert_eq!(w.client().scope_generation(), 1);
    let entry = l.entry(l.guess(&l.game, "guess", 0), &old_ids);
    let before = raw_entries(&w.env);
    assert!(!l.call(&l.game, "guess", 0, &[entry]));
    assert_eq!(raw_entries(&w.env), before);
}

#[test]
fn changing_a_root_keeps_cap_history_and_enforces_the_new_pair() {
    let l = Lab::new("guess", 2 * UNIT);
    let id = l.id("transfer");
    let entry = l.entry(l.guess(&l.game, "guess", 0), &[l.id("game"), id]);
    assert!(l.call(&l.game, "guess", 0, &[entry]));
    let mut doc = l.doc.clone();
    doc["rules"][2]["auth-root"]["function"] = json!("other");
    l.apply(&doc);
    assert_eq!(l.id("transfer"), id);
    assert_eq!(l.spent(), UNIT);
    perch_testkit::rule_set::check_scope(&l.w.env, &l.w.account, SCOPE).unwrap();
    let entry = l.entry(l.guess(&l.game, "guess", 0), &[l.id("game"), id]);
    assert!(!l.call(&l.game, "guess", 0, &[entry]));
    let entry = l.entry(l.guess(&l.game, "other", 0), &[l.id("game"), id]);
    assert!(l.call(&l.game, "other", 0, &[entry]));
    assert_eq!(l.spent(), 2 * UNIT);
    // Reordering then renaming the surviving rule preserves its condition.
    doc["rules"].as_array_mut().unwrap().reverse();
    doc["rules"][0]["name"] = json!("renamed-transfer");
    l.apply(&doc);
    let rebuilt = perch_testkit::rebuild::scope_text(&l.w.env, &l.w.account, SCOPE).unwrap();
    assert_eq!(
        rebuilt,
        perch_ir::canonical_json(&perch_ir::from_json(&doc.to_string()).unwrap())
    );
    let renamed = l.id("renamed-transfer");
    l.w.env.set_auths(&[l.entry(l.transfer(), &[renamed])]);
    assert!(token::Client::new(&l.w.env, &l.token)
        .try_transfer(&l.w.account, &l.game, &UNIT)
        .is_err());
}

#[test]
fn account_gate_reads_legacy_and_malformed_stored_roots_without_lenient_conversion() {
    use soroban_sdk::{TryFromVal, Val};
    for case in 0..4 {
        let l = Lab::new("guess", 2 * UNIT);
        let id = l.id("transfer");
        l.w.env.as_contract(&l.w.account, || {
            let e = &l.w.env;
            let key: Vec<Val> =
                soroban_sdk::vec![e, Symbol::new(e, "Scopes").into_val(e), SCOPE.into_val(e)];
            let mut scope: Map<Symbol, Val> = e.storage().persistent().get(&key).unwrap();
            let mut records = Vec::<Map<Symbol, Val>>::try_from_val(
                e,
                &scope.get(symbol_short!("rules")).unwrap(),
            )
            .unwrap();
            let mut record = records.get_unchecked(2);
            let mut rule =
                Map::<Symbol, Val>::try_from_val(e, &record.get(symbol_short!("rule")).unwrap())
                    .unwrap();
            match case {
                0 => {
                    rule.remove(Symbol::new(e, "auth_root"));
                } // exact legacy layout
                1 => {
                    rule.set(Symbol::new(e, "auth_root"), Vec::<Val>::new(e).into_val(e));
                }
                2 => {
                    let root = rule.get(Symbol::new(e, "auth_root")).unwrap();
                    rule.remove(Symbol::new(e, "auth_root"));
                    rule.set(Symbol::new(e, "auth_rooot"), root);
                }
                _ => {
                    rule.remove(Symbol::new(e, "threshold"));
                }
            }
            record.set(symbol_short!("rule"), rule.into_val(e));
            records.set(2, record);
            scope.set(symbol_short!("rules"), records.into_val(e));
            e.storage().persistent().set(&key, &scope);
        });
        l.w.env.set_auths(&[l.entry(l.transfer(), &[id])]);
        let before = raw_entries(&l.w.env);
        let accepted = token::Client::new(&l.w.env, &l.token)
            .try_transfer(&l.w.account, &l.game, &UNIT)
            .is_ok();
        assert_eq!(accepted, case == 0, "storage case {case}");
        if !accepted {
            assert_eq!(raw_entries(&l.w.env), before);
        }
    }
}
