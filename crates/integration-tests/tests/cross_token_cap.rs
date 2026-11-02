//! Real compiler/apply and exported account __check_auth, including the
//! spending-limit policy. Auth mocks are used only for installation; each
//! authorization below explicitly enters the host's check-auth frame.
use ed25519_dalek::{Signer as _, SigningKey};
use perch_doc_compiler::{DocCompilerError, RuleScope, MAX_DOC_RULES};
use perch_smart_account::infra;
use perch_testkit::{auth_digest, Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{map, vec, Address, Bytes, BytesN, IntoVal, Map, Symbol, Val, Vec};
use stellar_accounts::smart_account::{AuthPayload, Signer, SmartAccountError};

const GAME: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
const TOKEN: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
const TREASURY: &str = "GCY63ZN3C232UXXWENGF5I3PUHSYLR45MKCXS53MI3NSCWBFERWKHEPH";

fn setup() -> World {
    let w = Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9; 32])
        .build();
    w.env.ledger().with_mut(|l| l.sequence_number = 500);
    w
}

fn document(w: &World, recipient: Option<serde_json::Value>) -> serde_json::Value {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut cap = serde_json::json!({"token":TOKEN,"limit":"2","period-ledgers":1000});
    if let Some(recipient) = recipient {
        cap["recipient"] = recipient;
    }
    serde_json::json!({
        "version":1,"network":FIXTURE_NETWORK,
        "signers":[{"id":"owner","verifier":w.verifier.to_string().to_string(),"key":hex::encode(key.verifying_key().to_bytes())}],
        "rules":[
            {"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}},
            {"name":"game","scope":{"type":"contract","address":GAME},"principals":{"type":"all","signers":["owner"]},
             "functions":["guess"],"args":[{"index":0,"pred":{"type":"is-self"}}],"not-after-ledger":5000,"cap":cap}
        ]
    })
}

fn bytes(w: &World, d: &serde_json::Value) -> Bytes {
    Bytes::from_slice(&w.env, d.to_string().as_bytes())
}

fn apply(w: &World, d: &serde_json::Value) {
    w.account_client().apply_doc(&bytes(w, d), &0, &None);
}

fn ids(w: &World) -> Vec<u32> {
    let rules = w.account_client().configuration().rules;
    Vec::from_iter(
        &w.env,
        rules
            .iter()
            .filter(|r| r.name.to_string() == "game")
            .map(|r| r.id),
    )
}

fn contexts(w: &World, to: Val, amount: i128) -> Vec<Context> {
    vec![
        &w.env,
        Context::Contract(ContractContext {
            contract: Address::from_str(&w.env, GAME),
            fn_name: Symbol::new(&w.env, "guess"),
            args: vec![&w.env, w.account.clone().into_val(&w.env)],
        }),
        Context::Contract(ContractContext {
            contract: Address::from_str(&w.env, TOKEN),
            fn_name: Symbol::new(&w.env, "transfer"),
            args: vec![
                &w.env,
                w.account.clone().into_val(&w.env),
                to,
                amount.into_val(&w.env),
            ],
        }),
    ]
}

fn check(w: &World, ids: Vec<u32>, contexts: Vec<Context>, signed: bool) -> bool {
    let payload = BytesN::from_array(&w.env, &[42; 32]);
    let digest = auth_digest(&w.env, &w.account, &payload, &ids);
    let key = SigningKey::from_bytes(&[9; 32]);
    let signers = if signed {
        map![
            &w.env,
            (
                Signer::External(
                    w.verifier.clone(),
                    Bytes::from_slice(&w.env, &key.verifying_key().to_bytes())
                ),
                Bytes::from_slice(&w.env, &key.sign(&digest).to_bytes())
            )
        ]
    } else {
        Map::new(&w.env)
    };
    let auth = AuthPayload {
        signers,
        context_rule_ids: ids,
    };
    w.env
        .try_invoke_contract_check_auth::<SmartAccountError>(
            &w.account,
            &payload,
            auth.into_val(&w.env),
            &contexts,
        )
        .is_ok()
}

fn pay(w: &World, to: &Address) -> bool {
    check(w, ids(w), contexts(w, to.into_val(&w.env), 1), true)
}

#[test]
fn pair_compiles_and_installs_with_the_source_hash_and_only_transfer_capped() {
    let w = setup();
    let d = document(&w, None);
    let compiled = w.compiler_client().compile_doc(&bytes(&w, &d));
    assert_eq!(compiled.rules.len(), 3);
    let call = compiled.rules.get(1).unwrap();
    let transfer = compiled.rules.get(2).unwrap();
    assert_eq!(
        call.scope,
        RuleScope::Contract(Address::from_str(&w.env, GAME))
    );
    assert_eq!(
        transfer.scope,
        RuleScope::Contract(Address::from_str(&w.env, TOKEN))
    );
    assert_eq!(call.name, transfer.name);
    assert_eq!(call.signers, transfer.signers);
    assert_eq!(call.valid_until, Some(4999));
    assert_eq!(call.valid_until, transfer.valid_until);
    let parsed = perch_ir::from_json(&d.to_string()).unwrap();
    let hash = BytesN::from_array(&w.env, &perch_ir::rule_hash(&parsed.rules[1]));
    assert_eq!(call.install.first().unwrap().doc_hash, hash);
    assert_eq!(transfer.install.first().unwrap().doc_hash, hash);
    assert!(call.cap.is_empty());
    assert_eq!(transfer.cap.len(), 1);
    apply(&w, &d);
    let pair = ids(&w);
    assert_eq!(pair.len(), 2);
    let call = w.account_client().get_context_rule(&pair.get(0).unwrap());
    let transfer = w.account_client().get_context_rule(&pair.get(1).unwrap());
    assert_eq!(call.policies.len(), 1);
    assert_eq!(transfer.policies.len(), 2);
    assert!(transfer
        .policies
        .contains(infra::perch_spending_limit::address(&w.env)));
}

#[test]
fn payments_stop_at_the_cap_and_resume_after_the_window() {
    let w = setup();
    apply(&w, &document(&w, None));
    let game = Address::from_str(&w.env, GAME);
    assert!(pay(&w, &game));
    assert!(pay(&w, &game));
    assert!(!pay(&w, &game));
    w.env.ledger().with_mut(|l| l.sequence_number += 1001);
    assert!(pay(&w, &game));
}

#[test]
fn default_recipient_refuses_other_addresses_and_non_address_values() {
    for to_address in [true, false] {
        let w = setup();
        apply(&w, &document(&w, None));
        let to = if to_address {
            Address::generate(&w.env).into_val(&w.env)
        } else {
            7u64.into_val(&w.env)
        };
        assert!(!check(&w, ids(&w), contexts(&w, to, 1), true));
    }
}

#[test]
fn explicit_treasury_and_any_recipient_have_the_declared_meaning() {
    let w = setup();
    apply(
        &w,
        &document(
            &w,
            Some(serde_json::json!({"type":"address-eq","address":TREASURY})),
        ),
    );
    assert!(pay(&w, &Address::from_str(&w.env, TREASURY)));
    assert!(!pay(&w, &Address::from_str(&w.env, GAME)));
    let w = setup();
    apply(&w, &document(&w, Some(serde_json::json!({"type":"any"}))));
    assert!(pay(&w, &Address::generate(&w.env)));
    assert!(pay(&w, &Address::generate(&w.env)));
    assert!(!pay(&w, &Address::generate(&w.env)));
}

#[test]
fn each_context_needs_its_own_id_and_a_signature() {
    for mode in 0..4 {
        let w = setup();
        apply(&w, &document(&w, None));
        let pair = ids(&w);
        let selection = match mode {
            0 => vec![&w.env, pair.get(0).unwrap()],
            1 => vec![&w.env, pair.get(0).unwrap(), pair.get(0).unwrap()],
            2 => vec![&w.env, pair.get(1).unwrap(), pair.get(0).unwrap()],
            _ => pair,
        };
        assert!(!check(
            &w,
            selection,
            contexts(&w, Address::from_str(&w.env, GAME).into_val(&w.env), 1),
            mode != 3
        ));
    }
}

#[test]
fn transfer_can_be_called_directly_but_still_obeys_recipient_and_cap() {
    let w = setup();
    apply(&w, &document(&w, None));
    let transfer = contexts(&w, Address::from_str(&w.env, GAME).into_val(&w.env), 1)
        .get(1)
        .unwrap();
    let selection = vec![&w.env, ids(&w).get(1).unwrap()];
    assert!(check(
        &w,
        selection.clone(),
        vec![&w.env, transfer.clone()],
        true
    ));
    assert!(check(
        &w,
        selection.clone(),
        vec![&w.env, transfer.clone()],
        true
    ));
    assert!(!check(&w, selection, vec![&w.env, transfer], true));
}

#[test]
fn reapply_preserves_both_slots_and_spending_history() {
    let w = setup();
    let d = document(&w, None);
    apply(&w, &d);
    let before = w.account_client().configuration().rules;
    let game = Address::from_str(&w.env, GAME);
    assert!(pay(&w, &game));
    apply(&w, &d);
    assert_eq!(w.account_client().configuration().rules, before);
    assert!(pay(&w, &game));
    assert!(!pay(&w, &game));
}

#[test]
fn cap_edits_refresh_both_program_hashes_and_only_the_transfer_cap() {
    let w = setup();
    let mut d = document(&w, None);
    apply(&w, &d);
    let before = w.account_client().configuration().rules;
    d["rules"][1]["cap"]["limit"] = "3".into();
    apply(&w, &d);
    let after = w.account_client().configuration().rules;
    assert_eq!(before.get(0), after.get(0));
    for i in 1..=2 {
        assert_eq!(before.get(i).unwrap().id, after.get(i).unwrap().id);
        assert_ne!(
            before.get(i).unwrap().policies,
            after.get(i).unwrap().policies
        );
    }
    assert_eq!(after.get(1).unwrap().policies.len(), 1);
    assert_eq!(after.get(2).unwrap().policies.len(), 2);
}

#[test]
fn compiled_rule_count_is_the_v1_limit() {
    let w = setup();
    let mut d = document(&w, None);
    let template = d["rules"][1].clone();
    let rules = d["rules"].as_array_mut().unwrap();
    rules.truncate(1);
    for i in 0..(MAX_DOC_RULES / 2) {
        let mut r = template.clone();
        r["name"] = format!("game{i}").into();
        rules.push(r);
    }
    // Eleven installed slots: one admin plus five pairs. The input has only
    // six source rules, so the bound must be checked after expansion.
    assert_eq!(
        w.compiler_client().compile_doc(&bytes(&w, &d)).rules.len(),
        MAX_DOC_RULES
    );
    let mut extra = d["rules"][0].clone();
    extra["name"] = "extra".into();
    d["rules"].as_array_mut().unwrap().push(extra);
    assert!(matches!(
        w.compiler_client().try_compile_doc(&bytes(&w, &d)),
        Err(Ok(DocCompilerError::DocTooLarge))
    ));
}

#[test]
fn scope_constraints_and_expiry_are_not_lost_in_the_pair() {
    for expired in [false, true] {
        let w = setup();
        apply(&w, &document(&w, None));
        let mut ctx = contexts(&w, Address::from_str(&w.env, GAME).into_val(&w.env), 1);
        if expired {
            w.env.ledger().with_mut(|l| l.sequence_number = 5000);
        } else if let Context::Contract(mut call) = ctx.get(0).unwrap() {
            call.args = vec![&w.env, Address::generate(&w.env).into_val(&w.env)];
            ctx.set(0, Context::Contract(call));
        }
        assert!(!check(&w, ids(&w), ctx, true));
    }
}

#[soroban_sdk::contract]
struct Game;

#[soroban_sdk::contractimpl]
impl Game {
    pub fn guess(e: soroban_sdk::Env, player: Address, token: Address) {
        player.require_auth();
        soroban_sdk::token::Client::new(&e, &token).transfer(
            &player,
            e.current_contract_address(),
            &1,
        );
    }
}

/// An actual game -> SAC transfer tree, with host-enforced authorization and
/// a real Ed25519 signature. Balances move only when BOTH contexts authorize.
#[test]
fn game_pulls_stakes_under_enforcing_auth_until_the_cap_then_recovers() {
    use soroban_sdk::xdr::{
        Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
        ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation, SorobanCredentials, StringM, WriteXdr,
    };
    use soroban_sdk::TryFromVal;
    let w = setup();
    let game = w.env.register(Game, ());
    let issuer = Address::generate(&w.env);
    let token = w.env.register_stellar_asset_contract_v2(issuer).address();
    soroban_sdk::token::StellarAssetClient::new(&w.env, &token).mint(&w.account, &10);
    let mut d = document(&w, None);
    d["rules"][1]["scope"]["address"] = game.to_string().to_string().into();
    d["rules"][1]["cap"]["token"] = token.to_string().to_string().into();
    apply(&w, &d);
    let sc = |value: Val| ScVal::try_from_val(&w.env, &value).unwrap();
    let invoke = |contract: &Address, function: &str, args: std::vec::Vec<ScVal>| {
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract.clone().into(),
                function_name: StringM::try_from(function).unwrap().into(),
                args: args.try_into().unwrap(),
            }),
            sub_invocations: Default::default(),
        }
    };
    let mut root = invoke(
        &game,
        "guess",
        std::vec![
            sc(w.account.clone().into_val(&w.env)),
            sc(token.clone().into_val(&w.env))
        ],
    );
    root.sub_invocations = std::vec![invoke(
        &token,
        "transfer",
        std::vec![
            sc(w.account.clone().into_val(&w.env)),
            sc(game.clone().into_val(&w.env)),
            sc(1i128.into_val(&w.env))
        ]
    )]
    .try_into()
    .unwrap();
    let authorize = |nonce: i64| {
        let expiration = 4000;
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: Hash(w.env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: expiration,
            invocation: root.clone(),
        })
        .to_xdr(Limits::none())
        .unwrap();
        let payload = w
            .env
            .crypto()
            .sha256(&Bytes::from_slice(&w.env, &preimage))
            .to_bytes();
        let selection = ids(&w);
        let digest = auth_digest(&w.env, &w.account, &payload, &selection);
        let key = SigningKey::from_bytes(&[9; 32]);
        let signature = AuthPayload {
            context_rule_ids: selection,
            signers: map![
                &w.env,
                (
                    Signer::External(
                        w.verifier.clone(),
                        Bytes::from_slice(&w.env, &key.verifying_key().to_bytes())
                    ),
                    Bytes::from_slice(&w.env, &key.sign(&digest).to_bytes())
                )
            ],
        };
        let signature: Val = signature.into_val(&w.env);
        w.env.set_auths(&[SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: w.account.clone().into(),
                nonce,
                signature_expiration_ledger: expiration,
                signature: sc(signature),
            }),
            root_invocation: root.clone(),
        }]);
    };
    let client = GameClient::new(&w.env, &game);
    let balance = || soroban_sdk::token::Client::new(&w.env, &token).balance(&game);
    for nonce in 1..=2 {
        authorize(nonce);
        client.guess(&w.account, &token);
    }
    assert_eq!(balance(), 2);
    authorize(3);
    assert!(client.try_guess(&w.account, &token).is_err());
    assert_eq!(balance(), 2);
    w.env.ledger().with_mut(|l| l.sequence_number += 1001);
    authorize(4);
    client.guess(&w.account, &token);
    assert_eq!(balance(), 3);
}

/// Exercise the no_std parser/lowering in the actual compiler WASM. The
/// account, interpreter and spending limit remain the existing native types.
#[test]
#[ignore = "run stellar contract build --package perch-doc-compiler first"]
fn wasm_compiler_installs_and_enforces_cross_token_caps() {
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/wasm32v1-none/release/perch_doc_compiler.wasm"
    ))
    .unwrap();
    for recipient in [
        None,
        Some(serde_json::json!({"type":"any"})),
        Some(serde_json::json!({"type":"address-eq","address":TREASURY})),
    ] {
        let w = setup();
        w.env.register_at(&w.compiler, wasm.as_slice(), ());
        let to = Address::from_str(
            &w.env,
            if recipient
                .as_ref()
                .is_some_and(|r| r["type"] == "address-eq")
            {
                TREASURY
            } else {
                GAME
            },
        );
        apply(&w, &document(&w, recipient));
        assert_eq!(ids(&w).len(), 2);
        assert!(pay(&w, &to));
        assert!(pay(&w, &to));
        assert!(!pay(&w, &to));
    }
}

#[test]
fn muxed_recipient_cannot_satisfy_address_eq_for_the_same_base_address() {
    use soroban_sdk::testutils::MuxedAddress as _;
    let w = setup();
    apply(
        &w,
        &document(
            &w,
            Some(serde_json::json!({"type":"address-eq","address":TREASURY})),
        ),
    );
    let treasury = Address::from_str(&w.env, TREASURY);
    assert!(pay(&w, &treasury));
    let muxed = soroban_sdk::MuxedAddress::new(treasury, 42);
    assert!(!check(&w, ids(&w), contexts(&w, muxed.to_val(), 1), true));
}
