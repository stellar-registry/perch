extern crate std;

use crate::{pins, AccountCreated, PerchAccountFactory, PerchAccountFactoryClient};
use perch_account::PerchAccountClient;
use perch_doc_compiler::PerchDocCompiler;
use perch_interpreter::PerchInterpreter;
use perch_smart_account::infra;
use perch_spending_limit::PerchSpendingLimit;
use perch_testkit::passkey::{auth_entry, SoftPasskey};
use perch_testkit::FIXTURE_NETWORK;
use perch_webauthn_verifier::PerchWebAuthnVerifier;
use soroban_sdk::testutils::{Address as _, EnvTestConfig, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    InvokeContractArgs, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, StringM,
    VecM,
};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, Event as _, IntoVal, String, TryFromVal, Val};
use std::format;
use stellar_accounts::smart_account::Signer;

/// The account wasm the factory pinned, uploaded where `deploy_v2` finds it.
const ACCOUNT_WASM: &[u8] = include_bytes!("../wasm/perch-account.wasm");

struct World {
    env: Env,
    factory: Address,
    verifier: Address,
}

fn world() -> World {
    // No test snapshot: the world registers the pinned account wasm, whose
    // hash changes with every rebuild of the stack.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let network_id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, FIXTURE_NETWORK.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1_000;
        l.network_id = network_id;
    });
    // The infra at the content addresses the account wasm pins, and the
    // verifier at the address the factory pins.
    env.register_at(
        &infra::perch_doc_compiler::address(&env),
        PerchDocCompiler,
        (),
    );
    env.register_at(
        &infra::perch_interpreter::address(&env),
        PerchInterpreter,
        (),
    );
    env.register_at(
        &infra::perch_spending_limit::address(&env),
        PerchSpendingLimit,
        (),
    );
    let verifier = pins::perch_webauthn_verifier::address(&env);
    env.register_at(&verifier, PerchWebAuthnVerifier, ());
    env.deployer().upload_contract_wasm(ACCOUNT_WASM);
    let factory = env.register(PerchAccountFactory, ());
    World {
        env,
        factory,
        verifier,
    }
}

impl World {
    fn client(&self) -> PerchAccountFactoryClient<'_> {
        PerchAccountFactoryClient::new(&self.env, &self.factory)
    }

    fn salt(&self, n: u8) -> BytesN<32> {
        BytesN::from_array(&self.env, &[n; 32])
    }

    fn key_data(&self, key: &SoftPasskey) -> Bytes {
        Bytes::from_slice(&self.env, &key.key_data())
    }
}

fn strkey(a: &Address) -> std::string::String {
    let s = a.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    std::string::String::from_utf8(buf).unwrap()
}

fn sc<T: IntoVal<Env, Val>>(env: &Env, v: T) -> ScVal {
    let val: Val = v.into_val(env);
    ScVal::try_from_val(env, &val).unwrap()
}

#[test]
fn the_pinned_account_wasm_is_the_one_deployed() {
    let w = world();
    let expected = w
        .env
        .crypto()
        .sha256(&Bytes::from_slice(&w.env, ACCOUNT_WASM));
    assert_eq!(w.client().account_wasm_hash(), expected.to_bytes());
    assert_eq!(w.client().webauthn_verifier(), w.verifier);
    assert_eq!(w.client().version(), crate::VERSION);
}

#[test]
fn a_passkey_account_lands_at_its_predicted_address_with_the_passkey_as_admin() {
    let w = world();
    let key = SoftPasskey::from_seed([3; 32]);
    let predicted = w.client().passkey_address(&w.salt(1), &w.key_data(&key));
    let account = w.client().create_passkey(&w.salt(1), &w.key_data(&key));
    assert_eq!(account, predicted);

    let created = w.env.events().all().filter_by_contract(&w.factory);
    let event = AccountCreated {
        account: account.clone(),
        salt: w.salt(1),
        admin_signers: vec![
            &w.env,
            Signer::External(w.verifier.clone(), w.key_data(&key)),
        ],
    };
    assert_eq!(
        created.events().last(),
        Some(&event.to_xdr(&w.env, &w.factory))
    );

    let a = PerchAccountClient::new(&w.env, &account);
    let admin = a.get_context_rule(&0);
    assert_eq!(admin.name, String::from_str(&w.env, "admin"));
    assert_eq!(
        admin.signers,
        vec![
            &w.env,
            Signer::External(w.verifier.clone(), w.key_data(&key))
        ]
    );
    // The deployed account resolves the infra this world registered: its
    // wasm was built against the same pins.
    assert_eq!(
        a.infra(),
        perch_account::InfraPins {
            doc_compiler: infra::perch_doc_compiler::address(&w.env),
            interpreter: infra::perch_interpreter::address(&w.env),
            spending_limit: infra::perch_spending_limit::address(&w.env),
        }
    );
}

#[test]
fn an_address_commits_to_its_admin_signers() {
    let w = world();
    let victim = SoftPasskey::from_seed([3; 32]);
    let thief = SoftPasskey::from_seed([4; 32]);
    let salt = w.salt(1);
    let victims = w.client().passkey_address(&salt, &w.key_data(&victim));

    // Someone who learns the victim's salt gets a different address for any
    // other signer set; the victim's predicted address stays theirs.
    let squatted = w.client().create_passkey(&salt, &w.key_data(&thief));
    assert_ne!(squatted, victims);
    assert_eq!(
        w.client().create_passkey(&salt, &w.key_data(&victim)),
        victims
    );

    let generic = w.client().address_of(
        &salt,
        &vec![&w.env, Signer::Delegated(Address::generate(&w.env))],
    );
    assert_ne!(generic, victims);
}

#[test]
fn an_account_is_created_once() {
    let w = world();
    let key = SoftPasskey::from_seed([3; 32]);
    w.client().create_passkey(&w.salt(1), &w.key_data(&key));
    assert!(w
        .client()
        .try_create_passkey(&w.salt(1), &w.key_data(&key))
        .is_err());
}

#[test]
fn a_new_passkey_account_applies_a_document_signed_by_its_passkey() {
    let w = world();
    let key = SoftPasskey::from_seed([3; 32]);
    let account = w.client().create_passkey(&w.salt(1), &w.key_data(&key));
    let doc = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"owner","verifier":"{}","key":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["owner"]}}}}]}}"#,
        strkey(&w.verifier),
        hex(&key.key_data()),
    );
    let doc = Bytes::from_slice(&w.env, doc.as_bytes());
    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: account.clone().into(),
            function_name: StringM::try_from("apply_doc").unwrap().into(),
            args: std::vec![sc(&w.env, doc.clone()), sc(&w.env, 0u32)]
                .try_into()
                .unwrap(),
        }),
        sub_invocations: VecM::default(),
    };
    let a = PerchAccountClient::new(&w.env, &account);

    // Enforcing authorization: the account's real `__check_auth` runs OZ,
    // which calls the WebAuthn verifier on the passkey's assertion.
    let forged = SoftPasskey::from_seed([5; 32]);
    let mut wrong = auth_entry(
        &w.env,
        &account,
        &w.verifier,
        &forged,
        0,
        1,
        2_000,
        invocation.clone(),
    );
    w.env.set_auths(&[wrong.clone()]);
    assert!(a.try_apply_doc(&doc, &0).is_err());
    // The right key over a different invocation is refused too.
    wrong = auth_entry(
        &w.env,
        &account,
        &w.verifier,
        &key,
        0,
        2,
        2_000,
        invocation.clone(),
    );
    wrong.root_invocation.sub_invocations = std::vec![invocation.clone()].try_into().unwrap();
    w.env.set_auths(&[wrong]);
    assert!(a.try_apply_doc(&doc, &0).is_err());

    w.env.set_auths(&[auth_entry(
        &w.env,
        &account,
        &w.verifier,
        &key,
        0,
        3,
        2_000,
        invocation,
    )]);
    let doc_hash = a.apply_doc(&doc, &0);
    assert_eq!(a.applied_doc_hash(), Some(doc_hash));
}

fn hex(b: &[u8]) -> std::string::String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
