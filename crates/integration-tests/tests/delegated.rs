//! CAP-0071 dogfood: a `Signer::Delegated` CI signer authorizing through the
//! real `PerchAccount`'s exported `__check_auth`, with the compiled ci-publish
//! perch program enforcing fn/arg constraints — all under ENFORCED
//! authorization (no mocks). The delegate here is a custom account (the same
//! host path a G-account CI key takes on-network); its authentication rides
//! inside the perch account's single `AddressWithDelegates` auth entry.
//!
//! Requires the CAP-0071 stellar-accounts patch (theahaco/stellar-contracts-OZ
//! PR #3): `Signer::Delegated` authenticates via `delegate_account_auth`.
//! `env.try_invoke_contract_check_auth` cannot attach delegated signers, so
//! this drives a wrapper contract via `set_auths`, like the sdk's own
//! delegation test.

use perch_account::PerchAccount;
use perch_compile::{compile, CompileConfig};
use perch_ed25519_verifier::PerchEd25519Verifier;
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::{
    InvokeContractArgs, ScAddress, ScVal, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, StringM, VecM,
};
use soroban_sdk::{
    contract, contractimpl, map, vec, Address, Bytes, BytesN, Env, IntoVal, Map, String as SString,
    TryFromVal, Val, Vec,
};
use stellar_accounts::smart_account::{
    add_context_rule, AuthPayload, ContextRuleType, Signer, SmartAccountError,
};

mod common;
use common::fixture;

// Stand-in for the CI key: a custom account approving everything it is asked
// to co-sign. On-network this is a plain G-account whose classic signature the
// host verifies natively — the delegation plumbing is identical.
#[contract]
struct ApproveAllAccount;

#[contractimpl]
impl CustomAccountInterface for ApproveAllAccount {
    type Error = SmartAccountError;
    type Signature = Val;

    fn __check_auth(
        _e: Env,
        _signature_payload: Hash<32>,
        _signature: Val,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), SmartAccountError> {
        Ok(())
    }
}

// Registry stand-in with the fn shape the ci-publish program constrains:
// author at arg index 1, fn name in {publish, publish_hash}. `set_manager`
// exists to prove the program rejects out-of-policy functions.
#[contract]
struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn publish_hash(_wasm_name: u32, author: Address) {
        author.require_auth();
    }

    pub fn set_manager(_arg: u32, author: Address) {
        author.require_auth();
    }
}

struct World {
    env: Env,
    account: Address,
    delegate: Address,
    registry: Address,
    rule_id: u32,
}

/// Real PerchAccount (External admin at genesis, as in production), real
/// interpreter + verifier, and a ci-publish rule whose ONLY signer is the
/// delegated CI account — the compiled fixture program attached as policy.
fn setup() -> World {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 10);

    let verifier = env.register(PerchEd25519Verifier, ());
    let interpreter = env.register(perch_interpreter::PerchInterpreter, ());
    let delegate = env.register(ApproveAllAccount, ());
    let registry = env.register(MockRegistry, ());

    let admin_signers = vec![
        &env,
        Signer::External(verifier.clone(), Bytes::from_array(&env, &[9u8; 32])),
    ];
    let account = env.register(PerchAccount, (admin_signers,));

    // The compiled ci-publish program (MinSigners(1), fn in {publish,
    // publish_hash}, arg 1 is-self) — installed under a rule whose signer is
    // the DELEGATED account instead of the fixture's External ci key.
    let doc = perch_ir::from_json(&fixture()).expect("parse");
    perch_ir::validate(&doc).expect("valid");
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(&env, &[0xAB; 32]),
    };
    let plan = compile(&env, &doc, &cfg).expect("compile");
    let install = plan.rules[1]
        .install
        .clone()
        .expect("ci-publish attaches interpreter");
    let policies: Map<Address, Val> = map![&env, (interpreter.clone(), install.into_val(&env))];

    let rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(registry.clone()),
            &SString::from_str(&env, "ci-publish"),
            None,
            &vec![&env, Signer::Delegated(delegate.clone())],
            &policies,
        )
    });

    World {
        env,
        account,
        delegate,
        registry,
        rule_id: rule.id,
    }
}

/// The account's credential signature: AuthPayload selecting the ci rule and
/// naming the delegated signer. No cryptographic material — the delegate's
/// authentication is the host-forwarded delegation itself.
fn auth_payload_scval(w: &World) -> ScVal {
    let payload = AuthPayload {
        signers: map![
            &w.env,
            (Signer::Delegated(w.delegate.clone()), Bytes::new(&w.env))
        ],
        context_rule_ids: vec![&w.env, w.rule_id],
    };
    let payload_val: Val = payload.into_val(&w.env);
    ScVal::try_from_val(&w.env, &payload_val).unwrap()
}

/// One `AddressWithDelegates` entry authorizing `registry.<fn>(7, author)`.
fn entry(
    w: &World,
    fn_name: &str,
    author: &Address,
    nonce: i64,
    with_delegate: bool,
) -> SorobanAuthorizationEntry {
    let author_addr: ScAddress = author.clone().into();
    let delegates = if with_delegate {
        std::vec![SorobanDelegateSignature {
            address: w.delegate.clone().into(),
            signature: ScVal::Void,
            nested_delegates: VecM::default(),
        }]
    } else {
        std::vec![]
    };
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::AddressWithDelegates(
            SorobanAddressCredentialsWithDelegates {
                address_credentials: SorobanAddressCredentials {
                    address: w.account.clone().into(),
                    nonce,
                    signature_expiration_ledger: 100,
                    signature: auth_payload_scval(w),
                },
                delegates: delegates.try_into().unwrap(),
            },
        ),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: w.registry.clone().into(),
                function_name: StringM::try_from(fn_name).unwrap().into(),
                args: std::vec![ScVal::U32(7), ScVal::Address(author_addr)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    }
}

#[test]
fn delegated_ci_signer_publishes_as_self() {
    let w = setup();
    w.env
        .set_auths(&[entry(&w, "publish_hash", &w.account, 1, true)]);
    MockRegistryClient::new(&w.env, &w.registry).publish_hash(&7, &w.account);
}

#[test]
fn delegated_ci_signer_denied_other_function() {
    // The delegation authenticates, but the perch program rejects set_manager
    // — proving policy enforcement runs on the CAP-0071 path.
    let w = setup();
    w.env
        .set_auths(&[entry(&w, "set_manager", &w.account, 2, true)]);
    assert!(MockRegistryClient::new(&w.env, &w.registry)
        .try_set_manager(&7, &w.account)
        .is_err());
}

#[test]
fn delegated_ci_signer_denied_author_not_self() {
    let w = setup();
    let someone_else = w.env.register(ApproveAllAccount, ());
    w.env
        .set_auths(&[entry(&w, "publish_hash", &someone_else, 3, true)]);
    assert!(MockRegistryClient::new(&w.env, &w.registry)
        .try_publish_hash(&7, &someone_else)
        .is_err());
}

#[test]
fn delegate_missing_from_credentials_is_rejected() {
    // AuthPayload names the delegated signer but the entry carries no delegate
    // signature — the host's delegate_account_auth must fail.
    let w = setup();
    w.env
        .set_auths(&[entry(&w, "publish_hash", &w.account, 4, false)]);
    assert!(MockRegistryClient::new(&w.env, &w.registry)
        .try_publish_hash(&7, &w.account)
        .is_err());
}
