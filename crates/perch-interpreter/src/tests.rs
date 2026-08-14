use super::*;
use perch_program::{Op, RpnProgram};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, BytesN, IntoVal, String as SString, Symbol, Vec as SVec};
use stellar_accounts::smart_account::ContextRuleType;

const RULE_ID: u32 = 1;

fn setup() -> (Env, PerchInterpreterClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(PerchInterpreter, ());
    let client = PerchInterpreterClient::new(&env, &id);
    let account = Address::generate(&env);
    (env, client, account)
}

/// A rule whose fields enforce never reads except `id`.
fn rule(env: &Env) -> ContextRule {
    ContextRule {
        id: RULE_ID,
        context_type: ContextRuleType::Default,
        name: SString::from_str(env, "r"),
        signers: SVec::new(env),
        signer_ids: SVec::new(env),
        policies: SVec::new(env),
        policy_ids: SVec::new(env),
        valid_until: None,
    }
}

/// Program: All(MinSigners(1), FnIn[run], ArgAddrIsSelf(0)).
fn program(env: &Env) -> RpnProgram {
    let mut ops: SVec<Op> = SVec::new(env);
    ops.push_back(Op::MinSigners(1));
    ops.push_back(Op::FnIn(vec![env, Symbol::new(env, "run")]));
    ops.push_back(Op::ArgAddrIsSelf(0));
    ops.push_back(Op::All(3));
    RpnProgram {
        version: PROGRAM_VERSION,
        ops,
    }
}

fn install_params(env: &Env) -> InstallParams {
    InstallParams {
        program: program(env),
        doc_hash: BytesN::from_array(env, &[0x11; 32]),
    }
}

fn ctx(env: &Env, account: &Address, fn_name: &str) -> Context {
    Context::Contract(ContractContext {
        contract: Address::generate(env),
        fn_name: Symbol::new(env, fn_name),
        args: vec![env, account.into_val(env)],
    })
}

fn one_signer(env: &Env) -> SVec<Signer> {
    vec![env, Signer::Delegated(Address::generate(env))]
}

#[test]
fn program_version_is_current() {
    let (env, client, _) = setup();
    let _ = &env;
    assert_eq!(client.program_version(), PROGRAM_VERSION);
}

#[test]
fn install_stores_and_get_program_returns_it() {
    let (env, client, account) = setup();
    let params = install_params(&env);
    client.install(&params, &rule(&env), &account);
    assert_eq!(client.get_program(&account, &RULE_ID), Some(params));
}

#[test]
fn enforce_allows_when_program_true() {
    let (env, client, account) = setup();
    client.install(&install_params(&env), &rule(&env), &account);
    // fn=run, arg0=self, one signer → True → no error.
    client.enforce(
        &ctx(&env, &account, "run"),
        &one_signer(&env),
        &rule(&env),
        &account,
    );
}

#[test]
fn enforce_denies_when_program_false() {
    let (env, client, account) = setup();
    client.install(&install_params(&env), &rule(&env), &account);
    // wrong function → FnIn False → All False → Denied.
    let r = client.try_enforce(
        &ctx(&env, &account, "wrong"),
        &one_signer(&env),
        &rule(&env),
        &account,
    );
    assert_eq!(r, Err(Ok(Error::Denied.into())));
}

#[test]
fn enforce_denies_empty_signers_even_when_program_would_pass() {
    // C4 floor: zero authenticated signers denies before the program runs.
    let (env, client, account) = setup();
    client.install(&install_params(&env), &rule(&env), &account);
    let r = client.try_enforce(
        &ctx(&env, &account, "run"),
        &SVec::new(&env),
        &rule(&env),
        &account,
    );
    assert_eq!(r, Err(Ok(Error::Denied.into())));
}

#[test]
fn enforce_denies_when_not_installed() {
    // C2 dangling: a rule pointing at the interpreter with no stored program.
    let (env, client, account) = setup();
    let r = client.try_enforce(
        &ctx(&env, &account, "run"),
        &one_signer(&env),
        &rule(&env),
        &account,
    );
    assert_eq!(r, Err(Ok(Error::NotInstalled.into())));
}

#[test]
fn install_rejects_double_install() {
    let (env, client, account) = setup();
    client.install(&install_params(&env), &rule(&env), &account);
    let r = client.try_install(&install_params(&env), &rule(&env), &account);
    assert_eq!(r, Err(Ok(Error::AlreadyInstalled.into())));
}

#[test]
fn install_rejects_invalid_program() {
    let (env, client, account) = setup();
    // Empty program fails validation.
    let bad = InstallParams {
        program: RpnProgram {
            version: PROGRAM_VERSION,
            ops: SVec::new(&env),
        },
        doc_hash: BytesN::from_array(&env, &[0; 32]),
    };
    let r = client.try_install(&bad, &rule(&env), &account);
    assert_eq!(r, Err(Ok(Error::InvalidProgram.into())));
}

#[test]
fn uninstall_removes_then_enforce_denies() {
    let (env, client, account) = setup();
    client.install(&install_params(&env), &rule(&env), &account);
    client.uninstall(&rule(&env), &account);
    assert_eq!(client.get_program(&account, &RULE_ID), None);
    let r = client.try_enforce(
        &ctx(&env, &account, "run"),
        &one_signer(&env),
        &rule(&env),
        &account,
    );
    assert_eq!(r, Err(Ok(Error::NotInstalled.into())));
}

#[test]
fn entry_points_require_smart_account_auth() {
    // C1: without the account's auth, install must fail. No mock_all_auths here.
    let env = Env::default();
    let id = env.register(PerchInterpreter, ());
    let client = PerchInterpreterClient::new(&env, &id);
    let account = Address::generate(&env);
    let r = client.try_install(&install_params(&env), &rule(&env), &account);
    assert!(
        r.is_err(),
        "install without account auth must fail (require_auth)"
    );
}
