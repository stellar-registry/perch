//! The host and OZ-fork authorization behaviour `docs/recovery/spec.md`
//! relies on, pinned under ENFORCING authorization (`set_auths`, never
//! `mock_all_auths`, which skips `__check_auth` entirely — see AGENTS.md).
//! Each test is one property in `docs/recovery/cap-0071.md`:
//!
//! - C1: a delegated signer is authenticated only through the account's own
//!   `AddressWithDelegates` entry.
//! - C2: a contract delegate's `__check_auth` receives the delegating
//!   account's signature payload and auth contexts.
//! - C3: a delegate that refuses fails the delegating account's
//!   authorization, so the freeze propagates through delegation.
//! - C4: a delegate's approval does not bind the delegating account's
//!   `context_rule_ids`.
//! - C5: a zero-signer, policy-only rule defers entirely to the policy's
//!   `enforce`, whose `account.require_auth()` passes by invoker
//!   authorization.
//! - C6: a signature can satisfy a hook's `account.require_auth()` (#90); a
//!   reserved-name guard in `__check_auth` closes that, and the invoker path
//!   survives the guard.
//! - C7: a guardian authorizes exactly the statement digest it is asked for.
//!
//! The contracts here are minimal stand-ins (an OZ `do_check_auth` account, a
//! recording delegate, a hook, a policy), so these tests pin the pinned
//! `stellar-accounts` fork and `soroban-env-host`, not perch's own contracts.

extern crate std;

use perch_recovery_interface::account::is_reserved_invoker_only;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::xdr::{
    InvokeContractArgs, ScAddress, ScVal, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, StringM, VecM,
};
use soroban_sdk::{
    contract, contractclient, contractimpl, map, symbol_short, vec, Address, Bytes, BytesN, Env,
    IntoVal, Map, String, Symbol, TryFromVal, Val, Vec,
};
use stellar_accounts::policies::Policy;
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRule, ContextRuleType, Signer,
    SmartAccountError,
};

// ---------------------------------------------------------------------------
// Stand-in contracts
// ---------------------------------------------------------------------------

const GUARD: Symbol = symbol_short!("guard");

/// An OZ smart account. With `GUARD` set, `__check_auth` first refuses any
/// context naming a reserved invoker-only function (spec §15).
#[contract]
struct TestAccount;

#[contractimpl]
impl CustomAccountInterface for TestAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), SmartAccountError> {
        if e.storage().instance().has(&GUARD) {
            for c in auth_contexts.iter() {
                if let Context::Contract(ContractContext { fn_name, .. }) = c {
                    if is_reserved_invoker_only(&e, &fn_name) {
                        return Err(SmartAccountError::UnvalidatedContext);
                    }
                }
            }
        }
        do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

#[allow(unused)]
#[contractclient(name = "HookCallClient")]
trait HookInterface {
    fn rcv_sync(e: &Env, account: Address);
}

#[contractimpl]
impl TestAccount {
    pub fn enable_guard(e: Env) {
        e.storage().instance().set(&GUARD, &true);
    }

    /// The invoker path: the account's own code calls the hook, the way
    /// `apply_doc` calls a controller's `rcv_sync`.
    pub fn call_hook(e: Env, hook: Address) {
        HookCallClient::new(&e, &hook).rcv_sync(&e.current_contract_address());
    }
}

const FROZEN: Symbol = symbol_short!("frozen");
const PAYLOAD: Symbol = symbol_short!("payload");
const CONTEXTS: Symbol = symbol_short!("contexts");

/// A custom account that records what the host hands its `__check_auth`
/// and refuses everything while `FROZEN` is set — the shape of a frozen
/// `Protected` perch account acting as someone's delegate.
#[contract]
struct RecordingDelegate;

#[contractimpl]
impl CustomAccountInterface for RecordingDelegate {
    type Error = SmartAccountError;
    type Signature = Val;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        _signature: Val,
        auth_contexts: Vec<Context>,
    ) -> Result<(), SmartAccountError> {
        if e.storage().instance().has(&FROZEN) {
            return Err(SmartAccountError::UnvalidatedContext);
        }
        e.storage()
            .instance()
            .set(&PAYLOAD, &signature_payload.to_bytes());
        e.storage().instance().set(&CONTEXTS, &auth_contexts);
        Ok(())
    }
}

#[contractimpl]
impl RecordingDelegate {
    pub fn freeze(e: Env) {
        e.storage().instance().set(&FROZEN, &true);
    }
}

/// Anything requiring the account's authorization.
#[contract]
struct Target;

#[contractimpl]
impl Target {
    pub fn protected(account: Address) {
        account.require_auth();
    }
}

const HIT: Symbol = symbol_short!("hit");

/// A controller-style hook: `account.require_auth()` is meant to mean "the
/// account's own code is calling".
#[contract]
struct Hook;

#[contractimpl]
impl Hook {
    pub fn rcv_sync(e: Env, account: Address) {
        account.require_auth();
        e.storage().instance().set(&HIT, &true);
    }

    pub fn hit(e: Env) -> bool {
        e.storage().instance().has(&HIT)
    }
}

const DENY: Symbol = symbol_short!("deny");
const ENFORCED: Symbol = symbol_short!("enforced");

/// The only policy on a zero-signer rule, like the recovery controller on the
/// `"recovery"` rule.
#[contract]
struct GatePolicy;

#[contractimpl]
impl Policy for GatePolicy {
    type AccountParams = u32;

    fn enforce(
        e: &Env,
        _context: Context,
        authenticated_signers: Vec<Signer>,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Passes by invoker authorization: the account's `do_check_auth`
        // is the direct caller. No extra auth entry exists for it.
        smart_account.require_auth();
        assert!(authenticated_signers.is_empty());
        assert!(!e.storage().instance().has(&DENY), "gate closed");
        let n: u32 = e.storage().instance().get(&ENFORCED).unwrap_or(0);
        e.storage().instance().set(&ENFORCED, &(n + 1));
    }

    fn install(
        _e: &Env,
        _install_params: u32,
        _context_rule: ContextRule,
        _smart_account: Address,
    ) {
    }

    fn uninstall(_e: &Env, _context_rule: ContextRule, _smart_account: Address) {}
}

#[contractimpl]
impl GatePolicy {
    pub fn close(e: Env) {
        e.storage().instance().set(&DENY, &true);
    }

    pub fn enforced(e: Env) -> u32 {
        e.storage().instance().get(&ENFORCED).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Auth-entry builders
// ---------------------------------------------------------------------------

fn payload_scval(e: &Env, signers: Map<Signer, Bytes>, rule_ids: Vec<u32>) -> ScVal {
    let payload = AuthPayload {
        signers,
        context_rule_ids: rule_ids,
    };
    let v: Val = payload.into_val(e);
    ScVal::try_from_val(e, &v).unwrap()
}

fn invocation(
    contract: &Address,
    fn_name: &str,
    args: std::vec::Vec<ScVal>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.clone().into(),
            function_name: StringM::try_from(fn_name).unwrap().into(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

fn addr_arg(a: &Address) -> ScVal {
    let sc: ScAddress = a.clone().into();
    ScVal::Address(sc)
}

/// An `AddressWithDelegates` entry for `account`, selecting `rule_ids`,
/// naming `delegate` as the signer, and carrying `delegate` in the
/// credentials iff `with_delegate`.
fn delegated_entry(
    e: &Env,
    account: &Address,
    delegate: &Address,
    rule_ids: Vec<u32>,
    with_delegate: bool,
    root: SorobanAuthorizedInvocation,
) -> SorobanAuthorizationEntry {
    let delegates = if with_delegate {
        std::vec![SorobanDelegateSignature {
            address: delegate.clone().into(),
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
                    address: account.clone().into(),
                    nonce: 7,
                    signature_expiration_ledger: 100,
                    signature: payload_scval(
                        e,
                        map![e, (Signer::Delegated(delegate.clone()), Bytes::new(e))],
                        rule_ids,
                    ),
                },
                delegates: delegates.try_into().unwrap(),
            },
        ),
        root_invocation: root,
    }
}

struct World {
    env: Env,
    account: Address,
    delegate: Address,
    target: Address,
}

/// An account with one rule: `CallContract(target)`, signer
/// `Delegated(delegate)`. Returns the world and that rule's id.
fn world() -> (World, u32) {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 10);
    let account = env.register(TestAccount, ());
    let delegate = env.register(RecordingDelegate, ());
    let target = env.register(Target, ());
    let rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(target.clone()),
            &String::from_str(&env, "delegated"),
            None,
            &vec![&env, Signer::Delegated(delegate.clone())],
            &Map::new(&env),
        )
    });
    (
        World {
            env,
            account,
            delegate,
            target,
        },
        rule.id,
    )
}

fn protected_root(w: &World) -> SorobanAuthorizedInvocation {
    invocation(&w.target, "protected", std::vec![addr_arg(&w.account)])
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

#[test]
fn c1_delegate_must_ride_in_the_accounts_own_entry() {
    let (w, rule) = world();
    let client = TargetClient::new(&w.env, &w.target);

    w.env.set_auths(&[delegated_entry(
        &w.env,
        &w.account,
        &w.delegate,
        vec![&w.env, rule],
        false,
        protected_root(&w),
    )]);
    assert!(client.try_protected(&w.account).is_err());

    w.env.set_auths(&[delegated_entry(
        &w.env,
        &w.account,
        &w.delegate,
        vec![&w.env, rule],
        true,
        protected_root(&w),
    )]);
    client.protected(&w.account);
}

#[test]
fn c2_delegate_sees_the_delegating_accounts_payload_and_contexts() {
    let (w, rule) = world();
    w.env.set_auths(&[delegated_entry(
        &w.env,
        &w.account,
        &w.delegate,
        vec![&w.env, rule],
        true,
        protected_root(&w),
    )]);
    TargetClient::new(&w.env, &w.target).protected(&w.account);

    let contexts: Vec<Context> = w
        .env
        .as_contract(&w.delegate, || w.env.storage().instance().get(&CONTEXTS))
        .unwrap();
    assert_eq!(contexts.len(), 1);
    let Context::Contract(ContractContext {
        contract,
        fn_name,
        args,
    }) = contexts.get_unchecked(0)
    else {
        panic!("expected a contract context");
    };
    // The context is the *delegating account's*: a call to `target`, not
    // anything naming the delegate.
    assert_eq!(contract, w.target);
    assert_eq!(fn_name, Symbol::new(&w.env, "protected"));
    let arg: Address = args.get_unchecked(0).into_val(&w.env);
    assert_eq!(arg, w.account);
    let recorded: Option<BytesN<32>> = w
        .env
        .as_contract(&w.delegate, || w.env.storage().instance().get(&PAYLOAD));
    assert!(recorded.is_some());
}

#[test]
fn c3_a_refusing_delegate_fails_the_delegating_account() {
    let (w, rule) = world();
    RecordingDelegateClient::new(&w.env, &w.delegate).freeze();
    w.env.set_auths(&[delegated_entry(
        &w.env,
        &w.account,
        &w.delegate,
        vec![&w.env, rule],
        true,
        protected_root(&w),
    )]);
    assert!(TargetClient::new(&w.env, &w.target)
        .try_protected(&w.account)
        .is_err());
}

/// The same delegate approval passes under either of two rules that both
/// list the delegate, and the delegate sees the identical payload: its
/// approval is not bound to the rule the submitter selects. (OZ binds
/// `context_rule_ids` only into the digest *external* signers sign.)
#[test]
fn c4_delegate_approval_does_not_bind_rule_selection() {
    let run = |pick_second: bool| -> BytesN<32> {
        let (w, first) = world();
        let second = w.env.as_contract(&w.account, || {
            add_context_rule(
                &w.env,
                &ContextRuleType::CallContract(w.target.clone()),
                &String::from_str(&w.env, "second"),
                None,
                &vec![&w.env, Signer::Delegated(w.delegate.clone())],
                &Map::new(&w.env),
            )
            .id
        });
        let rule = if pick_second { second } else { first };
        w.env.set_auths(&[delegated_entry(
            &w.env,
            &w.account,
            &w.delegate,
            vec![&w.env, rule],
            true,
            protected_root(&w),
        )]);
        TargetClient::new(&w.env, &w.target).protected(&w.account);
        w.env
            .as_contract(&w.delegate, || w.env.storage().instance().get(&PAYLOAD))
            .unwrap()
    };
    assert_eq!(run(false), run(true));
}

#[test]
fn c5_zero_signer_policy_rule_defers_to_enforce_with_invoker_auth() {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 10);
    let account = env.register(TestAccount, ());
    let target = env.register(Target, ());
    let policy = env.register(GatePolicy, ());
    let rule = env.as_contract(&account, || {
        let policies: Map<Address, Val> = map![&env, (policy.clone(), 0u32.into_val(&env))];
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(target.clone()),
            &String::from_str(&env, "gate"),
            None,
            &Vec::new(&env),
            &policies,
        )
    });
    // No signers, no delegates: the account's entry only selects the rule.
    let entry = |nonce: i64| SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: account.clone().into(),
            nonce,
            signature_expiration_ledger: 100,
            signature: payload_scval(&env, Map::new(&env), vec![&env, rule.id]),
        }),
        root_invocation: invocation(&target, "protected", std::vec![addr_arg(&account)]),
    };
    let client = TargetClient::new(&env, &target);
    let gate = GatePolicyClient::new(&env, &policy);

    env.set_auths(&[entry(1)]);
    client.protected(&account);
    assert_eq!(gate.enforced(), 1);

    gate.close();
    env.set_auths(&[entry(2)]);
    assert!(client.try_protected(&account).is_err());
}

/// The #90 root cause and its fix. A rule scoped to a hook's contract lets
/// its signers satisfy the hook's `account.require_auth()` by signature. The
/// reserved-name guard in `__check_auth` refuses that, and the account's own
/// invoker path still works with no auth entries at all.
#[test]
fn c6_reserved_names_close_signature_auth_but_keep_invoker_auth() {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 10);
    let account = env.register(TestAccount, ());
    let delegate = env.register(RecordingDelegate, ());

    // A hook plus a document-style rule scoped to it, signed by `delegate`.
    let hook_with_rule = |name: &str| -> (Address, u32) {
        let hook = env.register(Hook, ());
        let rule = env.as_contract(&account, || {
            add_context_rule(
                &env,
                &ContextRuleType::CallContract(hook.clone()),
                &String::from_str(&env, name),
                None,
                &vec![&env, Signer::Delegated(delegate.clone())],
                &Map::new(&env),
            )
        });
        (hook, rule.id)
    };
    let signed_call = |hook: &Address, rule: u32| {
        delegated_entry(
            &env,
            &account,
            &delegate,
            vec![&env, rule],
            true,
            invocation(hook, "rcv_sync", std::vec![addr_arg(&account)]),
        )
    };

    // Without the guard: a direct, signature-authorized call reaches the hook.
    let (exposed, exposed_rule) = hook_with_rule("exposed");
    env.set_auths(&[signed_call(&exposed, exposed_rule)]);
    HookClient::new(&env, &exposed).rcv_sync(&account);
    assert!(
        HookClient::new(&env, &exposed).hit(),
        "signature auth satisfied the hook (the #90 shape)"
    );

    // With the guard: the same shape is refused.
    let (guarded, guarded_rule) = hook_with_rule("guarded");
    TestAccountClient::new(&env, &account).enable_guard();
    env.set_auths(&[signed_call(&guarded, guarded_rule)]);
    assert!(HookClient::new(&env, &guarded)
        .try_rcv_sync(&account)
        .is_err());
    assert!(!HookClient::new(&env, &guarded).hit());

    // The invoker path needs no auth entry and is unaffected by the guard.
    env.set_auths(&[]);
    TestAccountClient::new(&env, &account).call_hook(&guarded);
    assert!(HookClient::new(&env, &guarded).hit());
}

#[contract]
struct ApproveController;

#[contractimpl]
impl ApproveController {
    /// A guardian approval, bound to a statement digest the way the
    /// controller binds `submit_guardian`.
    pub fn submit_guardian(e: Env, guardian: Address, digest: BytesN<32>) {
        guardian.require_auth_for_args(vec![&e, digest.into_val(&e)]);
    }
}

/// A contract guardian authorizes exactly `(controller, fn, [digest])`: an
/// auth entry for a different digest does not satisfy it.
#[test]
fn c7_guardian_authorizes_exactly_the_digest() {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 10);
    let guardian = env.register(RecordingDelegate, ());
    let controller = env.register(ApproveController, ());
    let digest = BytesN::from_array(&env, &[0xd1; 32]);
    let other = BytesN::from_array(&env, &[0xd2; 32]);
    let entry = |d: &BytesN<32>, nonce: i64| SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: guardian.clone().into(),
            nonce,
            signature_expiration_ledger: 100,
            signature: ScVal::Void,
        }),
        root_invocation: invocation(
            &controller,
            "submit_guardian",
            std::vec![ScVal::Bytes(d.to_array().to_vec().try_into().unwrap())],
        ),
    };
    let client = ApproveControllerClient::new(&env, &controller);

    env.set_auths(&[entry(&other, 1)]);
    assert!(client.try_submit_guardian(&guardian, &digest).is_err());

    env.set_auths(&[entry(&digest, 2)]);
    client.submit_guardian(&guardian, &digest);
    let contexts: Vec<Context> = env
        .as_contract(&guardian, || env.storage().instance().get(&CONTEXTS))
        .unwrap();
    let Context::Contract(ContractContext { args, .. }) = contexts.get_unchecked(0) else {
        panic!("expected a contract context");
    };
    assert_eq!(args.len(), 1);
    let signed: BytesN<32> = args.get_unchecked(0).into_val(&env);
    assert_eq!(signed, digest);
}
