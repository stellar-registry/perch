//! The account's recovery-completion check (`authorize_completion`) against
//! OpenZeppelin's `do_check_auth`, the check it replaces, on one account
//! holding the recovery rule both ways: as the account records it, and in
//! OZ's registry (installed by OZ's `add_context_rule`, as the only rule
//! there, under the same id).
//!
//! Over a grid of payloads — signers present, a wrong id, an expired rule, a
//! wrong context, a second context, mismatched lengths, a refusing
//! controller, and combinations that fix the order of the checks — both give
//! the same verdict, error code included, and ask the controller about the
//! same contexts in the same order. OZ asks through the `Policy` hook
//! `enforce(context, authenticated_signers, ContextRule, account)`, the
//! account through `rcv_complete(account, context, RecoveryRule)`; the
//! controller here records each as the latter, `enforce`'s rule projected
//! onto its signer count and scope, and requires `enforce`'s authenticated
//! signers to be empty. Those are all a controller checks besides its own
//! state (`recovery.rs`, `controller_differential.rs`).
//!
//! Each check runs as its own contract call on the account, so a refusal
//! rolls back like an authorization the host refuses.

use perch_account_types::{AuthPayload, ContextRule, ContextRuleType, Signer, SmartAccountError};
use perch_recovery_interface::controller::RecoveryRule;
use perch_rule_eval::StoredFunctions;
use perch_smart_account::{InstalledPolicy, RuleRecord, StoredRule};
use soroban_sdk::auth::{Context, ContractContext, CreateContractHostFnContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, map, symbol_short, vec, Address, Bytes, BytesN, ContractExecutable,
    Env, IntoVal, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account as oz;

/// The admin rule's id, and the recovery rule's.
const ADMIN: u32 = 0;
const RECOVERY: u32 = 1;

/// The controller's refusal code when it is set to refuse.
const REFUSED: u32 = 77;

/// A recovery controller that accepts every completion it is asked about
/// and records it, or refuses every one (`refuse`).
#[contract]
struct Controller;

#[contractimpl]
impl Controller {
    pub fn install(_e: Env, _params: Val, _rule: ContextRule, _account: Address) {}

    /// OZ's question, recorded as the account's.
    pub fn enforce(
        e: Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        assert!(authenticated_signers.is_empty());
        let rule = RecoveryRule {
            signers: context_rule.signers.len(),
            contract: match context_rule.context_type {
                ContextRuleType::CallContract(contract) => Some(contract),
                _ => None,
            },
        };
        record(&e, smart_account, context, rule);
    }

    pub fn rcv_complete(e: Env, account: Address, context: Context, rule: RecoveryRule) {
        record(&e, account, context, rule);
    }

    pub fn refuse(e: Env) {
        e.storage().instance().set(&symbol_short!("refuse"), &true);
    }

    /// Every accepted call since the last `take`, as XDR, and forget them.
    pub fn take(e: Env) -> Vec<Bytes> {
        let calls = e
            .storage()
            .instance()
            .get(&symbol_short!("calls"))
            .unwrap_or(Vec::new(&e));
        e.storage().instance().remove(&symbol_short!("calls"));
        calls
    }
}

/// Accept and record `rcv_complete(account, context, rule)`, unless set to
/// refuse.
fn record(e: &Env, account: Address, context: Context, rule: RecoveryRule) {
    if e.storage().instance().has(&symbol_short!("refuse")) {
        soroban_sdk::panic_with_error!(e, soroban_sdk::Error::from_contract_error(REFUSED));
    }
    let call = (account, context, rule).to_xdr(e);
    let mut calls: Vec<Bytes> = e
        .storage()
        .instance()
        .get(&symbol_short!("calls"))
        .unwrap_or(Vec::new(e));
    calls.push_back(call);
    e.storage().instance().set(&symbol_short!("calls"), &calls);
}

/// The account: each check as one of its entry points, over its storage.
#[contract]
struct Account;

#[contractimpl]
impl Account {
    pub fn perch(
        e: Env,
        payload: AuthPayload,
        contexts: Vec<Context>,
    ) -> Result<(), soroban_sdk::Error> {
        perch_smart_account::authorize_completion(&e, RECOVERY, &payload, &contexts)
    }

    pub fn oz(e: Env, payload: oz::AuthPayload, contexts: Vec<Context>) {
        // The host's payload hash: no signer reaches authentication here,
        // since the recovery rule has none.
        let hash = e.crypto().sha256(&Bytes::from_array(&e, &[0x11; 32]));
        oz::do_check_auth(&e, &hash, &payload, &contexts).unwrap();
    }
}

struct World {
    env: Env,
    account: Address,
    controller: Address,
}

/// An account whose recovery rule, id 1, is last valid at `valid_until`,
/// with the controller as its one policy: in the account's records (beside
/// an admin rule, id 0) and in OZ's registry (alone).
fn world(valid_until: Option<u32>) -> World {
    let env = Env::default();
    env.ledger().with_mut(|l| l.sequence_number = 100);
    let account = env.register(Account, ());
    let controller = env.register(Controller, ());
    // A rule on the account, with `signers` all required, last valid at
    // `valid_until`.
    let rule = |signers: Vec<Signer>, valid_until: Option<u32>| StoredRule {
        contract: account.clone(),
        functions: StoredFunctions::AnyExcept(Vec::new(&env)),
        conds: Vec::new(&env),
        threshold: signers.len(),
        signers,
        cap: Vec::new(&env),
        valid_until,
        generation: None,
    };
    let records = vec![
        &env,
        RuleRecord {
            id: ADMIN,
            name: String::from_str(&env, "admin"),
            policies: Vec::new(&env),
            rule: rule(vec![&env, Signer::Delegated(Address::generate(&env))], None),
        },
        RuleRecord {
            id: RECOVERY,
            name: String::from_str(&env, "recovery"),
            policies: vec![
                &env,
                InstalledPolicy {
                    policy: controller.clone(),
                    params: BytesN::from_array(&env, &[3; 32]),
                },
            ],
            rule: rule(Vec::new(&env), valid_until),
        },
    ];
    env.as_contract(&account, || {
        perch_smart_account::testutils::set_rule_records(&env, &records);
        env.storage()
            .instance()
            .set(&oz::SmartAccountStorageKey::NextId, &RECOVERY);
        let rule = oz::add_context_rule(
            &env,
            &oz::ContextRuleType::CallContract(account.clone()),
            &String::from_str(&env, "recovery"),
            valid_until,
            &Vec::new(&env),
            &map![
                &env,
                (
                    controller.clone(),
                    BytesN::from_array(&env, &[3; 32]).into_val(&env)
                )
            ],
        );
        assert_eq!(rule.id, RECOVERY);
    });
    World {
        env,
        account,
        controller,
    }
}

/// What a check did: its verdict, and the controller calls it made.
type Outcome = (Result<(), soroban_sdk::Error>, std::vec::Vec<Bytes>);

impl World {
    fn run(&self, check: &str, payload: &AuthPayload, contexts: &Vec<Context>) -> Outcome {
        let args: Vec<Val> = vec![
            &self.env,
            payload.into_val(&self.env),
            contexts.into_val(&self.env),
        ];
        let verdict = match self.env.try_invoke_contract::<(), soroban_sdk::Error>(
            &self.account,
            &Symbol::new(&self.env, check),
            args,
        ) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(e)) => Err(e),
            other => panic!("{check}: {other:?}"),
        };
        let calls = ControllerClient::new(&self.env, &self.controller)
            .take()
            .iter()
            .collect();
        (verdict, calls)
    }

    /// Both checks' outcomes, which must agree; returns the verdict.
    fn same(&self, payload: &AuthPayload, contexts: &Vec<Context>) -> Outcome {
        let perch = self.run("perch", payload, contexts);
        let oz = self.run("oz", payload, contexts);
        assert_eq!(perch, oz, "the account's check against OZ's");
        perch
    }

    fn payload(&self, signers: Map<Signer, Bytes>, ids: &[u32]) -> AuthPayload {
        let mut context_rule_ids = Vec::new(&self.env);
        for id in ids {
            context_rule_ids.push_back(*id);
        }
        AuthPayload {
            signers,
            context_rule_ids,
        }
    }

    fn no_signer(&self, ids: &[u32]) -> AuthPayload {
        self.payload(Map::new(&self.env), ids)
    }

    /// A completion's context: `apply_doc` on `contract`.
    fn apply_doc(&self, contract: &Address) -> Context {
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&self.env, "apply_doc"),
            args: vec![
                &self.env,
                Bytes::from_array(&self.env, b"{}").into_val(&self.env),
            ],
        })
    }

    fn on_account(&self) -> Context {
        self.apply_doc(&self.account)
    }
}

fn code(e: SmartAccountError) -> Result<(), soroban_sdk::Error> {
    Err(e.into())
}

#[test]
fn a_completion_is_accepted_with_the_same_controller_call() {
    let w = world(None);
    let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY]), &vec![&w.env, w.on_account()]);
    assert_eq!(verdict, Ok(()));
    assert_eq!(calls.len(), 1);

    // The call is `rcv_complete(account, context, rule)` with the rule as
    // OZ's registry gives it: no signer, and calls on the account.
    let rule = w
        .env
        .as_contract(&w.account, || oz::get_context_rule(&w.env, RECOVERY));
    assert!(rule.signers.is_empty());
    assert_eq!(
        rule.context_type,
        oz::ContextRuleType::CallContract(w.account.clone())
    );
    let expected = (
        w.account.clone(),
        w.on_account(),
        RecoveryRule {
            signers: 0,
            contract: Some(w.account.clone()),
        },
    )
        .to_xdr(&w.env);
    assert_eq!(calls[0], expected);
}

#[test]
fn signers_present_are_refused_before_the_controller() {
    let w = world(None);
    let contexts = vec![&w.env, w.on_account()];
    let delegated = map![
        &w.env,
        (
            Signer::Delegated(Address::generate(&w.env)),
            Bytes::new(&w.env)
        )
    ];
    let external = map![
        &w.env,
        (
            Signer::External(
                Address::generate(&w.env),
                Bytes::from_array(&w.env, &[1; 32])
            ),
            Bytes::from_array(&w.env, &[2; 64])
        )
    ];
    for signers in [delegated, external] {
        let (verdict, calls) = w.same(&w.payload(signers, &[RECOVERY]), &contexts);
        assert_eq!(verdict, code(SmartAccountError::UnauthorizedSigner));
        assert!(calls.is_empty());
    }
}

#[test]
fn a_wrong_id_is_not_found() {
    let w = world(None);
    let contexts = vec![&w.env, w.on_account()];
    // The admin rule's id: a rule of the account, but not in OZ's registry
    // and not the recovery rule. And an id no rule has.
    for id in [ADMIN, 7] {
        let (verdict, calls) = w.same(&w.no_signer(&[id]), &contexts);
        assert_eq!(verdict, code(SmartAccountError::ContextRuleNotFound));
        assert!(calls.is_empty());
    }
}

#[test]
fn an_expired_rule_is_unvalidated() {
    let w = world(Some(150));
    let contexts = vec![&w.env, w.on_account()];
    let (verdict, _) = w.same(&w.no_signer(&[RECOVERY]), &contexts);
    assert_eq!(verdict, Ok(()), "valid through its last ledger");
    w.env.ledger().with_mut(|l| l.sequence_number = 150);
    assert_eq!(w.same(&w.no_signer(&[RECOVERY]), &contexts).0, Ok(()));
    w.env.ledger().with_mut(|l| l.sequence_number = 151);
    let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY]), &contexts);
    assert_eq!(verdict, code(SmartAccountError::UnvalidatedContext));
    assert!(calls.is_empty());
}

#[test]
fn a_wrong_context_is_unvalidated() {
    let w = world(None);
    let elsewhere = w.apply_doc(&Address::generate(&w.env));
    let create = Context::CreateContractHostFn(CreateContractHostFnContext {
        executable: ContractExecutable::Wasm(BytesN::from_array(&w.env, &[4; 32])),
        salt: BytesN::from_array(&w.env, &[5; 32]),
    });
    for context in [elsewhere, create] {
        let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY]), &vec![&w.env, context]);
        assert_eq!(verdict, code(SmartAccountError::UnvalidatedContext));
        assert!(calls.is_empty());
    }
}

#[test]
fn a_second_context_is_checked_and_enforced_in_turn() {
    let w = world(None);
    // Two contexts on the account: each is enforced, in order.
    let other_fn = Context::Contract(ContractContext {
        contract: w.account.clone(),
        fn_name: Symbol::new(&w.env, "execute"),
        args: Vec::new(&w.env),
    });
    let two = vec![&w.env, w.on_account(), other_fn];
    let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY, RECOVERY]), &two);
    assert_eq!(verdict, Ok(()));
    assert_eq!(calls.len(), 2);

    // A second context elsewhere, or under another id, fails the whole.
    let elsewhere = vec![
        &w.env,
        w.on_account(),
        w.apply_doc(&Address::generate(&w.env)),
    ];
    let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY, RECOVERY]), &elsewhere);
    assert_eq!(verdict, code(SmartAccountError::UnvalidatedContext));
    assert!(calls.is_empty());
    let (verdict, _) = w.same(&w.no_signer(&[RECOVERY, ADMIN]), &two);
    assert_eq!(verdict, code(SmartAccountError::ContextRuleNotFound));

    // One id for two contexts, or two for one.
    for ids in [&[RECOVERY][..], &[RECOVERY, RECOVERY, RECOVERY][..]] {
        let (verdict, _) = w.same(&w.no_signer(ids), &two);
        assert_eq!(
            verdict,
            code(SmartAccountError::ContextRuleIdsLengthMismatch)
        );
    }
}

#[test]
fn the_checks_run_in_the_same_order() {
    // A signer on an expired rule: the context is checked first.
    let w = world(Some(120));
    w.env.ledger().with_mut(|l| l.sequence_number = 200);
    let signers = map![
        &w.env,
        (
            Signer::Delegated(Address::generate(&w.env)),
            Bytes::new(&w.env)
        )
    ];
    let contexts = vec![&w.env, w.on_account()];
    let (verdict, _) = w.same(&w.payload(signers, &[RECOVERY]), &contexts);
    assert_eq!(verdict, code(SmartAccountError::UnvalidatedContext));

    // A signer and a wrong id: the id first. A wrong id after a wrong
    // context: the first context's failure.
    let w = world(None);
    let signers = map![
        &w.env,
        (
            Signer::Delegated(Address::generate(&w.env)),
            Bytes::new(&w.env)
        )
    ];
    let contexts = vec![&w.env, w.on_account()];
    let (verdict, _) = w.same(&w.payload(signers, &[ADMIN]), &contexts);
    assert_eq!(verdict, code(SmartAccountError::ContextRuleNotFound));
    let elsewhere = w.apply_doc(&Address::generate(&w.env));
    let (verdict, _) = w.same(
        &w.no_signer(&[RECOVERY, ADMIN]),
        &vec![&w.env, elsewhere, w.on_account()],
    );
    assert_eq!(verdict, code(SmartAccountError::UnvalidatedContext));
}

#[test]
fn a_refusing_controller_fails_both_with_its_error() {
    let w = world(None);
    ControllerClient::new(&w.env, &w.controller).refuse();
    let (verdict, calls) = w.same(&w.no_signer(&[RECOVERY]), &vec![&w.env, w.on_account()]);
    assert_eq!(
        verdict,
        Err(soroban_sdk::Error::from_contract_error(REFUSED))
    );
    assert!(calls.is_empty());
}
