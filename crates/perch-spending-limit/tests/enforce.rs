//! Standalone proof that the policy contract enforces a cumulative cap: install
//! it on a `CallContract(token)` rule, then `enforce` a transfer within the cap
//! (ok) and a cumulative transfer over it (panics). No interpreter and no
//! signatures — `spending_limit` meters the transfer amount (arg index 2), not
//! who signed, so this isolates the wrapped cap. The full composition with the
//! interpreter + real ed25519 auth is proven in `integration-tests/cap_matrix`.

use perch_spending_limit::{
    PerchSpendingLimit, PerchSpendingLimitClient, SpendingLimitAccountParams,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, map, vec, Address, Env, IntoVal, Map, String as SString, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{add_context_rule, ContextRule, ContextRuleType, Signer};

/// A bare account contract, just to own the context-rule storage.
#[contract]
struct Account;

const LIMIT: i128 = 10;
const PERIOD_LEDGERS: u32 = 1000;

struct Harness {
    env: Env,
    account: Address,
    policy: Address,
    token: Address,
    rule: ContextRule,
}

/// Register an account + the policy, then install the cap on a
/// `CallContract(token)` rule and return the installed rule.
fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    // Positive ledger sequence so the rolling window doesn't evict entries at
    // sequence 0 (which would reset the cumulative total each call).
    env.ledger().with_mut(|l| l.sequence_number = 500);

    let account = env.register(Account, ());
    let policy = env.register(PerchSpendingLimit, ());
    let token = Address::generate(&env);

    // A single signer just so the rule is well-formed; spending_limit ignores
    // signer identity — it meters the transfer amount.
    let signer = Signer::Delegated(Address::generate(&env));
    let params = SpendingLimitAccountParams {
        spending_limit: LIMIT,
        period_ledgers: PERIOD_LEDGERS,
    };
    let policies: Map<Address, Val> = map![&env, (policy.clone(), params.into_val(&env))];

    let rule = env.as_contract(&account, || {
        add_context_rule(
            &env,
            &ContextRuleType::CallContract(token.clone()),
            &SString::from_str(&env, "spend"),
            None,
            &vec![&env, signer],
            &policies,
        )
    });

    Harness {
        env,
        account,
        policy,
        token,
        rule,
    }
}

/// `token.transfer(from, to, amount)` — spending_limit reads the amount at arg 2.
fn transfer_ctx(h: &Harness, amount: i128) -> Context {
    Context::Contract(ContractContext {
        contract: h.token.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: vec![
            &h.env,
            Address::generate(&h.env).into_val(&h.env),
            Address::generate(&h.env).into_val(&h.env),
            amount.into_val(&h.env),
        ],
    })
}

/// Drive the policy's `enforce` for a transfer of `amount` (panics if the
/// cumulative window would exceed the cap). `spending_limit` requires at least
/// one authenticated signer but ignores which — it meters the amount, not the
/// signer — so any non-empty set works.
fn enforce(h: &Harness, amount: i128) {
    let signers: Vec<Signer> = vec![&h.env, Signer::Delegated(Address::generate(&h.env))];
    PerchSpendingLimitClient::new(&h.env, &h.policy).enforce(
        &transfer_ctx(h, amount),
        &signers,
        &h.rule,
        &h.account,
    );
}

#[test]
fn allows_a_transfer_within_the_limit() {
    let h = setup();
    enforce(&h, 8); // 8 <= 10
}

#[test]
#[should_panic]
fn denies_cumulative_spend_over_the_limit() {
    let h = setup();
    enforce(&h, 6); // total 6, within the cap
    enforce(&h, 6); // total 12 > 10 → spending_limit denies
}

#[test]
fn reports_the_wrapper_policy_version() {
    let h = setup();
    let client = PerchSpendingLimitClient::new(&h.env, &h.policy);
    assert_eq!(client.policy_version(), 1);
}
