//! End-to-end cap proof (#19 PR6): compile a document carrying a cumulative
//! `cap`, attach BOTH the perch interpreter and OZ's `spending_limit` policy to
//! one OZ context rule, and drive the real `do_check_auth` with real ed25519
//! signatures. OZ enforces every attached policy (AND), so a transfer within the
//! cap authorizes and a cumulative transfer over the cap is denied — the
//! stateless interpreter and the stateful cap composing on one rule.

use ed25519_dalek::{Signer as _, SigningKey};
use perch_compile::{compile, CompileConfig};
use perch_ed25519_verifier::PerchEd25519Verifier;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, contractimpl, crypto::Hash, map, vec, Address, Bytes, BytesN, Env, IntoVal, Map,
    String as SString, Symbol, Val,
};
use stellar_accounts::policies::{
    spending_limit, spending_limit::SpendingLimitAccountParams, Policy,
};
use stellar_accounts::smart_account::{
    add_context_rule, do_check_auth, AuthPayload, ContextRule, ContextRuleType, Signer,
};

use perch_testkit::auth_digest;

/// The token contract the cap is denominated in (also the rule's scope).
const TOKEN: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";
/// A shape-valid verifier strkey for the document (the real verifier address is
/// dynamic and attached separately, as in the ci-publish matrix).
const ED25519_VERIFIER: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";

const LIMIT: i128 = 10;
const PERIOD_LEDGERS: u32 = 1000;

// --- account, verifier, and the spending_limit policy wrapper ---------------

#[contract]
struct Account;

/// The reusable OZ spending-limit policy wrapped as a `Policy` contract, exactly
/// as an applier would deploy it.
#[contract]
struct SpendingLimitPolicy;

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: soroban_sdk::Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::enforce(
            e,
            &context,
            &authenticated_signers,
            &context_rule,
            &smart_account,
        )
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &install_params, &context_rule, &smart_account)
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &context_rule, &smart_account)
    }
}

// --- a capped document, built in-code ---------------------------------------

fn cap_doc(pubkey_hex: &str) -> perch_ir::PolicyDoc {
    use perch_ir::{
        AllPrincipals, CapConstraint, PolicyDoc, Principals, Rule, Scope, SignerDecl, SignerMethod,
    };
    PolicyDoc {
        version: 1,
        network: None,
        signers: std::vec![SignerDecl {
            id: "ci".into(),
            method: SignerMethod::External {
                verifier: ED25519_VERIFIER.into(),
                key: pubkey_hex.into(),
            },
        }],
        rules: std::vec![Rule {
            name: "spend".into(),
            scope: Scope::contract(TOKEN),
            principals: Principals::All(AllPrincipals {
                signers: std::vec!["ci".into()],
            }),
            functions: Some(std::vec!["transfer".into()]),
            args: None,
            not_after_ledger: None,
            cap: Some(CapConstraint {
                token: None, // denominate in the scope contract (TOKEN)
                limit: LIMIT.to_string(),
                period_ledgers: PERIOD_LEDGERS,
            }),
        }],
    }
}

struct World {
    env: Env,
    account: Address,
    verifier: Address,
    token: Address,
    signing_key: SigningKey,
    pubkey: BytesN<32>,
    rule_id: u32,
}

/// Compile the capped document and attach both the interpreter and the
/// spending_limit policy to a single `CallContract(TOKEN)` rule.
fn setup() -> World {
    let env = Env::default();
    env.mock_all_auths();
    // Run at a positive ledger sequence so spending_limit's rolling window
    // (period > sequence ⇒ cutoff saturates to 0) does not evict entries whose
    // sequence is 0; otherwise the cumulative total would reset each call.
    env.ledger().with_mut(|l| l.sequence_number = 500);

    let account = env.register(Account, ());
    let verifier = env.register(PerchEd25519Verifier, ());
    let interpreter = env.register(perch_interpreter::PerchInterpreter, ());
    let spending = env.register(SpendingLimitPolicy, ());

    let signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = BytesN::from_array(&env, &signing_key.verifying_key().to_bytes());
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let doc = cap_doc(&pubkey_hex);
    perch_ir::validate(&doc).expect("valid");
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(&env, &[0xAB; 32]),
    };
    let plan = compile(&env, &doc, &cfg).expect("compile");
    let lowered = &plan.rules[0];
    let install = lowered
        .install
        .clone()
        .expect("interpreter attached (INV-1)");
    let cap = lowered.cap.clone().expect("cap attached");

    // Map the CapSpec onto OZ spending_limit params.
    let sl_params = SpendingLimitAccountParams {
        spending_limit: cap.limit,
        period_ledgers: cap.period_ledgers,
    };

    let token = Address::from_str(&env, TOKEN);
    let signer = Signer::External(verifier.clone(), pubkey.clone().into());
    let policies: Map<Address, Val> = map![
        &env,
        (interpreter.clone(), install.into_val(&env)),
        (spending.clone(), sl_params.into_val(&env)),
    ];

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

    World {
        env,
        account,
        verifier,
        token,
        signing_key,
        pubkey,
        rule_id: rule.id,
    }
}

fn payload_hash(env: &Env) -> Hash<32> {
    env.crypto().sha256(&Bytes::from_array(env, &[0x11; 32]))
}

fn signed_payload(w: &World) -> AuthPayload {
    let ids = vec![&w.env, w.rule_id];
    let digest = auth_digest(&w.env, &payload_hash(&w.env).to_bytes(), &ids);
    let sig = w.signing_key.sign(&digest).to_bytes();
    let signer = Signer::External(w.verifier.clone(), w.pubkey.clone().into());
    let signers: Map<Signer, Bytes> = map![&w.env, (signer, Bytes::from_array(&w.env, &sig))];
    AuthPayload {
        signers,
        context_rule_ids: ids,
    }
}

/// `TOKEN.transfer(from, to, amount)` — spending_limit reads the amount at
/// argument index 2.
fn transfer_ctx(w: &World, amount: i128) -> Context {
    let from = Address::generate(&w.env);
    let to = Address::generate(&w.env);
    Context::Contract(ContractContext {
        contract: w.token.clone(),
        fn_name: Symbol::new(&w.env, "transfer"),
        args: vec![
            &w.env,
            from.into_val(&w.env),
            to.into_val(&w.env),
            amount.into_val(&w.env),
        ],
    })
}

fn run(w: &World, amount: i128) -> Result<(), ()> {
    let hash = payload_hash(&w.env);
    let payload = signed_payload(w);
    let contexts = vec![&w.env, transfer_ctx(w, amount)];
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        w.env.as_contract(&w.account, || {
            do_check_auth(&w.env, &hash, &payload, &contexts).unwrap();
        });
    }));
    r.map_err(|_| ())
}

// --- the proof --------------------------------------------------------------

#[test]
fn cap_allows_a_transfer_within_the_limit() {
    let w = setup();
    // 8 <= 10: interpreter (fn=transfer, 1 signer) and spending_limit both pass.
    assert!(run(&w, 8).is_ok());
}

#[test]
fn cap_denies_cumulative_spend_over_the_limit() {
    let w = setup();
    // First transfer of 6 is within the cap...
    assert!(run(&w, 6).is_ok());
    // ...the second pushes the rolling total to 12 > 10, so spending_limit
    // denies and do_check_auth fails, even though the interpreter still passes.
    assert!(run(&w, 6).is_err());
}
