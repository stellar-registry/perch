//! Tests for `registry_contract!` — pinned and runtime resolution modes.
//!
//! The derivation under test is pure SDK: `address(env, registry)` must equal
//! `env.deployer().with_address(registry, wasm_hash).deployed_address()`, which
//! is what the registry uses when it actually deploys a stateless singleton with
//! `salt == wasm_hash`. We prove that against a real `deploy_v2` (pinned mode)
//! and against a real cross-contract `fetch_hash` (runtime mode).

use perch_registry_resolve::registry_contract;
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, BytesN, Env, String};

/// The soroban-sdk doctest `test_add_u64` contract — a real, deployable wasm,
/// embedded as bytes (see the module docs for why it isn't a `.wasm` file).
/// Its sha256 (== the soroban wasm hash) is [`FIXTURE_HASH_HEX`]; the
/// deploy-match test re-uploads it and asserts the two agree, so the pinned
/// literal can never silently drift.
#[path = "fixtures/deployable_wasm.rs"]
mod deployable_wasm;
use deployable_wasm::DEPLOYABLE_WASM;

const FIXTURE_HASH_HEX: &str = "33d12fec8f6f3ddf2eb0ec76ee9a75a9e37d1fa20af35908d90d278af8264311";

/// Trivial local contract: mints the `FixtureClient` type used for `client:`,
/// and gives `env.as_contract` a real contract address with instance storage.
#[contract]
pub struct Fixture;

#[contractimpl]
impl Fixture {
    pub fn ping(_env: Env) -> u32 {
        1
    }
}

/// The hash the fake registry returns from `fetch_hash`, for runtime mode.
const RUNTIME_HASH: [u8; 32] = [7u8; 32];

/// Minimal stand-in for the registry's `Publishable::fetch_hash`.
#[contract]
pub struct FakeRegistry;

#[contractimpl]
impl FakeRegistry {
    pub fn fetch_hash(env: Env, _wasm_name: String, _version: Option<String>) -> BytesN<32> {
        BytesN::from_array(&env, &RUNTIME_HASH)
    }
}

// Pinned mode: compile-time hash literal, no cross-contract calls.
registry_contract! {
    mod: pinned,
    wasm_name: "fixture",
    client: crate::FixtureClient,
    hash: "33d12fec8f6f3ddf2eb0ec76ee9a75a9e37d1fa20af35908d90d278af8264311",
}

// Runtime mode: hash resolved from the registry via `fetch_hash`.
registry_contract! {
    mod: runtime,
    wasm_name: "fixture",
    client: crate::FixtureClient,
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *slot = (hi << 4) | lo;
    }
    out
}

#[test]
fn pinned_hash_literal_decodes_to_bytes() {
    let env = Env::default();
    let expected = hex32(FIXTURE_HASH_HEX);
    assert_eq!(pinned::WASM_HASH, expected);
    assert_eq!(pinned::hash(&env), BytesN::from_array(&env, &expected));
    assert_eq!(pinned::WASM_NAME, "fixture");
}

#[test]
fn pinned_address_equals_hand_computed_derivation() {
    let env = Env::default();
    let registry = Address::generate(&env);
    let hash = pinned::hash(&env);
    let expected = env
        .deployer()
        .with_address(registry.clone(), hash)
        .deployed_address();
    assert_eq!(pinned::address(&env, &registry), expected);
}

#[test]
fn pinned_client_is_bound_to_the_derived_address() {
    let env = Env::default();
    let registry = Address::generate(&env);
    let client = pinned::client(&env, &registry);
    assert_eq!(client.address, pinned::address(&env, &registry));
}

#[test]
fn pinned_address_matches_actual_deployment() {
    let env = Env::default();
    env.mock_all_auths();
    let registry = Address::generate(&env);

    // Upload the real fixture wasm; its hash must equal the pinned literal.
    let wasm_hash = env.deployer().upload_contract_wasm(DEPLOYABLE_WASM);
    assert_eq!(
        wasm_hash,
        pinned::hash(&env),
        "pinned literal drifted from the fixture's sha256"
    );

    // Deploy it with salt == wasm hash and deployer == registry, exactly as the
    // registry deploys a stateless singleton.
    let deployed = env
        .deployer()
        .with_address(registry.clone(), wasm_hash.clone())
        .deploy_v2(wasm_hash, ());

    // The macro-derived address equals the actually-deployed instance address.
    assert_eq!(pinned::address(&env, &registry), deployed);
}

#[test]
fn runtime_hash_is_fetched_via_cross_contract_call() {
    let env = Env::default();
    let registry = env.register(FakeRegistry, ());
    let expected = BytesN::from_array(&env, &RUNTIME_HASH);
    assert_eq!(runtime::hash(&env, &registry), expected);
}

#[test]
fn runtime_address_derives_from_the_fetched_hash() {
    let env = Env::default();
    let registry = env.register(FakeRegistry, ());
    let fetched = BytesN::from_array(&env, &RUNTIME_HASH);
    let expected = env
        .deployer()
        .with_address(registry.clone(), fetched)
        .deployed_address();
    assert_eq!(runtime::address(&env, &registry), expected);
}

#[test]
fn runtime_memoized_address_matches_and_is_cacheable() {
    let env = Env::default();
    let registry = env.register(FakeRegistry, ());
    let consumer = env.register(Fixture, ());
    let expected = runtime::address(&env, &registry);

    // Instance storage requires a contract context.
    env.as_contract(&consumer, || {
        assert_eq!(runtime::address_memoized(&env, &registry), expected);
        // Second call is served from instance storage (still correct).
        assert_eq!(runtime::address_memoized(&env, &registry), expected);
        runtime::clear_memo(&env);
        assert_eq!(runtime::address_memoized(&env, &registry), expected);
    });
}
