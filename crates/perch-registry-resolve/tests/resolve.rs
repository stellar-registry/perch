//! Tests for `registry_contract!` — pinned and runtime resolution modes.
//!
//! The derivation under test is pure SDK: `address(env, registry)` must equal
//! `env.deployer().with_address(registry, wasm_hash).deployed_address()`, which
//! is what the registry uses when it actually deploys a stateless singleton with
//! `salt == wasm_hash`. We prove that against a real `deploy_v2` (pinned mode)
//! and against a real cross-contract `fetch_hash` (runtime mode).

use perch_registry_resolve::registry_contract;
use soroban_sdk::{
    contract, contractimpl, testutils::Address as _, Address, Bytes, BytesN, Env, String,
};

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

// Address-only: no `client:` — resolves the address (and, pinned, the hash)
// without naming or linking any client type. This is how the account resolves
// the interpreter, which it uses solely as a policy-map key.
registry_contract! {
    mod: address_only,
    wasm_name: "fixture",
    hash: "33d12fec8f6f3ddf2eb0ec76ee9a75a9e37d1fa20af35908d90d278af8264311",
}

// Name-salted mode: salt = sha256(normalized name). Resolves a *named* deploy
// (e.g. a subregistry) from its PARENT registry — how the account derives the
// stateless subregistry from the pinned perch registry.
registry_contract! {
    mod: named,
    deploy_name: "fixture",
}

// Name-salted mode normalizes the name (lowercase, `_`→`-`) before hashing, to
// match the registry's `NormalizedName` salt.
registry_contract! {
    mod: named_norm,
    deploy_name: "My_Sub",
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
fn address_only_matches_pinned_derivation() {
    // The no-`client:` module derives the identical address + hash as the
    // client-bearing one; it only omits `client()`.
    let env = Env::default();
    let registry = Address::generate(&env);
    assert_eq!(
        address_only::address(&env, &registry),
        pinned::address(&env, &registry)
    );
    assert_eq!(address_only::WASM_HASH, pinned::WASM_HASH);
}

#[test]
fn named_address_equals_name_salt_derivation() {
    // salt = sha256(name); address = deployer(parent, salt).deployed_address().
    let env = Env::default();
    let parent = Address::generate(&env);
    let salt = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"fixture"))
        .to_bytes();
    let expected = env
        .deployer()
        .with_address(parent.clone(), salt)
        .deployed_address();
    assert_eq!(named::address(&env, &parent), expected);
    assert_eq!(named::DEPLOY_NAME, "fixture");
}

#[test]
fn named_normalizes_the_name_for_the_salt() {
    // "My_Sub" → "my-sub"; the salt hashes the normalized form.
    let env = Env::default();
    let parent = Address::generate(&env);
    assert_eq!(named_norm::DEPLOY_NAME, "my-sub");
    let salt = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"my-sub"))
        .to_bytes();
    let expected = env
        .deployer()
        .with_address(parent.clone(), salt)
        .deployed_address();
    assert_eq!(named_norm::address(&env, &parent), expected);
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
