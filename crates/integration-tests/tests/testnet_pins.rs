//! Guards the **account's actual shipped pins** — the build-time-resolved
//! `stateless_registry()` id and the `infra::*` modules whose hashes are the
//! sha256 of the fetched `crates/perch-smart-account/wasm/*.wasm` — against the
//! live testnet deployment. Binds testnet's network id and asserts (a) the
//! resolved `stateless_registry()` equals `name-salt(perch registry, "stateless")`
//! and (b) the pinned wasm hashes derive the exact content-addressed ids live on
//! testnet. So if the fetched wasm/id is a version that isn't deployed (or drifts),
//! CI fails here.
use perch_registry_resolve::registry_contract;
use perch_smart_account::{infra, stateless_registry};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, Env};

/// The perch registry (`unverified/perch`) on testnet — used to cross-check the
/// pinned stateless id against `name-salt(perch registry, "stateless")`.
const PERCH_REGISTRY: &str = "CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7";

// The stateless subregistry by name-salt, and the verifier (content-addressed but
// not resolved by the account — docs name it directly), pinned here to guard the
// live ids.
registry_contract! {
    mod: stateless,
    deploy_name: "stateless",
}
registry_contract! {
    mod: verifier,
    wasm_name: "perch-ed25519-verifier",
    client: perch_ed25519_verifier::PerchEd25519VerifierClient,
    hash: "6ddf7cadcb85059cffa5b127f994490ee560f8a46b2bb437975fbe5bd0cc7de4",
}

#[test]
fn account_pins_derive_the_deployed_testnet_addresses() {
    let env = Env::default();
    // Bind to Stellar testnet's network id — address derivation is a function of
    // (network_id, registry, salt=wasm_hash).
    let net = env
        .crypto()
        .sha256(&Bytes::from_slice(
            &env,
            b"Test SDF Network ; September 2015",
        ))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net);

    // The account resolves the stateless registry id by name at build time;
    // cross-check it is exactly the name-salt derivation from the perch registry.
    let stateless = stateless_registry(&env);
    let perch_registry = Address::from_str(&env, PERCH_REGISTRY);
    assert_eq!(stateless, stateless::address(&env, &perch_registry));

    // The account's *actual* pinned compiler + interpreter (hashes = sha256 of
    // the fetched `wasm/*.wasm`) derive the live ids.
    assert_eq!(
        infra::perch_doc_compiler::address(&env),
        Address::from_str(
            &env,
            "CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY"
        ),
    );
    assert_eq!(
        infra::perch_interpreter::address(&env),
        Address::from_str(
            &env,
            "CBYWKTO6IALDRI7LQM2IBHK7SDKXKO5JTMJCVQVKEI4XMJ724ZVJI2YM"
        ),
    );
    assert_eq!(
        verifier::address(&env, &stateless),
        Address::from_str(
            &env,
            "CBVCTXCSF4HJJCQLLIM543CH5MJW3A2MMZ2T35GSCSN6QSC6BGSDJNNY"
        ),
    );
}
