//! Guards the **account's actual shipped pins** — the `PERCH_REGISTRY` anchor and
//! the `compiler`/`interpreter` modules whose hashes are the sha256 of the
//! committed `crates/perch-smart-account/wasm/*.wasm` — against the live testnet
//! deployment. Binds testnet's network id and asserts that `stateless` =
//! name-salt(perch registry, "stateless") and that the pinned wasm hashes derive
//! the exact content-addressed ids live on testnet. So if the committed wasm is
//! refreshed to a version that isn't deployed (or the anchor drifts), CI fails
//! here.
use perch_registry_resolve::registry_contract;
use perch_smart_account::{compiler, interpreter, stateless, PERCH_REGISTRY};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, Env};

// The verifier is content-addressed too, but the account doesn't resolve it
// (docs name it directly); pinned here only to guard its live id.
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

    // The account pins only the perch registry; the `stateless` subregistry is a
    // name-salt derivation off it (the account uses this exact module).
    let perch_registry = Address::from_str(&env, PERCH_REGISTRY);
    let stateless = stateless::address(&env, &perch_registry);

    // The account's *actual* pinned compiler + interpreter (hashes = sha256 of
    // the committed `wasm/*.wasm`) derive the live ids.
    assert_eq!(
        compiler::address(&env, &stateless),
        Address::from_str(
            &env,
            "CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY"
        ),
    );
    assert_eq!(
        interpreter::address(&env, &stateless),
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
