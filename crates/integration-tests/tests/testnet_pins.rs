//! The resolver-macro pins for the perch infra published to
//! `unverified/perch/stateless` on **testnet**. Proves `registry_contract!`
//! derives the exact live ids deployed on testnet:
//! `address = sha256(network_id || Address-preimage(registry, salt))`, so pinning
//! testnet's network id + the perch registry reproduces the whole chain — the
//! `stateless` subregistry (name-salt) and each content-addressed infra id. This
//! mirrors what the account does: pin only the perch registry, derive the rest.
//! If perch republishes an infra wasm (new hash), redeploys the stateless
//! registry, or moves the perch registry, update the pins here + in the account.
use perch_registry_resolve::registry_contract;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, Env};

/// The perch registry (`unverified/perch`) on testnet — the single pinned anchor
/// (matches `perch_smart_account::PERCH_REGISTRY`).
const PERCH_REGISTRY: &str = "CASB2M4JQSGP3QHFBGK5U6DGJXJX34GX37C2JFBU73LKKDXXNNIZHCP7";
/// `unverified/perch/stateless` on testnet (the content-addressed deployer),
/// derived below from `PERCH_REGISTRY` + name "stateless".
const STATELESS_REGISTRY: &str = "CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O";

// The stateless subregistry, resolved from the perch registry by name-salt.
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
registry_contract! {
    mod: doc_compiler,
    wasm_name: "perch-doc-compiler",
    client: perch_doc_compiler::DocCompilerClient,
    hash: "3645bd0de34f4896c5e6fd8ca141713eb9f8658728bf16d82026418d4ab0b27f",
}
registry_contract! {
    mod: interpreter,
    wasm_name: "perch-interpreter",
    client: perch_interpreter::PerchInterpreterClient,
    hash: "f8320d3031e7dffe51fac14177c5353b8818f8e6df3bda6c4c1b714f5ce1d858",
}

#[test]
fn pins_derive_the_deployed_testnet_addresses() {
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

    // The account pins only the perch registry; the stateless subregistry is a
    // name-salt derivation off it. Prove that derivation lands on the live id,
    // then use it as the deployer for the content-addressed infra below.
    let perch_registry = Address::from_str(&env, PERCH_REGISTRY);
    let registry = stateless::address(&env, &perch_registry);
    assert_eq!(registry, Address::from_str(&env, STATELESS_REGISTRY));

    assert_eq!(
        verifier::address(&env, &registry),
        Address::from_str(
            &env,
            "CBVCTXCSF4HJJCQLLIM543CH5MJW3A2MMZ2T35GSCSN6QSC6BGSDJNNY"
        ),
    );
    assert_eq!(
        doc_compiler::address(&env, &registry),
        Address::from_str(
            &env,
            "CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY"
        ),
    );
    assert_eq!(
        interpreter::address(&env, &registry),
        Address::from_str(
            &env,
            "CBYWKTO6IALDRI7LQM2IBHK7SDKXKO5JTMJCVQVKEI4XMJ724ZVJI2YM"
        ),
    );
}
