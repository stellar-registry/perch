//! The resolver-macro pins for the perch infra published to
//! `unverified/perch/stateless` on **testnet**. Proves `registry_contract!`'s
//! pinned mode derives the exact content-addressed ids deployed on testnet:
//! `address = sha256(network_id || Address-preimage(registry, salt = wasm_hash))`,
//! so pinning testnet's network id + the stateless registry reproduces the live
//! ids. If perch republishes any infra wasm (new hash) or redeploys the stateless
//! registry (new id), update the pins here and in `perch-registry-resolve` docs.
use perch_registry_resolve::registry_contract;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, Env};

/// `unverified/perch/stateless` on testnet (the content-addressed deployer).
const STATELESS_REGISTRY: &str = "CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O";

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

    let registry = Address::from_str(&env, STATELESS_REGISTRY);

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
