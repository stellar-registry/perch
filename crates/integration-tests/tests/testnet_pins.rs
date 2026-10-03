//! Guards the build-time pins every consumer **actually compiled in** against
//! the deployment manifest (`deployments/testnet.json`):
//!
//! - the account's `stateless_registry()` is the manifest's registry, and its
//!   `infra::*` modules (hashes = sha256 of the fetched
//!   `crates/perch-smart-account/wasm/*.wasm`) derive the manifest's
//!   compiler, interpreter, and spending-limit addresses;
//! - the factory's pinned account wasm hash and WebAuthn verifier are the
//!   manifest's;
//! - every manifest address is the content address of its recorded hash.
//!
//! `scripts/fetch-infra-wasm.sh` checks the fetched bytes against the chain
//! and `scripts/verify-deployment.sh` checks the manifest against the chain;
//! this test closes the loop on what was compiled. A cache built locally by
//! `scripts/build-stack.sh` for another registry fails it by design.
use perch_account_factory::pins;
use perch_smart_account::{infra, stateless_registry};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, BytesN, Env};

const MANIFEST: &str = include_str!("../../../deployments/testnet.json");

fn hash(m: &serde_json::Value, name: &str) -> [u8; 32] {
    let hex = m["contracts"][name]["sha256"].as_str().expect(name);
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn consumers_pin_the_deployment_manifest() {
    let m: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest");
    let env = Env::default();
    let net = env
        .crypto()
        .sha256(&Bytes::from_slice(
            &env,
            m["network_passphrase"].as_str().unwrap().as_bytes(),
        ))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net);

    let registry = Address::from_str(&env, m["registry"]["id"].as_str().unwrap());
    let address =
        |name: &str| Address::from_str(&env, m["contracts"][name]["address"].as_str().expect(name));
    for (name, c) in m["contracts"].as_object().unwrap() {
        if c.get("address").is_none() {
            continue;
        }
        let content = env
            .deployer()
            .with_address(registry.clone(), BytesN::from_array(&env, &hash(&m, name)))
            .deployed_address();
        assert_eq!(
            content,
            address(name),
            "{name} is not at its content address"
        );
    }

    assert_eq!(stateless_registry(&env), registry);
    assert_eq!(
        infra::perch_doc_compiler::address(&env),
        address("perch-doc-compiler")
    );
    assert_eq!(
        infra::perch_interpreter::address(&env),
        address("perch-interpreter")
    );
    assert_eq!(
        infra::perch_spending_limit::address(&env),
        address("perch-spending-limit")
    );
    assert_eq!(pins::account::WASM_HASH, hash(&m, "perch-account"));
    assert_eq!(
        pins::perch_webauthn_verifier::address(&env),
        address("perch-webauthn-verifier")
    );
}
