//! Guards the build-time pins every consumer **actually compiled in** against
//! the deployment manifest (`deployments/testnet.json`):
//!
//! - the account's and the factory's registry paths
//!   (`crates/*/wasm/registry.path`) are the same, and on the manifest's
//!   network they derive the manifest's registry, or the registry a declared
//!   pending migration names (below);
//! - the account's `infra::*` modules (hashes = sha256 of the fetched
//!   `crates/perch-smart-account/wasm/*.wasm`) derive the manifest's
//!   compiler, interpreter, and spending-limit hashes' content addresses
//!   under that registry;
//! - the factory's pinned account wasm hash is the manifest's, and its
//!   WebAuthn verifier the manifest's hash under that registry;
//! - every manifest address is the content address of its recorded hash.
//!
//! **Pending migration.** When the source derives another registry than the
//! manifest records, `deployments/pending-registry.json` must declare exactly
//! that pair for the manifest's network: the source has moved to a layout no
//! deployment has created yet. The test then checks every hash against the
//! manifest and every derived address against the declared registry, and
//! says so. An undeclared mismatch fails, and so does a declaration the
//! manifest has already caught up with.
//!
//! `scripts/fetch-infra-wasm.sh` checks the fetched bytes against the chain
//! and `scripts/verify-deployment.sh` checks the manifest against the chain;
//! this test closes the loop on what was compiled. `scripts/check-pins.sh`
//! applies the same rule offline.
use perch_account_factory::pins;
use perch_smart_account::{constructorless_registry, infra};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, BytesN, Env};

const MANIFEST: &str = include_str!("../../../deployments/testnet.json");
const PENDING: &str = include_str!("../../../deployments/pending-registry.json");

fn hash(m: &serde_json::Value, name: &str) -> [u8; 32] {
    let hex = m["contracts"][name]["sha256"].as_str().expect(name);
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
fn consumers_pin_the_deployment_manifest() {
    let m: serde_json::Value = serde_json::from_str(MANIFEST).expect("manifest");
    let pending: serde_json::Value = serde_json::from_str(PENDING).expect("pending-registry.json");
    let env = Env::default();
    let net = env
        .crypto()
        .sha256(&Bytes::from_slice(
            &env,
            m["network_passphrase"].as_str().unwrap().as_bytes(),
        ))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = net);

    let recorded = Address::from_str(&env, m["registry"]["id"].as_str().unwrap());
    let address =
        |name: &str| Address::from_str(&env, m["contracts"][name]["address"].as_str().expect(name));
    let content = |registry: &Address, name: &str| {
        env.deployer()
            .with_address(registry.clone(), BytesN::from_array(&env, &hash(&m, name)))
            .deployed_address()
    };
    for (name, c) in m["contracts"].as_object().unwrap() {
        if c.get("address").is_none() {
            continue;
        }
        assert_eq!(
            content(&recorded, name),
            address(name),
            "{name} is not at its content address"
        );
    }

    // Both crates derive the same registry from the same path.
    assert_eq!(
        (
            infra::perch_doc_compiler::ROOT_DEPLOYER,
            infra::perch_doc_compiler::ROOT_SALT,
            infra::perch_doc_compiler::REGISTRY_PATH.as_slice(),
        ),
        (
            pins::perch_webauthn_verifier::ROOT_DEPLOYER,
            pins::perch_webauthn_verifier::ROOT_SALT,
            pins::perch_webauthn_verifier::REGISTRY_PATH.as_slice(),
        )
    );
    let derived = constructorless_registry(&env);
    assert_eq!(pins::perch_webauthn_verifier::registry(&env), derived);

    let network = m["network"].as_str().unwrap();
    let declared = &pending[network];
    if derived == recorded {
        assert!(
            declared.is_null(),
            "{network}.json now records the derived registry: delete the {network} entry \
             from deployments/pending-registry.json"
        );
    } else {
        let strkey = |k: &str| declared[k].as_str().map(|s| Address::from_str(&env, s));
        assert!(
            strkey("recorded") == Some(recorded.clone())
                && strkey("derived") == Some(derived.clone()),
            "the source derives another registry than {network}.json records, and \
             deployments/pending-registry.json does not declare that migration"
        );
        println!(
            "pending registry migration on {network}: {network}.json records {}, this source \
             derives {}; checking the pins against the derived registry",
            m["registry"]["id"].as_str().unwrap(),
            declared["derived"].as_str().unwrap(),
        );
    }

    assert_eq!(
        infra::perch_doc_compiler::address(&env),
        content(&derived, "perch-doc-compiler")
    );
    assert_eq!(
        infra::perch_interpreter::address(&env),
        content(&derived, "perch-interpreter")
    );
    assert_eq!(
        infra::perch_spending_limit::address(&env),
        content(&derived, "perch-spending-limit")
    );
    assert_eq!(pins::account::WASM_HASH, hash(&m, "perch-account"));
    assert_eq!(
        pins::perch_webauthn_verifier::address(&env),
        content(&derived, "perch-webauthn-verifier")
    );
}
