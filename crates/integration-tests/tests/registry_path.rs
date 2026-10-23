//! The registry path the account and the factory compile in
//! (`crates/*/wasm/registry.path`): one root deployer and salt, then the named
//! deploys `perch/constructorless`, every hop derived under the ledger's
//! network id.
//!
//! The expected registries are derived here hop by hop, independently of the
//! generated code: the Stellar Registry root on each network is
//! `deployer(GAMPJROH…, sha256("2026-04-24T13:41:00"))` (the registry CLI's
//! deployer and its `.salt` file), and each named deploy is
//! `deployer(parent, sha256(name))`. The roots are the live ones; testnet's and
//! mainnet's `perch/constructorless` are where the named deploys put them.
//!
//! `testnet_pins` checks the path against the deployment manifest, and
//! `release_stack`'s `one_build_resolves_each_networks_own_registry` runs one
//! built account and factory under several networks.
use perch_account_factory::pins;
use perch_registry_resolve::registry_contract;
use perch_smart_account::{constructorless_registry, infra};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{Address, Bytes, BytesN, Env};

const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";
const FUTURENET: &str = "Test SDF Future Network ; October 2022";

const ROOT_DEPLOYER: &str = "GAMPJROHOAW662FINQ4XQOY2ULX5IEGYXCI4SMZYE75EHQBR6PSTJG3M";
const ROOT_SALT: &str = "2026-04-24T13:41:00";

// A registry's named deploy: salt = sha256(name), the registry as deployer.
registry_contract! { mod: perch, deploy_name: "perch" }
registry_contract! { mod: constructorless, deploy_name: "constructorless" }

fn on(passphrase: &str) -> Env {
    let env = Env::default();
    let id = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, passphrase.as_bytes()))
        .to_array();
    env.ledger().with_mut(|l| l.network_id = id);
    env
}

fn root(env: &Env) -> Address {
    let salt = env
        .crypto()
        .sha256(&Bytes::from_slice(env, ROOT_SALT.as_bytes()))
        .to_array();
    env.deployer()
        .with_address(
            Address::from_str(env, ROOT_DEPLOYER),
            BytesN::from_array(env, &salt),
        )
        .deployed_address()
}

#[test]
fn both_crates_compile_in_the_same_root_and_path() {
    let salt: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(ROOT_SALT.as_bytes()).into()
    };
    for (deployer, root_salt, path) in [
        (
            infra::perch_doc_compiler::ROOT_DEPLOYER,
            infra::perch_doc_compiler::ROOT_SALT,
            infra::perch_doc_compiler::REGISTRY_PATH,
        ),
        (
            infra::perch_interpreter::ROOT_DEPLOYER,
            infra::perch_interpreter::ROOT_SALT,
            infra::perch_interpreter::REGISTRY_PATH,
        ),
        (
            infra::perch_spending_limit::ROOT_DEPLOYER,
            infra::perch_spending_limit::ROOT_SALT,
            infra::perch_spending_limit::REGISTRY_PATH,
        ),
        (
            pins::perch_webauthn_verifier::ROOT_DEPLOYER,
            pins::perch_webauthn_verifier::ROOT_SALT,
            pins::perch_webauthn_verifier::REGISTRY_PATH,
        ),
    ] {
        assert_eq!(deployer, ROOT_DEPLOYER);
        assert_eq!(root_salt, salt);
        assert_eq!(path, ["perch", "constructorless"]);
    }
}

#[test]
fn each_network_resolves_perch_constructorless_under_its_own_root() {
    for (passphrase, live_root, registry) in [
        (
            TESTNET,
            "CAAXJETKPYAATU4HVVQUTE2FFBULNFGZNEOC3MS635U5K3GZLAY2HI4M",
            "CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM",
        ),
        (
            MAINNET,
            "CDU4M3LDIOUJJ5F3YXKJ4EJEP5VPRPG6N2LJ5HOQIMN7MNGL3NS3EGUY",
            "CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN",
        ),
    ] {
        let env = on(passphrase);
        let root = root(&env);
        assert_eq!(root, Address::from_str(&env, live_root), "{passphrase}");
        let derived = constructorless::address(&env, &perch::address(&env, &root));
        assert_eq!(derived, Address::from_str(&env, registry), "{passphrase}");
        assert_eq!(constructorless_registry(&env), derived, "{passphrase}");
        assert_eq!(pins::perch_webauthn_verifier::registry(&env), derived);
    }
}

/// Nothing in the build names a network: on one Perch never listed, the same
/// formula gives that network's own chain. No registry exists there unless
/// someone creates it (the root needs the registry deployer's key), so until
/// then every infra call there fails.
#[test]
fn an_unlisted_network_resolves_its_own_chain() {
    let env = on(FUTURENET);
    let derived = constructorless::address(&env, &perch::address(&env, &root(&env)));
    assert_eq!(
        derived,
        Address::from_str(
            &env,
            "CBPWEPHLO2QDXWMWMHLOWCLRKQT24EFH7GYW6G3UOFY45RYOHS32A5JP"
        )
    );
    assert_eq!(constructorless_registry(&env), derived);
}
