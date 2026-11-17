//! Verified verifiers in a unit env.
//!
//! An account's constructor admits an external admin signer only when its
//! verifier is a contract `perch/verifiers` deployed: a wasm at its content
//! address in that registry (`perch_smart_account::is_verified_verifier`).
//! And the doc compiler resolves a document's `verifier-name` through that
//! registry's `fetch_hash`. [`deploy`] and its siblings put a verifier where
//! the registry's `deploy_stateless` would, with no auth and no registry
//! contract involved; [`name`] publishes a `name@version` for it in
//! [`RegistryStub`], which [`registry`] registers at the derived
//! `perch/verifiers` address.

use soroban_sdk::testutils::ContractFunctionSet;
use soroban_sdk::{
    contract, contracterror, contractimpl, Address, BytesN, ContractExecutable, Env, Executable,
    Map, String,
};

/// The `perch/verifiers` address under the env's current network.
pub fn registry_address(env: &Env) -> Address {
    perch_smart_account::verifier_registry(env)
}

/// Register [`RegistryStub`] at [`registry_address`], once, and return it.
pub fn registry(env: &Env) -> Address {
    let at = registry_address(env);
    if at.executable().is_none() {
        env.register_at(&at, RegistryStub, ());
    }
    at
}

/// Deploy `contract`, uploaded under a fresh hash, at that hash's content
/// address in `perch/verifiers`.
pub fn deploy<C: ContractFunctionSet + 'static>(env: &Env, contract: C) -> Address {
    let hash = env.upload(contract);
    instance(env, &hash)
}

/// [`deploy`] `contract` and publish it as `name_at_version` ([`name`]): a
/// verifier a document can name.
pub fn deploy_named<C: ContractFunctionSet + 'static>(
    env: &Env,
    contract: C,
    name_at_version: &str,
) -> Address {
    let verifier = deploy(env, contract);
    name(env, name_at_version, &verifier);
    verifier
}

/// The name [`deploy_auto`] publishes `verifier` under:
/// `v-<the first 16 hex of sha256(its strkey)>@1.0.0`, one per address.
pub fn auto_name(verifier: &Address) -> std::string::String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(crate::delta::strkey(verifier).as_bytes());
    std::format!("v-{}@1.0.0", &hex::encode(digest)[..16])
}

/// [`deploy`] `contract` and publish it under [`auto_name`]: for harnesses
/// that rename abstract verifiers onto real ones.
pub fn deploy_auto<C: ContractFunctionSet + 'static>(env: &Env, contract: C) -> Address {
    let verifier = deploy(env, contract);
    name(env, &auto_name(&verifier), &verifier);
    verifier
}

/// Deploy `contract`, uploaded under `hash` (a pinned wasm's, say), at that
/// hash's content address in `perch/verifiers`.
pub fn deploy_at_hash<C: ContractFunctionSet + 'static>(
    env: &Env,
    hash: &BytesN<32>,
    contract: C,
) -> Address {
    env.upload_at(hash.clone(), contract);
    instance(env, hash)
}

/// Deploy a verifier's wasm at its content address in `perch/verifiers`.
pub fn deploy_wasm(env: &Env, wasm: &[u8]) -> Address {
    let hash = env
        .deployer()
        .upload_contract_wasm(soroban_sdk::Bytes::from_slice(env, wasm));
    instance(env, &hash)
}

/// The instance of the code uploaded under `hash` at its content address in
/// `perch/verifiers`, as the registry's `deploy_stateless` puts one there.
fn instance(env: &Env, hash: &BytesN<32>) -> Address {
    let registry = registry(env);
    let at = env
        .deployer()
        .with_address(registry.clone(), hash.clone())
        .deployed_address();
    if at.executable().is_none() {
        env.as_contract(&registry, || {
            env.deployer()
                .with_current_contract(hash.clone())
                .deploy_contract(ContractExecutable::Wasm(hash.clone()), ())
        });
    }
    at
}

/// Publish `name_at_version` (`<name>@<version>`) in [`RegistryStub`] for the
/// code `verifier` runs: the hash a document naming it resolves to.
pub fn name(env: &Env, name_at_version: &str, verifier: &Address) {
    let Some(Executable::Wasm(hash)) = verifier.executable() else {
        panic!("{verifier:?} runs no wasm");
    };
    let (name, version) =
        perch_ir::parse_verifier_name(name_at_version).expect("a `<name>@<version>`");
    RegistryStubClient::new(env, &registry(env)).set_hash(
        &String::from_str(env, name),
        &String::from_str(env, version),
        &hash,
    );
}

/// `doc` with every verifier it names by contract id alone named instead:
/// for each such address, in declaration order, a fresh `contract()`
/// deployed and published as `stand-in-<n>@1.0.0`, and every signer under
/// that address moved to it. The signers' ids and keys, the rules and the
/// recovery member are kept.
pub fn name_raw<C: ContractFunctionSet + 'static>(
    env: &Env,
    doc: &perch_ir::PolicyDoc,
    contract: impl Fn() -> C,
) -> perch_ir::PolicyDoc {
    let mut out = doc.clone();
    for (n, raw) in perch_ir::unverified_verifiers(doc).into_iter().enumerate() {
        let name = std::format!("stand-in-{n}@1.0.0");
        let at = crate::delta::strkey(&deploy_named(env, contract(), &name));
        for s in &mut out.signers {
            if let perch_ir::SignerMethod::External {
                verifier,
                verifier_name: verifier_name @ None,
                ..
            } = &mut s.method
            {
                if verifier == raw {
                    *verifier = at.clone();
                    *verifier_name = Some(name.clone());
                }
            }
        }
    }
    out
}

/// Why [`RegistryStub::fetch_hash`] has no hash: the registry's own codes.
#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StubError {
    NoSuchWasmPublished = 1,
    NoSuchVersion = 2,
}

/// A stand-in for the `perch/verifiers` registry's `fetch_hash`, with a
/// setter in place of `publish` and its manager. Hashes can be repointed,
/// which the real registry never does for a published version.
#[contract]
pub struct RegistryStub;

#[contractimpl]
impl RegistryStub {
    /// The hash published as `wasm_name@version`.
    pub fn fetch_hash(
        env: Env,
        wasm_name: String,
        version: Option<String>,
    ) -> Result<BytesN<32>, StubError> {
        let versions: Map<String, BytesN<32>> = env
            .storage()
            .persistent()
            .get(&wasm_name)
            .ok_or(StubError::NoSuchWasmPublished)?;
        versions
            .get(version.ok_or(StubError::NoSuchVersion)?)
            .ok_or(StubError::NoSuchVersion)
    }

    /// Publish (or repoint) `wasm_name@version` as `hash`.
    pub fn set_hash(env: Env, wasm_name: String, version: String, hash: BytesN<32>) {
        let mut versions: Map<String, BytesN<32>> = env
            .storage()
            .persistent()
            .get(&wasm_name)
            .unwrap_or(Map::new(&env));
        versions.set(version, hash);
        env.storage().persistent().set(&wasm_name, &versions);
    }
}
