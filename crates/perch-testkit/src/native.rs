//! Native mode: the bare-minimum, ship-first bootstrap. Registers the four
//! perch contract *types* directly into a unit [`Env`], wires their addresses,
//! binds the network, mocks auth, and hands back a fully wired [`World`] with
//! typed clients.
//!
//! The compiler + interpreter are registered at exactly the content addresses
//! the account's `apply_doc` resolves them to: the `stateless` subregistry is
//! derived from the pinned `PERCH_REGISTRY` by name-salt, a tiny [`MockRegistry`]
//! stands in there and answers `fetch_hash`, and each infra type is registered at
//! `perch_registry_resolve::address(stateless, hash)`. So native mode drives the
//! *real* resolution path (name-salt → fetch the hash → derive the address)
//! without a live registry contract or any wasm artifact — see [`crate::faithful`]
//! for the phase-2 variant on the true registry wasm.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_interpreter::{PerchInterpreter, PerchInterpreterClient};
use perch_smart_account::{compiler, interpreter, stateless, PERCH_REGISTRY};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{contract, contractimpl, vec, Address, Bytes, BytesN, Env, String, Vec};
use stellar_accounts::smart_account::Signer;

use crate::fixture::{self, AnyKeyVerifier, FIXTURE_VERIFIERS};
use crate::Bootstrap;

/// A minimal stand-in for the stateless registry's `Publishable::fetch_hash`,
/// deployed at the derived `stateless` subregistry address so the account's
/// runtime resolution reaches it. Its `wasm_name → hash` map is seeded directly
/// in storage by [`deploy_registry`]; the hash it returns is what the account
/// derives the content-addressed infra address from.
#[contract]
pub struct MockRegistry;

#[contractimpl]
impl MockRegistry {
    pub fn fetch_hash(env: Env, wasm_name: String, _version: Option<String>) -> BytesN<32> {
        env.storage()
            .persistent()
            .get(&wasm_name)
            .expect("wasm_name not seeded in the mock registry")
    }
}

/// The synthetic content hashes native mode assigns the two infra contracts.
/// Arbitrary but deterministic (`sha256(wasm_name)`): the account fetches these
/// from [`MockRegistry`] and both sides derive the same address from them. Unit
/// mode registers *types*, not wasm, so there is no real bytecode hash to use.
fn infra_hashes(env: &Env) -> (BytesN<32>, BytesN<32>) {
    let h = |name: &str| {
        env.crypto()
            .sha256(&Bytes::from_slice(env, name.as_bytes()))
            .to_bytes()
    };
    (h(compiler::WASM_NAME), h(interpreter::WASM_NAME))
}

/// Derive the `stateless` subregistry from the pinned perch registry (name-salt,
/// exactly as the account does), deploy [`MockRegistry`] there, and seed its
/// `wasm_name → hash` map. Returns the stateless registry address (the deployer
/// the compiler + interpreter content-address off). Network-dependent, so it
/// must run after the network bind.
fn deploy_registry(env: &Env) -> Address {
    let perch = Address::from_str(env, PERCH_REGISTRY);
    let registry = stateless::address(env, &perch);
    env.register_at(&registry, MockRegistry, ());
    let (hc, hi) = infra_hashes(env);
    env.as_contract(&registry, || {
        let p = env.storage().persistent();
        p.set(&String::from_str(env, compiler::WASM_NAME), &hc);
        p.set(&String::from_str(env, interpreter::WASM_NAME), &hi);
    });
    registry
}

/// Register the compiler + interpreter types at the content addresses the
/// account derives under the CURRENTLY bound network. Derivation is
/// network-dependent, so this must run after the network is bound — and again
/// if a test rebinds the ledger (see [`World::reregister_infra_for_current_network`]).
fn register_infra_at_derived(env: &Env, registry: &Address) -> (Address, Address) {
    let (hc, hi) = infra_hashes(env);
    let compiler_addr = perch_registry_resolve::address(env, registry, &hc);
    env.register_at(&compiler_addr, PerchDocCompiler, ());
    let interpreter_addr = perch_registry_resolve::address(env, registry, &hi);
    env.register_at(&interpreter_addr, PerchInterpreter, ());
    (compiler_addr, interpreter_addr)
}

/// A fully wired unit-`Env` world: the account, the three stateless infra
/// contracts, their addresses, and the admin signer set. Typed clients are
/// handed out by accessor methods (each clones the cheap `Rc`-backed `Env`, so
/// there is no self-borrow).
pub struct World {
    /// The unit host every contract shares.
    pub env: Env,
    /// The stateless-registry address the account resolves infra through —
    /// derived from the pinned `PERCH_REGISTRY` by name-salt, where native mode
    /// deploys a [`MockRegistry`] answering `fetch_hash`. Always `Some` in native
    /// mode now that resolution runs for real; [`crate::faithful`] mode populates
    /// it with the true registry.
    pub registry: Option<Address>,
    /// The stateless doc-compiler (`compile_doc`).
    pub compiler: Address,
    /// The interpreter, attachable as an OZ policy.
    pub interpreter: Address,
    /// The ed25519 verifier backing the admin signer.
    pub verifier: Address,
    /// The `PerchAccount` (constructor-installed admin-root as rule 0).
    pub account: Address,
    /// The admin signer set handed to the account constructor.
    pub admin_signers: Vec<Signer>,
}

impl World {
    /// Typed client for the doc-compiler.
    pub fn compiler_client(&self) -> PerchDocCompilerClient<'_> {
        PerchDocCompilerClient::new(&self.env, &self.compiler)
    }

    /// Typed client for the interpreter.
    pub fn interpreter_client(&self) -> PerchInterpreterClient<'_> {
        PerchInterpreterClient::new(&self.env, &self.interpreter)
    }

    /// Typed client for the account — the `apply_doc` entry point.
    pub fn account_client(&self) -> PerchAccountClient<'_> {
        PerchAccountClient::new(&self.env, &self.account)
    }

    /// The fixture's frozen canonical `doc_hash`, in this world's `Env`.
    pub fn ci_publish_doc_hash(&self) -> BytesN<32> {
        fixture::ci_publish_doc_hash(&self.env)
    }

    /// Re-derive the whole resolution chain under the CURRENTLY bound network —
    /// the `stateless` subregistry (with its mock), then the compiler +
    /// interpreter — returning the new `(compiler, interpreter)`. `build()` does
    /// this once after the fixture-network bind; a test that rebinds the ledger
    /// to another network (to prove cross-network rejection) calls it so the
    /// account's resolution reaches a real compiler at the *new* network's
    /// derived address — one that then returns `WrongNetwork` for the foreign
    /// document. The stateless address is network-dependent, so the mock must be
    /// re-stood-up at the new derivation, not reused from `self.registry`.
    pub fn reregister_infra_for_current_network(&self) -> (Address, Address) {
        let registry = deploy_registry(&self.env);
        register_infra_at_derived(&self.env, &registry)
    }
}

/// Build a native-mode [`World`] from a configured [`Bootstrap`].
///
/// The compiler + interpreter now live at content-addressed derivations rather
/// than sequential `register()` ids, so their addresses (and any snapshot that
/// embeds them) are a function of the pinned registry id, the fixture network,
/// and the infra hashes — stable across runs, but not the old sequential ids.
pub(crate) fn build(cfg: Bootstrap) -> World {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();

    // Bind the test chain to the requested network passphrase, if any.
    if let Some(net) = &cfg.network {
        let net_id = env
            .crypto()
            .sha256(&Bytes::from_slice(&env, net.as_bytes()))
            .to_array();
        env.ledger().with_mut(|l| l.network_id = net_id);
    }

    // Derive the stateless subregistry from the pinned perch registry, deploy
    // the mock registry there, then register the compiler + interpreter at the
    // content addresses `apply_doc` derives from it — so the zero-arg
    // `apply_doc(doc)` resolves to these by name-salt → fetch hash → derive,
    // exactly as on-chain, with no live registry contract. All network-dependent,
    // so it runs after the network bind above.
    let registry = deploy_registry(&env);
    let (compiler, interpreter) = register_infra_at_derived(&env, &registry);
    let verifier = env.register(PerchEd25519Verifier, ());
    for addr in FIXTURE_VERIFIERS {
        env.register_at(&Address::from_str(&env, addr), AnyKeyVerifier, ());
    }

    let admin_signers = vec![
        &env,
        Signer::External(
            verifier.clone(),
            Bytes::from_array(&env, &cfg.admin_ed25519),
        ),
    ];
    let account = env.register(PerchAccount, (admin_signers.clone(),));

    World {
        env,
        registry: Some(registry),
        compiler,
        interpreter,
        verifier,
        account,
        admin_signers,
    }
}
