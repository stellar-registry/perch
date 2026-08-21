//! Native mode: the bare-minimum, ship-first bootstrap. Registers the four
//! perch contract *types* directly into a unit [`Env`], wires their addresses,
//! binds the network, mocks auth, and hands back a fully wired [`World`] with
//! typed clients.
//!
//! The compiler + interpreter are registered at exactly the content addresses
//! the account's `apply_doc` resolves them to: `stateless` = name-salt(perch
//! registry, "stateless"), then each infra's pinned wasm hash derives
//! `deployer(stateless, hash)`, and the infra type is registered there.
//! Resolution is pinned (offline, no `fetch_hash` XCC), so native mode needs no
//! registry contract, no mock, and no wasm artifact — just the same derivation
//! the account uses. See [`crate::faithful`] for the phase-2 variant on the true
//! registry wasm.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_interpreter::{PerchInterpreter, PerchInterpreterClient};
use perch_smart_account::{compiler, interpreter, stateless, PERCH_REGISTRY};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, Vec};
use stellar_accounts::smart_account::Signer;

use crate::fixture::{self, AnyKeyVerifier, FIXTURE_VERIFIERS};
use crate::Bootstrap;

/// Register the compiler + interpreter types at the content addresses the
/// account derives — `deployer(stateless, pinned_hash)` — under the
/// CURRENTLY bound network. Derivation is network-dependent, so this runs after
/// the network is bound, and again if a test rebinds the ledger (see
/// [`World::reregister_infra_for_current_network`]).
fn register_infra_at_derived(env: &Env) -> (Address, Address) {
    let stateless = stateless_address(env);
    let compiler_addr = compiler::address(env, &stateless);
    env.register_at(&compiler_addr, PerchDocCompiler, ());
    let interpreter_addr = interpreter::address(env, &stateless);
    env.register_at(&interpreter_addr, PerchInterpreter, ());
    (compiler_addr, interpreter_addr)
}

/// The `stateless` subregistry address the account derives — name-salt(perch
/// registry, "stateless") under the current env's network.
fn stateless_address(env: &Env) -> Address {
    stateless::address(env, &Address::from_str(env, PERCH_REGISTRY))
}

/// A fully wired unit-`Env` world: the account, the three stateless infra
/// contracts, their addresses, and the admin signer set. Typed clients are
/// handed out by accessor methods (each clones the cheap `Rc`-backed `Env`, so
/// there is no self-borrow).
pub struct World {
    /// The unit host every contract shares.
    pub env: Env,
    /// The `stateless` subregistry address the account content-addresses its
    /// infra off (`deployer(stateless, hash)`). Native mode deploys no contract there —
    /// resolution is a pure offline derivation — but the field is populated for
    /// parity with [`crate::faithful`] mode, which puts the real registry here.
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

    /// Re-register the compiler + interpreter at the content addresses derived
    /// under the CURRENTLY bound network, returning the new `(compiler,
    /// interpreter)`. `build()` does this once after the fixture-network bind; a
    /// test that rebinds the ledger to another network (to prove cross-network
    /// rejection) calls it so the account's resolution reaches a real compiler at
    /// the *new* network's derived address — one that then returns `WrongNetwork`
    /// for the foreign document. Content addresses are network-dependent, so they
    /// must be re-registered after a rebind.
    pub fn reregister_infra_for_current_network(&self) -> (Address, Address) {
        register_infra_at_derived(&self.env)
    }
}

/// Build a native-mode [`World`] from a configured [`Bootstrap`].
///
/// The compiler + interpreter live at content-addressed derivations rather than
/// sequential `register()` ids, so their addresses (and any snapshot that embeds
/// them) are a function of the derived `stateless` id, the pinned infra
/// hashes, and the fixture network — stable across runs, but not the old
/// sequential ids.
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

    // Register the compiler + interpreter at the content addresses `apply_doc`
    // derives — `deployer(stateless, pinned_hash)` — so the zero-arg
    // `apply_doc(doc)` resolves to exactly these, offline, with no registry
    // contract. Network-dependent, so it runs after the network bind above.
    let (compiler, interpreter) = register_infra_at_derived(&env);
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

    let registry = stateless_address(&env);
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
