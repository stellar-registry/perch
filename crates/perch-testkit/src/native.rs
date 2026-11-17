//! Native mode: the bare-minimum, ship-first bootstrap. Registers the four
//! perch contract *types* directly into a unit [`Env`], wires their addresses,
//! binds the network, mocks auth, and hands back a fully wired [`World`] with
//! typed clients.
//!
//! The compiler and interpreter are registered at exactly the content addresses
//! the account's `apply_doc` resolves them to: each infra address is
//! `deployer(constructorless_registry, pinned_wasm_hash)`, and the infra type is
//! registered there. Resolution is pinned (offline, no `fetch_hash` XCC), so
//! native mode needs no registry contract, no mock, and no wasm artifact — just
//! the same derivation the account uses. See [`crate::faithful`] for the phase-2
//! variant on the true registry wasm.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_account_types::Signer;
use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_interpreter::{PerchInterpreter, PerchInterpreterClient};
use perch_smart_account::{constructorless_registry, infra};
use perch_spending_limit::PerchSpendingLimit;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, Vec};

use crate::fixture::{self, AnyKeyVerifier, FIXTURE_VERIFIERS};
use crate::{verifiers, Bootstrap};

/// The `verifier-name` [`World::verifier`] is published under.
pub const ED25519_VERIFIER_NAME: &str = "perch-ed25519-verifier@1.0.0";

/// The `verifier-name`s [`World::fixture`] gives the fixture's admin and ci
/// verifiers, in [`FIXTURE_VERIFIERS`]'s order.
pub const FIXTURE_VERIFIER_NAMES: [&str; 2] =
    ["fixture-admin-verifier@1.0.0", "fixture-ci-verifier@1.0.0"];

/// Register the compiler + interpreter types at the content addresses the
/// account derives — `deployer(constructorless, pinned_hash)` — under the
/// CURRENTLY bound network. Derivation is network-dependent, so this runs after
/// the network is bound, and again if a test rebinds the ledger (see
/// [`World::reregister_infra_for_current_network`]).
fn register_infra_at_derived(env: &Env) -> (Address, Address) {
    let compiler_addr = infra::perch_doc_compiler::address(env);
    env.register_at(&compiler_addr, PerchDocCompiler, ());
    let interpreter_addr = infra::perch_interpreter::address(env);
    env.register_at(&interpreter_addr, PerchInterpreter, ());
    // The stateful cap policy, at its (placeholder-pinned) content-addressed
    // derivation, so `apply_doc` on a capped document resolves a real contract
    // here and installs the cap beside the interpreter.
    let spending_addr = infra::perch_spending_limit::address(env);
    env.register_at(&spending_addr, PerchSpendingLimit, ());
    (compiler_addr, interpreter_addr)
}

/// A fully wired unit-`Env` world: the account, the three constructorless infra
/// contracts, their addresses, and the admin signer set. Typed clients are
/// handed out by accessor methods (each clones the cheap `Rc`-backed `Env`, so
/// there is no self-borrow).
pub struct World {
    /// The unit host every contract shares.
    pub env: Env,
    /// The registry the account content-addresses its infra off
    /// (`deployer(registry, hash)`, the registry its `registry.path` derives
    /// on the bound network). Native
    /// mode deploys no contract there — resolution is a pure offline
    /// derivation — but the field is populated for parity with
    /// [`crate::faithful`] mode, which puts the real registry here.
    pub registry: Option<Address>,
    /// The stateless doc-compiler (`compile_doc`).
    pub compiler: Address,
    /// The interpreter, attachable as an OZ policy.
    pub interpreter: Address,
    /// The ed25519 verifier backing the admin signer, deployed as
    /// `perch/verifiers` deploys one and published there as
    /// [`ED25519_VERIFIER_NAME`].
    pub verifier: Address,
    /// The [`AnyKeyVerifier`]s [`World::fixture`] names, in
    /// [`FIXTURE_VERIFIER_NAMES`]'s order, published there likewise.
    pub fixture_verifiers: [Address; 2],
    /// The `PerchAccount` (constructor-installed admin as rule 0).
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

    /// The frozen ci-publish fixture as an admin document can hold it: its
    /// two verifiers named ([`FIXTURE_VERIFIER_NAMES`]), at
    /// [`Self::fixture_verifiers`] in place of the frozen addresses, and the
    /// text otherwise as written.
    pub fn fixture(&self) -> std::string::String {
        let mut json = fixture::fixture();
        for (i, frozen) in FIXTURE_VERIFIERS.iter().enumerate() {
            let named = format!(
                r#""verifier": "{}", "verifier-name": "{}""#,
                crate::delta::strkey(&self.fixture_verifiers[i]),
                FIXTURE_VERIFIER_NAMES[i]
            );
            let written = format!(r#""verifier": "{frozen}""#);
            assert!(json.contains(&written), "the fixture names {frozen}");
            json = json.replace(&written, &named);
        }
        json
    }

    /// The canonical `doc_hash` of [`Self::fixture`].
    pub fn fixture_doc_hash(&self) -> BytesN<32> {
        let doc = perch_ir::from_json(&self.fixture()).expect("the fixture parses");
        BytesN::from_array(&self.env, &perch_ir::doc_hash(&doc))
    }

    /// The frozen fixture's canonical `doc_hash`, in this world's `Env`.
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
/// them) are a function of the derived `constructorless` id, the pinned infra
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
    // derives — `deployer(constructorless, pinned_hash)` — so the zero-arg
    // `apply_doc(doc)` resolves to exactly these, offline, with no registry
    // contract. Network-dependent, so it runs after the network bind above.
    let (compiler, interpreter) = register_infra_at_derived(&env);
    // The verifiers an admin document names, where `perch/verifiers`
    // deploys them and published there under their names; the frozen
    // fixture's raw addresses keep a stand-in too.
    let verifier = verifiers::deploy(&env, PerchEd25519Verifier);
    verifiers::name(&env, ED25519_VERIFIER_NAME, &verifier);
    let fixture_verifiers = FIXTURE_VERIFIER_NAMES.map(|name| {
        let v = verifiers::deploy(&env, AnyKeyVerifier);
        verifiers::name(&env, name, &v);
        v
    });
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

    let registry = constructorless_registry(&env);
    World {
        env,
        registry: Some(registry),
        compiler,
        interpreter,
        verifier,
        fixture_verifiers,
        account,
        admin_signers,
    }
}
