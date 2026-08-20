//! Native mode: the bare-minimum, ship-first bootstrap. Registers the four
//! perch contract *types* directly into a unit [`Env`] (no wasm, no registry
//! deploy), wires their addresses, binds the network, mocks auth, and hands
//! back a fully wired [`World`] with typed clients.
//!
//! This is the exact `setup()` every `apply_doc`-style suite used to hand-roll,
//! hoisted into one call. It has **no** upstream dependency and needs no wasm
//! artifact — see [`crate::faithful`] for the phase-2 variant that exercises
//! real registry-resolved wiring.

use perch_account::{PerchAccount, PerchAccountClient};
use perch_doc_compiler::{PerchDocCompiler, PerchDocCompilerClient};
use perch_ed25519_verifier::PerchEd25519Verifier;
use perch_interpreter::{PerchInterpreter, PerchInterpreterClient};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, Vec};
use stellar_accounts::smart_account::Signer;

use crate::fixture::{self, AnyKeyVerifier, FIXTURE_VERIFIERS};
use crate::Bootstrap;

/// A fully wired unit-`Env` world: the account, the three stateless infra
/// contracts, their addresses, and the admin signer set. Typed clients are
/// handed out by accessor methods (each clones the cheap `Rc`-backed `Env`, so
/// there is no self-borrow).
pub struct World {
    /// The unit host every contract shares.
    pub env: Env,
    /// The registry address, when one was deployed. `None` in native mode
    /// (native wires addresses by hand rather than resolving through a real
    /// registry); populated by [`crate::faithful`] mode.
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
}

/// Build a native-mode [`World`] from a configured [`Bootstrap`].
///
/// The registration order is load-bearing: it reproduces, operation for
/// operation, the `setup()` that `apply_doc.rs` shipped, so the committed
/// `test_snapshots/*` regenerate byte-identically.
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

    let compiler = env.register(PerchDocCompiler, ());
    let interpreter = env.register(PerchInterpreter, ());
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
        registry: None,
        compiler,
        interpreter,
        verifier,
        account,
        admin_signers,
    }
}
