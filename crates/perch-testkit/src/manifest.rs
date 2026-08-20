//! Cross-network vision (**defined, not fully built**).
//!
//! The same perch bootstrap should run against three targets: a unit [`Env`]
//! (fast, native), komet (K-framework symbolic), and testnet (real). A
//! [`BootstrapManifest`] describes *what* to do — publish, deploy, apply,
//! rotate — declaratively; a [`Backend`] decides *how* against its target.
//!
//! Only [`UnitEnvBackend`] is implemented here. [`KometBackend`] and
//! [`TestnetBackend`] are stubs; the testnet spec is the six phases of
//! `scripts/bootstrap-testnet.sh`, transcribed onto the manifest below. This
//! mirrors `cli/crates/stellar-registry-test`'s `RegistryTest`/`TestEnv` split.
//!
//! [`Env`]: soroban_sdk::Env

use crate::native::World;
use crate::Bootstrap;

/// Who authors a published wasm in the registry. Phase 3 of the testnet
/// bootstrap makes the interpreter's author the smart account — an
/// *irreversible* choice (the registry has no author transfer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Author {
    /// The human deployer key (verifier, doc-compiler, account in phase 2).
    Deployer,
    /// The perch smart account (the interpreter, phase 3 onward).
    SmartAccount,
}

/// Publish a named wasm into the (sub)registry. Testnet phases 2–3.
#[derive(Clone, Debug)]
pub struct Publish {
    /// The registry name to publish under (e.g. `"perch-interpreter"`).
    pub name: String,
    /// Who the published wasm is authored by.
    pub author: Author,
}

/// Deploy a published wasm. For the stateless helpers this is content-addressed
/// (`salt = wasm_hash`), so it is idempotent and permissionless. Testnet
/// phases 1 and 4.
#[derive(Clone, Debug)]
pub struct Deploy {
    /// The published name to deploy.
    pub name: String,
    /// If set, the wasm-hash-as-salt derivation is content-addressed and the
    /// deployed address is a pure function of `registry_id + wasm_hash`.
    pub content_addressed: bool,
}

/// Apply a whole policy document to the account in one transaction — the
/// account's `apply_doc`. Testnet phase 5.
#[derive(Clone, Debug)]
pub struct Apply {
    /// A path to (or the inline JSON of) the policy document to apply.
    pub document: String,
}

/// Hand day-to-day management to the smart account. Testnet phase 6: after
/// this, every initial publish/deploy/register needs a smart-account auth
/// entry, even for humans.
#[derive(Clone, Debug)]
pub struct Rotate {
    /// The new manager (a smart-account address, as a strkey).
    pub new_manager: String,
}

/// A declarative bootstrap: what to publish, deploy, apply, and rotate. A
/// [`Backend`] interprets it against a concrete target. The four lists map onto
/// the six phases of `scripts/bootstrap-testnet.sh` (preflight and subregistry
/// creation are backend setup; the rest are manifest entries).
#[derive(Clone, Debug, Default)]
pub struct BootstrapManifest {
    /// Wasms to publish (phases 2–3).
    pub publishes: Vec<Publish>,
    /// Deploys of published wasms (phases 1, 4).
    pub deploys: Vec<Deploy>,
    /// Documents to apply to the account (phase 5).
    pub applies: Vec<Apply>,
    /// Manager rotations (phase 6).
    pub rotations: Vec<Rotate>,
}

impl BootstrapManifest {
    /// An empty manifest.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Errors a backend can surface while materializing a manifest.
#[derive(Debug)]
pub enum BackendError {
    /// The backend is a stub and does nothing yet.
    Unimplemented(&'static str),
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BackendError::Unimplemented(what) => write!(f, "backend not implemented: {what}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// A target that can materialize a [`BootstrapManifest`]. Implemented by the
/// unit backend; komet and testnet are stubs.
pub trait Backend {
    /// What a successful bootstrap hands back (a [`World`] for the unit
    /// backend; a network handle for the real ones).
    type Handle;

    /// Materialize `manifest` against this backend.
    fn bootstrap(&mut self, manifest: &BootstrapManifest) -> Result<Self::Handle, BackendError>;
}

/// The unit-`Env` backend: the only implemented one. It delegates to
/// [`Bootstrap::native`] — the manifest's publish/deploy/apply entries are, in
/// a unit env, satisfied by registering the native types and letting the tests
/// drive `apply_doc` directly.
pub struct UnitEnvBackend {
    /// The bootstrap config the native world is built from.
    pub bootstrap: Bootstrap,
}

impl UnitEnvBackend {
    /// A unit backend over the given native [`Bootstrap`] config.
    pub fn new(bootstrap: Bootstrap) -> Self {
        Self { bootstrap }
    }
}

impl Backend for UnitEnvBackend {
    type Handle = World;

    fn bootstrap(&mut self, _manifest: &BootstrapManifest) -> Result<World, BackendError> {
        // In a unit env there is no real registry to publish/deploy into; the
        // native world *is* the materialized manifest. Cross-network backends
        // will replay the manifest phase by phase against their target.
        Ok(self.bootstrap.clone().build())
    }
}

/// The komet (K-framework symbolic) backend. **STUB.** Would replay the
/// manifest against a komet-hosted registry to get symbolic coverage of the
/// wasm-hash-as-salt derivation.
pub struct KometBackend;

impl Backend for KometBackend {
    type Handle = ();

    fn bootstrap(&mut self, _manifest: &BootstrapManifest) -> Result<(), BackendError> {
        Err(BackendError::Unimplemented(
            "komet backend: replay the manifest against a komet-hosted registry",
        ))
    }
}

/// The testnet backend. **STUB.** Its spec is the six phases of
/// `scripts/bootstrap-testnet.sh`: (0) preflight, (1) managed subregistry,
/// (2) publish+deploy verifier/doc-compiler/account (author = deployer),
/// (3) publish interpreter (author = smart account, irreversible),
/// (4) deploy interpreter, (5) apply the whole document (phase-5 `Apply`),
/// (6) rotate manager to the smart account.
pub struct TestnetBackend;

impl Backend for TestnetBackend {
    type Handle = ();

    fn bootstrap(&mut self, _manifest: &BootstrapManifest) -> Result<(), BackendError> {
        Err(BackendError::Unimplemented(
            "testnet backend: run the six phases of scripts/bootstrap-testnet.sh",
        ))
    }
}
