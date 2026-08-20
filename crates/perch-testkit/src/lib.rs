//! `perch-testkit` — one-call bootstrap of the perch registry + stateless infra
//! + account for tests.
//!
//! Every perch e2e suite used to re-implement a `struct World`/`fn setup()` to
//! register the doc-compiler, interpreter, ed25519 verifier and account and
//! wire them together. This crate gives them one call:
//!
//! ```no_run
//! use perch_testkit::{Bootstrap, FIXTURE_NETWORK};
//!
//! let w = Bootstrap::native()
//!     .network(FIXTURE_NETWORK)
//!     .admin_ed25519([9u8; 32])
//!     .build();
//!
//! let doc = soroban_sdk::Bytes::from_slice(&w.env, perch_testkit::fixture().as_bytes());
//! let _hash = w.account_client().apply_doc(&doc, &w.compiler, &w.interpreter);
//! ```
//!
//! # Modes
//!
//! - [`Bootstrap::native`] — **implemented.** Registers the four contract
//!   *types* into a unit [`Env`], wires addresses, binds the network, mocks
//!   auth. No upstream dependency, no wasm artifact. See [`native`].
//! - [`Bootstrap::faithful`] — **stub (phase 2).** Publishes + deploys the
//!   helpers through a real imported `registry.wasm` so wasm-hash-as-salt
//!   resolution is genuinely exercised. See [`faithful`] for its prerequisites.
//!
//! # Cross-network vision
//!
//! [`manifest`] declares a [`BootstrapManifest`] + a [`Backend`] trait and
//! implements only [`UnitEnvBackend`]; [`KometBackend`]/[`TestnetBackend`] are
//! stubs, with `scripts/bootstrap-testnet.sh`'s six phases as the testnet spec.
//!
//! [`Env`]: soroban_sdk::Env

pub mod faithful;
pub mod fixture;
pub mod manifest;
pub mod native;

pub use fixture::{
    auth_digest, ci_publish_doc_hash, fixture, AnyKeyVerifier, CI_PUBLISH_DOC_HASH,
    FIXTURE_NETWORK, FIXTURE_REGISTRY, FIXTURE_VERIFIERS,
};
pub use manifest::{
    Apply, Author, Backend, BackendError, BootstrapManifest, Deploy, KometBackend, Publish, Rotate,
    TestnetBackend, UnitEnvBackend,
};
pub use native::World;

/// Which bootstrap strategy [`Bootstrap::build`] materializes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Register native contract types into a unit `Env`.
    Native,
    /// Publish + deploy through a real imported `registry.wasm` (phase 2).
    Faithful,
}

/// Builder for a wired test [`World`].
///
/// Start with [`Bootstrap::native`] (or [`Bootstrap::faithful`]), configure the
/// network passphrase and admin key, then [`build`](Bootstrap::build).
#[derive(Clone, Debug)]
pub struct Bootstrap {
    mode: Mode,
    pub(crate) network: Option<String>,
    pub(crate) admin_ed25519: [u8; 32],
}

impl Bootstrap {
    /// Native mode: register the four contract types into a unit `Env`. The
    /// fast, ship-first path with no upstream dependency.
    pub fn native() -> Self {
        Self {
            mode: Mode::Native,
            network: None,
            admin_ed25519: [0u8; 32],
        }
    }

    /// Faithful mode (**stub**): publish + deploy the helpers through a real
    /// imported `registry.wasm`. See [`faithful`] for its prerequisites.
    pub fn faithful() -> Self {
        Self {
            mode: Mode::Faithful,
            network: None,
            admin_ed25519: [0u8; 32],
        }
    }

    /// Bind the unit chain to this network passphrase (`apply_doc` binds
    /// documents to the chain). Unset leaves the default network id untouched.
    pub fn network(mut self, passphrase: &str) -> Self {
        self.network = Some(passphrase.to_string());
        self
    }

    /// The 32-byte key data for the admin `Signer::External(verifier, key)`.
    pub fn admin_ed25519(mut self, key: [u8; 32]) -> Self {
        self.admin_ed25519 = key;
        self
    }

    /// Materialize the configured [`World`].
    pub fn build(self) -> World {
        match self.mode {
            Mode::Native => native::build(self),
            Mode::Faithful => faithful::build(self),
        }
    }
}
