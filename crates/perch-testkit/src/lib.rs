//! `perch-testkit` — one-call bootstrap of the perch registry + constructorless infra
//! + account for tests.
//!
//! Registering the doc-compiler, interpreter, ed25519 verifier and account and
//! wiring them together is one call:
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
//! // `approval_valid_until` matters only to a `Protected` reconfiguration.
//! let _hash = w.account_client().apply_doc(&doc, &0, &None);
//! ```
//!
//! [`Bootstrap::native`] registers the four contract *types* into a unit
//! [`Env`], wires addresses, binds the network, and mocks auth, with no
//! upstream dependency and no wasm artifact; see [`native`]. The suites that
//! publish and `deploy_stateless` through a real registry are
//! `crates/integration-tests/tests/release_stack.rs` and `crates/perch-testnet`.
//!
//! [`Env`]: soroban_sdk::Env

pub mod delta;
pub mod denote;
pub mod fixture;
pub mod native;
pub mod passkey;
pub mod rebuild;
pub mod rpn;
pub mod rule_set;
pub mod verifiers;

pub use fixture::{
    auth_digest, ci_publish_doc_hash, ci_publish_rule, fixture, twin, AnyKeyVerifier,
    CI_PUBLISH_DOC_HASH, FIXTURE_NETWORK, FIXTURE_REGISTRY, FIXTURE_VERIFIERS,
};
pub use native::{World, ED25519_VERIFIER_NAME, FIXTURE_VERIFIER_NAMES};

/// Builder for a wired test [`World`].
///
/// Start with [`Bootstrap::native`], configure the network passphrase and
/// admin key, then [`build`](Bootstrap::build).
#[derive(Clone, Debug)]
pub struct Bootstrap {
    pub(crate) network: Option<String>,
    pub(crate) admin_ed25519: [u8; 32],
}

impl Bootstrap {
    /// Native mode: register the four contract types into a unit `Env`, with
    /// no upstream dependency.
    pub fn native() -> Self {
        Self {
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
        native::build(self)
    }
}
