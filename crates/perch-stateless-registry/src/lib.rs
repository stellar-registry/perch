//! # perch-stateless-registry
//!
//! A **managed subregistry** whose policy is *"publish here iff your contract is
//! stateless."* It is deployed and registered under the perch registry as
//! `stateless` (`unverified/perch` → registers `stateless`), with
//! `manager =` the perch smart account and `root =` the root registry.
//!
//! ## What makes it "stateless"
//!
//! Two things, neither of which is bytecode-checkable — hence *managed*:
//!
//! 1. **Content-addressed deploys.** Deploys are keyed by the wasm hash itself
//!    (`salt = wasm_hash`), not by a caller-chosen name. Identical bytecode
//!    always resolves to the same on-chain address, so a redeploy of the same
//!    wasm is a no-op that returns the existing address. This is the
//!    [`StatelessDeployable`] surface; the name-salted [`Deployable::deploy`]
//!    path is deliberately **omitted** because a per-name salt conflicts with
//!    content-addressing.
//! 2. **Manager-gated publish/deploy.** Statelessness cannot be proven from
//!    bytecode, so the manager (the perch smart account) gates the *initial*
//!    publish/deploy of a wasm — that is where the "only stateless-eligible
//!    wasm" policy is enforced off-chain. This falls out of composing
//!    [`Manageable`] + [`Publishable`] with a `manager` set at construction.
//!
//! ## Composition (the pattern this epic demonstrates)
//!
//! The contract is nothing but a `#[contract]` struct, a `__constructor`, and a
//! series of empty `#[contractimpl(contracttrait)] impl Trait for _ {}` lines
//! that pull the trait's default methods into the exported ABI — exactly the
//! idiom the base registry uses (`contracts/registry/src/lib.rs`) and the perch
//! analog of `perch_smart_account::impl_perch_smart_account!`.
//!
//! It composes **five** registry contracttraits:
//! [`Administratable`], [`Upgradable`], [`Publishable`], [`Manageable`], and the
//! new [`StatelessDeployable`].
//!
//! ## Status: BLOCKED ON stellar-registry/contracts#38
//!
//! The `registry` crate is not importable yet. This module is written against
//! #38's *intended* interface and is gated behind the `contract` feature; it
//! compiles once the (currently commented) `registry` dependency in `Cargo.toml`
//! is enabled and #38 lands the requirements enumerated there. Build the
//! skeleton green today with `--no-default-features`.
//!
//! [`Administratable`]: registry::Administratable
//! [`Upgradable`]: registry::Upgradable
//! [`Publishable`]: registry::Publishable
//! [`Manageable`]: registry::Manageable
//! [`StatelessDeployable`]: registry::StatelessDeployable
//! [`Deployable::deploy`]: registry::Deployable::deploy
//
// `no_std` only for the on-chain (`contract`) build — soroban's contract macros
// supply the wasm panic handler. With `--no-default-features` the crate is an
// empty `std` library, which lets the skeleton + workspace wiring build green
// while #38 is unmerged.
#![cfg_attr(feature = "contract", no_std)]

// The composed, deployable contract. Everything that touches the (blocked)
// `registry` crate lives here so `--no-default-features` yields a clean, empty
// library and the rest of the workspace keeps building while #38 is unmerged.
#[cfg(feature = "contract")]
mod contract {
    // Same-name imports: soroban's `#[contractimpl(contracttrait)]` derives the
    // exported entry-point symbol names from the trait path *as written*, so the
    // `impl` headers below must reference bare trait identifiers. #38 must
    // `pub use` this exact set at the `registry` crate root (Administratable /
    // Upgradable are themselves re-exports of `admin_sep`).
    use registry::{
        Administratable, Manageable, Publishable, StatelessDeployable, Upgradable,
    };
    // `set_admin` is provided by admin-sep's extension trait (re-exported by #38).
    use registry::AdministratableExtension;
    // Manager + root wiring currently lives in the registry crate's `pub(crate)`
    // `Storage`; #38 must make it (or an equivalent public setter) importable.
    // See `__constructor` below.
    use registry::Storage;

    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct StatelessRegistry;

    #[contractimpl(contracttrait)]
    impl Administratable for StatelessRegistry {}

    #[contractimpl(contracttrait)]
    impl Upgradable for StatelessRegistry {}

    #[contractimpl(contracttrait)]
    impl Publishable for StatelessRegistry {}

    #[contractimpl(contracttrait)]
    impl Manageable for StatelessRegistry {}

    // The content-addressed deploy surface (salt = wasm_hash) + the read/resolve
    // methods carried over from `Deployable`. `Deployable` itself is NOT
    // composed: its name-salted `deploy` conflicts with content-addressing.
    #[contractimpl(contracttrait)]
    impl StatelessDeployable for StatelessRegistry {}

    #[contractimpl]
    impl StatelessRegistry {
        /// Construct the managed `stateless` subregistry.
        ///
        /// - `admin`: upgrades this registry and adds/sets/removes the manager.
        /// - `manager`: the perch smart account. Being *managed* means the
        ///   manager gates the initial publish/deploy of any wasm — the enforcement
        ///   point for the "only stateless-eligible wasm" policy.
        /// - `root`: the root registry. This subregistry defers to `root` to
        ///   resolve sibling subregistry names during cross-registry deploys.
        ///
        /// Unlike the base registry — where `manager`/`root` are `Option` and a
        /// `None` root makes it the root registry — this contract requires both:
        /// it is *definitionally* a managed subregistry rooted at the perch/root
        /// registry, and there is no unmanaged or root mode.
        ///
        /// Modeled on the `root = Some(_)` (subregistry) branch of
        /// `registry::Contract::__constructor`.
        pub fn __constructor(env: &Env, admin: Address, manager: Address, root: Address) {
            Self::set_admin(env, &admin);
            // TODO(#38): expose these two seams publicly. Today both are
            // `pub(crate)` on the registry crate's `Storage`.
            Storage::set_manager_no_auth(env, &manager);
            Storage::new(env).root_registry.set(&root);
        }
    }
}

#[cfg(feature = "contract")]
pub use contract::{StatelessRegistry, StatelessRegistryClient};

// ─────────────────────────────────────────────────────────────────────────────
// In-SDK acceptance test. `#[ignore]`d until #38 lands (the `contract` feature
// cannot pull the `registry` crate yet). It encodes the issue-#39 acceptance
// criterion: publish a fixture wasm, `deploy_stateless` it content-addressed,
// assert the deployed address equals the offline derivation, and assert that a
// redeploy of identical bytecode is a no-op (returns the same address).
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "contract"))]
mod test {
    use super::{StatelessRegistry, StatelessRegistryClient};
    use soroban_sdk::{
        testutils::Address as _, Address, Bytes, BytesN, Env, String,
    };

    // A deployable fixture wasm to publish and content-address deploy. Any valid
    // contract works. TODO(#38): point `contractimport!` at a real fixture wasm
    // (e.g. a small hello-world) once the crate builds; a symlink/build step will
    // materialize it under the crate before `cargo test`.
    mod fixture {
        // soroban_sdk::contractimport!(file = "fixtures/stateless_fixture.wasm");
        pub const WASM: &[u8] = &[]; // placeholder — replaced by contractimport! WASM
    }

    #[test]
    #[ignore = "blocked on stellar-registry/contracts#38 (importable registry + StatelessDeployable)"]
    fn deploy_stateless_is_content_addressed_and_idempotent() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let root = Address::generate(&env);

        // Deploy the managed subregistry: __constructor(admin, manager, root).
        let registry_id =
            env.register(StatelessRegistry, (admin.clone(), manager.clone(), root.clone()));
        let client = StatelessRegistryClient::new(&env, &registry_id);

        // Manager gates the initial publish (the perch smart account, mocked here).
        let wasm_name = String::from_str(&env, "fixture");
        let version = String::from_str(&env, "0.0.1");
        let wasm = Bytes::from_slice(&env, fixture::WASM);
        client.publish(&wasm_name, &manager, &wasm, &version);
        let wasm_hash: BytesN<32> = client.fetch_hash(&wasm_name, &Some(version.clone()));

        // Content-addressed deploy: salt = wasm_hash.
        let deployed = client.deploy_stateless(&wasm_name, &Some(version.clone()));

        // Offline derivation: deployer = the registry contract, salt = wasm_hash.
        let expected = env
            .deployer()
            .with_address(registry_id.clone(), wasm_hash.clone())
            .deployed_address();
        assert_eq!(
            deployed, expected,
            "deployed address must equal the offline content-addressed derivation"
        );

        // Redeploy of identical bytecode is a no-op → same deterministic address.
        let again = client.deploy_stateless(&wasm_name, &Some(version));
        assert_eq!(
            again, deployed,
            "redeploy of identical wasm must be a no-op (same address)"
        );
    }
}
