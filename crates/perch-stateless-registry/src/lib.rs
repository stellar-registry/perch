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
//! that pull each trait's default methods into the exported ABI — exactly the
//! idiom the base registry uses (`contracts/registry/src/lib.rs`) and the perch
//! analog of `perch_smart_account::impl_perch_smart_account!`.
//!
//! It composes the importable registry contracttraits from
//! [`registry-traits`](https://github.com/stellar-registry/contracts) (PR #33):
//! [`Publishable`], [`Manageable`], and the content-addressed
//! [`StatelessDeployable`].
//!
//! ## registry-traits gap worked around here (follow-up)
//!
//! The canonical `registry` contract also composes `Administratable` and
//! `Upgradable`, but those live in **`admin-sep`**, which caps at
//! `soroban-sdk ^25` and therefore cannot be depended on from this sdk-27
//! workspace. `registry-traits` deliberately excludes `admin-sep` and ships
//! only the [`registry_traits::admin`] free-function key convention (admin at
//! the `ADMIN` instance key, byte-identical to admin-sep's). So there is **no
//! importable `Administratable`/`Upgradable` contracttrait** to compose. The
//! `admin` / `set_admin` / `upgrade` entry points below are therefore provided
//! as thin local glue over that convention + `env.deployer()`. Everything else
//! — including the `manager`/`root` wiring the constructor needs — is a public
//! seam on `registry_traits::storage::Storage`, so no other glue was required.
//!
//! Follow-up: once an sdk-27-compatible `Administratable`/`Upgradable`
//! contracttrait exists upstream (either in `registry-traits` or an
//! sdk-version-flexible admin crate), replace the local glue with composed
//! `#[contractimpl(contracttrait)]` blocks.
//!
//! [`Publishable`]: registry_traits::registry::wasm::Publishable
//! [`Manageable`]: registry_traits::registry::contract::Manageable
//! [`StatelessDeployable`]: registry_traits::registry::contract::StatelessDeployable
//! [`Deployable::deploy`]: registry_traits::registry::contract::Deployable::deploy
//
// `no_std` only for the on-chain (`contract`) build — soroban's contract macros
// supply the wasm panic handler. With `--no-default-features` the crate is an
// empty `std` library, which lets the skeleton + workspace wiring build green
// without pulling the `registry-traits` git dependency at all.
#![cfg_attr(feature = "contract", no_std)]

// The composed, deployable contract. Everything that touches `registry-traits`
// lives here so `--no-default-features` yields a clean, empty library and the
// rest of the workspace keeps building without the git dependency.
#[cfg(feature = "contract")]
mod contract {
    // Same-name imports: soroban's `#[contractimpl(contracttrait)]` derives the
    // exported entry-point symbol names — and copies the `Error` return type
    // token verbatim — from the trait path *as written*, so the `impl` headers
    // must reference bare trait identifiers and `Error` must be in scope.
    use registry_traits::registry::contract::{Manageable, StatelessDeployable};
    use registry_traits::registry::wasm::Publishable;
    use registry_traits::Error;

    // Public seams: manager + root wiring for the constructor, and the admin
    // key convention that stands in for the (unavailable, sdk-25-capped)
    // `admin-sep::Administratable`/`Upgradable` — see the crate-level docs.
    use registry_traits::admin as registry_admin;
    use registry_traits::storage::Storage;

    use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

    #[contract]
    pub struct StatelessRegistry;

    #[contractimpl(contracttrait)]
    impl Publishable for StatelessRegistry {}

    #[contractimpl(contracttrait)]
    impl Manageable for StatelessRegistry {}

    // The content-addressed deploy surface (salt = wasm_hash, init = () always,
    // idempotent). `Deployable` itself is NOT composed: its name-salted `deploy`
    // conflicts with content-addressing.
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
        /// `registry::Contract::__constructor`. `manager`/`root` are set via the
        /// public `Storage` seam; `admin` via the `registry_traits::admin`
        /// key convention.
        pub fn __constructor(env: &Env, admin: Address, manager: Address, root: Address) {
            registry_admin::set_admin_no_auth(env, &admin);
            Storage::set_manager_no_auth(env, &manager);
            Storage::set_root_registry(env, &root);
        }

        /// The admin account (registry-traits key convention). Local stand-in
        /// for `admin-sep::Administratable::admin` — see crate docs.
        pub fn admin(env: &Env) -> Address {
            registry_admin::admin(env).unwrap()
        }

        /// Rotate the admin. Requires the current admin's auth. Local stand-in
        /// for `admin-sep::AdministratableExtension::set_admin`.
        pub fn set_admin(env: &Env, new_admin: Address) {
            registry_admin::require_admin(env);
            registry_admin::set_admin_no_auth(env, &new_admin);
        }

        /// Upgrade this registry's own wasm. Requires admin auth. Local stand-in
        /// for `admin-sep::Upgradable::upgrade`.
        pub fn upgrade(env: &Env, new_wasm_hash: BytesN<32>) {
            registry_admin::require_admin(env);
            env.deployer().update_current_contract_wasm(new_wasm_hash);
        }

        /// The manager account which gates initial publishes / stateless deploys.
        pub fn manager(env: &Env) -> Option<Address> {
            Storage::manager(env)
        }

        /// Admin can set a new manager.
        pub fn set_manager(env: &Env, new_manager: Address) {
            registry_admin::require_admin(env);
            Storage::set_manager_no_auth(env, &new_manager);
        }

        /// Admin can remove the manager.
        pub fn remove_manager(env: &Env) {
            registry_admin::require_admin(env);
            Storage::remove_manager_no_auth(env);
        }
    }
}

#[cfg(feature = "contract")]
pub use contract::{StatelessRegistry, StatelessRegistryClient};

// ─────────────────────────────────────────────────────────────────────────────
// Tests. The first is fully self-contained and green: it validates that the
// registry-traits composition + local admin/manager glue wire up correctly (and
// that soroban-sdk unifies to a single version across perch + registry-traits).
//
// The second encodes the issue-#39 acceptance criterion end to end (publish →
// content-addressed `deploy_stateless` → assert derived address → assert
// idempotent redeploy). It stays `#[ignore]`d: the #38/#33 import blocker is now
// RESOLVED, but it needs a real fixture wasm whose `__constructor` takes no args
// (`deploy_stateless` always inits with `()`), and the embedded placeholder is
// empty bytes that `upload_contract_wasm` rejects. Materializing that fixture
// (a build step that drops a `.wasm` under the crate for `contractimport!`) is
// the remaining follow-up.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "contract"))]
mod test {
    use super::{StatelessRegistry, StatelessRegistryClient};
    use soroban_sdk::{
        testutils::Address as _, Address, Bytes, BytesN, Env, String,
    };

    /// Self-contained, green: constructing the subregistry wires `admin`,
    /// `manager`, and `root` through the composed registry-traits seams. Also
    /// exercises the composed ABI (the `#[contracttrait]` glue) at compile time,
    /// which is what validates the soroban-sdk 27 ⇄ registry-traits `<28` pin.
    #[test]
    fn constructor_wires_admin_manager_and_root() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let manager = Address::generate(&env);
        let root = Address::generate(&env);

        let registry_id =
            env.register(StatelessRegistry, (admin.clone(), manager.clone(), root.clone()));
        let client = StatelessRegistryClient::new(&env, &registry_id);

        assert_eq!(client.admin(), admin, "admin must be the constructor admin");
        assert_eq!(
            client.manager(),
            Some(manager.clone()),
            "manager must be the constructor manager"
        );

        // Admin can rotate the manager; a fresh manager reads back.
        let new_manager = Address::generate(&env);
        client.set_manager(&new_manager);
        assert_eq!(client.manager(), Some(new_manager));
    }

    // A deployable fixture wasm to publish and content-address deploy. Any valid
    // no-arg-`__constructor` contract works. TODO: point `contractimport!` at a
    // real fixture wasm once a build step materializes it under the crate.
    mod fixture {
        // soroban_sdk::contractimport!(file = "fixtures/stateless_fixture.wasm");
        pub const WASM: &[u8] = &[]; // placeholder — replaced by contractimport! WASM
    }

    #[test]
    #[ignore = "needs a real no-arg-__constructor fixture wasm; embedded placeholder is empty bytes (upload_contract_wasm rejects)"]
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

        // Content-addressed deploy: salt = wasm_hash, deployer defaults to the
        // registry itself (`None`).
        let deployed = client.deploy_stateless(&wasm_name, &Some(version.clone()), &None);

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
        let again = client.deploy_stateless(&wasm_name, &Some(version), &None);
        assert_eq!(
            again, deployed,
            "redeploy of identical wasm must be a no-op (same address)"
        );
    }
}
