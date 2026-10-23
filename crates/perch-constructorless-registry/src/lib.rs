//! # perch-constructorless-registry
//!
//! A **managed subregistry** whose deploys are *constructorless*: every
//! instance is initialised with no constructor arguments, at an address that
//! is a pure function of the registry and the wasm hash. perch's one canonical
//! instance is deployed by the perch registry as `constructorless`, with
//! `root =` the root registry and `manager =` the key that approves each new
//! name (`docs/deploy/README.md`, "Bootstrapping a network's registry chain").
//!
//! ## What makes it "constructorless"
//!
//! Two things, neither of which is bytecode-checkable — hence *managed*:
//!
//! 1. **Content-addressed deploys.** Deploys are keyed by the wasm hash itself
//!    (`salt = wasm_hash`), not by a caller-chosen name, and always pass `()`
//!    to the constructor. Identical bytecode always resolves to the same
//!    on-chain address, so a redeploy of the same wasm is a no-op that returns
//!    the existing address. This is the upstream [`StatelessDeployable`]
//!    surface (`deploy_stateless` is its name in `registry-traits`); the
//!    name-salted [`Deployable::deploy`] path is deliberately **omitted**
//!    because a per-name salt conflicts with content-addressing.
//! 2. **Manager-gated first publish.** Whether a wasm is safe to share as one
//!    constructorless instance cannot be proven from bytecode, so the manager
//!    approves the *initial* publish of each name, which binds its author —
//!    that is where the eligibility policy is enforced off-chain. Later
//!    versions need only the author, and `deploy_stateless` is
//!    permissionless. This falls out of composing [`Manageable`] +
//!    [`Publishable`] with a `manager` set at construction.
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
//! [`StatelessDeployable`]; plus [`Administratable`] and [`Upgradable`] from
//! [`admin-sep`](https://github.com/theahaco/admin-sep) (`v0.27.0`).
//!
//! ## Admin: a single `ADMIN` key shared with registry-traits
//!
//! The canonical `registry` contract composes `Administratable` and
//! `Upgradable` from **`admin-sep`**. That crate now ships on soroban-sdk 27
//! (`v0.27.0`), so this sdk-27 workspace composes the same real
//! `#[contracttrait]`s for its public `admin` / `set_admin` / `upgrade` entry
//! points — no local glue.
//!
//! This interoperates with `registry-traits`' internal auth because both sides
//! keep the admin at the **same** instance-storage key,
//! `symbol_short!("ADMIN")`: admin-sep at [`admin_sep::STORAGE_KEY`] and
//! registry-traits at [`registry_traits::admin::ADMIN_KEY`] (whose own docs
//! call it "byte-identical to admin-sep's"). The constructor sets that one key
//! via admin-sep's `Administratable::set_admin`; the `manager`-gated
//! `Publishable`/`Manageable`/`StatelessDeployable` trait bodies read it back
//! through registry-traits' `require_admin`. The `manager`/`root` wiring is a
//! public seam on `registry_traits::storage::Storage`.
//!
//! [`Publishable`]: registry_traits::registry::wasm::Publishable
//! [`Manageable`]: registry_traits::registry::contract::Manageable
//! [`StatelessDeployable`]: registry_traits::registry::contract::StatelessDeployable
//! [`Deployable::deploy`]: registry_traits::registry::contract::Deployable::deploy
//! [`Administratable`]: admin_sep::Administratable
//! [`Upgradable`]: admin_sep::Upgradable
//
// `no_std` only for the on-chain (`contract`) build — soroban's contract macros
// supply the wasm panic handler. With `--no-default-features` the crate is an
// empty `std` library, which lets the skeleton + workspace wiring build green
// without pulling the `registry-traits` git dependency at all.
#![cfg_attr(feature = "contract", no_std)]

// The composed, deployable contract. Everything that touches `registry-traits`
// / `admin-sep` lives here so `--no-default-features` yields a clean, empty
// library and the rest of the workspace keeps building without the git
// dependency.
#[cfg(feature = "contract")]
mod contract {
    // Same-name imports: soroban's `#[contractimpl(contracttrait)]` derives the
    // exported entry-point symbol names — and copies the `Error` return type
    // token verbatim — from the trait path *as written*, so the `impl` headers
    // must reference bare trait identifiers and `Error` must be in scope.
    use registry_traits::registry::contract::{Manageable, StatelessDeployable};
    use registry_traits::registry::wasm::Publishable;
    use registry_traits::Error;

    // Public seam: manager + root wiring for the constructor. Admin auth is
    // owned by admin-sep's `Administratable` below; it and registry-traits'
    // internal `require_admin` share the one `symbol_short!("ADMIN")` key.
    use registry_traits::storage::Storage;

    // The real admin/upgrade contracttraits, composed exactly as the canonical
    // `registry` contract does. `AdministratableExtension` supplies the
    // `require_admin` used by the manager setters.
    use admin_sep::{Administratable, AdministratableExtension, Upgradable};

    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct ConstructorlessRegistry;

    #[contractimpl(contracttrait)]
    impl Administratable for ConstructorlessRegistry {}

    #[contractimpl(contracttrait)]
    impl Upgradable for ConstructorlessRegistry {}

    #[contractimpl(contracttrait)]
    impl Publishable for ConstructorlessRegistry {}

    #[contractimpl(contracttrait)]
    impl Manageable for ConstructorlessRegistry {}

    // The content-addressed deploy surface (salt = wasm_hash, init = () always,
    // idempotent). `Deployable` itself is NOT composed: its name-salted `deploy`
    // conflicts with content-addressing.
    #[contractimpl(contracttrait)]
    impl StatelessDeployable for ConstructorlessRegistry {}

    #[contractimpl]
    impl ConstructorlessRegistry {
        /// Construct the managed `constructorless` subregistry.
        ///
        /// - `admin`: upgrades this registry and sets or removes the manager.
        /// - `manager`: approves the initial publish of each wasm name (later
        ///   versions need only that name's author). Being *managed* makes
        ///   this approval the enforcement point for the eligibility policy.
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
        /// public `Storage` seam; `admin` via admin-sep's
        /// `Administratable::set_admin` (which, at construction time, has no
        /// prior admin to auth against and simply writes the `ADMIN` key).
        pub fn __constructor(env: &Env, admin: Address, manager: Address, root: Address) {
            Self::set_admin(env, admin);
            Storage::set_manager_no_auth(env, &manager);
            Storage::set_root_registry(env, &root);
        }

        /// The manager, which approves the initial publish of each name, if
        /// one is set.
        pub fn manager(env: &Env) -> Option<Address> {
            Storage::manager(env)
        }

        /// Replace the manager. Admin only.
        pub fn set_manager(env: &Env, new_manager: Address) {
            Self::require_admin(env);
            Storage::set_manager_no_auth(env, &new_manager);
        }

        /// Remove the manager, after which a name's first publish needs only
        /// its author. Admin only.
        pub fn remove_manager(env: &Env) {
            Self::require_admin(env);
            Storage::remove_manager_no_auth(env);
        }
    }
}

#[cfg(feature = "contract")]
pub use contract::{ConstructorlessRegistry, ConstructorlessRegistryClient};

// ─────────────────────────────────────────────────────────────────────────────
// Tests. The first is fully self-contained and green: it validates that the
// registry-traits + admin-sep composition wires up correctly (and that
// soroban-sdk unifies to a single version across perch + registry-traits +
// admin-sep).
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
    use super::{ConstructorlessRegistry, ConstructorlessRegistryClient};
    use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String};

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

        let registry_id = env.register(
            ConstructorlessRegistry,
            (admin.clone(), manager.clone(), root.clone()),
        );
        let client = ConstructorlessRegistryClient::new(&env, &registry_id);

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
        // soroban_sdk::contractimport!(file = "fixtures/constructorless_fixture.wasm");
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
        let registry_id = env.register(
            ConstructorlessRegistry,
            (admin.clone(), manager.clone(), root.clone()),
        );
        let client = ConstructorlessRegistryClient::new(&env, &registry_id);

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
