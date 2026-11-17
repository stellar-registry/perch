#![no_std]
#![allow(clippy::too_many_arguments)]
//! Importable `#[contracttrait]`s for the stellar registry.
//!
//! Every trait default body routes through the neutral [`RegistryHelpers`]
//! namespace and a fixed storage-key convention rather than any concrete
//! contract type, so a downstream contract can wire the registry's behavior
//! onto itself with empty `impl` blocks:
//!
//! ```ignore
//! use registry_traits::registry::contract::{Deployable, StatelessDeployable};
//! use registry_traits::Error;
//!
//! #[soroban_sdk::contract]
//! pub struct MyRegistry;
//!
//! #[soroban_sdk::contractimpl(contracttrait)]
//! impl Deployable for MyRegistry {}
//! #[soroban_sdk::contractimpl(contracttrait)]
//! impl StatelessDeployable for MyRegistry {}
//! ```
//!
//! The crate depends only on `soroban-sdk` (version-flexible) — never on
//! `soroban-sdk-tools` or `admin-sep`, which pin sdk ^25 — so it compiles for a
//! sdk 26/27 consumer as well as the sdk 25 registry contract.

pub mod admin;
pub mod error;
pub mod events;
pub mod name;
pub mod registry;
pub mod storage;
pub mod version;

pub use error::Error;
pub use registry::contract::RegistryHelpers;

pub use registry::contract::{
    Batchable, Deployable, Manageable, Proxyable, Redeployable, StatelessDeployable,
};
pub use registry::wasm::Publishable;
