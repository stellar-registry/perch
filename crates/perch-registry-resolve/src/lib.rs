#![no_std]
//! Resolve a stateless contract's on-chain address from the registry id and the
//! contract's wasm hash, and hand callers a typed client — the "extend
//! `stellar-registry`" macro, mirroring `import_contract_client!`.
//!
//! # Why
//!
//! `perch-compile` already assumes `registry_id + wasm_hash → address` (its
//! [`CompileConfig::interpreter_wasm_hash`] is documented as "the interpreter
//! address is derivable (registry id + this hash)"). This macro formalizes that
//! derivation and gives you a typed client for the resolved contract.
//!
//! The derivation is **pure SDK** — no deployment and no network passphrase.
//! Perch deploys its stateless singletons (interpreter, compiler) with
//! `salt == wasm_hash`, so the address is
//!
//! ```text
//! env.deployer().with_address(registry, wasm_hash).deployed_address()
//! ```
//!
//! which is exactly [`Env::get_contract_id`]`(registry, wasm_hash)`. Because the
//! address is a function of `(registry id, wasm hash)` only, it is identical on
//! every network where the registry address and the published wasm match.
//!
//! # Usage
//!
//! ```ignore
//! use perch_registry_resolve::registry_contract;
//!
//! // Pinned mode — compile-time hash literal, zero cross-contract calls, offline.
//! registry_contract! {
//!     mod: interpreter,
//!     wasm_name: "perch-interpreter",
//!     client: perch_interpreter::PolicyClient,
//!     hash: "9f3c…",              // 64 hex chars, optional `0x` prefix
//! }
//!
//! // Runtime mode — omit `hash:`; the current hash is fetched from the registry
//! // via `Publishable::fetch_hash(wasm_name)` (tracks the latest version).
//! registry_contract! {
//!     mod: compiler,
//!     wasm_name: "perch-doc-compiler",
//!     client: perch_doc_compiler::DocCompilerClient,
//! }
//!
//! // Both expand to a module `interpreter` / `compiler` exposing:
//! //   pub fn address(env: &Env, registry: &Address) -> Address
//! //   pub fn client<'a>(env: &Env, registry: &Address) -> <client>
//! //   pub const WASM_NAME: &str
//! // Pinned mode also exposes `WASM_HASH: [u8; 32]` and `hash(env)`.
//! // Runtime mode also exposes `hash(env, registry)`, plus `address_memoized`
//! // and `clear_memo` for an opt-in instance-storage memo.
//! ```
//!
//! ## Grammar
//!
//! - `mod:` — required — identifier naming the generated module.
//! - `wasm_name:` — required — string literal; the registry name (used verbatim
//!   in runtime mode's `fetch_hash`).
//! - `client:` — required — path to the typed client `client()` returns. Use an
//!   absolute/extern-crate path (e.g. `perch_interpreter::PolicyClient`); the
//!   path is re-emitted inside the generated child module.
//! - `hash:` — optional — 64-hex-char string (optional `0x` prefix). Present
//!   selects **pinned mode**; absent selects **runtime mode**.
//!
//! [`CompileConfig::interpreter_wasm_hash`]: https://github.com/stellar-registry/perch
//! [`Env::get_contract_id`]: soroban_sdk::Env
//! [`Env`]: soroban_sdk::Env

/// Generate a module that resolves a registry-published contract's address and
/// client. See the [crate-level docs](crate) for the grammar and modes.
pub use perch_registry_resolve_macro::registry_contract;
