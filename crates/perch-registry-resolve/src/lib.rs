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
//! The derivation is **pure SDK** — no deployment, no RPC. Perch deploys its
//! stateless singletons (interpreter, compiler) with `salt == wasm_hash`, so the
//! address is
//!
//! ```text
//! env.deployer().with_address(registry, wasm_hash).deployed_address()
//! ```
//!
//! which is exactly [`Env::get_contract_id`]`(registry, wasm_hash)`. The host
//! computes `sha256(network_id ‖ Address-preimage(registry, salt = wasm_hash))`,
//! so the address is a function of `(network id, registry id, wasm hash)` and is
//! taken from the *current env's* ledger network id. It is therefore derivable
//! offline for a given network, but **network-specific**: the same registry
//! address + wasm hash yield different contract ids on testnet vs mainnet
//! (their network ids differ). Resolve under an env bound to the target
//! network's id (`env.ledger().with_mut(|l| l.network_id = …)` in tests).
//!
//! # Usage
//!
//! ```ignore
//! use perch_registry_resolve::registry_contract;
//!
//! // Pinned mode — compile-time hash literal, zero cross-contract calls, offline.
//! // Hashes below are the perch infra published to `unverified/perch/stateless`
//! // on **testnet** (registry CC6ELNH6YVRRO4WIETIURY3PZLD7NHSDXHRMTJQUT7D733SYVQFYB26O);
//! // `address(env, &that_registry)` under testnet's network id derives the live ids.
//! registry_contract! {
//!     mod: interpreter,
//!     wasm_name: "perch-interpreter",
//!     client: perch_interpreter::PerchInterpreterClient,
//!     hash: "f8320d3031e7dffe51fac14177c5353b8818f8e6df3bda6c4c1b714f5ce1d858",
//!     // → CBYWKTO6IALDRI7LQM2IBHK7SDKXKO5JTMJCVQVKEI4XMJ724ZVJI2YM
//! }
//! registry_contract! {
//!     mod: verifier,
//!     wasm_name: "perch-ed25519-verifier",
//!     client: perch_ed25519_verifier::PerchEd25519VerifierClient,
//!     hash: "6ddf7cadcb85059cffa5b127f994490ee560f8a46b2bb437975fbe5bd0cc7de4",
//!     // → CBVCTXCSF4HJJCQLLIM543CH5MJW3A2MMZ2T35GSCSN6QSC6BGSDJNNY
//! }
//!
//! // Runtime mode — omit `hash:`; the current hash is fetched from the registry
//! // via `Publishable::fetch_hash(wasm_name)` (tracks the latest version).
//! registry_contract! {
//!     mod: compiler,
//!     wasm_name: "perch-doc-compiler",
//!     client: perch_doc_compiler::DocCompilerClient,
//!     // pinned hash 3645bd0de34f4896c5e6fd8ca141713eb9f8658728bf16d82026418d4ab0b27f
//!     // → CCUU7RYG23ZBZZCKS2PPSZ2GJIBTBYXF47GZCYG5PUBN54Z7AKQBF2SY
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
