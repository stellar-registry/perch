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
//! // Name-only mode — the ergonomic default, like `import_contract_client!`. A
//! // bare ident matching the crate (or a "hyphenated-string", optional channel
//! // prefix + `@version`) generates a same-named module. It bakes, at build time,
//! // both the wasm hash (sha256 of `wasm/<name>.wasm`) and the deployer registry
//! // id (`wasm/stateless.id`), so `address(env)` takes NO registry arg. Missing
//! // files are build errors — fetch them first. Group in a module if the derived
//! // name would collide with the like-named crate:
//! mod infra {
//!     registry_contract!(perch_doc_compiler); // wasm "perch-doc-compiler"
//!     registry_contract!(perch_interpreter);
//!     // registry_contract!("perch-doc-compiler@1.0.0"); // pin a specific version
//! }
//! // infra::perch_doc_compiler::address(env) -> Address   (registry baked in)
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
//! // Name-salted mode — `deploy_name:` instead of `wasm_name:`. Resolves a
//! // *named* deploy (salt = sha256(name), the base `deploy` convention) from its
//! // PARENT registry, so e.g. the stateless subregistry derives from the perch
//! // registry id — no need to hardcode the child's strkey.
//! registry_contract! {
//!     mod: stateless,
//!     deploy_name: "stateless",
//! }
//! // stateless::address(env, &perch_registry) → CC6ELNH6…RY26O (on testnet)
//!
//! // Content-addressed modes expand to a module exposing:
//! //   pub fn address(env: &Env, registry: &Address) -> Address
//! //   pub const WASM_NAME: &str
//! //   pub fn client<'a>(env: &Env, registry: &Address) -> <client>  // iff `client:` given
//! // Pinned mode also exposes `WASM_HASH: [u8; 32]` and `hash(env)`.
//! // Runtime mode also exposes `hash(env, registry)`, plus `address_memoized`
//! // and `clear_memo` for an opt-in instance-storage memo.
//! // Name-salted mode exposes `address(env, parent)` + `DEPLOY_NAME: &str`
//! // (+ `client()` iff `client:` given).
//! ```
//!
//! ## Grammar
//!
//! Two forms. **Name-only** (positional): `registry_contract!(<name>)` where
//! `<name>` is a bare ident (module = the ident, wasm name = it with `_`→`-`) or a
//! string literal (module = leaf with `-`→`_`, optional channel prefix +
//! `@version`). It pins the wasm hash to `sha256(wasm/<leaf>.wasm)` AND bakes the
//! deployer registry id from `wasm/stateless.id`, both at build time — so
//! `address(env)` takes no `registry` arg and no `client()` is generated. **Keyed**
//! (`{ … }`), whose `address(env, registry)` takes the registry explicitly — the
//! fields below:
//!
//! - `mod:` — required — identifier naming the generated module.
//! - `wasm_name:` — string literal; the registry name (used verbatim in runtime
//!   mode's `fetch_hash`). Selects **content-addressed** derivation
//!   (`salt = wasm_hash`). Mutually exclusive with `deploy_name:`; exactly one is
//!   required.
//! - `deploy_name:` — string literal; a *named* deploy. Selects **name-salted**
//!   derivation (`salt = sha256(normalized_name)`), the base `deploy` convention —
//!   `address(env, parent)` resolves the child from its PARENT registry id.
//!   Normalized (lowercased, `_`→`-`) at expansion time. No `hash:`/`fetch_hash`.
//! - `client:` — optional — path to the typed client `client()` returns. Use an
//!   absolute/extern-crate path (e.g. `perch_interpreter::PolicyClient`); the
//!   path is re-emitted inside the generated child module. Omit it for
//!   address-only resolution (no `client()` is generated, and no client type is
//!   linked) — e.g. an interpreter used solely as a policy-map key.
//! - `hash:` — optional; **content-addressed only** — 64-hex-char string
//!   (optional `0x` prefix). A compile-time-pinned wasm hash.
//! - `wasm_file:` — optional; **content-addressed only**; mutually exclusive with
//!   `hash:` — path (relative to the invoking crate's `CARGO_MANIFEST_DIR`) to a
//!   local `.wasm`. The macro reads it at build time and pins `sha256(bytes)` (the
//!   content-address salt). A missing file is a build error naming it, so the pin
//!   comes from a wasm you have on disk — fetch it first. Present `hash:`/`wasm_file:`
//!   selects **pinned mode**; both absent selects **runtime mode** (call-time `fetch_hash`).
//!
//! [`CompileConfig::interpreter_wasm_hash`]: https://github.com/stellar-registry/perch
//! [`Env::get_contract_id`]: soroban_sdk::Env
//! [`Env`]: soroban_sdk::Env

/// Generate a module that resolves a registry-published contract's address and
/// client. See the [crate-level docs](crate) for the grammar and modes.
pub use perch_registry_resolve_macro::registry_contract;

use soroban_sdk::{Address, BytesN, Env};

/// The one derivation the macro is built on, as a plain function: the on-chain
/// address of a stateless contract deployed with `salt == wasm_hash`, from the
/// registry id and that hash.
///
/// `address = env.deployer().with_address(registry, wasm_hash).deployed_address()`
/// `        = sha256(network_id ‖ Address-preimage(registry, salt = wasm_hash))`.
///
/// Pure and offline — no deploy, no RPC — but **network-specific**: it reads the
/// current env's ledger network id, so the same `(registry, wasm_hash)` yields
/// different ids on testnet vs mainnet. Use this when you only need the address
/// (e.g. an interpreter attached as a policy-map key) and don't want the typed
/// client the [`registry_contract!`] macro also generates.
pub fn address(env: &Env, registry: &Address, wasm_hash: &BytesN<32>) -> Address {
    env.deployer()
        .with_address(registry.clone(), wasm_hash.clone())
        .deployed_address()
}
