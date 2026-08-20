//! Faithful mode (**phase 2 — STUB**).
//!
//! Where [`crate::native`] registers the contract *types* and hand-wires their
//! addresses, faithful mode `contractimport!`s the real `registry.wasm`,
//! `publish`es the three stateless helpers (doc-compiler, interpreter,
//! verifier) into it, and `deploy_stateless`es them so their addresses are
//! genuinely *resolved* from `registry_id + wasm_hash` — exercising the
//! wasm-hash-as-salt derivation and the resolver macro's runtime mode against
//! real hashes, exactly as production does.
//!
//! It is deliberately not implemented yet. It has three hard prerequisites, all
//! out of scope for the native-mode ship:
//!
//! 1. **`deploy_stateless`** — the upstream `StatelessDeployable` trait from
//!    epic #37 workstream A (issue #38): wasm hash = deploy salt.
//! 2. **A built/vendored `registry.wasm`** to `contractimport!` — faithful mode
//!    can't register a native type; it needs the real managed-registry bytes.
//! 3. **An SDK-skew check** — the vendored `registry.wasm` is built with an
//!    older soroban-sdk (e.g. 25) and loaded into a 27 host; faithful mode must
//!    assert the host tolerates the skew before trusting resolution.
//!
//! Unique bytes per test (borrow `RandomizedWasm` from
//! `cli/crates/stellar-registry-test`) avoid `HashAlreadyPublished` when many
//! tests publish into one shared registry.

use crate::native::World;
use crate::Bootstrap;

/// Build a faithful-mode [`World`]. **Unimplemented** — see the module docs for
/// the three prerequisites (`deploy_stateless`, a built `registry.wasm`, and an
/// SDK-skew check).
pub(crate) fn build(_cfg: Bootstrap) -> World {
    todo!(
        "faithful mode is phase 2: needs #38's `deploy_stateless` (wasm hash = salt), \
         a built/vendored `registry.wasm` to contractimport!, and an SDK-skew check \
         for the 25-built wasm in a 27 host. Use `Bootstrap::native()` today."
    )
}
