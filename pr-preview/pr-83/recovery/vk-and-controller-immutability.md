# VK, controller, and code immutability review

Per the authoritative decision record §5.4 ("Constructorless verifier and
explicit upgrades") and the captain's instruction to review "code and VK
immutability, controller governance," this document states the invariant
this stage requires, shows the precedent already established elsewhere in
this repo, and states exactly how the new `perch-recovery` crate and any ZK
verifier meet it.

## The invariant

> A verifier (or controller) in Perch's constructorless registry remains
> immutable until an explicit upgrade. An upgrade is deploying a new
> immutable artifact and explicitly adopting its identity through the
> account's own document — never rewriting code, admin state, or verification
> configuration at an already-adopted address.

Three consequences follow directly, and are treated as hard requirements
for anything this stage ships:

1. **No constructor that sets mutable configuration.** If a contract's
   verification behavior (a VK, a circuit identity, a policy the controller
   enforces) can be set once at construction and never again, that's fine —
   but if it can be set *and later changed* by anyone, including the
   deployer, the artifact is not immutable, no matter how it was deployed.
2. **No admin/owner entry point at all.** An "admin-gated upgrade" is not
   the same guarantee as immutability — it's a promise that the admin key
   won't be misused, which is exactly the kind of trust the "no mutable
   shared controller... may silently bypass commitment" language in §5.4
   rules out. The bar is that there is **nothing to misuse**: no pause
   switch, no fee/parameter setter, no logic branch keyed by any mutable
   flag.
3. **Identity is content, not address history.** Deploying at a
   content-addressed address (`deployer(stateless_registry_id,
   sha256(wasm))`, as `perch-doc-compiler` and `perch-interpreter` already
   do — `crates/perch-smart-account/src/lib.rs`'s `infra` module) means the
   address itself is a function of the code. Two different builds are two
   different addresses; there is no way to have "the same address, new
   code" at all, which is a stronger guarantee than an admin merely
   *promising* not to redeploy at a pinned address.

## Precedent already in this repo

`perch-doc-compiler` and `perch-interpreter` already meet this bar today,
and are the model this stage follows rather than invents:

```rust
#[cfg(feature = "contract")]
#[contract]
pub struct PerchDocCompiler;

#[cfg(feature = "contract")]
#[contractimpl]
impl PerchDocCompiler {
    pub fn compile_doc(e: &Env, doc_json: Bytes) -> Result<CompiledDoc, DocCompilerError> {
        // pure: no auth, no storage, no admin
    }
}
```

(`crates/perch-doc-compiler/src/lib.rs`) — no `__constructor`, no storage
write, no auth check. Its own module doc states the property directly:
*"deployed once per network, immutable, and shared by every perch
account."* `perch-account`'s own accessor for it
(`infra::perch_doc_compiler::address`) derives the address fully offline
from a build-time-pinned WASM hash — see
[`migration.md`](migration.md) for why that specific mechanism is also what
makes a schema change require a new deployed instance rather than an
in-place change.

## What this stage adds, and how each piece meets the bar

- **The recovery controller (`perch-recovery`).** No constructor beyond
  whatever the Soroban toolchain requires for deployment plumbing; no
  admin/owner storage key anywhere in its schema; no entry point that
  changes its own code's behavior globally. Per-account state
  (`Config(Address)`, `Attempt(Address)`, ...) is mutated only through the
  account's own authorization (ordinary admin, or the enrolled recovery
  condition, depending on the operation) — never through anything resembling
  a controller-wide admin key. See
  [`controller-governance.md`](controller-governance.md) for the exact
  entry points and their authorization requirements.
- **A ZK verifier, if a deployment enrolls a ZK-involving mode.** The bar
  from §5.4 is explicit: *"Embedding the VK and proof-format identity in the
  artifact is a straightforward candidate... Merely removing a constructor
  while retaining mutable verification configuration is insufficient."*
  Concretely, any verifier a `ZkVerifierConfig.verifier` names must:
  - embed its verification key as a compiled-in constant (e.g.
    `include_bytes!` at build time), never a storage value a constructor or
    any other entry point writes;
  - expose no entry point that changes which VK or circuit it accepts;
  - commit to its circuit/proof-format identity in a form the account's own
    document also carries (`ZkVerifierConfig.circuit_id`, §5.4's "defense in
    depth" binding) — so a verifier address confused with another still
    fails the circuit-identity check, not just the address check.

  This stage does not ship a production circuit or its verifier (see
  [`controller-governance.md`](controller-governance.md)'s "ZK adapter
  scope" section for why that's a deliberate, documented boundary, not an
  oversight) — but the controller's ZK adapter interface is written against
  exactly this contract, and is exercised in tests against a stand-in
  verifier that satisfies it.

## "Upgrade" means adoption, not mutation

Concretely, for both the controller and any verifier: a new version is a
**new build → a new content-addressed instance → a new address**. Nothing
about deploying that new instance changes any already-enrolled account's
behavior. An account adopts it — meaning: it appears in that account's *own*
document (`recovery.controller`, or nested inside `recovery.mode`'s
`verifier` field), which the profile-gated authorization rules in
[`controller-governance.md`](controller-governance.md) apply to exactly like
any other recovery-configuration change. There is no "everyone
auto-upgrades" path, by construction — an account that never re-applies a
document naming the new instance keeps using the old one, forever, exactly
as immutable-artifact semantics require.
