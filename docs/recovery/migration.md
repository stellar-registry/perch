# Migrating existing accounts to recovery support

**Audience:** wallets, integrators, and account owners deciding whether an
already-deployed `perch-account` can gain recovery support in place, or needs
a new account.

**Hard rule this document follows throughout:** shipping this release does
not, and cannot, change the behavior of any already-deployed `PerchAccount`
or already-deployed `perch-doc-compiler` instance. Both are constructorless
and immutable by construction (see
[`vk-and-controller-immutability.md`](vk-and-controller-immutability.md)).
Nothing below is a claim that a future library release changes deployed
accounts — it is the opposite claim, worked out to its consequences.

## Why a deployed account cannot pick up new schema support in place

`PerchAccount::apply_doc` (`crates/perch-smart-account/src/lib.rs`) resolves
the document compiler it calls **offline, at build time**, not from any
runtime-configurable address:

```rust
let interpreter = infra::perch_interpreter::address(e);
let compiled: CompiledDoc =
    DocCompilerClient::new(e, &infra::perch_doc_compiler::address(e))
        .try_compile_doc(&doc_json)??;
```

`infra::perch_doc_compiler::address(e)` (via
`perch_registry_resolve::registry_contract!`, `crates/perch-smart-account/src/lib.rs:59-61`)
derives `deployer(stateless_registry_id, sha256(pinned_wasm_bytes))` where
`pinned_wasm_bytes` is read from a file fetched into the build tree by
`scripts/fetch-infra-wasm.sh` **before `perch-account` is compiled**. That
hash — and therefore the exact compiler address — is baked into the
account's own WASM. It is not stored in instance storage, not passed as a
constructor argument, and has no setter. `perch-account`'s own module doc is
explicit about the consequence: *"The account is not upgradeable and has no
execution entry point: replacing it means deploying a new account and moving
[external] ownership."*

Two independent immutable artifacts must both understand recovery for
enrollment to be possible at all:

1. **The doc-compiler instance the account calls.** A pre-Stage-4 compiler's
   own statically-linked `perch-ir` has no `recovery` field in its
   `deny_unknown_fields` list (`crates/perch-ir/src/parse.rs`) — a document
   containing a `"recovery"` key is rejected as an unknown field, on-chain,
   before anything else happens. This is not a permissions error; the old
   compiler genuinely does not know the shape exists.
2. **The account's own `apply_doc` logic.** Even if a document could get
   past compilation, a pre-Stage-4 account's `apply_doc` has no code path
   that calls a recovery controller — that call only exists in a
   post-Stage-4 build of `perch-smart-account`/`perch-account`.

Consequently: **a `PerchAccount` deployed before this release can never
enroll recovery through its own `apply_doc`, under any circumstances.**
This is a permanent property of that deployment, not a temporary gap this
document works around.

## The two cases

### Case A — account built before this release

Recovery is permanently unavailable in place. The only path is:

1. Deploy a new `PerchAccount` from a post-Stage-4 build. Its constructor
   takes the same shape as before (`admin_signers: Vec<Signer>`) — the
   user's existing signer keys/credentials are reused as-is; nothing about a
   WebAuthn credential, ed25519 key, or delegated address is
   perch-version-specific.
2. Submit the desired document (the old account's document content, plus a
   `recovery` section) to the **new** account via its `apply_doc`. Because
   `RuleScope::SelfAdmin` resolves to `e.current_contract_address()` at
   apply time rather than being baked into the compiled rule
   (`crates/perch-doc-compiler/src/lib.rs`'s `RuleScope` has no
   account-address field at all), and `Scope::Contract` rules name some
   *other* contract's address, not the account's own — **the exact same
   document JSON the old account was running compiles and installs
   identically on the new account.** A policy document is portable across
   this kind of migration by construction; only the `recovery` section (and
   any deliberate policy change) needs to be added.
3. Move everything that isn't inside the document:
   - **Balances.** A contract account's balance lives at that contract's
     address. Moving it is an explicit transfer transaction, signed under
     the *old* account's still-valid authorization, sent to the *new*
     account's address. Do this before decommissioning the old account —
     once its own admin rule can no longer be satisfied (e.g. after signer
     rotation elsewhere), it cannot authorize anything, including its own
     exit transfer.
   - **External references to the old account's address** — anything
     outside perch that stores "the owner/session/allowlisted caller is
     `<old address>`" (other contracts' stored state, a dApp's session
     table, a name/registry entry an integrator maintains for their own
     users). Perch has no visibility into these; enumerating and
     re-pointing them is integration-specific and is the responsible
     wallet/integrator's job, not something perch's contracts can automate.
4. Treat the old account as retired. It cannot be deleted (no
   self-destruct, no upgrade path); it simply stops being referenced.

**Practical note for tooling:** because there is no on-chain field recording
which `perch-account`/`perch-doc-compiler` build an account was deployed
against, a wallet cannot currently *discover* whether a given account is
Case A or Case B by inspecting the account alone. Until perch grows a
queryable version marker (tracked as follow-up work, not part of this
release), integrators should record the release each account was deployed
from at deploy time (e.g. alongside however they already track deployments —
see `DEPLOYED.md`-style records used elsewhere in this repo's tooling) and
consult that record rather than guessing.

### Case B — account built from this release or later, recovery not yet enrolled

No migration is needed. Recovery is enrolled, changed, or removed the same
way any other policy change is made: submit a new document via `apply_doc`.
The [profile-based authorization rules](controller-governance.md) govern
*who* may make that change (ordinary admin alone under `loss`; ordinary
admin plus the currently-enrolled recovery condition under `protected`) —
there is never a "new account" requirement for this case.

## What does *not* need to migrate

Nothing recovery-specific, because a Case A account never had any: no
enrolled `RecoveryConfig`, no controller state, no baseline, no guardian
set, no pending attempt. There is no in-place recovery state to carry over
— only the account's existing (non-recovery) document content, which is, as
shown above, portable as-is.

## What this document does not claim

- It does not claim perch can make a pre-Stage-4 account upgradeable after
  the fact. It cannot, by design (see
  [`vk-and-controller-immutability.md`](vk-and-controller-immutability.md)).
- It does not claim balance or external-reference migration is automated by
  perch tooling. Both are explicit, integration-specific steps an
  integrator must perform.
- It does not claim every Case A account *should* migrate. An account owner
  who doesn't need recovery has no reason to.
