# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Release pipeline: intra-workspace pins are auto-synced after each bump

`.github/workflows/release.yml`'s `release-pr` job (git-cliff) computes each
contract's next version from commits touching a fixed `paths_for()` path list
per contract (see the job for the current lists), then — after the bump
loop — greps **every** `crates/*/Cargo.toml` (not just the crates in scope
for a given contract, and not just other tracked contracts; dev-only
consumers like `crates/integration-tests`/`crates/perch-testkit` are
included) for a `{ version = "...", path = "..." }` pin naming a
just-bumped crate, and rewrites that pin's version to match. This exists
specifically because a stale pin fails `cargo metadata` for the **whole
workspace** the moment a contract bumps a 0.x **minor** version (Cargo's
caret rules treat 0.x minor bumps as breaking) — see PR #79 for a case
where a stale dev-only pin, fixed by hand at the time, silently blocked
`perch-doc-compiler-v0.2.0`'s publish for a day. If you're bumping a
version by hand outside this job (a one-off manual release), still grep for
the crate's name across `crates/*/Cargo.toml` and bump every match — the
automation only runs inside `release-pr`.

Once a contract's tag (`<contract>-v<version>`) exists, `detect-releases`
will never retry that version even if the build later succeeds after a
fix — it only tags versions with no existing tag. Recovering a
build-that-never-published requires a fresh version bump (see PR #79), not a
rerun once the underlying commit's tree is fixed.

Adding a brand-new deployable contract crate needs entries in **four**
places in `release.yml`, not just workspace membership: both `CONTRACTS=`
lists (`detect-releases` and `release-pr` — kept as duplicated literals, not
one shared value), a `paths_for()` case for its own intra-workspace scope,
and — only once the contract is actually meant to auto-publish on-chain when
tagged — the `publish-plan` job's `ALLOW` list and `DISPATCH_TAG` regex.
Deliberately leaving a new contract out of `ALLOW` (while still tagging it
via `CONTRACTS`/`paths_for()`) is the correct way to ship its source and keep
its version-bump/pin tracking correct without triggering an on-chain publish
before that's a deliberate decision — see `perch-recovery`'s introduction
(PR that added `docs/recovery/`) for a worked example of this split.

## Infra contracts are resolved from a build-time-pinned wasm hash, not a runtime address

`perch-smart-account`'s `infra` module (`perch_registry_resolve::registry_contract!`)
derives the doc-compiler/interpreter/spending-limit addresses as
`deployer(stateless_registry_id, sha256(pinned_wasm_bytes))`, where the wasm
bytes are fetched into the build tree (`scripts/fetch-infra-wasm.sh`) and
baked into the *consuming* contract's own wasm at compile time — there is no
constructor argument or storage slot naming these addresses, and no way to
repoint them post-deploy. Two consequences that are easy to miss:

- **Any change to the doc/wire schema the doc-compiler accepts or emits
  (`perch-ir`, `CompiledDoc`/`CompiledRule`) requires a new `perch-doc-compiler`
  build, which is a new address — no existing deployed `PerchAccount` will
  ever call it, no matter what's published later.** A schema change is never
  a live upgrade for deployed accounts; it's a new option only newly-built
  accounts can use. See `docs/recovery/migration.md` for the worked-out
  consequence (an account built before a schema change can never adopt it in
  place — only a new account can).
- A new deployable that other in-repo crates need to *cross-call the client
  of* without linking its full logic (parser, storage, `Policy` impl, ...)
  should split like `perch-doc-compiler` does: a `contract` feature
  (default-on) gating the actual `#[contract]` struct/impl, plus an
  always-available hand-written `#[contractclient]` trait outside that gate
  for the entry points consumers actually call. `perch-recovery` follows this
  split (`RecoveryControllerClient`, ungated, vs. the full `PerchRecovery`
  contract, gated) so `perch-smart-account` links no controller storage or
  `Policy`-lifecycle code into account wasm.

## Soroban auth mocking never invokes a custom account's `__check_auth`

`env.mock_all_auths()`/`mock_all_auths_allowing_non_root_auth()` puts the
host in recording-auth mode, which — confirmed by reading
`soroban-env-host`'s own source (`auth.rs`, `require_auth_recording`: "we
don't call `__check_auth` in this flow") — **skips invoking a custom
account's `__check_auth` entirely**, for every address including the account
under test. `perch_testkit::Bootstrap`'s `World` uses this mode, so any test
built on it (the whole `apply_doc*.rs`/`cap_matrix.rs` suite) proves
*compiler-level* validation and rule-installation shape, never OZ's
context-rule *selection*/`Policy::enforce` mechanics — those calls succeed
regardless of which rule, if any, would actually have authorized them.
To test real rule-selection/policy-enforcement behavior (as `matrix.rs` does,
and `crates/integration-tests/tests/recovery.rs` following its pattern for
the recovery controller), call
`stellar_accounts::smart_account::do_check_auth` directly with a hand-built
`AuthPayload`/`Context`, wrapped in `env.as_contract(&account, || {...})` —
this bypasses host-level auth entirely rather than depending on it, so it
works the same with or without mocking. Relatedly: OZ's
`remove_context_rule` calls a policy's `uninstall` via `try_uninstall` and
discards the result even if it panics — a policy can never rely on
`uninstall` as a security gate (see `docs/recovery/controller-governance.md`
for how `perch-recovery` handles this). When chaining several
`do_check_auth` calls that are expected to panic (via
`catch_unwind`) inside one test, keep it to one or two per `Env` — this
host's test call-stack bookkeeping was observed not to reliably survive a
longer chain of recovered panics in one `Env`; prefer a fresh `Env` (a new
`setup()`) per scenario instead of accumulating them.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
