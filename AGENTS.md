# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Release pipeline sharp edge: dev-only crates aren't in a contract's version-bump scope

`.github/workflows/release.yml`'s `release-pr` job (git-cliff) computes each
contract's next version from commits touching a fixed `paths_for()` path list
per contract (see the job for the current lists). Crates that are **only**
`[dev-dependencies]` consumers of a contract — `crates/integration-tests`,
`crates/perch-testkit` — are not in any contract's scope, so a commit that
only touches them never triggers a version bump there, and their
intra-workspace `path` dependency version pins (e.g. `perch-account = {
version = "0.1.1", path = "..." }`) can silently go stale when a contract
bumps a 0.x **minor** version (Cargo's caret rules treat 0.x minor bumps as
breaking). A stale pin fails `cargo metadata` for the **whole workspace**,
which only surfaces when `release.yml`'s `constructorless-build` job runs for
an unrelated contract — see PR #79 for a case where this silently blocked
`perch-doc-compiler-v0.2.0`'s publish for a day. When bumping any contract's
version, grep for its name across `crates/*/Cargo.toml` `{ version = "...",
path = "..." }` pins and bump every match, not just the crates in that
contract's `paths_for()` scope.

Once a contract's tag (`<contract>-v<version>`) exists, `detect-releases`
will never retry that version even if the build later succeeds after a
fix — it only tags versions with no existing tag. Recovering a
build-that-never-published requires a fresh version bump (see PR #79), not a
rerun once the underlying commit's tree is fixed.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
