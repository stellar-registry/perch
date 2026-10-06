# Deploying the perch stack

How the perch contracts are built, published, and pinned to each other, and
how a deployment is checked. This is workstream 4 of epic
[#99](https://github.com/stellar-registry/perch/issues/99). The current
testnet deployment is [`deployments/testnet.json`](../../deployments/testnet.json),
and its measured exercise is [`testnet-exercise.md`](testnet-exercise.md).

## Why order matters

Consumers pin their dependencies when they are **built**, not when they are
deployed. The account derives the compiler, interpreter, and spending-limit
addresses as `deployer(registry, sha256(wasm))` from bytes in its
git-ignored `wasm/` cache (`perch_registry_resolve::registry_contract!`). The
factory pins the account wasm hash and the WebAuthn verifier the same way.
Nothing can repoint a deployed account or factory (AGENTS.md, "Infra
contracts are resolved from a build-time-pinned wasm hash"). So:

1. a dependency must exist, as exact bytes, before anything that pins it is
   built; and
2. "the account uses compiler X" is only true if the bytes in the cache when
   the account was built are X's.

[#95](https://github.com/stellar-registry/perch/issues/95) was the second
point failing. `fetch-infra-wasm.sh` looked the compiler up through a
name-salted deploy that nothing updated, so every build pinned the pre-cap
v0.1.0 compiler, and `testnet_pins` only checked that the stale address was
self-consistent.

## Tiers

| Tier | Contracts | Pins |
| --- | --- | --- |
| 0 | `perch-doc-compiler`, `perch-interpreter`, `perch-spending-limit`, `perch-ed25519-verifier`, `perch-webauthn-verifier`, `perch-zk-pool`, `perch-zk-adapter`, `perch-recovery` | nothing (the adapter compiles in its circuit's VK) |
| 1 | `perch-account` | compiler, interpreter, spending limit, and the registry they are under |
| 2 | `perch-account-factory` | the account wasm, the WebAuthn verifier, and the registry |

Tier-0 and tier-2 contracts are constructorless, hold no admin, and are
deployed content-addressed (`deploy_stateless`, salt = wasm hash), so an
address is a function of `(network, registry, wasm)` and is known before
anything is deployed. The account has a constructor and per-user state; it is
installed (uploaded) for the factory, never deployed on its own. Recovery
controller, adapter, and pool addresses are not build-time pins at all: the
account's applied document names them (`recovery.controller`, `adapter`,
`pool`), and the controller checks the adapter's circuit and depth against
the pool when a ZK factor is enrolled.

Every stack contract links a 64 KiB wasm stack instead of rustc's 1 MiB
default (its `build.rs`): the host charges each cross-contract call's VM its
whole initial memory, and with the default a recovery completion at the
document caps exceeded the network's memory limit
([`budgets.md`](../recovery/budgets.md), "Document caps").

The resolve macro's pins are build inputs cargo tracks: replacing a cached
wasm rebuilds the consumer (`perch-registry-resolve-macro`, `pin_file`).
Before, the macro read the file itself, and cargo kept the stale pin until
something else invalidated the crate.

## The manifest

`deployments/<network>.json` is the one record a deployment produces and
every consumer reads.

| Field | |
| --- | --- |
| `registry` | the content-addressing registry: id, its own wasm hash, admin/manager, root |
| `contracts.<name>` | `version`, `sha256`, `address` (absent for the account), `tier`, `bytes`, and `pins`: the sha256 of every contract it was built against |
| `zk` | the circuit id (the adapter's VK hash) and tree depth |
| `source`, `toolchain` | the commit the stack was built from, whether the tree was clean, and rustc / stellar-cli / scaffold versions |
| `deployed_ledger` | where an indexer starts scanning the pool's events |

## Commands

| Command | Does |
| --- | --- |
| `scripts/build-stack.sh --registry <id>` | Builds tier 0, stages its wasm and `<id>` as the account's pins, builds the account, stages it and the WebAuthn verifier as the factory's pins, builds the factory. `target/stack/build.json` records every hash and the pins each consumer was built against. Deployments build with `stellar scaffold build`; `--builder contract` uses core `stellar contract build`, the same code without scaffold's metadata. It overwrites the account's and factory's pin caches: run `fetch-infra-wasm.sh` afterwards to pin the deployment again. |
| `scripts/deploy-stack.sh --source <identity>` | Deploys a new instance of the registry wasm the network's perch registries already run, runs `build-stack.sh` against it, then publishes tier 0 and the factory (upload with hash check, `publish_hash`, `deploy_stateless`, derived-address and code-hash checks), installs the account, writes the manifest, and runs `verify-deployment.sh`. Idempotent. `--registry` publishes into an existing registry instead. |
| `scripts/verify-deployment.sh` | Read-only, by hash and address only: the registry's code; each contract at its content address, running its recorded wasm, served by the registry for its name and version; the account installed; the manifest's recorded pins equal to the deployed hashes; and what consumers resolve on-chain, from the factory's `account_wasm_hash`/`webauthn_verifier`, the adapter's `circuit_id`/`tree_depth` against the pool's `depth`, to the code hash and `infra()` of every account the exercise report lists. A report from another stack commit is skipped with a notice. |
| `scripts/fetch-infra-wasm.sh` | Fills the account and factory pin caches from the manifest. Each wasm is fetched by its recorded address (the account by its hash) and refused unless its sha256 and content address match. `--stack <dir>` fetches every deployed artifact with a `build.json`. |
| `cargo test -p perch-integration-tests --test testnet_pins` | The pins actually compiled into the account and the factory equal the manifest's. |
| `cargo test -p perch-integration-tests --test release_stack -- --ignored` | Every recovery flow through the stack's wasm, with real proofs (`PERCH_STACK_DIR`, default `target/stack`). |
| `cargo run -p perch-testnet` | The same flows on the deployed contracts (see [`testnet-exercise.md`](testnet-exercise.md)). |
| `scripts/bindings-contracts.sh` | Regenerates `packages/perch-contracts` from the deployed wasm and the manifest. |
| `scripts/check-packages.sh` | Packs every npm package, installs the tarballs into an empty project, imports every entry point, and runs every command they install. Publishes nothing. |

CI's `rust` job runs `fetch-infra-wasm.sh --stack`, the workspace tests
(including `testnet_pins`), `verify-deployment.sh`, and the release-stack
suite against the deployed bytes when the deployment was built from a commit
in the branch's history (after a rebase it runs other contract code, and the
step says so and skips until the next deployment). The `release-stack-source` job builds the
PR's own source in pin order (`build-stack.sh --builder contract`, against
the manifest's registry) and runs the release-stack suite on those fresh
bytes, so a change that only a rebuilt stack would break fails the PR. The
`packages` job runs `check-packages.sh`.

## What is verified, and where

| Claim | Check |
| --- | --- |
| A consumer was built against the bytes it names | `build-stack.sh` stages exactly the built tier-0 files; `build.json` records their hashes; `release_stack.rs` refuses a stack whose recorded pins are not the hashes of the wasm it carries |
| The chain runs those bytes | `deploy-stack.sh`: uploaded hash = built hash, deployed address = offline `deployer(registry, hash)`, deployed code hash = built hash; `verify-deployment.sh` repeats all three later |
| The registry serves them | `fetch_hash(name, version)` = recorded hash |
| Consumers resolve them | factory `account_wasm_hash()` and `webauthn_verifier()`, each account's code hash and `infra()`, adapter `circuit_id()`, adapter and pool depth |
| A fresh build pins the deployment | `fetch-infra-wasm.sh` checks every fetched byte; `testnet_pins` checks what was compiled |
| The deployed bytes behave as specified | `release_stack.rs` on the fetched bytes; `perch-testnet` on the chain |
| The source reproduces them | rebuilding the stack from the deployment commit, in another directory, with the recorded toolchain gives every recorded hash ([`testnet-exercise.md`](testnet-exercise.md#reproducibility)) |

A registry name lookup is never the evidence: names only select what to
fetch, and every fetched byte is checked against a hash the manifest
records.

## The testnet registry

The stack is published to its own instance of the registry wasm the perch
registries already run (`4b2d9ea4…`, the code at `unverified/perch/stateless`
and `unverified/perch/constructorless`). The instance is deployed unnamed,
with a fresh deployer key as admin, manager, and author. Publishing pre-merge
builds into the canonical registries instead would have:

- taken version numbers the release pipeline will publish later with
  different bytes. A registry refuses a second hash under a version, so the
  pipeline's publish would fail;
- bound the canonical names of five new contracts to an author permanently,
  because the registry has no author transfer.

Both are maintainers' decisions, not a deployment script's. `release.yml`
therefore tags and version-tracks the new contracts but keeps them out of
the publish allow-list (see its `publish-plan` comment). Publishing the stack
canonically means:

1. adding the tier-0 contracts to `ALLOW`;
2. having the manager make the one-time initial publish of each new name;
3. building the account and the factory against the published tier-0 hashes;
4. running `deploy-stack.sh --registry <canonical>`, or the equivalent
   ordered pipeline job, and committing the manifest it writes.

The spending-limit release job publishes to the canonical `stateless`
registry by its id (`vars.PERCH_STATELESS_REGISTRY_ID`), not through the
account's pin cache, which now follows the manifest.

## Simulating a recovery completion

A completion is `apply_doc` of the attempt's target, authorized through the
zero-signer recovery rule. The controller recognizes it from a marker its
`enforce` writes inside the account's `__check_auth`. Recording-mode
simulation, the default way a client learns a transaction's auth entries,
never runs `__check_auth`, so `enforce` never runs, `rcv_sync` sees no
marker, and the simulation fails with `AttemptAuthorized`, as if the call
were a policy change during the window.

So a client building a completion must put the recovery-rule entry in the
transaction itself: address credentials for the account, a fresh nonce, an
`AuthPayload` with no signers selecting the recovery rule, and a root
invocation of exactly `apply_doc(target, 0)`. Then it simulates, in
enforcing mode. `perch-testnet` does this (`Entries::Root`). The same goes
for any check that should observe the `Protected` freeze rather than the
controller's own refusal.

## Testnet resets

Testnet resets quarterly. After a reset, run `deploy-stack.sh` with a funded
identity, then `scripts/bindings-contracts.sh` and `cargo run -p
perch-testnet`, and commit the manifest, the bindings, and the exercise
report. Every address changes. The hashes do not change unless the source
does.

## Packages

| Package | Contents |
| --- | --- |
| `@stellar-registry/perch` (`packages/perch-js`) | PolicyDoc schemas, builder, canonical JSON, `doc_hash` |
| `@stellar-registry/perch-interpreter` | interpreter bindings |
| `@stellar-registry/perch-zk` | commitments, witnesses, bb.js proving; `/indexer`: the trust-free pool indexer, serving witnesses from `PoolWitnessIndex` (one chunk of leaves per witness; node stores and a snapshot to resume) |
| `@stellar-registry/perch-relay` | the guardian-approval relay: admits an approval only once authenticated (enforcing simulation of the controller call, or a `G...` guardian's own signature), including CAP-0071 delegated entries; `/node` and the `perch-relay` command serve it from one process |
| `@stellar-registry/perch-contracts` | bindings for every stack contract, from the deployed wasm, and the manifests |

The last three are built, tested, and pack-checked in CI, but are not in
`release.yml`'s `NPM_PACKAGES`. Listing one there publishes it on its next
merge. Rust crates are never published to crates.io (`release-plz.toml`).
Hosting the indexer or the relay, with storage, routes, and schedules, is the
operator's concern. Nido's hosted services are deployments of these packages.
