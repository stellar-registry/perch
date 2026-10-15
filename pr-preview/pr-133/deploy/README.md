# Deploying the perch stack

How the perch contracts are built, published, and pinned to each other, and
how a deployment is checked. The current testnet deployment is
[`deployments/testnet.json`](../../deployments/testnet.json); its build
provenance is recorded in the audit manifest
([`audit-scope.md`](../audit-scope.md#deployment-provenance)), and its
measured exercise is [`testnet-exercise.md`](testnet-exercise.md).

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

A lookup by name can return stale bytes without failing, and a check that
an address is self-consistent does not catch it. So pins are fetched by the
address and hash the manifest records, and checked against both
(`fetch-infra-wasm.sh`, below).

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

Every stack contract links a 64 KiB wasm stack (128 KiB for the ZK
adapter) instead of rustc's 1 MiB default (its `build.rs`): the host charges
each cross-contract call's VM its whole initial memory, and with the default
a recovery completion at the document caps exceeds the network's memory
limit ([`budgets.md`](../recovery/budgets.md), "Document caps").

The resolve macro's pins are build inputs cargo tracks: replacing a cached
wasm rebuilds the consumer (`perch-registry-resolve-macro`, `pin_file`).

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
| `scripts/deploy-stack.sh --source <identity>` | Deploys a new instance of the registry wasm the network's perch registries already run, runs `build-stack.sh` against it, then publishes tier 0 and the factory (upload with hash check, `publish_hash`, `deploy_stateless`, derived-address and code-hash checks), installs the account, writes the manifest, and runs `verify-deployment.sh`. Idempotent. `--registry` publishes into an existing registry instead. `--author <C…>` binds every name to a smart account and signs its authorization through the `theahaco/stellar-cli` fork (source/fee stays the delegate). `--reuse "<names>"` fetches those already-published tier-0 by hash and pins them instead of rebuilding — the canonical path (see [The canonical registry](#the-canonical-registry-and-publishing-the-stack-to-it)). |
| `scripts/verify-deployment.sh` | Read-only, by hash and address only: the registry's code; each contract at its content address, running its recorded wasm, served by the registry for its name and version; the account installed; the manifest's recorded pins equal to the deployed hashes; and what consumers resolve on-chain, from the factory's `account_wasm_hash`/`webauthn_verifier`, the adapter's `circuit_id`/`tree_depth` against the pool's `depth`, to the code hash and `infra()` of every account the exercise report lists. A report from another stack commit is skipped with a notice. |
| `scripts/fetch-infra-wasm.sh` | Fills the account and factory pin caches from the manifest. Each wasm is fetched by its recorded address (the account by its hash) and refused unless its sha256 and content address match. `--stack <dir>` fetches every deployed artifact with a `build.json`. |
| `cargo test -p perch-integration-tests --test testnet_pins` | The pins actually compiled into the account and the factory equal the manifest's. |
| `cargo test -p perch-integration-tests --test release_stack -- --ignored` | Every recovery flow through the stack's wasm, with real proofs (`PERCH_STACK_DIR`, default `target/stack`). |
| `cargo run -p perch-testnet` | The same flows on the deployed contracts (see [`testnet-exercise.md`](testnet-exercise.md)). |
| `scripts/bindings-contracts.sh` | Regenerates `packages/perch-contracts` from the deployed wasm and the manifest. |
| `scripts/check-packages.sh` | Packs every npm package, installs the tarballs into an empty project, imports every entry point, and runs every command they install. Publishes nothing. |

CI's `rust` job runs `fetch-infra-wasm.sh --stack`, the workspace tests
(including `testnet_pins`), `verify-deployment.sh`, and the release-stack
suite against the deployed bytes when the deployment's commit is an
ancestor of the tested commit. Otherwise the deployed bytes may run other
contract code: the job pins this source's own build (`build-stack.sh
--builder contract`), the workspace tests run against it without
`testnet_pins`, and the deployed-bytes suite skips with a notice.
`verify-deployment.sh` checks the chain against the manifest either way.
The `release-stack-source` job builds the tested source in pin order
(`build-stack.sh --builder contract`, against the manifest's registry) and
runs the release-stack suite on those fresh bytes, so a change that only a
rebuilt stack would break fails CI. The `packages` job runs
`check-packages.sh`.

## What is verified, and where

| Claim | Check |
| --- | --- |
| A consumer was built against the bytes it names | `build-stack.sh` stages exactly the built tier-0 files; `build.json` records their hashes; `release_stack.rs` refuses a stack whose recorded pins are not the hashes of the wasm it carries |
| The chain runs those bytes | `deploy-stack.sh`: uploaded hash = built hash, deployed address = offline `deployer(registry, hash)`, deployed code hash = built hash; `verify-deployment.sh` repeats all three later |
| The registry serves them | `fetch_hash(name, version)` = recorded hash |
| Consumers resolve them | factory `account_wasm_hash()` and `webauthn_verifier()`, each account's code hash and `infra()`, adapter `circuit_id()`, adapter and pool depth |
| A fresh build pins the deployment | `fetch-infra-wasm.sh` checks every fetched byte; `testnet_pins` checks what was compiled |
| The deployed bytes behave as specified | `release_stack.rs` on the fetched bytes; `perch-testnet` on the chain |
| The source reproduces them | rebuilding the stack from the deployment commit, in another directory, with the recorded toolchain gives every recorded hash (the current deployment's record: [`audit-scope.md`](../audit-scope.md#deployment-provenance)) |

A registry name lookup is never the evidence: names only select what to
fetch, and every fetched byte is checked against a hash the manifest
records.

## The canonical registry, and publishing the stack to it

Perch has one canonical registry, `unverified/perch/constructorless`
(`CDX2DMYM…PDA7`, `vars.PERCH_REGISTRY_CONTRACT_ID`;
[`../testnet-deployment.md`](../testnet-deployment.md)). An account or factory
bakes one registry id and derives every infra address from it as
`deployer(registry, sha256(wasm))`, so everything one consumer resolves must
live in that one registry. The `unverified/perch/stateless` registry is
retired: it keeps `perch-spending-limit` 0.1.1 and earlier, and nothing new is
published there.

`deploy-stack.sh` has two modes. A **rehearsal** deploys to its own fresh
instance of the same registry wasm (`4b2d9ea4…`), with a throwaway key as
admin, manager, and author — self-contained, so it builds and publishes its
own bytes and the account pins exactly those. The **canonical** mode
(`--registry <canonical> --author <smart account> --reuse …`) is what CI runs.

**The same version is different bytes in the two registries.** The current
deployment ([`deployments/testnet.json`](../../deployments/testnet.json)) is a
rehearsal in its own registry instance. Its interpreter, compiler, spending
limit, and ed25519 verifier carry versions that `release.yml` also publishes
canonically, but `release.yml` builds through
stellar-registry/actions' attested release build and `build-stack.sh` runs its
own scaffold build, so the bytes differ (interpreter 0.1.3 is `2254f17d…` in
the deployment and `e4d7fb8d…` canonically, as observed on 2026-10-09).
Resolve infra by the manifest's hash or address, never by `(name, version)`
across registries.

### Authority

Three signers, the same split as the constructorless publishes
([`../testnet-deployment.md`](../testnet-deployment.md)):

| Signer | Role |
| --- | --- |
| `perch-author` smart account (`vars.PERCH_AUTHOR_ADDRESS`, `CDIFS3JD…`) | **author** of every published name. The registry has no author transfer, so the binding is permanent. |
| `ci-publish` delegate (`secrets.CI_PUBLISH_SECRET_KEY`, in the `testnet` environment) | signs the account's `publish_hash` authorization and pays the fees; a CAP-71 delegate rule, expiry-bounded. Where each secret lives: [`../testnet-deployment.md`](../testnet-deployment.md#secrets-and-environments). |
| manager (`GA327GGW…`, human-held) | the **one-time initial publish of each new name** (`#12 ManagerRequired` otherwise), which binds that name's author. |

Canonical mode mirrors `release.yml`'s constructorless publishes exactly:
`--author` is the smart account, the source/fee key is the delegate
(`STELLAR_ACCOUNT`), and the delegate signs the account's authorization through
the `theahaco/stellar-cli` fork, which discovers the account's context rule
on-chain (`STELLAR_SIGN_WITH_KEY`). No new authority is introduced.

### The `deploy-stack` job (`release.yml`)

On a release that bumps a recovery-stack contract, the gated `deploy-stack`
job runs `deploy-stack.sh` against the canonical registry — SA-authored, in
pin order — attests each built wasm, and opens a `deploy(<network>)` PR with
the manifest and regenerated bindings for a human to merge (testnet is
automatic inside the gated release run; merging the manifest PR is the second
deliberate human act, flipping consumers and CI's deployed-bytes checks onto
the new deployment). The job runs only when `vars.PERCH_DEPLOY_STACK` is
`true` — see the bootstrap below.

**Why it reuses the published tier-0 rather than rebuilding them.** The
account pins the compiler, interpreter, and spending-limit by the sha256 of
the exact bytes on-chain, and those (with the ed25519 verifier) are the
allow-listed tier-0 the constructorless jobs already published — built with
`stellar scaffold build` **and** `stellar contract optimize` on the reusable
build workflow's `rustup update` toolchain. `build-stack.sh` here builds with
`stellar scaffold build` on the pinned toolchain and does not optimize, so for
the same source it produces **different bytes**: `perch-doc-compiler` 0.3.2 is
`f8bc1b…` canonically but `ccea12…` from `build-stack.sh`. An account built
against the rebuild would pin a hash the registry never `deploy_stateless`'d.
So canonical mode `--reuse`s those names — fetching each by the hash the
registry serves and pinning exactly that — and publishes only the
recovery-specific names (webauthn verifier, ZK pool/adapter, controller) and
the factory. Pinning the shared `contract-release` toolchain to a concrete
rustc + stellar-cli would make the rebuilds byte-identical and remove the need
to reuse; that is a follow-up (design step 7), tracked outside this
workstream.

### One-time manager bootstrap

The registry is managed, so the **first** publish of each new name needs the
manager's signature; afterward the delegate alone (the account's `ci-publish`
rule) publishes every later version. Read read-only against `CDX2DMYM…PDA7`,
the allow-listed tier-0 are already bootstrapped (`perch-doc-compiler`,
`perch-interpreter`, `perch-spending-limit`, `perch-ed25519-verifier`) and
these five recovery-stack names are **not** (`#1 NoSuchWasmPublished`):

- `perch-webauthn-verifier`
- `perch-recovery`
- `perch-zk-pool`
- `perch-zk-adapter`
- `perch-account-factory`

(`perch-account` is install-only — uploaded, never `publish_hash`'d, because
the factory deploys it by its pinned hash — so it needs no name binding.)

Each needs the manager's one-time initial publish, authored by the perch-author
account, at a version below the first CI release (so that CI publish is
accepted as greater). It must publish a **hash-distinct placeholder** wasm, not
the real release bytes: the registry records each wasm hash once, so a second
publish of an already-published hash is refused (`#11 HashAlreadyPublished`),
and the later SA-authored CI release publishes exactly the real bytes — so
bootstrapping the real bytes here would block that release. A benign trailing
custom section keeps the wasm valid while changing its hash; the placeholder is
only `publish_hash`'d (never `deploy_stateless`'d), so its bytes never run and
only the name→author binding survives. The manager (`GA327GGW…`) is human-held;
these are the **exact commands to run by hand** — never signed by CI or
automation. Build the stack once for the wasm, then publish each name:

```sh
REG=CDX2DMYMMEYU6FGN3HPJ2GQSSL5EZHIAMEJD4SPF55FZE5LEUBPPPDA7    # constructorless
AUTHOR=CDIFS3JDMVQBVANOSHEL6AUAKRYLFZFQQVX37QKQGJGQVQXQEHJCJ6PG  # perch-author SA
MANAGER=perch-demo                                              # the manager key (GA327GGW…), human-held

scripts/build-stack.sh --registry "$REG" --out target/stack

for name in perch-webauthn-verifier perch-recovery perch-zk-pool \
            perch-zk-adapter perch-account-factory; do
  real="target/stack/$(echo "$name" | tr - _).wasm"
  # A hash-distinct PLACEHOLDER — the trailing custom section keeps the wasm
  # valid but changes its hash, so CI's later publish of the real release bytes
  # is not refused with #11 HashAlreadyPublished. Only publish_hash'd, never
  # deployed, so these bytes never run.
  ph="${real%.wasm}.bootstrap.wasm"
  cp "$real" "$ph"; printf '\x00\x09\x08bootstrp' >> "$ph"
  hash=$(stellar contract upload --network testnet --source-account "$MANAGER" --wasm "$ph")
  stellar contract invoke --network testnet --source-account "$MANAGER" --id "$REG" -- \
    publish_hash --wasm_name "$name" --author "$AUTHOR" --wasm_hash "$hash" --version 0.0.0
  rm -f "$ph"
done
```

Each name is then bound to the perch-author account, and every later version
publishes with the delegate alone. Finally set `vars.PERCH_DEPLOY_STACK=true`
so the `deploy-stack` job runs on the next release.

### Notifying Nido (`nido-dispatch.yml`)

When a change to `deployments/testnet.json` or `deployments/mainnet.json`
lands on `main` (normally by merging a `deploy(<network>)` PR), the
`Notify Nido` workflow sends a `repository_dispatch` to `nidohq/nido`, once
per changed network. Nido's receiving workflow opens a repin PR; a Nido
maintainer merges it, and Nido's factory redeploy follows that merge. Perch
never deploys anything for Nido and never merges on its behalf.

The event is `perch-deployed`. Its `client_payload` is the contract the
receiver consumes:

| Field | |
| --- | --- |
| `schema` | `1`. Bumped on any incompatible change; a receiver rejects a schema it does not know. |
| `repository` | `stellar-registry/perch` |
| `network` | `testnet` or `mainnet`; equals the manifest's own `network` field |
| `perch_sha` | the 40-hex `main` commit the manifest was read at — the ref to repin to |
| `manifest_path` | `deployments/<network>.json` |
| `manifest_sha256` | sha256 of the manifest file's bytes at `perch_sha` |
| `source_commit` | the manifest's `source.commit`: the commit the stack was built from |
| `run_url` | the Perch workflow run that sent it |

The payload carries no addresses or hashes beyond the manifest's own digest:
the manifest is the one record. A receiver fetches
`https://raw.githubusercontent.com/<repository>/<perch_sha>/<manifest_path>`,
checks its sha256 against `manifest_sha256`, and reads everything else from
it, still resolving each contract by name and hash (`fetch-infra-wasm.sh`),
never by bare name. The same `perch_sha` can arrive more than once (a manual
re-send), so a receiver keys its repin branch on `network` and updates an
open PR rather than opening a second.

The workflow plans in a job with no secrets, then sends from a job bound to
the GitHub environment named after the network, which holds the
`perch-nido-sync` GitHub App's credentials. That app is installed on
`nidohq/nido` only, with **Contents: read & write** and **Pull requests: read
& write** (the latter for the receiver; the dispatch itself mints a token
narrowed to `contents: write` on `nidohq/nido`, which the dispatches endpoint
requires). Each environment (`testnet`, and `mainnet` before a mainnet
manifest exists) needs two secrets:

- `PERCH_NIDO_SYNC_CLIENT_ID` — the app's Client ID (`Iv…`, from the app's settings page)
- `PERCH_NIDO_SYNC_PRIVATE_KEY` — the app's PEM private key

Without them the send step fails with an error naming the environment. To
re-send the manifest currently on `main` — after adding the secrets, or after
a receiver failure — run the workflow by hand (`workflow_dispatch`, choosing
the network).

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
invocation of exactly `apply_doc(target, 0, expected_revision)` (`None`,
or the revision the target was derived at). Then it simulates, in
enforcing mode. `perch-testnet` does this (`Entries::Root`). The same goes
for any check that should observe the `Protected` freeze rather than the
controller's own refusal.

## Testnet resets

Testnet resets quarterly. After a reset, run `deploy-stack.sh` with a funded
identity, then `scripts/bindings-contracts.sh` and `cargo run -p
perch-testnet`, and commit the manifest, the bindings, and the exercise
report, and update the deployment provenance in
[`audit-scope.md`](../audit-scope.md#deployment-provenance). Every address
changes. The hashes do not change unless the source does.

## Packages

| Package | Contents |
| --- | --- |
| `@stellar-registry/perch` (`packages/perch-js`) | PolicyDoc schemas, builder, canonical JSON and hashes, statement encodings, and the consumer interface ([`packages/perch-js/README.md`](../../packages/perch-js/README.md)) |
| `@stellar-registry/perch-interpreter` | interpreter bindings |
| `@stellar-registry/perch-zk` | commitments, witnesses, bb.js proving; `/indexer`: the trust-free pool indexer, serving witnesses from `PoolWitnessIndex` (one chunk of leaves per witness; node stores and a snapshot to resume) |
| `@stellar-registry/perch-relay` | the guardian-approval relay: admits an approval only once authenticated (enforcing simulation of the controller call, or a `G...` guardian's own signature with the call rebuilt from the posted statement), including CAP-0071 delegated entries; `/node` and the `perch-relay` command serve it from one process |
| `@stellar-registry/perch-contracts` | bindings for every stack contract, from the deployed wasm, and the manifests |

The last three are built, tested, and pack-checked in CI, but are not in
`release.yml`'s `NPM_PACKAGES`, so they are unpublished
([`DEFERRED.md`](../DEFERRED.md#npm-publishing-of-perch-zk-and-the-contract-clients)).
Listing one there publishes it on its next merge. Rust crates are never
published to crates.io; contract releases are on-chain wasm publishes
(`release.yml`). Hosting the indexer or the relay, with storage, routes, and
schedules, is the operator's concern. Nido's hosted services are deployments
of these packages.
