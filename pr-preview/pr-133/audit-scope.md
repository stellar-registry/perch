# Audit manifest and scope

This file identifies the Perch code under audit, separates it from the
deployment it was measured on, assigns every component to a review unit or
a named exclusion, and gives the reading order.

**Deferred until after the audit:** [`DEFERRED.md`](DEFERRED.md) lists the
work deliberately outside this audit, each item with the current behaviour
that is audited, its residual risk, its exit criterion, and its owner.

## Audit identity

### Reviewed source

The audited source is the `stellar-registry/perch` commit that contains
this file. The audit handoff records its full SHA (`git rev-parse HEAD` in a
checkout of that commit) and the audit date. No branch name is part of the
identity. A consumer that is audited with Perch (Nido) pins the same SHA as
its `vendor/perch` submodule. A finding that changes a contract or signing
behaviour produces a new commit, and the review baseline moves to that
commit's SHA.

### Deployment provenance

The testnet deployment is a record of built bytes, not the reviewed source.
[`deployments/testnet.json`](../deployments/testnet.json) is its
authoritative record; `scripts/verify-deployment.sh` checks it against the
chain ([`deploy/README.md`](deploy/README.md)). This section names the
manifest's fields instead of copying its hashes:

```sh
jq '{source, deployed_at, deployed_ledger, toolchain, registry, zk}' deployments/testnet.json
jq -r '.contracts | to_entries[] | [.key, .value.version, .value.tier, .value.sha256] | @tsv' \
  deployments/testnet.json
```

| Field | Manifest field | Value in the manifest at this commit |
| --- | --- | --- |
| Build commit | `source.commit`, `source.dirty` | `7b164b6ea99119569c9ceacdf2860713212f00a9`, clean tree |
| Network, channel | `network_passphrase`, `channel` | testnet (`Test SDF Network ; September 2015`), `beta` |
| Deployed | `deployed_at`, `deployed_ledger` | 2026-10-12T17:27:53Z, from ledger 5160473 |
| Build toolchain | `toolchain` | rustc 1.97.1 (8bab26f4f 2026-07-14), stellar 27.0.0, scaffold 0.0.27 (`builder`: `scaffold`) |
| Registry instance | `registry.id`, `registry.wasm_hash` | `CAR2DSSOBJB76GGD6MAAKWUK36Y7I7O3NDWTN7HTIRV5I3XZ27U3ZBVZ`, an instance of the canonical registry's Wasm |
| ZK circuit | `zk.circuit_id`, `zk.tree_depth` | the circuit in `circuits/manifest.json`, tree depth 32 |
| Contracts | `contracts.<name>.version`, `.sha256`, `.address`, `.pins` | the ten below |

| Tier | Contracts | Pins |
| --- | --- | --- |
| 0 | `perch-doc-compiler`, `perch-interpreter`, `perch-spending-limit`, `perch-ed25519-verifier`, `perch-webauthn-verifier`, `perch-zk-pool`, `perch-zk-adapter`, `perch-recovery` | none |
| 1 | `perch-account` | the doc compiler, interpreter, and spending limit |
| 2 | `perch-account-factory` | the account and the WebAuthn verifier |

A redeploy rewrites the manifest, and the third column of the first table
changes with it.

**Reproduction record.** On 2026-10-14, on a macOS arm64 host with the
manifest's toolchain, a `git archive` export of `7b164b6` at another path,
built by `scripts/build-stack.sh` with the manifest's builder and
`registry.id`, reproduced all ten `contracts.<name>.sha256` values. Take
`registry.id` from this commit's manifest, not the export's: the export's
own `deployments/testnet.json` names the previous deployment's registry, and
the account and the factory bake the registry id, so building against it
gives other account and factory hashes. Other hosts and toolchains have not been
checked; `stellar scaffold build` optimizes with the wasm-opt its own version
ships.

**Relating the deployment to the reviewed source.** `verify-deployment.sh`
applies to the manifest's hashes only. The [testnet
exercise](deploy/testnet-exercise.md) is evidence for the previous
deployment (build commit `7ae915d`). Six of its contracts have the same hash
in the current deployment: the interpreter, the spending limit, both
verifiers, the ZK pool, and the ZK adapter. The doc compiler, the recovery
controller, the account, and the factory have new hashes that no testnet
exercise has run. To carry the deployment evidence to the reviewed commit,
rebuild the stack there with `scripts/build-stack.sh --registry <registry
id>` and the recorded toolchain, and compare each hash with the manifest;
the handoff records the result. A contract whose hash differs is covered by
source review and in-process tests, not by the deployment evidence.

### Toolchains and locked inputs

| Input | Pin | Where |
| --- | --- | --- |
| Rust | channel `stable`, target `wasm32v1-none`. **Not version-pinned**: reproducing the deployed hashes needs the recorded rustc 1.97.1 | `rust-toolchain.toml` |
| Release profile | `opt-level = "z"`, `overflow-checks = true`, `panic = "abort"`, `lto = true`, `codegen-units = 1` | `Cargo.toml` `[profile.release]` |
| Wasm stack | 64 KiB per contract, 128 KiB for the ZK adapter (an overflow traps) | `crates/*/build.rs` |
| Soroban | `soroban-sdk` 27.0.6, `soroban-env-host` 27.0.1 (test host), `soroban-poseidon` 27.0.0 | `Cargo.lock` |
| OpenZeppelin accounts | `stellar-accounts` 0.7.1 at theahaco/stellar-contracts-OZ `33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` | `Cargo.toml`, `Cargo.lock` |
| Stellar CLI | deployment build: stellar 27.0.0, scaffold 0.0.27 (manifest `toolchain`); CI: stellar-cli 27.1.0, SHA-256-checked | `.github/actions/setup-stellar` |
| ZK proving | nargo 1.0.0-beta.9, bb 0.87.0, every download SHA-256-pinned per platform; proofs are `UltraKeccakZKFlavor` | `scripts/zk-toolchain.sh`, `circuits/manifest.json` |
| ZK proving (JS) | `@noir-lang/noir_js` 1.0.0-beta.9, `@aztec/bb.js` 0.87.0, exact versions | `packages/perch-zk/package.json` |
| UltraHonk verifier base | NethermindEth/rs-soroban-ultrahonk `c2160987260284c656ffbdad8344210fc162b177` | `vendor/ultrahonk-soroban-verifier/NOTICE`, `UPSTREAM.sha256` |
| Lean | `leanprover/lean4:v4.33.0` | `formal/lean-toolchain` |

### Packages

| npm package | Path | Manifest version | Published |
| --- | --- | --- | --- |
| `@stellar-registry/perch` | `packages/perch-js` | 0.3.2 | Yes (`release.yml` `NPM_PACKAGES`, `npm publish --provenance`). 0.3.2 (2026-10-10) contains the consumer interface; this source differs from it in `src/apply.ts`, `src/auth.ts`, and `src/snapshot.ts`, and adds `schemas/policy.schema.json`, so no published release equals this source. |
| `@stellar-registry/perch-interpreter` | `packages/perch-interpreter-js` | 0.1.0 | Yes (0.1.0, 2026-09-09) |
| `@stellar-registry/perch-zk` | `packages/perch-zk` | 0.1.0 | No ([deferred](DEFERRED.md#npm-publishing-of-perch-zk-and-the-contract-clients)) |
| `@stellar-registry/perch-contracts` | `packages/perch-contracts` | 0.1.0 | No ([deferred](DEFERRED.md#npm-publishing-of-perch-zk-and-the-contract-clients)) |
| `@stellar-registry/perch-relay` | `packages/perch-relay` | 0.1.0 | No |

This repository records no npm integrity hashes; a consumer's lockfile does.
The audit reviews the package source at the reviewed commit. A consumer
that resolves a published version instead must show it equal to that source
([`DEFERRED.md`](DEFERRED.md), "Packaging rule"). Rust crates are not
published to crates.io; contract releases are on-chain Wasm publishes.

## Review units

| Unit | Covers | Who reviews |
| --- | --- | --- |
| **Perch core** | Backend-independent: the recovery controller's state machine, the statement, ZK circuit, pool, and adapter, revocation, the freeze, upgrades, the document compiler and CANON, the interpreter, the verifiers, the factory | This audit |
| **Perch OZ materialization** | How a compiled document becomes OZ context rules: the delta reconcile, the install paths, the document caps, the spending-limit wrapper, and the `stellar-accounts` pin | This audit |
| **Explicit dependency review** | Code Perch does not own line by line but every contract or consumer relies on: the three OZ fork deltas, the UltraHonk ZK-flavour delta, the consumed JS packages, and artifact selection | This audit, as named dependency deltas |
| **Nido integration and browser review** | How Nido deploys and calls this stack: its factory, wallet, and browser code | Nido's own audit manifest (`nidohq/nido`, `docs/AUDIT_SCOPE.md`) |

The split between the two Perch units is a review boundary: a later backend
would replace the OZ materialization unit. It is not a guarantee that such a
backend needs no integration review with the core paths it touches
([`DEFERRED.md`](DEFERRED.md#versioned-policy-backend-and-larger-limits)).

### Assignments of named items

| Item | Identity | Assigned to |
| --- | --- | --- |
| OZ fork PR [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3): CAP-0071 delegated auth | in theahaco/stellar-contracts-OZ `33726766` | Explicit dependency review |
| OZ fork PR [#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4): `_no_events` variants | in `33726766` | Explicit dependency review |
| OZ fork PR [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5): `reconcile_signers` | head `33726766` | Explicit dependency review |
| UltraHonk `UltraKeccakZKFlavor` delta | `vendor/ultrahonk-soroban-verifier/src/zk.rs` and the visibility-only changes NOTICE lists | Explicit dependency review |
| Upstream UltraHonk verifier (non-ZK base) | `vendor/ultrahonk-soroban-verifier/**` except the delta | Named exclusion: covered by upstream's internal review and OpenZeppelin audit (NOTICE, `VERIFIER_PROVENANCE.md`); its bytes are checked against `UPSTREAM.sha256` by `crates/perch-zk-adapter/tests/vendor.rs` |
| `@stellar-registry/perch` | `packages/perch-js` | Explicit dependency review |
| `@stellar-registry/perch-zk` | `packages/perch-zk`, including `/indexer` | Explicit dependency review |
| Artifact selection | `scripts/fetch-infra-wasm.sh`, `scripts/build-stack.sh`, `scripts/verify-deployment.sh`, `.github/actions/fetch-infra-wasm`, `testnet_pins` | Explicit dependency review |
| Generated contract clients | `packages/perch-contracts`, `packages/perch-interpreter-js` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Guardian-approval relay | `packages/perch-relay` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Deployment and release execution | `scripts/deploy-stack.sh`, `scripts/bindings-contracts.sh`, `scripts/bootstrap-testnet.sh`, `.github/workflows/release.yml`, `crates/perch-deploy`, `crates/perch-derive-id` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Registry contract | Wasm `4b2d9ea4…` (manifest `registry`), built from `crates/perch-stateless-registry` at an unrecorded commit | Named exclusion (see [Outside the review units](#outside-the-review-units)) |

## Perch core

| Path | What |
| --- | --- |
| `crates/perch-recovery/**` | The controller: attempts, evidence, promotion, cancellation, `enforce` and `rcv_sync`, completion, the two-digest target binding, configuration changes, the enrollment-id check on a changed ZK factor |
| `crates/perch-recovery-interface/**` | The statement and its encoding; the controller, account, pool, and configuration interfaces; credential fingerprints; `rule_hash` and `config_hash` |
| `crates/perch-zk-primitives/**`, `crates/perch-zk-pool/**`, `crates/perch-zk-adapter/**` | Host-side Poseidon2 for the circuit's formulas, the membership pool, and the adapter that checks proofs for the controller |
| `circuits/perch_zk/**`, `circuits/perch_zk_recovery/**`, `circuits/perch_zk_recovery_d24/**` | The Noir recovery circuit, its depth-32 release and depth-24 variants |
| `crates/perch-ir/**`, [`CANONICAL.md`](../CANONICAL.md) | The document schema, validation, and CANON v1 canonical bytes |
| `crates/perch-doc-compiler/**` except the caps | `compile_doc`, `derive_target`, `config_hash`, credential canonicalization |
| `crates/perch-compile/**`, `crates/perch-interpreter/**`, `crates/perch-program/**` | Lowering rules to interpreter programs (with per-rule provenance) and the interpreter policy |
| `crates/perch-smart-account/src/lib.rs`: the recovery and capability paths | `check_auth`, `is_completion`, `complete_recovery`, the freeze mirror and `rcv_gate`, reserved names, `cancel_recovery`, `schedule_upgrade`/`execute_upgrade`/`cancel_upgrade`, `renew`, `execute`, the revision and consumer views, and inside `apply` the revocation and enrollment-id checks, `expected_revision`, and the `rcv_sync` gate |
| `crates/perch-account/**` | The deployable account contract over `perch-smart-account` |
| `crates/perch-webauthn-verifier/**`, `crates/perch-ed25519-verifier/**` | Constructorless signature verifiers for external signers (passkey over OZ `webauthn::verify`; ed25519) |
| `crates/perch-account-factory/**` | Constructorless factory: deploys the pinned account build at an address bound to the admin signers |
| `crates/perch-registry-resolve/**`, `crates/perch-registry-resolve-macro/**` | Build-time infra resolution: the account and factory derive `deployer(registry, sha256(pinned wasm))` with no runtime address |
| `crates/*/build.rs` | The Wasm stack size (see the toolchain table) |

**Evidence:** `crates/integration-tests/tests/{recovery,account_capabilities,target_binding,cap71_semantics,revision}.rs`
(enforcing authorization through `set_auths`); the ZK crates' tests,
including `crates/perch-zk-adapter/tests/{zk_verifier,vendor}.rs`; the
statement vectors `testdata/recovery/statement-v2.json`; the Lean model
(`formal/`); `release_stack.rs` on real Wasm with real proofs. The map from
each spec requirement to its code and tests is
[`recovery/implementation.md`](recovery/implementation.md). Coverage note:
Perch's recovery integration world uses delegated stand-in keys, so recovery
target binding with External (WebAuthn) credentials — where the credential-id
suffix and key canonicalization matter — is exercised by Nido's suite
(`crates/integration-tests` in the superproject), not Perch's.

## Perch OZ materialization

| Path | What |
| --- | --- |
| `crates/perch-smart-account/src/rules.rs` | The delta reconcile: rules matched by slot, the cheaper of an in-place edit and a replacement per rule (`Cost`, `Meter`), every OZ mutation through its `_no_events` variant, the `DeltaSummary` |
| `crates/perch-smart-account/src/lib.rs`: the install paths | `apply_rules`, the install half of `apply` (rules, enrollment write, `DocApplied`), `installed_rules`, the OZ rule views, `install_admin` |
| `crates/perch-doc-compiler/src/lib.rs`: the caps | `MAX_DOC_SIGNERS` = 8, `MAX_DOC_RULES` = 11, `MAX_DOC_CANONICAL_BYTES` = 8,192, `MAX_RULE_NAME_BYTES` (OZ's `MAX_NAME_SIZE`, 20), and the `DocTooLarge` refusal |
| `crates/perch-spending-limit/**` | The deployable wrapper of OZ `spending_limit`, installing and uninstalling without events |
| `Cargo.toml`: `stellar-accounts` | The fork pin, which applies to every contract that links it (all but the ZK pool and adapter) |

**Evidence:** `crates/integration-tests/tests/{apply_delta,delta_security,doc_caps}.rs`;
the full-replace oracle `crates/perch-testkit/src/delta.rs` and the fuzz
target `fuzz/fuzz_targets/apply_doc_delta.rs`. The full replace shares
compile and the desired rule set (expiry drop, recovery rule) with the
delta, so it checks the reconcile only; each accepted step is also checked
against the grant the document model computes on its own
(`DocModel::expected_rules` against `live_rules`, read from OZ's context
rules and the policies' stored parameters). The generator reaches the
document caps, permutes signer lists, spells keys in either hex case and cap
limits with leading zeros or a sign, and advances the ledger past rule
expiries between documents; `release_stack.rs`
(`worst_case_*`, `signer_transitions`, `cap_sweep`,
`the_metered_footprint_is_the_simulated_transactions`);
[`recovery/budgets.md`](recovery/budgets.md), "Document caps", which sizes
the caps.

## Explicit dependency review

### The OZ fork

`stellar-accounts` is pinned to theahaco/stellar-contracts-OZ at
`33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9`: upstream OpenZeppelin
`fbfde38` (the fork's `main`) plus three commits, one for each of three
open, stacked fork pull requests. Review the fork's changes as the diff
from `fbfde38` to `33726766`.

| Fork PR | What its commit changes |
| --- | --- |
| [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3) | `Signer::Delegated` authenticates through `delegate_account_auth` (CAP-0071): one `AddressWithDelegates` auth entry instead of a separate `require_auth_for_args` entry per delegate |
| [#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4) | `_no_events` variants of every context-rule, signer, and policy mutation, and of `spending_limit`'s install and uninstall |
| [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5) | `reconcile_signers[_no_events]`: one validated, atomic signer-set update |

None of this code is in the Perch repository. It is in scope because every
Perch contract except the ZK pool and adapter links it. The host and OZ behaviour the recovery design
relies on is pinned by tests in [`recovery/cap-0071.md`](recovery/cap-0071.md).
Merging the pull requests is
[deferred](DEFERRED.md#oz-quiet-events-fork-pull-requests).

### The UltraHonk ZK-flavour delta

`vendor/ultrahonk-soroban-verifier` is NethermindEth's audited, non-ZK
UltraHonk verifier at `c2160987…`, plus Perch's delta: `src/zk.rs` (new,
1,030 lines; the `UltraKeccakZKFlavor` verifier), three added lines in
`src/lib.rs`, visibility-only changes in `src/transcript.rs`,
`src/sumcheck.rs`, `src/utils.rs`, and `src/verifier.rs`, the `Cargo.toml`
changes the NOTICE records (`soroban-sdk` pinned to the upstream workspace's
version and the `[dev-dependencies]` dropped), and the vendored `README.md`
that documents the delta. The README maps each delta function to the audited
function it mirrors, where one exists, and its Barretenberg v0.87.0 reference;
the ZK flavour also adds functions with no non-ZK counterpart (its own
proof-verification path). `crates/perch-zk-adapter/tests/vendor.rs` fails if
any file outside the delta differs from upstream's `UPSTREAM.sha256` bytes; it
does not re-audit the delta. No audit covered the delta
before this one ([`zk/README.md`](zk/README.md)). For an offline handoff, a
review of the delta needs the Barretenberg v0.87.0 reference sources the
README maps to (the ZK-flavour reference files — e.g. `honk_zk_contract.hpp`,
`small_subgroup_ipa.hpp`, `shplemini.hpp`, `sumcheck.hpp`, and
`row_disabling_polynomial.hpp`) at their exact upstream commit, not only the
`v0.87.0` release tag, plus the generated Solidity verifier for the committed
recovery VK; record that commit and ship the reference files (checksummed) in
the handoff bundle.

### Consumed JS packages

- **`packages/perch-js`**: canonical JSON and `doc_hash`, `ruleHash`,
  `configHash`, the statement and credential encodings, `signingDigest` and
  `buildAuthPayload`, and the consumer interface (`readSnapshot`,
  `selectRules`, `assertSignable`, `applyDocument`, `mapSubmissionError`).
  A wallet signs what these compute. Vectors the Rust suite writes from the
  contracts' own code pin them (`testdata/auth/`, `testdata/recovery/`,
  `testdata/rule-hashes.json`).
- **`packages/perch-zk`**: secret generation (`randomSecret`),
  commitments, the witness index (`PoolWitnessIndex`, `/indexer`), circuit
  inputs, bb.js proving, and the evidence the controller receives. Its tests
  check Poseidon2 parity with the circuit and the host and the shipped
  artifacts against `circuits/manifest.json`.

### Artifact selection

`scripts/fetch-infra-wasm.sh` (and the CI action that runs it) and
`scripts/build-stack.sh` decide which compiler, interpreter,
spending-limit, account, and WebAuthn-verifier bytes are compiled into the
account and the factory as `registry_contract!` pins. Each fetched Wasm is
refused unless its SHA-256, and for a deployed contract its content
address, match the manifest. `cargo test -p perch-integration-tests --test
testnet_pins` checks the pins actually compiled in, and
`scripts/verify-deployment.sh` checks that every pinned address runs its
recorded Wasm and that consumers resolve it
([`deploy/README.md`](deploy/README.md)).

## Outside the review units

These cannot change what a deployed contract does, or their effect is
checked by hash. They are not reviewed line by line.

- **Generated contract clients** (`packages/perch-contracts`,
  `packages/perch-interpreter-js`): generated by `stellar contract bindings
  typescript` from the deployed Wasm. Each `perch-contracts` module's
  `WASM_SHA256` is tested against the manifest; the interpreter bindings
  are tested against the golden XDR vectors (`testdata/golden/`).
- **The guardian-approval relay** (`packages/perch-relay`): the chain
  decides every approval, so a relay can delay or drop approvals but never
  make the controller accept one. Its admission checks protect only a
  guardian's slot from displacement. An operator (Nido's hosted relay)
  reviews its own deployment.
- **Deployment and release execution** (`scripts/deploy-stack.sh`,
  `bindings-contracts.sh`, `bootstrap-testnet.sh`,
  `.github/workflows/`, `crates/perch-deploy`, `crates/perch-derive-id`):
  they choose what is deployed and published. The deployed bytes are checked
  by hash against the manifest, and the manifest's hashes are reproducible
  from source ([Deployment provenance](#deployment-provenance)).
- **The registry contract** (Wasm `4b2d9ea4…`): a
  `crates/perch-stateless-registry` build that `deploy-stack.sh` reuses by
  hash from the canonical registry instead of rebuilding; this repository
  does not record which commit built it. Its `deploy_stateless` places code
  at the content addresses the account and factory derive.
  `verify-deployment.sh` checks that each address runs its recorded Wasm,
  and that check must pass for each new deployment before it is used.
- **Off-chain tooling and harnesses** (`crates/perch-testnet`,
  `crates/perch-zk-prover`, `crates/perch-testkit`, `crates/perch-bench*`,
  `crates/perch-conformance`, `crates/perch-golden`, `crates/perch-analyze`,
  `crates/integration-tests`): evidence and tools, not deployed contract
  code.
- **Documentation and slides** (`docs/**`, `*.md`). The recovery spec is
  normative for both Perch units.

## Generated and vendored content

Checked for provenance, not read line by line. `.gitattributes` collapses
the generated paths in GitHub diffs.

| Path | Produced by | Checked by |
| --- | --- | --- |
| `**/test_snapshots/**` | `cargo test` (test-host snapshots) | regenerated on every run |
| `Cargo.lock`, `**/package-lock.json` | cargo, npm | `--locked` builds, `npm ci` |
| `packages/perch-contracts/src/**` | `scripts/bindings-contracts.sh` from the deployed Wasm | `packages/perch-contracts/test` (`WASM_SHA256` equals the manifest's) |
| `deployments/**` | `scripts/deploy-stack.sh`, `cargo run -p perch-testnet` | `scripts/verify-deployment.sh`, `testnet_pins` |
| `circuits/artifacts/**`, `circuits/manifest.json`, `packages/perch-zk/artifacts/**`, `testdata/zk/**` | `nargo`/`bb` with the pinned toolchain, `perch-zk-fixtures` | CI's `zk` job (`perch-zk-fixtures check`) |
| `vendor/ultrahonk-soroban-verifier/**` except the delta | NethermindEth's audited UltraHonk verifier | `UPSTREAM.sha256`, `CHECKSUMS.sha256`, `crates/perch-zk-adapter/tests/vendor.rs` |
| `circuits/vendor/poseidon/**` | upstream Noir Poseidon, including generated constants | `CHECKSUMS.sha256`, `crates/perch-zk-adapter/tests/vendor.rs` |

## Known limitations at this revision

Each is stated in full where linked.

- `Protected` without a baseline does not protect against a thief who holds
  the owner key ([spec](recovery/spec.md) §2).
- The `Protected` freeze stops new authorizations by the account; a
  permission granted earlier, such as a token allowance, stays usable
  (spec §9).
- Only `apply_doc` is bound to a configuration revision; an ordinary
  signature executes under an in-place edit of its selected rule (spec §15,
  [`DEFERRED.md`](DEFERRED.md#revision-bound-ordinary-signatures)).
- Replacing a capped rule, or changing its cap, starts an empty spending
  window ([`DEFERRED.md`](DEFERRED.md#persistent-spending-budgets-across-replacements)).
- An archived persistent entry makes every transaction that touches it fail
  until it is restored. Permissionless renewal entry points extend most
  entries, but the account's `renew` does not extend its installed-rule
  records or OZ's context-rule, signer, and policy entries, so an idle
  account may need a restore before its next transaction (spec §3.6 lists
  what renews what). Restoring is the submitting client's job.
- The adapter still exports the raw `verify_proof`, which nothing in Perch
  calls ([`zk/README.md`](zk/README.md)).
- Client proving on the reference phone and laptop is unmeasured
  ([`recovery/budgets.md`](recovery/budgets.md) §1).
- `rust-toolchain.toml` does not pin a Rust version (see the toolchain
  table).

## Reading order

1. This manifest and [`DEFERRED.md`](DEFERRED.md).
2. [`recovery/spec.md`](recovery/spec.md): the normative recovery and
   authorization specification for both Perch units.
3. [`recovery/statement.md`](recovery/statement.md): byte layouts of the
   recovery statement, credential fingerprints, and replacement sets.
4. [`../CANONICAL.md`](../CANONICAL.md): CANON v1, the document identity
   and fragment hashes.
5. [`recovery/cap-0071.md`](recovery/cap-0071.md): the host and OZ
   delegated-auth and invoker-auth behaviour the spec relies on.
6. [`recovery/implementation.md`](recovery/implementation.md): where each
   part of the spec is implemented and tested.
7. [`zk/README.md`](zk/README.md), then [`zk/circuit.md`](zk/circuit.md),
   [`zk/pool.md`](zk/pool.md), and [`zk/measurements.md`](zk/measurements.md).
8. [`recovery/budgets.md`](recovery/budgets.md): measured costs and the
   document caps.
9. [`recovery/formal-verification-impact.md`](recovery/formal-verification-impact.md)
   and [`verification/PLAN.md`](verification/PLAN.md): what is proved,
   what is differentially tested, and what has no formal model.
10. [`deploy/README.md`](deploy/README.md): build order, pins, and
    deployment verification.

The [testnet exercise](deploy/testnet-exercise.md) is an evidence report
for the previous deployment, not part of the reading order.

## Deferred until after the audit

[`DEFERRED.md`](DEFERRED.md) holds one entry per deferral: CANON v2
identity, canonical value spellings, the PolicyDoc JSON Schema's strict
profile and out-of-schema checks, a versioned policy backend and larger
limits, revision-bound ordinary signatures, stable numeric rule ids,
persistent spending budgets, additional formal models, the OZ fork pull
requests, npm publishing of `perch-zk` and the contract clients, completion
input-byte binding, and contract-admin governance behind a multisig and
timelock.

[Completion input-byte binding](DEFERRED.md#completion-input-byte-binding)
affects authorization: a leftover completion marker lets an `apply_doc`
under ordinary owner authority, carrying a differently formatted spelling of
the authorized canonical target in the same ledger and authorized window, be
classified as a recovery completion instead of an ordinary write.
