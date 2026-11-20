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
| Build commit | `source.commit`, `source.dirty` | `c135aca277745434f2abf679edd9868c95204b51`, from before this stack; `dirty: false` |
| Network, channel | `network_passphrase`, `channel` | testnet (`Test SDF Network ; September 2015`), `beta` |
| Deployed | `deployed_at`, `deployed_ledger` | 2026-10-22T13:41:43Z, from ledger 5330546 |
| Build toolchain | `toolchain` | rustc 1.99.1 (58cf8f9c3 2026-10-13), stellar 28.0.0-aha.0 (the `theahaco/stellar-cli` fork), scaffold 0.0.27 (`builder`: `scaffold`) |
| Registry | `registry.id`, `registry.wasm_hash` | `CDZGU4AIND6QRCGAN72I7DCS2EKRZ76JSKYY7KKJR4CG5IR2AMFIBZTM`, the canonical `constructorless` registry ([`testnet-deployment.md`](testnet-deployment.md)) |
| ZK circuit | `zk.circuit_id`, `zk.tree_depth` | the circuit in `circuits/manifest.json`, tree depth 32 |
| Contracts | `contracts.<name>.version`, `.sha256`, `.address`, `.pins` | the ten below |

| Tier | Contracts | Pins |
| --- | --- | --- |
| 0 | `perch-doc-compiler`, `perch-interpreter`, `perch-spending-limit`, `perch-ed25519-verifier`, `perch-webauthn-verifier`, `perch-zk-pool`, `perch-zk-adapter`, `perch-recovery` | none |
| 1 | `perch-account` | the doc compiler, interpreter, and spending limit |
| 2 | `perch-account-factory` | the account and the WebAuthn verifier |

A redeploy rewrites the manifest, and the third column of the first table
changes with it. [`deployments/mainnet.json`](../deployments/mainnet.json)
records the mainnet deployment of the same build commit with the same
toolchain (deployed 2026-10-26T01:28:04Z, from ledger 65138427), into
mainnet's registry `CC236AK2RX7MUO7BV7JYDDW5KHZ3X7YYJOJKCVDC543BQBNNSUCZB7NN`.

**How these bytes were built.** `release.yml`'s `deploy-stack` job deploys
in canonical mode
([`deploy/README.md`](deploy/README.md#the-canonical-registry-and-publishing-the-stack-to-it)):
it reuses the bytes the registry already serves for contracts it does not
rebuild, which `release.yml`'s attested release build produced, and builds
the rest with `scripts/build-stack.sh` on a GitHub-hosted Linux runner,
using the manifest's toolchain, attesting each one's build provenance. The
manifest does not record which contracts were reused. `source.dirty` is
`false`: the checkout had no uncommitted changes in an input
`scripts/source-dirty.sh` checks.

**Reproduction record.** No reproduction of these manifests' hashes is
recorded. Rebuilding `c135aca` with `build-stack.sh` and the recorded
toolchain should give the hashes of the contracts the job built; a reused
contract comes from the attested release build, not from `build-stack.sh`,
so rebuilding it gives other bytes
([`deploy/README.md`](deploy/README.md#the-canonical-registry-and-publishing-the-stack-to-it)).
An earlier deployment (build commit `7b164b6`, clean tree, manifest
[`deployments/testnet.json` at `845c49a`](https://github.com/stellar-registry/perch/blob/845c49a376c08aeeed9f5d3c63356b753dc617f4/deployments/testnet.json))
was reproduced in full on 2026-10-14. On a macOS arm64 host with that
manifest's toolchain, `scripts/build-stack.sh` built a `git archive` export
of `7b164b6` against that manifest's `registry.id` and reproduced all ten
hashes.

**Relating the deployment to the reviewed source.** `verify-deployment.sh`
applies to the manifest's hashes only. The [testnet
exercise](deploy/testnet-exercise.md) is evidence for an earlier deployment
(build commit `7ae915d`). None of that deployment's contract hashes appear
in the current deployment, so no testnet exercise has run the current
bytes. To relate the deployment to the reviewed commit, rebuild the stack
there with `scripts/build-stack.sh --registry <registry id>` and the
recorded toolchain, and compare each built hash with the manifest; the
handoff records the result. For the four reused contracts, compare against
the attested release build of their tagged versions instead. Source review
and in-process tests cover any contract whose hash differs; the deployment
evidence does not.

### Toolchains and locked inputs

| Input | Pin | Where |
| --- | --- | --- |
| Rust | rustc 1.99.1, target `wasm32v1-none`: the version both manifests record for the current deployments | `rust-toolchain.toml`; `toolchain:` in `.github/workflows/` |
| Release profile | `opt-level = "z"`, `overflow-checks = true`, `panic = "abort"`, `lto = true`, `codegen-units = 1` | `Cargo.toml` `[profile.release]` |
| Wasm stack | 64 KiB per contract, 128 KiB for the ZK adapter (an overflow traps) | `crates/*/build.rs` |
| Soroban | `soroban-sdk` 29.0.1, `soroban-env-host` 29.0.1 (test host), `soroban-poseidon` 28.0.0 (moved to soroban-sdk 29, pinned to bitswell-hq/stellar__rs-soroban-poseidon `f2226191bf442dafa9972ca37db8975013d965a2` until stellar/rs-soroban-poseidon PR [#21](https://github.com/stellar/rs-soroban-poseidon/pull/21) is released) | `Cargo.toml`, `Cargo.lock` |
| OpenZeppelin accounts | `stellar-accounts` 0.7.1 at bitswell-hq/theahaco__stellar-contracts-OZ `42089fc90684fdab33a85eac3e8311259b69a61b` (theahaco's fork at `33726766`, moved to soroban-sdk 29.0.1) | `Cargo.toml`, `Cargo.lock` |
| Stellar CLI | deployment build: stellar 28.0.0-aha.0 (the `theahaco/stellar-cli` fork) and scaffold 0.0.27, SHA-256-checked by `release.yml`'s `deploy-stack` (manifest `toolchain`); CI: stellar-cli 27.1.0, SHA-256-checked | `.github/workflows/release.yml`, `.github/actions/setup-stellar` |
| ZK proving | nargo 1.0.0-beta.9, bb 0.87.0, every download SHA-256-pinned per platform; proofs are `UltraKeccakZKFlavor` | `scripts/zk-toolchain.sh`, `circuits/manifest.json` |
| ZK proving (JS) | `@noir-lang/noir_js` 1.0.0-beta.9, `@aztec/bb.js` 0.87.0, exact versions | `packages/perch-zk/package.json` |
| rule-core | `rule-eval`, `soroban-facade`, and `rule-eval-conformance` (tests only) at stellar-registry/soroban-rule-core `a3c92ba074dcac4052727b7599e5fd8674af6c0a`, one rev for all three; `soroban-facade` pins `soroban-sdk` `=29.0.1` | `Cargo.toml`, `Cargo.lock` |
| UltraHonk verifier base | NethermindEth/rs-soroban-ultrahonk `c2160987260284c656ffbdad8344210fc162b177` | `vendor/ultrahonk-soroban-verifier/NOTICE`, `UPSTREAM.sha256` |
| Lean | `leanprover/lean4:v4.33.0` | `formal/lean-toolchain` |

### Packages

| npm package | Path | Manifest version | Published |
| --- | --- | --- | --- |
| `@stellar-registry/perch` | `packages/perch-js` | 0.4.0 | 0.4.0 (2026-10-15), from tag `perch-js-v0.4.0`; `src/` there equals this source |
| `@stellar-registry/perch-interpreter` | `packages/perch-interpreter-js` | 0.1.0 | 0.1.0 (2026-09-09) |
| `@stellar-registry/perch-zk` | `packages/perch-zk` | 0.1.0 | 0.1.0 (2026-10-15), from tag `perch-zk-v0.1.0`; `src/` there equals this source |
| `@stellar-registry/perch-relay` | `packages/perch-relay` | 0.1.0 | 0.1.0 (2026-10-15), from tag `perch-relay-v0.1.0`; `src/` there equals this source |
| `@stellar-registry/perch-contracts` | `packages/perch-contracts` | 0.1.0 | 0.1.0 (2026-10-15), from tag `perch-contracts-v0.1.0`, which predates the current deployment: its bindings and manifest name the previous one, so it differs from this source |
| `@stellar-registry/perch-artifacts` | `packages/perch-artifacts` | 0.1.0 | 0.1.0 (2026-10-15), from tag `perch-artifacts-v0.1.0`, which predates the current deployment: its `deployments/testnet.json` is the previous one, so it differs from this source |

`release.yml`'s `npm-publish` job publishes each package, with
`npm publish --provenance`, when a merge bumps its manifest version.
This repository records no npm integrity hashes; a consumer's lockfile does.
The audit reviews the package source at the reviewed commit. A consumer
that resolves a published version instead must show it equal to that source
([`DEFERRED.md`](DEFERRED.md), "Packaging rule"). Rust crates are not
published to crates.io; contract releases are on-chain Wasm publishes.

## Review units

| Unit | Covers | Who reviews |
| --- | --- | --- |
| **Perch core** | Backend-independent: the recovery controller's state machine, the statement, ZK circuit, pool, and adapter, revocation, the freeze, upgrades, the document compiler and CANON, the interpreter, the verifiers, the factory | This audit |
| **Perch rule storage** | How a compiled document becomes the account's own rule records: the delta reconcile, the install paths, the stored rule layout, the account- and grant-document caps, and the legacy policy contracts that still link `stellar-accounts` | This audit |
| **Explicit dependency review** | Code Perch does not own line by line but every contract or consumer relies on: rule-core's evaluator, the three OZ fork deltas, the UltraHonk ZK-flavour delta, the consumed JS packages, and artifact selection | This audit, as named dependency deltas |
| **Nido integration and browser review** | How Nido deploys and calls this stack: its factory, wallet, and browser code | Nido's own audit manifest (`nidohq/nido`, `docs/AUDIT_SCOPE.md`) |

The split between the two Perch units is a review boundary: a later backend
would replace the rule storage unit. It is not a guarantee that such a
backend needs no integration review with the core paths it touches
([`DEFERRED.md`](DEFERRED.md#versioned-policy-backend-and-larger-limits)).

### Assignments of named items

| Item | Identity | Assigned to |
| --- | --- | --- |
| rule-core: `rule-eval` and `soroban-facade` | stellar-registry/soroban-rule-core `a3c92ba0` | Explicit dependency review |
| OZ fork PR [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3): CAP-0071 delegated auth | in theahaco/stellar-contracts-OZ `33726766` | Explicit dependency review |
| OZ fork PR [#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4): `_no_events` variants | in `33726766` | Explicit dependency review |
| OZ fork PR [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5): `reconcile_signers` | head `33726766` | Explicit dependency review |
| soroban-sdk 29 port of the OZ fork | bitswell-hq/theahaco__stellar-contracts-OZ PR #1, head `42089fc9` | Explicit dependency review |
| UltraHonk `UltraKeccakZKFlavor` delta | `vendor/ultrahonk-soroban-verifier/src/zk.rs` and the visibility-only changes NOTICE lists | Explicit dependency review |
| Upstream UltraHonk verifier (non-ZK base) | `vendor/ultrahonk-soroban-verifier/**` except the delta | Named exclusion: covered by upstream's internal review and OpenZeppelin audit (NOTICE, `VERIFIER_PROVENANCE.md`); its bytes are checked against `UPSTREAM.sha256` by `crates/perch-zk-adapter/tests/vendor.rs` |
| `@stellar-registry/perch` | `packages/perch-js` | Explicit dependency review |
| `@stellar-registry/perch-zk` | `packages/perch-zk`, including `/indexer` | Explicit dependency review |
| Artifact selection | `scripts/fetch-infra-wasm.sh`, `scripts/build-stack.sh`, `scripts/verify-deployment.sh`, `.github/actions/fetch-infra-wasm`, `testnet_pins` | Explicit dependency review |
| Generated contract clients | `packages/perch-contracts`, `packages/perch-interpreter-js` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Guardian-approval relay | `packages/perch-relay` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Deployment and release execution | `scripts/deploy-stack.sh`, `scripts/derive-id.py`, `scripts/bindings-contracts.sh`, `scripts/bootstrap-testnet.sh`, `.github/workflows/release.yml`, `crates/perch-deploy`, `crates/perch-derive-id` | Named exclusion (see [Outside the review units](#outside-the-review-units)) |
| Registry contract | Wasm `4b2d9ea4…` (manifest `registry`), built from `crates/perch-stateless-registry` (since renamed `crates/perch-constructorless-registry`) at an unrecorded commit | Named exclusion (see [Outside the review units](#outside-the-review-units)) |

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
| `crates/perch-rule-eval/**` | Perch's rules as rule-core's evaluator reads them: host-value conversions, the storage mirrors `__check_auth` reads, and the anti-brick checks |
| `crates/perch-webauthn-verifier/**`, `crates/perch-ed25519-verifier/**`, `crates/perch-mldsa-verifier/**` | Constructorless signature verifiers for external signers (passkey over OZ `webauthn::verify`; ed25519 over OZ's `ed25519` verifier; ML-DSA-65 over the unaudited `fips204` crate) |
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

## Perch rule storage

The account links no `stellar-accounts` code. Its own records are its rule
registry: every rule is one record, in `RuleSet` for the account document
and in its grant's record for a grant document, under an id the account
allocates and never reuses. Each record holds the stored rule-eval rule
(`StoredRule`, snapshot 3) that `__check_auth` evaluates. The ids, the
signer and payload wire types, and the `get_context_rule` views keep OZ's
shapes, so wallets select the same ids
([`account-interface.md`](account-interface.md)).

| Path | What |
| --- | --- |
| `crates/perch-smart-account/src/rules.rs` | The delta reconcile for `apply_doc` and `apply_grant`: rules matched by name and scope (the recovery rule by role), unchanged rules kept, differing rules edited in place under their id, the rest removed or added under new ids; OZ's install-time limits (`check`); id allocation; the `DeltaSummary` |
| `crates/perch-smart-account/src/rule_set.rs` | Lowering a compiled document's model to the stored rule-eval rules, for account documents (`lowered`) and grant documents (`lowered_grant`, which refuses token-admin functions); the constructor's admin rule |
| `crates/perch-smart-account/src/lib.rs`: the install paths | `apply_rules`, the install half of `apply` (rules, enrollment write, `DocApplied`), `apply_grant`, `remove_grant`, `gc_grant`, the grant-escalation and normal-form checks, the signer tables, `installed_rules`, `rule_set`, and the OZ-shaped rule views |
| `crates/perch-account-types/**` | The account's signer, `__check_auth` payload, context-rule, and error types, XDR- and spec-identical to OZ's (`tests/openzeppelin.rs` checks each against its OZ twin) |
| `crates/perch-doc-compiler/src/lib.rs`: the caps | Account documents: `MAX_DOC_SIGNERS` = 8, `MAX_DOC_RULES` = 10, `MAX_DOC_CANONICAL_BYTES` = 8,192. Grant documents: `MAX_GRANT_SIGNERS` = 15, `MAX_GRANT_RULES` = 50, `MAX_GRANT_CANONICAL_BYTES` = 8,192, `MAX_GRANT_STORED_BYTES` = 49,152. Both: `MAX_RULE_NAME_BYTES` (OZ's `MAX_NAME_SIZE`, 20) and the `DocTooLarge` refusal |
| `crates/perch-spending-limit/**`, `crates/perch-interpreter/**` | Legacy policy contracts, which current accounts attach to no rule: the deployable wrapper of OZ `spending_limit` and the interpreter policy. The account still pins both. With the verifiers, they are the deployed contracts that link `stellar-accounts` |
| `Cargo.toml`: `stellar-accounts` | The fork pin, for the contracts that still link it: the WebAuthn, ed25519, and ML-DSA verifiers, the interpreter, and the spending limit |

**Evidence:** `crates/integration-tests/tests/{apply_delta,apply_grant_delta,delta_security,doc_caps,grant_docs,grant_stored_size,rule_set}.rs`;
the full-replace oracle `crates/perch-testkit/src/delta.rs` and the fuzz
targets `fuzz/fuzz_targets/{apply_doc_delta,apply_grant_delta}.rs`. The full
replace shares compile and the desired rule set (expiry drop, recovery rule)
with the delta, so it checks the reconcile only; each accepted step is also
checked against the grant the document model computes on its own
(`DocModel::expected_rules` against `live_rules`, read from the account's
context-rule views and the stored rule-eval rule each id selects), and,
after each grant step, the stored rule set against the lowering of the
document's model. The generator reaches the document caps, permutes signer
lists, spells keys in either hex case and cap limits with leading zeros or a
sign, interleaves `apply_doc` with `apply_grant` and `remove_grant`, and
advances the ledger past rule expiries between documents; `release_stack.rs`
(`worst_case_*`, `signer_transitions`, `cap_sweep`,
`the_metered_footprint_is_the_simulated_transactions`);
[`recovery/budgets.md`](recovery/budgets.md), "Document caps", which sizes
the caps.

## Explicit dependency review

### The OZ fork

`stellar-accounts` is pinned to bitswell-hq/theahaco__stellar-contracts-OZ
at `42089fc90684fdab33a85eac3e8311259b69a61b`, a fork of theahaco's fork.
theahaco/stellar-contracts-OZ `33726766a1fd5e7e3d2977d79f64ee29e1ea3ca9` is
upstream OpenZeppelin `fbfde38` (the fork's `main`) plus three commits, one
for each of three open, stacked fork pull requests; `42089fc9` adds one
more, moving it to soroban-sdk 29.0.1 (the bitswell-hq fork's PR #1, branch
`fm/oz-quiet-events-x1-reconcile`). Review the changes as the diff from
`fbfde38` to `42089fc9`.

| Fork PR | What its commit changes |
| --- | --- |
| [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3) | `Signer::Delegated` authenticates through `delegate_account_auth` (CAP-0071): one `AddressWithDelegates` auth entry instead of a separate `require_auth_for_args` entry per delegate |
| [#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4) | `_no_events` variants of every context-rule, signer, and policy mutation, and of `spending_limit`'s install and uninstall |
| [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5) | `reconcile_signers[_no_events]`: one validated, atomic signer-set update |
| bitswell-hq PR #1 | The move to soroban-sdk 29.0.1 |

None of this code is in the Perch repository. The account, the recovery
controller, the doc compiler, the factory, and the ZK pool and adapter link
none of it: the account owns its authorization types
(`perch-account-types`) and authenticates `Delegated` signers itself
through the host's CAP-0071 `delegate_auth`. It is in scope because the
WebAuthn, ed25519, and ML-DSA verifiers (OZ's `Verifier` trait, and
`webauthn::verify` and `ed25519` for the first two) and the legacy
interpreter and spending-limit policies link it, and the account still
pins the latter two. The host and OZ behaviour the recovery design
relies on is pinned by tests in [`recovery/cap-0071.md`](recovery/cap-0071.md).
Merging the pull requests is
[deferred](DEFERRED.md#oz-quiet-events-fork-pull-requests).

### rule-core

`rule-eval` and `soroban-facade` come from stellar-registry/soroban-rule-core at
`a3c92ba074dcac4052727b7599e5fd8674af6c0a`, a git dependency, not vendored.
`rule-eval` is the rule-set evaluator and document lowering, proven against
rule-core's Lean model; `soroban-facade` reads Soroban values and
authorization contexts for it. `rule-eval-conformance`, at the same rev, runs
the vectors that model generates and is used only by tests.

The account decides every authorization except a recovery completion with
`rule_eval::check_auth` over its stored rule sets, after its own
reserved-name, freeze, and grant-escalation checks
([`account-interface.md`](account-interface.md)). It reaches the deployed
contracts through `perch-smart-account` (so `perch-account`) and, by way of
`crates/perch-rule-eval`, `perch-doc-compiler`; `perch-review-core` links it
off-chain to compute the same verdict. A recovery completion is decided by
the controller's `rcv_complete`, not by the evaluator.

Review the code at that rev that these crates link. The Lean proofs cover
the model; nothing checks that the compiled wasm matches the Lean
translation (`crates/perch-review-core/README.md`, "Out of scope"), so the
Rust is reviewed as code, with the proofs as its specification. Perch's own
side of the boundary, `crates/perch-rule-eval` (host conversions, storage
mirrors, the anti-brick checks), is Perch core. Evidence: Perch's
conformance run against rule-core's vectors, the recorded baseline, and the
authorization corpus recorded before the move to soroban-sdk 29
(`crates/integration-tests/tests/corpus/`: `rule-eval-baseline.json`,
`auth-outcomes.json`, `declared-differences.json`).

### The UltraHonk ZK-flavour delta

`vendor/ultrahonk-soroban-verifier` is NethermindEth's audited, non-ZK
UltraHonk verifier at `c2160987…`, plus Perch's delta: `src/zk.rs` (new,
1,030 lines; the `UltraKeccakZKFlavor` verifier), three added lines in
`src/lib.rs`, visibility-only changes in `src/transcript.rs`,
`src/sumcheck.rs`, `src/utils.rs`, and `src/verifier.rs`, the `Cargo.toml`
changes the NOTICE records (`soroban-sdk` pinned to the 29.0.1 Perch builds
with, where the upstream workspace pins 27.0.6 at that commit, and the
`[dev-dependencies]` dropped), and the vendored `README.md`
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
  `derive-id.py`, `bindings-contracts.sh`, `bootstrap-testnet.sh`,
  `.github/workflows/`, `crates/perch-deploy`, `crates/perch-derive-id`):
  they choose what is deployed and published. The deployed bytes are checked
  by hash against the manifest, and the manifest's hashes are reproducible
  from source ([Deployment provenance](#deployment-provenance)).
- **The registry contract** (Wasm `4b2d9ea4…`): a
  `crates/perch-stateless-registry` build (the crate is now
  `crates/perch-constructorless-registry`) the canonical registries run;
  `deploy-stack.sh` publishes into the instance `registry.path` derives and
  never deploys or rebuilds one, and this repository does not record which
  commit built it. Its `deploy_stateless` places code
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
  entries, but the account's `renew` does not extend its rule records
  (`RuleSet`, grant records, `GrantTags`, `SpendRecords`), so an idle
  account may need a restore before its next transaction (spec §3.6 lists
  what renews what). Restoring is the submitting client's job.
- The adapter still exports the raw `verify_proof`, which nothing in Perch
  calls ([`zk/README.md`](zk/README.md)).
- Client proving on the reference phone and laptop is unmeasured
  ([`recovery/budgets.md`](recovery/budgets.md) §1).

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
for an earlier deployment, not part of the reading order.

## Deferred until after the audit

[`DEFERRED.md`](DEFERRED.md) holds one entry per deferral: CANON v2
identity, canonical value spellings, the PolicyDoc JSON Schema's strict
profile and out-of-schema checks, a versioned policy backend and larger
limits, revision-bound ordinary signatures, stable numeric rule ids,
persistent spending budgets, additional formal models, the OZ fork pull
requests, completion input-byte binding, and contract-admin governance
behind a multisig and timelock.

[Completion input-byte binding](DEFERRED.md#completion-input-byte-binding)
affects authorization: a leftover completion marker lets an `apply_doc`
under ordinary owner authority, carrying a differently formatted spelling of
the authorized canonical target in the same ledger and authorized window, be
classified as a recovery completion instead of an ordinary write.
