# Audit scope

This maps the code of the #99 stack to the two audit units of RFC
[#109](https://github.com/stellar-registry/perch/issues/109), "split the audit
so a later swap is a delta review":

1. **The backend-independent core**: the controller state machine, the
   statement, ZK, the pool, revocation, the freeze, upgrades, the compiler and
   CANON, and the interpreter.
2. **The OZ materialization layer**: `rules.rs`, `apply`, the caps, and the
   OZ fork deltas.

The audit covers a frozen commit, not pull requests. The paths below are as of
the release head (`fm/perch-epic99-release-p8`). "Introduced in" gives the
pull request and commits that wrote or last reshaped each path, so a reviewer
can read them in the order they were built. Record the frozen commit here when
the audit starts.

Code that sits outside any perch diff is part of the scope: the
`stellar-accounts` fork the workspace pins (see
[The OZ fork](#the-oz-fork)).

## The stack

Each pull request is based on the one before it. Merges into a branch carry
`.gitattributes` forward from #100; they add no code. #103 was split into #111
and #103 on 2026-10-07. The history before the split is kept at
`fm/perch-epic99-release-p8-archive-17f2c9c`, and older measurement tables cite
its commits.

| Pull request | Branch | Commits (first parent) | Content |
| --- | --- | --- | --- |
| [#100](https://github.com/stellar-registry/perch/pull/100) | `fm/perch-epic99-spec-p5` | `19ee060..ffe6519`, then `48d2445` | spec, `perch-recovery-interface`, CANON fragment hash |
| [#101](https://github.com/stellar-registry/perch/pull/101) | `fm/perch-epic99-zkpool-p6` | `ffe6519..9978e36` | circuit, ZK primitives, pool, adapter, verifier ZK delta, prover |
| [#102](https://github.com/stellar-registry/perch/pull/102) | `fm/perch-epic99-controller-p7` | `9978e36..8557cd2` | controller, account capabilities, delta `apply_doc`, target binding |
| [#111](https://github.com/stellar-registry/perch/pull/111) | `fm/perch-epic99-oz-layer-p8` | `886486c..4ab2b72` | the OZ materialization layer: quiet OZ mutations, `reconcile_signers`, the OZ fork re-pin, caps |
| [#103](https://github.com/stellar-registry/perch/pull/103) | `fm/perch-epic99-release-p8` | `4ab2b72..` (this branch) | new deployables, release machinery, the release-stack harness, `perch-testnet`, JS packages |
| [#110](https://github.com/stellar-registry/perch/pull/110) | `fm/perch-consumer-interface-p11` | on #103 | the consumer interface: configuration revision, views, `expected_revision` |
| deployment record (top) | `fm/perch-epic99-deploy-p8` | on #110 | the testnet deployment built from everything below it |

## Unit 1: the backend-independent core

| Path | What | Introduced in |
| --- | --- | --- |
| `crates/perch-recovery/**` | The controller: attempts, evidence, promotion, cancellation, `enforce` and `rcv_sync`, completion, the two-digest target binding, configuration changes | #102 `ba28bfe`, `57f8e12`, `957129f`, `fa14e89`; target binding `8557cd2` |
| `crates/perch-recovery-interface/**` | The statement and its encoding, the controller, account, pool, and configuration interfaces, credential fingerprints | #100 `77f6c26`, `952ef5e`, `1f92b33`–`e98558c`; #102 `ba28bfe` |
| `crates/perch-zk-primitives/**`, `crates/perch-zk-pool/**`, `crates/perch-zk-adapter/**` | The ZK statement and nullifier primitives, the membership pool, the adapter that verifies proofs for the controller | #101 `1d36720`, `84ac875`, `2354d6a`, `4cae713`, `6ddea59` |
| `vendor/ultrahonk-soroban-verifier/src/zk.rs` | **Perch code under `vendor/`**, not upstream: the `UltraKeccakZKFlavor` delta (1,030 lines), and visibility-only changes to four audited upstream files (listed in the vendored README and NOTICE). Its audit is open release criterion 1 in `docs/zk/README.md`. | #101 `af43844`, `6ddea59`, `5d2ae88` |
| `circuits/perch_zk/**`, `circuits/perch_zk_recovery/**`, `circuits/perch_zk_recovery_d24/**` | The Noir recovery circuit and its depth variants | #101 `1d36720` |
| `crates/perch-ir/**`, `CANONICAL.md` | The document schema, validation, and CANON v1 canonical bytes (`doc_hash`, the per-rule fragment hash) | pre-existing; #100 `2e3c371`; #102 `ba28bfe` |
| `crates/perch-doc-compiler/**` except the caps | `compile_doc`, `derive_target`, `config_hash`, credential canonicalization; the test-only compilers behind `testutils` | pre-existing; #102 `ba28bfe`, `8557cd2` |
| `crates/perch-compile/**`, `crates/perch-interpreter/**`, `crates/perch-program/**` | Lowering rules to interpreter programs (with per-rule provenance), and the interpreter policy | pre-existing; #102 `849e4da` |
| `crates/perch-smart-account/src/lib.rs`: the recovery and capability paths | `check_auth`, `is_completion`, `complete_recovery`, the freeze mirror and `rcv_gate`, reserved names, `cancel_recovery`, `schedule_upgrade`/`execute_upgrade`/`cancel_upgrade`, `renew`, `execute`, and inside `apply` the revocation and enrollment-id checks and the `rcv_sync` gate | #102 `ba28bfe`, `57f8e12`, `957129f`, `fa14e89`; `infra()` view #103 `6c4af63` |
| `crates/perch-account/**` | The deployable account contract over `perch-smart-account` | pre-existing; #103 `6c4af63` (stack size) |
| `crates/perch-webauthn-verifier/**` | Constructorless passkey verifier (OZ `webauthn::verify`) | #103 `6c4af63` |
| `crates/perch-account-factory/**` | Constructorless factory: deploys the pinned account build, address bound to the admin signers | #103 `6c4af63` |
| `crates/perch-ed25519-verifier/**` | Ed25519 external-signer verifier | pre-existing |
| `crates/perch-registry-resolve/**`, `crates/perch-registry-resolve-macro/**` | Build-time infra resolution: the account calls `deployer(registry, sha256(pinned wasm))`, with no runtime address (`AGENTS.md`) | pre-existing; #103 `6c4af63` |
| `crates/*/build.rs` | Wasm stack size: 64 KiB per contract, 128 KiB for the ZK adapter. An overflow traps. | #103 `6c4af63` |

**Evidence** (tests, read first):
- `crates/integration-tests/tests/{recovery,account_capabilities,target_binding,cap71_semantics}.rs`;
- the ZK crates' tests and `crates/perch-zk-adapter/tests/{zk_verifier,vendor}.rs`;
- the statement vectors, `testdata/recovery/statement-v2.json`;
- the Lean model in [#104](https://github.com/stellar-registry/perch/pull/104), outside this stack.

## Unit 2: the OZ materialization layer

| Path | What | Introduced in |
| --- | --- | --- |
| `crates/perch-smart-account/src/rules.rs` | The delta reconcile: rules matched by slot; the cheaper of an in-place edit and a replacement per rule (the cost model, `Meter`); every OZ mutation through the `_no_events` variants (`Apply`); the `DeltaSummary` | #102 `2987383`, `849e4da`, part of `350b7cc`, `e4947c5`, `6fdd492`, `4d11470`; #111 `554cf48` (quiet mutations), `64bdeda` (`reconcile_signers`) |
| `crates/perch-smart-account/src/lib.rs`: the install paths | `apply_rules`, the install half of `apply` (`apply_rules`, enrollment write, `DocApplied`), the `DocApplied` event, `installed_rules`, the OZ rule views, `install_admin` | #102 `2987383`; #111 `554cf48` |
| `crates/perch-doc-compiler/src/lib.rs`: the caps | `MAX_DOC_SIGNERS` = 8, `MAX_DOC_RULES` = 11, `MAX_DOC_CANONICAL_BYTES` = 8 192, `MAX_RULE_NAME_BYTES` (OZ's 20), and the check that refuses a document past them | #111 `b5a581a` |
| `crates/perch-spending-limit/**` | The deployable wrapper of OZ's `spending_limit`, installing and uninstalling quietly | pre-existing; #111 `554cf48` |
| `Cargo.toml`: `stellar-accounts` | The pin, `8200220` (OZ fork #3) → `3372676` (OZ fork #5 on #4). It applies workspace-wide, so to every contract above. | #111 `554cf48`, `64bdeda` |
| theahaco/stellar-contracts-OZ #3, #4, #5 | The fork code those revisions add (below) | outside every perch diff |

**Evidence:**
- `crates/integration-tests/tests/{apply_delta,delta_security}.rs`;
- the full-replace oracle `perch-testkit/src/delta.rs` and the fuzz target `fuzz/fuzz_targets/apply_doc_delta.rs`;
- `crates/integration-tests/tests/release_stack.rs` (`worst_case_*`, `signer_transitions`, `cap_sweep`, the footprint simulation check);
- `docs/recovery/budgets.md`, "Document caps", which sizes the caps.

### The OZ fork

`stellar-accounts` is pinned to theahaco/stellar-contracts-OZ at `3372676`.
That is three open fork pull requests, stacked, on fork `main` (equal to
upstream OpenZeppelin `fbfde38`):

| Fork PR | Branch, head | Lines | What it changes |
| --- | --- | --- | --- |
| [#3](https://github.com/theahaco/stellar-contracts-OZ/pull/3) | `cap-71-delegate-auth`, `8200220` | +220 / −13 | `Signer::Delegated` authenticates through `delegate_account_auth` (CAP-0071) |
| [#4](https://github.com/theahaco/stellar-contracts-OZ/pull/4) | `fm/oz-quiet-events-x1`, `74f9f64` | +1,096 / −55 | `_no_events` variants of every context-rule, signer, and policy mutation, and of `spending_limit`'s install and uninstall |
| [#5](https://github.com/theahaco/stellar-contracts-OZ/pull/5) | `fm/oz-quiet-events-x1-reconcile`, `3372676` | +628 / −6 | `reconcile_signers[_no_events]`: one validated, atomic signer-set update |

About 1.9k lines of this are in no perch pull request's diff. Review them in
the fork pull requests. They are in scope because every perch contract links
them.

## Outside both units

These are reviewed with the release, not in the audit. They cannot change
what a deployed contract does.

- **Release machinery and supply chain:** `scripts/{build-stack,deploy-stack,fetch-infra-wasm,verify-deployment}.sh`, `crates/perch-deploy`, `crates/perch-derive-id`, `.github/workflows/`. Introduced in #103 `fa2da5d`. They decide which bytes are deployed and pinned. `verify-deployment.sh` and CI's `release-stack-source` job check them.
- **Off-chain tooling and harnesses:** `crates/perch-testnet`, `crates/perch-zk-prover` (the client prover), `crates/perch-testkit`, `crates/perch-bench*`, `crates/perch-conformance`, `crates/perch-golden`, `crates/perch-analyze`.
- **JS packages:** `packages/perch-js`, `packages/perch-zk` (with its `indexer` subpath), `packages/perch-relay`, and `packages/perch-interpreter-js`. The relay's admission and forgery checks (#103 `9df7b4a`) matter to Nido, but the chain, not the relay, decides an approval.
- **Docs and slides:** `docs/**`, `*.md`. `docs/recovery/spec.md` is normative for both units.

## Generated and vendored content

These are checked for provenance, not read line by line. `.gitattributes`
collapses them in GitHub diffs.

| Path | Produced by | Checked by |
| --- | --- | --- |
| `**/test_snapshots/**` | `cargo test` (soroban test-host snapshots) | regenerated on every run |
| `Cargo.lock`, `**/package-lock.json` | cargo, npm | `--locked` builds |
| `packages/perch-contracts/src/**` | `scripts/bindings-contracts.sh` from the deployed wasm | `packages/perch-contracts/test` (`WASM_SHA256` equals the manifest's) |
| `deployments/**` | `scripts/deploy-stack.sh`, `cargo run -p perch-testnet` | `scripts/verify-deployment.sh`, `testnet_pins` |
| `circuits/artifacts/**`, `circuits/manifest.json`, `*.vk`, `packages/perch-zk/artifacts/**`, `testdata/zk/**` | `nargo`/`bb` with the pinned toolchain (`scripts/zk-toolchain.sh`), `perch-zk-fixtures` | CI's `zk` job (`perch-zk-fixtures check`) |
| `vendor/ultrahonk-soroban-verifier/**` except `src/zk.rs` | NethermindEth's audited UltraHonk verifier | `UPSTREAM.sha256`, `CHECKSUMS.sha256`, `crates/perch-zk-adapter/tests/vendor.rs` |
| `circuits/vendor/poseidon/**` | upstream Poseidon (Noir), including generated constants | `CHECKSUMS.sha256`, `crates/perch-zk-adapter/tests/vendor.rs` |
