# Perch

A composable policy layer for Soroban smart accounts.

Perch is a policy library and toolchain on top of [OpenZeppelin `stellar-accounts`](https://github.com/OpenZeppelin/stellar-contracts). At its center is a declarative, reviewable policy document (canonical JSON, content-hashed) describing what each signer on a smart account may do. Builders in Rust and TypeScript produce the document, and the on-chain doc compiler lowers it onto OZ context rules: stock OZ policies where the shape fits, and one small interpreter contract for what they can't express. Perch accounts can also enroll opt-in recovery (guardians, a zero-knowledge proof, or both) in the same document.

The motivating use-case is a CI key stored in GitHub that can publish Wasm releases to the [Stellar Registry](https://github.com/stellar-registry) as a smart account, and do nothing else.

```ts
const doc = policy()
  .signer('admin', external(WEBAUTHN_VERIFIER, maintainerPasskey))
  .signer('ci',    delegated(CI_ACCOUNT)) // CAP-0071: host-authenticated G-account
  .rule('root', r => r.selfAdmin().signedBy('admin'))
  .rule('ci-publish', r => r
    .callContract(REGISTRY)
    .signedBy('ci')
    .func('publish', 'publish_hash')
    .arg(1, isSelf())
    .notAfter(QUARTER_EXPIRY))
  .build();
```

## Status

Pre-mainnet. The contracts are deployed on testnet (channel `beta`,
[`deployments/testnet.json`](./deployments/testnet.json)). For the external
security audit:

- [`docs/audit-scope.md`](./docs/audit-scope.md): the audit manifest: the
  reviewed commit, the deployed build and its hashes, toolchains, review
  units, known limitations, and the reading order.
- [`docs/DEFERRED.md`](./docs/DEFERRED.md): work deferred until after the
  audit, with the current behaviour each item leaves in place.

## Stateless predicates and cumulative caps

Every interpreter constraint is a stateless predicate over a *single*
invocation: this call's contract, function, arguments, signer count, and
ledger. A numeric argument bound limits one call, not a running total, so a
signer can call repeatedly to exceed any intended total. A cumulative limit
is a rule's `cap`: the compiler lowers it onto OZ's stateful
`spending_limit` policy (deployed as `perch-spending-limit`), attached to the
same context rule beside the interpreter, and OZ enforces every attached
policy, so both must pass. Replacing a capped rule, or changing its cap,
starts an empty spending window
([`docs/DEFERRED.md`](./docs/DEFERRED.md#persistent-spending-budgets-across-replacements)).
[`docs/verification/THEORY.md`](./docs/verification/THEORY.md) states which
policies a stateless monitor can enforce.

## Layout

```
CANONICAL.md          normative definition of the canonical form, doc_hash, and the
                      fragment hashes (CANON v1)
crates/
  perch-ir/           policy document model: canonical JSON, doc_hash, validation
  perch-schema/       host-side generator for the versioned PolicyDoc JSON Schema
                      (draft 2020-12), derived from perch-ir's constants; see docs/schema.md
  perch-program/      on-chain constraint encoding + fail-closed evaluation (no_std rlib)
  perch-interpreter/  the deployable OZ Policy contract that evaluates programs
  perch-compile/      lowering: PolicyDoc → OZ rules, each policy-free or with a program
  perch-doc-compiler/ deployable, stateless: doc JSON → compiled rules, doc_hash,
                      config_hash, document caps, and recovery target derivation
  perch-smart-account/  the account trait: apply_doc (the one write path for rules and
                      signers), the delta reconcile onto OZ, execute, upgrades, the
                      recovery hooks, and the consumer views
  perch-account/      the deployable account contract over perch-smart-account
  perch-account-factory/  deployable factory: deploys the build-time-pinned account
                      wasm at an address bound to its admin signers
  perch-spending-limit/  deployable wrapper of OZ spending_limit (cumulative caps)
  perch-ed25519-verifier/  deployable ed25519 verifier for External signers
  perch-webauthn-verifier/  deployable WebAuthn (passkey, secp256r1) verifier for
                      External signers; constructorless, no admin
  perch-recovery/     deployable recovery controller: the one implementation of
                      docs/recovery/spec.md (Loss/Protected × guardian/ZK/combined),
                      adopted through the document's `recovery` member
  perch-recovery-interface/  the recovery statement, its encoding, and the interfaces
                      between controller, account, adapter, and pool (no contract)
  perch-zk-pool/      deployable ZK membership pool: account-authorized enrollment,
                      depth-32 Poseidon2 trees with rollover (docs/zk/)
  perch-zk-adapter/   deployable ZK adapter: root check, statement binding, and the
                      zero-knowledge UltraHonk verifier with the circuit's VK compiled in
  perch-zk-primitives/  host-side Poseidon2 for the circuit's formulas (no_std)
  perch-zk-prover/    native witnesses/proving + `perch-zk-fixtures` (artifacts,
                      fixtures, bench)
  perch-registry-resolve/, perch-registry-resolve-macro/  build-time infra pins:
                      `deployer(registry, sha256(pinned wasm))`, no runtime address
  perch-stateless-registry/  the content-addressing registry contract
  perch-deploy/       deploy/CI tool (lib + bin): signs smart-account auth entries
  perch-testnet/      exercises a deployed stack on testnet: passkey owners, G-account
                      guardians, real proofs, enforcing auth, measured transactions
  perch-derive-id/    offline content-address and name-salt contract id derivation
  perch-conformance/  eval-semantics conformance vectors + compile→eval differential
                      + wasm-leg suites
  perch-analyze/      per-policy SMT prover (PolicyDoc → SMT-LIB, z3): dead rules,
                      intent conformance (only-calls), semantic attenuation (narrows)
  perch-golden/       golden XDR vectors of the on-chain wire format
  perch-bench/, perch-bench-rpn/  metered instruction-count canary for the program
                      encoding (crates/perch-program/BENCH.md)
  perch-testkit/      test bootstrap and the full-replace oracle for the delta apply
  integration-tests/  enforcing-auth, recovery, delta, revision, and release-stack suites
packages/
  perch-js/           @stellar-registry/perch: schemas, builder, canonical JSON and
                      hashes, statement encodings, and the consumer interface
                      (revision-consistent reads, rule selection, signing digests,
                      the apply lifecycle); ships the generated policy.schema.json
                      under schemas/ (see docs/schema.md)
  perch-interpreter-js/  @stellar-registry/perch-interpreter: interpreter client
                      bindings (generated from the wasm; `just bindings-interpreter-js`)
  perch-zk/           @stellar-registry/perch-zk: ZK recovery proof helpers (commitments,
                      witnesses, bb.js proving) and a trust-free pool indexer
                      (`@stellar-registry/perch-zk/indexer`)
  perch-relay/        @stellar-registry/perch-relay: store-and-forward relay for signed
                      guardian approvals
  perch-contracts/    @stellar-registry/perch-contracts: stack contract bindings generated
                      from the deployed wasm, plus the deployment manifests (regen via
                      scripts/bindings-contracts.sh)
  perch-artifacts/    @stellar-registry/perch-artifacts: deployments/, circuits/, test
                      vectors, document and program limits, fetch-infra-wasm.sh and
                      zk-toolchain.sh as files, copied at build time
circuits/             Noir ZK recovery circuit (depth 32 + depth-24 fallback), compiled
                      artifacts, and manifest.json pinning sources/VKs/proofs/toolchain
vendor/               vendored audited UltraHonk verifier plus perch's ZK-flavor delta
                      (see its README and NOTICE)
formal/               Lean 4 model of the v1 evaluator and CANON v1, with
                      machine-checked theorems; replays the conformance and canonical
                      vectors (`just drt`)
fuzz/                 cargo-fuzz targets: evaluator totality, parser/canonicalization
                      round-trip, recovery canonical form, delta apply
komet/                Komet (K-framework) property tests of the evaluator wasm
scripts/              build-stack.sh / deploy-stack.sh: the stack in pin order and its
                      manifest; fetch-infra-wasm.sh: build-time pins from the manifest,
                      hash- and address-checked; verify-deployment.sh: the manifest
                      against the chain; bindings-contracts.sh, check-packages.sh;
                      bootstrap-testnet.sh: the canonical registry + author account;
                      zk-toolchain.sh: pinned, checksummed nargo/bb
deployments/          deployment manifests (testnet.json) and the raw testnet exercise
                      record (testnet-exercise.json)
docs/audit-scope.md   the audit manifest
docs/DEFERRED.md      work deferred until after the audit
docs/recovery/        account recovery: the authoritative spec, statement layouts,
                      CAP-0071 reliance, the implementation map, budgets, and formal
                      coverage
docs/zk/              ZK recovery circuit, pool, adapter, and measurements (the
                      depth decision is in docs/recovery/budgets.md)
docs/deploy/          build order, manifests, pin verification, and the testnet exercise
                      report
docs/verification/    what is proved, differentially tested, and tested only (PLAN.md);
                      enforceability theory (THEORY.md)
docs/schema.md        the PolicyDoc JSON Schema: generation, drift, release path, versioning,
                      and the boundary between schema-valid and authorized/canonical
docs/testnet-deployment.md  the release pipeline's canonical testnet registry and
                      author account
docs/slides/          the perch story as an HTML deck (served via GitHub Pages)
testdata/             golden vectors shared by the Rust, TypeScript, and Lean suites
                      (frozen); see testdata/README.md
testdata/schema/      shared PolicyDoc JSON Schema conformance cases (Rust + perch-js suites)
```

The release pipeline (`.github/workflows/release.yml`) publishes the
interpreter, the doc compiler, the ed25519 verifier, and the spending limit
to the canonical registry, authored by the perch author account
([`docs/testnet-deployment.md`](./docs/testnet-deployment.md)). The
recovery stack (all ten contracts in the manifest) is deployed in pin order
into the same registry by `release.yml`'s `deploy-stack` job
(`scripts/deploy-stack.sh`), which reuses those four published contracts;
[`docs/deploy/`](./docs/deploy/README.md) covers the build order, the
manifest, and how a deployment is verified.

## Development

Building contract wasm requires the scaffold plugin:
`cargo install --locked stellar-scaffold-cli` (and `stellar-registry-cli` for
the deploy flow). `rust-toolchain.toml` selects the stable channel;
reproducing the deployed hashes needs the rustc version the manifest
records ([`docs/audit-scope.md`](./docs/audit-scope.md#toolchains-and-locked-inputs)).

```sh
just test              # cargo test --workspace
just build             # cargo build --workspace (native)
just build-contracts   # stellar scaffold build: all contract wasms with
                       #   name/binver meta, to target/stellar/$STELLAR_NETWORK/
just check             # cargo fmt --check + cargo clippy -D warnings
just formal            # build the Lean model, check every theorem (needs elan)
just drt               # differential conformance: Rust evaluator + Lean model
                       #   over the same frozen vectors
just fuzz              # coverage-guided fuzzing (needs cargo-fuzz + nightly)
just mutants           # mutation testing of the security core (cargo-mutants)
just coverage          # branch coverage incl. the conformance suite (cargo-llvm-cov)
just zk-artifacts check  # rebuild the ZK circuit artifacts, VKs, and proof fixtures
                         #   with the pinned toolchain; fail on any byte of drift
just zk-bench          # ZK proving + metered on-chain costs (docs/zk/measurements.md)
scripts/fetch-infra-wasm.sh   # build-time pins from deployments/testnet.json
scripts/verify-deployment.sh  # the manifest against the chain
```

[`docs/verification/PLAN.md`](./docs/verification/PLAN.md) covers what is
proved, what is differentially tested, and what is tested only.

## License

[Apache-2.0](./LICENSE)
