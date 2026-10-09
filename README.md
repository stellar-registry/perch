# Perch

A composable policy layer for Soroban smart accounts.

Perch is a policy library and toolchain on top of [OpenZeppelin `stellar-accounts`](https://github.com/OpenZeppelin/stellar-contracts). At its center is a declarative, reviewable policy document (canonical JSON, content-hashed) describing what each signer on a smart account may do. Builders in Rust and TypeScript produce the document, and a compiler lowers it onto OZ context rules: stock OZ policies where the shape fits, one small audited interpreter contract for what they can't express.

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

**Status: design phase.** See the [epic](https://github.com/stellar-registry/perch/issues/1) for the problem statement, design constraints, and roadmap.

## Stateless policies (and what that excludes)

Every perch constraint is a stateless predicate over a *single* invocation, this call's function and arguments. Perch holds no state, so it cannot express a **cumulative** limit (spend caps, rate limits, "N per day"). A numeric argument bound limits one call, not a running total, and a signer can call repeatedly to exceed any intended total. Cumulative caps require a stateful sibling policy, e.g. OpenZeppelin's `spending_limit`, attached to the same OZ context rule alongside perch's interpreter (OZ enforces every attached policy, so both must pass). Perch is the "what may be called" layer; cumulative accounting lives in a purpose-built stateful contract. See [#19](https://github.com/stellar-registry/perch/issues/19) for the compiler support that will lower a cap clause onto that sibling policy.

## Layout

```
CANONICAL.md          normative definition of the canonical form + doc_hash (CANON v1)
crates/
  perch-ir/           policy document model — canonical JSON, doc_hash, validation
  perch-program/      on-chain constraint encoding + fail-closed evaluation (no_std rlib)
  perch-interpreter/  the deployable OZ Policy contract (the policy-evaluation surface)
  perch-compile/      lowering: PolicyDoc → executable plan (OZ call sequence)
  perch-doc-compiler/ stateless deployable: doc JSON → compiled rules + doc_hash, on-chain
  perch-smart-account/  the doc-only account trait: apply_doc (the sole write path) on OZ
  perch-account/      deployable shell of perch-smart-account (21 exported functions, ~46 KB)
  perch-ed25519-verifier/  deployable ed25519 verifier for External signers
  perch-webauthn-verifier/  deployable WebAuthn (passkey, secp256r1) verifier for External
                      signers; constructorless, no admin
  perch-account-factory/  deployable account factory: deploys the build-time-pinned account
                      wasm at an address bound to its admin signers; passkey accounts name
                      the pinned WebAuthn verifier
  perch-recovery/     deployable account-recovery controller: the one implementation of
                      docs/recovery/spec.md (Loss/Protected × guardian/ZK/combined),
                      adopted through apply_doc's `recovery` document field
  perch-zk-pool/      deployable ZK recovery membership pool: account-authorized enrollment,
                      depth-32 Poseidon2 trees with rollover — see docs/zk/
  perch-zk-adapter/   deployable ZK recovery adapter: root check + statement binding + the
                      zero-knowledge UltraHonk verifier with the circuit's VK compiled in
  perch-zk-primitives/  host-side Poseidon2 for the circuit's formulas (no_std)
  perch-zk-prover/    native witnesses/proving + `perch-zk-fixtures` (artifacts, fixtures, bench)
  perch-deploy/       deploy/CI tool (lib + bin): signs smart-account auth entries
                      (apply_doc, publish)
  perch-testnet/      exercises a deployed stack on testnet: passkey owners, G-account
                      guardians, real proofs, enforcing auth, measured transactions
  perch-derive-id/    offline content-address and name-salt contract id derivation
  perch-conformance/  eval-semantics conformance vectors: hand-authored (program,
                      invocation) → verdict cases + compile→eval differential + wasm-leg suites
  perch-analyze/      per-policy SMT prover (PolicyDoc → SMT-LIB, z3): dead rules, intent
                      conformance (only-calls), semantic attenuation (narrows)
packages/
  perch-js/           TypeScript surface, published to npm as @stellar-registry/perch:
                      schemas, builder, canonical JSON + doc_hash (compile/apply/signing planned)
  perch-interpreter-js/  interpreter contract client bindings, published to npm as
                      @stellar-registry/perch-interpreter (generated from the wasm;
                      regen via `just bindings-interpreter-js`)
  perch-zk/           ZK recovery proof helpers: commitments, witnesses, bb.js proving,
                      and a trust-free pool indexer (`@stellar-registry/perch-zk/indexer`)
  perch-relay/        store-and-forward relay for signed guardian approvals
  perch-contracts/    stack contract bindings generated from the deployed wasm, plus the
                      deployment manifests (regen via scripts/bindings-contracts.sh)
circuits/             Noir ZK recovery circuit (depth 32 + depth-24 fallback), compiled
                      artifacts, and manifest.json pinning sources/VKs/proofs/toolchain
vendor/               vendored audited UltraHonk verifier plus perch's ZK-flavor delta
                      (the delta is unaudited; see its README and NOTICE)
formal/               Lean 4 model of the v1 semantics + machine-checked theorems
                      (fail-closed, validation soundness, lowering preservation, and CANON v1
                      canonicalizer injectivity); replays the conformance + canonical vectors
                      (`just drt`)
fuzz/                 cargo-fuzz targets: evaluator totality, parser/canonicalization round-trip
komet/                Komet (K-framework) symbolic property tests — an independent wasm-level
                      second opinion (maintainer-gated on the K toolchain; see komet/README.md)
scripts/              build-stack.sh / deploy-stack.sh — the stack in pin order and its
                      manifest; fetch-infra-wasm.sh — build-time pins from the manifest,
                      hash- and address-checked; verify-deployment.sh — the manifest
                      against the chain; bindings-contracts.sh, check-packages.sh;
                      bootstrap-testnet.sh — the canonical registry + author account;
                      zk-toolchain.sh — pinned, checksummed nargo/bb for the ZK circuit
deployments/          deployment manifests (testnet.json) and the testnet exercise report
docs/slides/          the perch story as an HTML deck (served via GitHub Pages)
docs/verification/    the layered verification plan (PLAN.md) + enforceability theory (THEORY.md)
docs/recovery/        opt-in account recovery: the authoritative spec, statement layouts,
                      the implementation map, and the pre-spec design records
docs/zk/              ZK recovery circuit, pool, adapter, measurements, and the depth decision
docs/deploy/          build order, manifests, pin verification, and the measured testnet
                      exercise of the stack
docs/testnet-deployment.md  verified live-state map of the canonical testnet deployment
testdata/             golden vectors shared by the Rust and TS suites (frozen)
testdata/eval/        eval-semantics vectors shared by Rust, the Lean model, and the wasm leg
testdata/zk/          real-proof ZK recovery fixtures, one per action and pool boundary
testdata/deploy/      deployment policy-doc template + generated per-network docs (NOT golden)
```

The release pipeline publishes the interpreter, the doc compiler, and the
ed25519 verifier to the canonical registry; the smart account authors those
releases. The recovery stack (WebAuthn verifier, ZK pool and adapter,
controller, account, factory) is deployed in pin order by
`scripts/deploy-stack.sh`; [`docs/deploy/`](./docs/deploy/README.md) covers the
build order, the manifest, and the testnet deployment.

## Development

Building contract wasm requires the scaffold plugin:
`cargo install --locked stellar-scaffold-cli` (and `stellar-registry-cli` for
the deploy flow).

```sh
just test              # cargo test --workspace
just build             # cargo build --workspace (native)
just build-contracts   # stellar scaffold build — all contract wasms with
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
proved, what is differentially tested, and what is planned.

## License

[Apache-2.0](./LICENSE)
