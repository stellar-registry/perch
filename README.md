# Perch

A composable policy layer for Soroban smart accounts.

Perch lets you describe **who can do what** in a reviewable policy document:
which signers may call which contracts, with what arguments, until which
ledger, and within what spending limits. Rust and TypeScript builders produce
canonical JSON with a content hash. An on-chain compiler prepares the document;
the account lowers it to rule-core's evaluator through `perch-rule-eval`.
Its signer, authorization payload, and context-rule wire types remain compatible
with [OpenZeppelin `stellar-accounts`](https://github.com/OpenZeppelin/stellar-contracts),
while the current account and recovery controller link none of its code.

**Source and deployment status.** Recorded deployments are in the
[testnet](./deployments/testnet.json) and [mainnet](./deployments/mainnet.json)
manifests. This source adds features beyond those builds. Read the
[client and deployment compatibility guide](./docs/auth-root.md#client-and-deployment-compatibility)
before using the new interface or choosing contract bindings. The
[audit manifest](./docs/audit-scope.md) records review scope and provenance;
[deferred work](./docs/DEFERRED.md) describes known limitations.

[Get started](#get-started) · [How it works](#how-it-works) ·
[Documentation](#documentation) · [Repository map](#repository-map) ·
[Development](#development)

## Get started

Install the TypeScript SDK (ESM):

```sh
npm install @stellar-registry/perch
```

The example uses the current source API; check the
[package version guidance](./packages/perch-js/README.md#install) against the SDK
and compiler you use. Give a CI key permission to publish Wasm releases to the
[Stellar Registry](https://github.com/stellar-registry), while a maintainer's
passkey retains account administration:

```ts
import {
  policy, named, delegated, isSelf, canonicalJson, docHash,
} from '@stellar-registry/perch';

const doc = policy()
  .network('Test SDF Network ; September 2015')
  .signer('admin', named(WEBAUTHN_VERIFIER_NAME, WEBAUTHN_VERIFIER, maintainerPasskey))
  .signer('ci', delegated(CI_ACCOUNT)) // CAP-0071: host-authenticated G-account
  .rule('admin', r => r.selfAdmin().signedBy('admin'))
  .rule('ci-publish', r => r
    .callContract(REGISTRY)
    .signedBy('ci')
    .func('publish', 'publish_hash')
    .arg(1, isSelf()) // The registry's author argument must be this account.
    .notAfter(EXPIRY_LEDGER))
  .build();

const docJson = canonicalJson(doc); // Bytes to submit through apply_doc.
const hash = docHash(doc);          // SHA-256 of the canonical document.
```

Supply a verifier `name@version` from Perch's managed `perch/verifiers` registry,
its resolved address, the publishing registry address, maintainer passkey public
key (bytes or hex), CI account address, and expiry ledger. The compiler checks
that the verifier name resolves to the supplied address; see
[verifier selection](./packages/perch-js/README.md#verifiers). Under this document,
the CI signer can authorize only the two publishing functions for this account,
within the ledger bound.

Building a document does not install it. Continue with the
[SDK guide](./packages/perch-js/README.md#using-a-perch-account) to read an account,
select its rules, construct signatures, and apply the document. The account's
pinned on-chain compiler is authoritative; the TypeScript SDK does not compile
policies.

A **signer** is a document slot named by an id (`admin` or `ci` here). A
**credential** is the delegated address or external verifier/key pair filling
that slot. OpenZeppelin's and Perch's wire types call that value a `Signer`.

## How it works

1. **Describe and review.** A `PolicyDoc` declares signers, rules, and optional
   recovery. [CANON v1](./CANONICAL.md) defines its canonical JSON and `doc_hash`,
   plus the `rule_hash` and recovery `config_hash` fragment identities.
2. **Apply.** `apply_doc` calls the account's pinned document compiler and
   reconciles its rules and signers. `apply_grant` installs a grant document.
   The [account interface](./docs/account-interface.md) describes both paths.
3. **Enforce.** The account authenticates credentials and checks authorization
   with rule-core's evaluator. Rules constrain calls, signers, expiry, and
   spending; the account stores each capped rule's spending record.

Signers can use external verifiers, including passkeys, ed25519, and ML-DSA-65,
or delegated host authentication through CAP-0071. Rules support all-of and
threshold signer groups. Optional [account recovery](./docs/recovery/README.md)
uses guardians, a zero-knowledge proof, or both, configured in the same document.
A rule can also require an [exact authorization-entry root](./docs/auth-root.md),
such as allowing a token transfer only within an entry rooted at a game's
`guess` call. Legacy interpreter proofs do not cover this condition.

### Per-call constraints and cumulative spending

Argument constraints inspect a **single invocation**: its contract,
function, arguments, authenticated signer count, and ledger. Repeating a call
can exceed an intended total even when each call satisfies its argument bounds.

Use a rule's `cap` for a cumulative limit. A capped rule allows only a metered
`transfer`; rule-eval charges the account's spending record for each transfer
it allows. **Replacing a capped rule or changing its cap starts an empty
spending record.** See the [budget lifecycle limitation](./docs/DEFERRED.md#persistent-spending-budgets-across-replacements)
and [stateless enforceability theory](./docs/verification/THEORY.md).

## Documentation

| I want to… | Start here |
| --- | --- |
| Build documents or integrate a wallet | [TypeScript SDK and account lifecycle](./packages/perch-js/README.md) |
| Inspect account entry points and grant documents | [Account interface](./docs/account-interface.md) · [Exact-root semantics](./docs/auth-root.md) |
| Understand document identity and validation | [Canonical format](./CANONICAL.md) · [PolicyDoc JSON Schema](./docs/schema.md) |
| Configure or implement recovery | [Recovery guide and specification](./docs/recovery/README.md) · [ZK circuit, pool, and adapter](./docs/zk/README.md) |
| Build or verify a deployment | [Deployment guide](./docs/deploy/README.md) · [Testnet exercise](./docs/deploy/testnet-exercise.md) |
| Review security and known limitations | [Audit scope](./docs/audit-scope.md) · [Threat model](./docs/THREAT_MODEL.md) · [Deferred work](./docs/DEFERRED.md) |
| Understand verification evidence | [Coverage and trusted base](./docs/verification/PLAN.md) · [Lean model and theorems](./formal/README.md) |
| Read the papers, walkthroughs, demos, or slides | [HTML reading hub](./docs/index.html) · [Slide deck](./docs/slides/README.md) |

The theorems in `formal/` cover the **Lean model** of the legacy v1 evaluator,
its lowering, and the canonical form. Shared vectors and differential tests
connect that model to Rust; they do not establish an end-to-end proof of the
current rule-core account or the deployed recovery stack. The verification guide
separates proofs, differential evidence, and components covered by tests only.

## Repository map

| Area | Entry points |
| --- | --- |
| Document model and schema | [`perch-ir`](./crates/perch-ir) · [`perch-schema`](./crates/perch-schema) |
| Compilation and evaluation | [`perch-doc-compiler`](./crates/perch-doc-compiler) · [`perch-rule-eval`](./crates/perch-rule-eval) · [`perch-analyze`](./crates/perch-analyze) |
| Accounts and wire types | [`perch-smart-account`](./crates/perch-smart-account) · [`perch-account`](./crates/perch-account) · [`perch-account-factory`](./crates/perch-account-factory) · [`perch-account-types`](./crates/perch-account-types) |
| Off-chain authorization review | [`perch-review-core`](./crates/perch-review-core/README.md): snapshot-based verdicts and cap budgets, with a private TypeScript wrapper |
| Legacy policies and differential tests | [`perch-compile`](./crates/perch-compile) · [`perch-program`](./crates/perch-program) · [`perch-interpreter`](./crates/perch-interpreter) · [`perch-spending-limit`](./crates/perch-spending-limit) |
| Recovery and ZK | [Implementation map](./docs/recovery/implementation.md) · [`circuits/`](./circuits) · [Vendored verifier](./vendor/ultrahonk-soroban-verifier/README.md) |
| Deployment and infrastructure pins | [`scripts/`](./scripts) · [`deployments/`](./deployments) · [Build order and pin verification](./docs/deploy/README.md) |
| Verification and tests | [`formal/`](./formal) · [`fuzz/`](./fuzz) · [`komet/`](./komet) · [`integration-tests`](./crates/integration-tests) · [Shared vectors](./testdata/README.md) |

Client packages each have their own API and usage guide:

| Package | Purpose |
| --- | --- |
| [`@stellar-registry/perch`](./packages/perch-js/README.md) | Policy builder, schema, canonical JSON, hashes, and account lifecycle |
| [`@stellar-registry/perch-contracts`](./packages/perch-contracts/README.md) | Stack bindings for recorded deployments and explicitly undeployed builds, plus manifests |
| [`@stellar-registry/perch-interpreter`](./packages/perch-interpreter-js/README.md) | Interpreter contract bindings |
| [`@stellar-registry/perch-zk`](./packages/perch-zk/README.md) | Recovery proof helpers and a trust-free pool indexer |
| [`@stellar-registry/perch-relay`](./packages/perch-relay/README.md) | Store-and-forward relay for signed guardian approvals |
| [`@stellar-registry/perch-artifacts`](./packages/perch-artifacts/README.md) | Deployment manifests, circuit artifacts, vectors, limits, and tooling |

## Development

Use Rust via rustup and `just`; [`rust-toolchain.toml`](./rust-toolchain.toml)
pins Rust 1.99.1, the Wasm target, rustfmt, and clippy. TypeScript CI uses
Node.js 22. Contract Wasm builds also need the Stellar CLI and scaffold plugin:

```sh
cargo install --locked stellar-scaffold-cli
```

The deploy flow additionally needs `stellar-registry-cli`; follow the
[deployment guide](./docs/deploy/README.md) for CLI requirements and build order.
Reproducing deployed bytes requires the manifest's recorded toolchain and inputs
([provenance and reproduction limits](./docs/audit-scope.md#deployment-provenance)).

Run from the repository root:

```sh
just build             # Native workspace build.
just test              # Rust workspace tests; some need the pinned Wasm below.
just check             # rustfmt check and clippy with warnings denied.
just build-contracts   # Scaffold Wasm build to target/stellar/$STELLAR_NETWORK/.
```

Tests that load deployment artifacts need `scripts/fetch-infra-wasm.sh`
(Stellar CLI, jq, and Python 3). It fetches by the recorded hashes and addresses
and refreshes the local pin files from the manifest. Follow the
[deployment guide](./docs/deploy/README.md) when testing source that differs
from the recorded stack. `scripts/verify-deployment.sh` checks the manifest
against the chain.

For the TypeScript SDK:

```sh
cd packages/perch-js
npm ci
npm run check
npm run build
npm test
```

Additional checks are in the [`justfile`](./justfile): `just formal` and
`just drt` for Lean proofs and differential conformance (requires elan),
`just fuzz` for fuzzing (cargo-fuzz and nightly), `just mutants` for mutation
testing (cargo-mutants), and `just coverage` for branch coverage (cargo-llvm-cov).
`just zk-artifacts check` rebuilds pinned circuit artifacts and fails on drift;
`just zk-bench` measures proving and on-chain costs. See
[verification coverage](./docs/verification/PLAN.md) and
[ZK measurements](./docs/zk/measurements.md) for scope and prerequisites.

## License

[Apache-2.0](./LICENSE)
