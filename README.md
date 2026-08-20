# Perch

A composable policy layer for Soroban smart accounts.

Perch is a policy library and toolchain on top of [OpenZeppelin `stellar-accounts`](https://github.com/OpenZeppelin/stellar-contracts): a declarative, reviewable policy document (canonical JSON, content-hashed) describing what each signer on a smart account may do, with builders in Rust and TypeScript and a compiler that lowers documents onto OZ context rules — stock OZ policies where the shape fits, one small audited interpreter contract for what they can't express.

The motivating use-case: a CI key stored in GitHub that can publish Wasm releases to the [Stellar Registry](https://github.com/stellar-registry) as a smart account — and do nothing else.

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

Every perch constraint is a stateless predicate over a *single* invocation — this call's function and arguments. Perch holds no state, so it cannot express a **cumulative** limit (spend caps, rate limits, "N per day"): a numeric argument bound limits one call, not a running total, and a signer can call repeatedly to exceed any intended total. Cumulative caps require a stateful sibling policy — e.g. OpenZeppelin's `spending_limit` — attached to the same OZ context rule alongside perch's interpreter (OZ enforces every attached policy, so both must pass). Perch is the "what may be called" layer; cumulative accounting lives in a purpose-built stateful contract. See [#19](https://github.com/stellar-registry/perch/issues/19) for the compiler support that will lower a cap clause onto that sibling policy.

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
  perch-account/      deployable shell of perch-smart-account (6 exported functions, ~28 KB)
  perch-ed25519-verifier/  deployable ed25519 verifier for External signers
  perch-deploy/       deploy/CI bin: signs smart-account auth entries (apply_doc, publish)
  perch-conformance/  eval-semantics conformance vectors: hand-authored (program,
                      invocation) → verdict cases + compile→eval differential + wasm-leg suites
  perch-analyze/      per-policy SMT prover (PolicyDoc → SMT-LIB, z3): dead rules, intent
                      conformance (only-calls), semantic attenuation (narrows)
packages/
  perch-js/           TypeScript surface: schemas, builder, compile parity, apply, signing helpers
formal/               Lean 4 model of the v1 semantics + machine-checked theorems
                      (fail-closed, validation soundness, lowering preservation, and CANON v1
                      canonicalizer injectivity); replays the conformance + canonical vectors
                      (`just drt`)
fuzz/                 cargo-fuzz targets: evaluator totality, parser/canonicalization round-trip
komet/                Komet (K-framework) symbolic property tests — an independent wasm-level
                      second opinion (maintainer-gated on the K toolchain; see komet/README.md)
scripts/              bootstrap-testnet.sh — one-time registry + account bootstrap
docs/slides/          the perch story as an HTML deck (served via GitHub Pages)
docs/verification/    the layered verification plan (PLAN.md) + enforceability theory (THEORY.md)
testdata/             golden vectors shared by the Rust and TS suites (frozen)
testdata/eval/        eval-semantics vectors shared by Rust, the Lean model, and the wasm leg
testdata/deploy/      deployment policy-doc template + generated per-network docs (NOT golden)
```

Three contracts deploy on-chain: the interpreter (immutable, multi-tenant policy
evaluation), the smart account (holds the authorization rules; the CI key is one
of its scoped signers), and the ed25519 verifier they share.

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
```

The verification story — what is proved, what is differentially tested, and
what is planned — lives in [`docs/verification/PLAN.md`](./docs/verification/PLAN.md).

## License

[Apache-2.0](./LICENSE)
