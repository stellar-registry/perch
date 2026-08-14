# Perch

A composable policy layer for Soroban smart accounts.

Perch is a policy library and toolchain on top of [OpenZeppelin `stellar-accounts`](https://github.com/OpenZeppelin/stellar-contracts): a declarative, reviewable policy document (canonical JSON, content-hashed) describing what each signer on a smart account may do, with builders in Rust and TypeScript and a compiler that lowers documents onto OZ context rules — stock OZ policies where the shape fits, one small audited interpreter contract for what they can't express.

The motivating use-case: a CI key stored in GitHub that can publish Wasm releases to the [Stellar Registry](https://github.com/stellar-registry) as a smart account — and do nothing else.

```ts
const doc = policy()
  .signer('admin', external(WEBAUTHN_VERIFIER, maintainerPasskey))
  .signer('ci',    external(ED25519_VERIFIER, ciPubKey))
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
crates/
  perch-ir/           policy document model — canonical JSON, doc_hash, validation
  perch-program/      on-chain constraint encoding + fail-closed evaluation (no_std rlib)
  perch-interpreter/  the single deployable OZ Policy contract
  perch-compile/      lowering: PolicyDoc → executable plan (OZ call sequence)
packages/
  perch-js/           TypeScript surface: schemas, builder, compile parity, apply, signing helpers
testdata/             golden vectors shared by the Rust and TS suites
```

## Development

```sh
just test              # cargo test --workspace
just build             # cargo build --workspace (native)
just build-contracts   # stellar contract build (interpreter wasm)
just check             # cargo fmt --check + cargo clippy -D warnings
```

## License

[Apache-2.0](./LICENSE)
