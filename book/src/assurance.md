# From proofs to implementation: the evidence boundary

“The policy is verified” is incomplete unless it says which property, which representation, and which assumptions. Perch combines several kinds of evidence; they should not be mistaken for one end-to-end theorem about every deployed contract.

## Follow the chain

```text
Policy document → Rust compiler → account rules + interpreter program
                                      ↓
                              Rust evaluator → compiled Wasm

Lean rule meaning = Lean compiled-program evaluation   (proved)
Lean outputs ↔ Rust outputs ↔ Wasm outputs             (tested on cases)
```

Lean proves statements about Lean definitions. Shared conformance vectors and differential tests compare those definitions with Rust behavior. A Wasm test leg executes a compiled wrapper around the same evaluator under the Soroban test host. Those tests provide valuable evidence of agreement, but a finite collection of passing cases is not a proof that all implementations agree on every input.

## The layers and their limits

| Evidence | What it contributes | What it does not establish |
|---|---|---|
| Lean proofs | General statements about the modeled semantics | Full Rust or deployed-account correctness |
| Golden vectors | Agreed examples and boundary behavior | Exhaustive coverage |
| Generated differential cases | Compiler/evaluator comparisons against reference behavior | A deductive link to the implementation |
| Wasm conformance | Exercises compiled evaluator behavior under a host | Proof of an entire deployed account or host |
| Flux checks | Refinement checks on annotated Rust invariants | All application-level intent |
| Fuzzing, mutation testing, coverage | Stress inputs and assess whether tests catch changes | Absence of all bugs |
| Komet tests | Independent execution through K-based semantics | A completed general symbolic proof merely because tests pass |
| Z3 policy analysis | Answers encoded questions about specific documents | A Lean-verified SMT translation |

The stronger `komet prove run` command is distinct from `komet test`. The repository documents symbolic proving as a local, more expensive path. Do not describe the ordinary CI tests as that proof.

## What remains trusted

At the model level, we rely on Lean's kernel and on choosing the right specification. Connecting model behavior to production still relies on test harnesses, Rust compilation, and runtime behavior. Actual authorization additionally depends on Soroban, the account framework, verifier contracts, deployed contract identities, and any stateful sibling. Hash-based document identity relies on SHA-256's collision resistance.

The most useful review question is concrete: “Could this evidence detect the failure I am worried about?” An expiry boundary test helps with an off-by-one translation. The stateless lowering theorem cannot settle whether a spending-limit reset is correct.

The [formalization chapter](formalization.md) records the threshold and canonical-model coverage gaps. The [verification plan](https://github.com/stellar-registry/perch/blob/main/docs/verification/PLAN.md) contains both completed work and future work; consult source declarations and CI jobs when determining current coverage, rather than treating every roadmap item as delivered.

## Reproduce the evidence

From the repository root, the existing commands are:

```sh
just formal             # Lean build: checks the proofs; needs elan/lake
just drt                # Rust and Lean replay of shared vectors
just conformance-wasm   # compiled Wasm replay; needs wasm32v1-none
```

`just` is the repository's command runner. Install it and rustup for Rust work; install elan for Lean. The files `rust-toolchain.toml` and `formal/lean-toolchain` select the toolchains. The [development README](https://github.com/stellar-registry/perch/blob/main/README.md#development) lists broader tools and checks. These commands are reproducibility instructions, not a claim that every check ran while writing this book.
