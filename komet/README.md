# Komet property tests — an independent wasm-level second opinion

[Komet](https://github.com/runtimeverification/komet) (Runtime Verification)
fuzzes and **symbolically executes** Soroban contracts against a mechanized
Soroban + WebAssembly (KWasm) semantics written in the K framework. Running
perch's evaluator under it gives a correctness check whose trusted base is the
K semantics rather than rustc/LLVM + wasmi — a genuinely independent stack from
every other leg of the verification plan (see `../docs/verification/PLAN.md`,
phase 3).

This directory is a self-contained Soroban contract (its own cargo workspace,
like `../fuzz`) whose `test_` methods are boolean properties over
`perch_program::rpn::eval`, compiled into the contract's own wasm so the
evaluator executes under the K host:

| Property | What `komet prove run` establishes for **all** `u32 signer_count` |
|---|---|
| `test_min_signers_floor` | `[MinSigners(1)]` authorizes iff `signer_count ≥ 1` — INV-1 at the bytecode level |
| `test_all_is_conjunction` | `All(MinSigners(1), MinSigners(3))` authorizes iff `signer_count ≥ 3` — correct Kleene-`and` folding |
| `test_missing_arg_denies` | a program reading a missing argument never authorizes — the fail-open trap stays closed under the wasm host |

`signer_count` is the symbolic knob; `komet prove run` discharges these over
the entire `u32` domain, the all-inputs guarantee the fixed conformance vectors
(`../testdata/eval/`) cannot give on their own.

## Status

**Runs in CI** — the `komet` job in `.github/workflows/assurance.yml` (weekly +
`workflow_dispatch`) installs Komet from Nix, pinned to release **v0.1.88**, and
pulls the whole prebuilt closure (K, the haskell backend, and the bundled
Soroban semantics) from RV's public `k-framework` Cachix cache, then runs
`komet test` and `komet prove run` from this directory. Nothing compiles from
source and no separate `komet-kdist build` step is needed. It is
`continue-on-error` during burn-in, because the semantics' own examples pin
soroban-sdk 22 while perch is on sdk 27 — CI confirms whether the sdk-27
contract runs under these semantics.

**Local run needs the K toolchain version-matched to Komet**, which is the
snag on a plain Homebrew setup: Komet v0.1.88 pins **K 7.1.323**
(`deps/k_release`), but Homebrew's `runtimeverification/k/kframework` bottle is
**7.1.282**, and building the Soroban semantics against the mismatched K fails
at link time (`Undefined symbols … _table_getArgumentSortsForTag`, an internal
K-runtime symbol that moved between those versions). The RV-supported install
is [`kup`](https://github.com/runtimeverification/kup) or Nix, which version-match
automatically — the same path CI takes.

## Running (once the toolchain matches)

```sh
# 1. Install K + Komet, version-matched (Nix path):
bash <(curl https://kframework.org/install)
kup install komet

# 2. Build the Soroban semantics (once):
komet-kdist build soroban-semantics.llvm     # ~4 min

# 3. From this directory:
cd komet
komet test                    # fuzz all test_ properties (default 100 examples)
komet test --max-examples 500 # deeper fuzzing
komet prove run               # symbolic: prove each property for all inputs
```

`just komet` wraps steps 2–3.

## Why call the evaluator directly (no `create_contract`)

Komet's cheatcodes can deploy a separate contract-under-test, but here the
property runs `rpn::eval` in the test contract itself. The evaluator is still
compiled to bytecode and executed under the K semantics — the independent-stack
guarantee holds — while the harness stays free of a cross-contract client and
symbolic `Context` construction, which keeps the symbolic-execution state space
small enough for `komet prove run` to terminate.
