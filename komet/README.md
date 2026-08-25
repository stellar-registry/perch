# Komet property tests: an independent wasm-level second opinion

[Komet](https://github.com/runtimeverification/komet) (Runtime Verification)
fuzzes and symbolically executes Soroban contracts against a mechanized
Soroban + WebAssembly (KWasm) semantics written in the K framework. Running
perch's evaluator under it gives a correctness check whose trusted base is the
K semantics rather than rustc/LLVM + wasmi, a stack independent of every other
leg of the verification plan (see `../docs/verification/PLAN.md`, phase 3).

This directory is a self-contained Soroban contract (its own cargo workspace,
like `../fuzz`) whose `test_` methods are boolean properties over
`perch_program::rpn::eval`, compiled into the contract's own wasm so the
evaluator executes under the K host:

| Property | Statement (over `signer_count`) |
|---|---|
| `test_min_signers_floor` | `[MinSigners(1)]` authorizes iff `signer_count ≥ 1`, INV-1 at the bytecode level |
| `test_all_is_conjunction` | `All(MinSigners(1), MinSigners(3))` authorizes iff `signer_count ≥ 3`, correct Kleene-`and` folding |
| `test_missing_arg_denies` | a program reading a missing argument never authorizes, the fail-open trap stays closed under the wasm host |

`komet test` fuzzes these (50 concrete `signer_count` each); `komet prove run`
discharges them symbolically over the entire `u32` domain, the all-inputs
guarantee the fixed conformance vectors (`../testdata/eval/`) cannot give on
their own.

## Status

**Fuzzing runs in CI.** The `komet` job in `.github/workflows/assurance.yml`
(weekly + `workflow_dispatch`) installs Komet from Nix pinned to release
v0.1.88 and pulls the whole prebuilt closure (K, the haskell backend, and
the bundled Soroban semantics) from RV's public `k-framework` Cachix cache.
Nothing compiles from source and no separate `komet-kdist build` step is
needed. The job then builds the contract with `cargo`, strips the DataCount section
(next paragraph), and runs `komet test --wasm …`. Verified green: all three
properties pass 50/50 examples, executing the real evaluator bytecode under the
K semantics.

**`komet prove run` (symbolic) is local-only.** It is the stronger check, a
proof for every `u32`, but takes well over CI's 30-minute budget on these
properties. CI runs the fuzzer; the symbolic proof is a documented local
command (below). This is a performance limit of symbolic execution, not a gap
in what the properties assert.

### Two soroban-sdk-27 compatibility fixes the CI job applies

Komet v0.1.88's toolchain predates soroban-sdk 27, so the job bridges two gaps
(both handled automatically in CI; relevant if you run locally):

1. **DataCount section.** Modern `wasm32v1-none` output carries a DataCount
   section (id `0x0c`, from the bulk-memory feature) that Komet's `pykwasm`
   parser rejects (`Invalid section id: 0xc`). `strip_datacount.py` deletes it.
   DataCount is only required for `memory.init`/`data.drop`, which soroban
   contracts don't use, so the stripped module is spec-valid and behaviourally
   identical. The script preserves every custom section, including the
   `contractspecv0` ABI Komet reads.
2. **`stellar` for the ABI.** Komet reads the contract interface via
   `stellar contract info interface --wasm` even when given `--wasm`, so the job
   installs stellar-cli v27.1.0 (the version Komet v0.1.88's flake tracks).

**A plain local Homebrew setup can't build the semantics**, which is why CI
uses Nix. Komet v0.1.88 pins K 7.1.323 (`deps/k_release`), but Homebrew's
`runtimeverification/k/kframework` bottle is 7.1.282, and building the
Soroban semantics against the mismatched K fails at link time (`Undefined
symbols … _table_getArgumentSortsForTag`, an internal K-runtime symbol that
moved between those versions). The RV-supported installs,
[`kup`](https://github.com/runtimeverification/kup) or Nix, version-match
automatically, the same path CI takes.

## Running locally

```sh
# 1. Install Komet, version-matched, via Nix (pulls prebuilt from the
#    k-framework Cachix cache — no source build, no komet-kdist step):
nix profile install github:runtimeverification/komet/v0.1.88

# 2. Install stellar-cli (komet reads the ABI via `stellar contract info`):
#    e.g. the v27.1.0 release, or `cargo install --locked stellar-cli`.

# 3. Build + prepare the wasm and run, from this directory:
cd komet
cargo build --release --target wasm32v1-none
python3 strip_datacount.py \
  target/wasm32v1-none/release/perch_komet_tests.wasm \
  target/perch_komet_tests.komet.wasm
komet test --wasm target/perch_komet_tests.komet.wasm   # fuzz (what CI runs)
komet prove run --wasm target/perch_komet_tests.komet.wasm  # symbolic: all u32
```

`just komet` wraps step 3. CI runs the fuzz command; `komet prove run` is the
stronger symbolic check but exceeds CI's time budget, so run it locally.

## Why call the evaluator directly (no `create_contract`)

Komet's cheatcodes can deploy a separate contract-under-test, but here the
property runs `rpn::eval` in the test contract itself. The evaluator is still
compiled to bytecode and executed under the K semantics, so the
independent-stack guarantee holds. The harness stays free of a cross-contract
client and symbolic `Context` construction, which keeps the symbolic-execution
state space small enough for `komet prove run` to terminate.
