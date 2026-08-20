test:
    cargo test --workspace

build:
    cargo build --workspace

# Builds every cdylib package (interpreter, account, verifier, bench-rpn) to
# target/stellar/$STELLAR_NETWORK/ ("local" when unset). The three deployable
# crates carry [package.metadata.stellar] cargo_inherit, so scaffold injects
# their name/binver wasm meta; bench-rpn has no metadata section (it is never
# published) and builds meta-less. Plain `stellar contract build` would produce
# meta-less wasm for ALL of them — don't mix.
build-contracts:
    stellar scaffold build

check:
    cargo fmt --all --check
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

# Build the RPN bench contract to metered wasm.
bench-build:
    cargo build -p perch-bench-rpn --target wasm32v1-none --release

# Run the metered RPN benchmark — the instruction-count canary for the frozen
# v1 format. Reference numbers: crates/perch-program/BENCH.md.
bench: bench-build
    cargo test -p perch-bench --test metered -- --ignored --nocapture

# Build the Lean 4 formal model and check every theorem (formal/). Setup:
# `curl -sSf https://elan.lean-lang.org/elan-init.sh | sh` — elan then picks
# the pinned toolchain from formal/lean-toolchain automatically.
formal:
    cd formal && lake build

# Differential conformance: run the frozen eval vectors through the real Rust
# evaluator AND the proved Lean model. Green = spec, implementation, and model
# agree on every case.
drt: formal
    cargo test -p perch-conformance
    cd formal && lake exe drt ../testdata/eval/eval-vectors.json \
      ../testdata/ci-publish.canonical.json \
      ../testdata/ci-publish-delegated.canonical.json

# Per-policy SMT prover (needs z3, e.g. `brew install z3`): dead rules,
# intent conformance, semantic attenuation. Example:
#   just analyze only-calls testdata/ci-publish.json C... publish publish_hash
analyze *ARGS:
    cargo run -q -p perch-analyze -- {{ARGS}}

# Wasm leg of the conformance vectors: replay every case through the COMPILED
# wasm32 artifact under the soroban test host — rustc, LLVM, and the wasm
# interpreter join the parity boundary.
conformance-wasm:
    cargo build -p perch-bench-rpn --target wasm32v1-none --release
    cargo test -p perch-conformance --test wasm_leg -- --ignored

# Coverage-guided fuzzing of a target in fuzz/fuzz_targets/ (default: the
# evaluator's fail-closed totality). Setup: `cargo install cargo-fuzz` and a
# nightly toolchain (the flux pin below works: nightly-2026-02-05).
# `-s none`: ASan fails to link soroban-sdk's rlib ("initializer pointer has
# no target"), and these targets are pure safe Rust — panic/divergence
# detection is the point, not memory errors.
fuzz target="eval_fail_closed" time="60":
    cargo +nightly-2026-02-05 fuzz run -s none {{target}} -- -max_total_time={{time}}

# Mutation testing over the security core: seeds small semantic bugs and
# checks the suite kills them — measures whether the golden vectors + property
# tests would actually catch a silent fail-open. Setup: `cargo install cargo-mutants`.
mutants:
    cargo mutants -p perch-program -p perch-compile -p perch-ir

# Branch coverage of the security core, including the conformance vectors.
# Every deny path in the evaluator should be exercised. Setup:
# `cargo install cargo-llvm-cov`; --branch needs a nightly toolchain (the
# flux pin works) with llvm-tools.
coverage:
    cargo +nightly-2026-02-05 llvm-cov -p perch-program -p perch-compile -p perch-ir -p perch-conformance --branch

# Komet (Runtime Verification, K framework) property tests: execute the RPN
# evaluator's wasm under the mechanized Soroban + KWasm semantics — an
# independent second opinion (trusted base = K, not rustc/LLVM+wasmi). Needs
# komet (via Nix) + stellar-cli; see komet/README.md. `komet test` is what CI
# runs; `komet prove run` is the stronger symbolic check (local — too slow for CI).
komet:
    cd komet && cargo build --release --target wasm32v1-none
    cd komet && python3 strip_datacount.py \
      target/wasm32v1-none/release/perch_komet_tests.wasm \
      target/perch_komet_tests.komet.wasm
    cd komet && komet test --wasm target/perch_komet_tests.komet.wasm
    cd komet && komet prove run --wasm target/perch_komet_tests.komet.wasm

# Flux refinement verification of perch-program (nidohq/soroban-flux). Runs
# under flux's pinned nightly toolchain; the repo's stable pin is untouched —
# the flux attributes are no-ops in normal builds. Setup: see
# https://github.com/nidohq/soroban-flux (`just flux-setup` there).
flux:
    PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly-2026-02-05 FLUXFLAGS="-Fpointer-width=32 -Fcheck-overflow=strict -Fcache=target/flux-cache" cargo flux -p perch-program
