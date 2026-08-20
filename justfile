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
    cd formal && lake exe drt ../testdata/eval/eval-vectors.json

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
# `cargo install cargo-llvm-cov`.
coverage:
    cargo llvm-cov -p perch-program -p perch-compile -p perch-ir -p perch-conformance --branch

# Flux refinement verification of perch-program (nidohq/soroban-flux). Runs
# under flux's pinned nightly toolchain; the repo's stable pin is untouched —
# the flux attributes are no-ops in normal builds. Setup: see
# https://github.com/nidohq/soroban-flux (`just flux-setup` there).
flux:
    PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly-2026-02-05 FLUXFLAGS="-Fpointer-width=32 -Fcheck-overflow=strict -Fcache=target/flux-cache" cargo flux -p perch-program
