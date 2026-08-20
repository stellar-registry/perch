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

# Flux refinement verification of perch-program (nidohq/soroban-flux). Runs
# under flux's pinned nightly toolchain; the repo's stable pin is untouched —
# the flux attributes are no-ops in normal builds. Setup: see
# https://github.com/nidohq/soroban-flux (`just flux-setup` there).
flux:
    PATH="$HOME/.cargo/bin:$PATH" RUSTUP_TOOLCHAIN=nightly-2026-02-05 FLUXFLAGS="-Fpointer-width=32 -Fcheck-overflow=strict -Fcache=target/flux-cache" cargo flux -p perch-program
