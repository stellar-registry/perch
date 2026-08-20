//! The wasm leg of the conformance vectors (PLAN.md phase 3): replays every
//! case through the COMPILED wasm32 artifact executing under the soroban test
//! host — so rustc, LLVM, and the wasm interpreter join the parity boundary.
//! The entry point is `perch-bench-rpn`'s exported `validate`/`eval`, which
//! wrap the same `perch_program` functions the native leg calls directly.
//!
//! Ignored by default because it needs the artifact built first; run via
//! `just conformance-wasm`.

use perch_bench_rpn::BenchRpnClient;
use perch_conformance::{cases, materialize, verdict_name, AddrBook};
use soroban_sdk::Env;

const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/wasm32v1-none/release/perch_bench_rpn.wasm"
);

#[test]
#[ignore = "needs the wasm artifact; run via `just conformance-wasm`"]
fn every_case_agrees_on_the_compiled_wasm() {
    let wasm = std::fs::read(WASM_PATH).unwrap_or_else(|e| {
        panic!(
            "wasm artifact not found at {WASM_PATH} ({e}).\n\
             Build it first: `cargo build -p perch-bench-rpn --target wasm32v1-none --release` \
             (or run `just conformance-wasm`)."
        )
    });

    for c in cases() {
        // Fresh env per case: isolated budget, ledger, and address space.
        let env = Env::default();
        let mut book = AddrBook::new();
        let id = env.register(wasm.as_slice(), ());
        let client = BenchRpnClient::new(&env, &id);

        let (program, ctx, signer_count, self_addr) = materialize(&env, &mut book, &c);

        assert_eq!(
            client.validate(&program),
            c.expect_valid.is_ok(),
            "case `{}` ({}): the wasm artifact's validate disagrees",
            c.name,
            c.pins
        );

        let got = client.eval(&program, &ctx, &signer_count, &self_addr);
        let want = match verdict_name(c.expect_verdict) {
            "false" => 0,
            "unknown" => 1,
            _ => 2,
        };
        assert_eq!(
            got, want,
            "case `{}` ({}): the wasm artifact's verdict disagrees with the vectors",
            c.name, c.pins
        );
    }
}
