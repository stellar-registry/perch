// The contract's wasm gets a 256 KiB stack instead of rustc's 1 MiB default.
// Every cross-contract call instantiates a fresh VM and is charged its whole
// initial linear memory (docs/recovery/budgets.md, "Wasm stack"), but the
// other contracts' 64 KiB is too small here: fips204 verifies with no
// allocation, so the expanded public-key matrix and the signature's vectors
// all live on the stack. Measured on 2026-10-22 (rustc 1.97.1), `verify`
// traps at 120 KiB and passes at 122 KiB, and its stack use does not depend
// on its input; like the ZK adapter, this links more than twice that.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("wasm") {
        println!("cargo:rustc-link-arg-cdylib=-zstack-size=262144");
    }
}
