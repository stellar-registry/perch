// The contract's wasm gets a 128 KiB stack instead of rustc's 1 MiB default.
// Every cross-contract call instantiates a fresh VM and is charged its whole
// initial linear memory, so the default stack alone made a recovery
// completion at the document caps exceed the network's memory limit
// (docs/recovery/budgets.md, "Wasm stack"). The UltraHonk verifier is the
// stack's deepest code: the ZK-flavor verifier traps at 32 KiB and passes at
// 48 KiB, so the adapter gets more than twice that; every other contract
// links 64 KiB.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("wasm") {
        println!("cargo:rustc-link-arg-cdylib=-zstack-size=131072");
    }
}
