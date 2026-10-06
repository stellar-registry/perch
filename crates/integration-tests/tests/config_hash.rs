//! The doc compiler's `config_hash` is `sha256("perch/recovery/config" ||
//! recovery_canonical_json)`, computed independently from the committed
//! recovery-member fixtures, and changes with every configuration field
//! (`support/config_hash.rs`). `release_stack.rs` runs the same check against
//! a release stack's compiler wasm.

mod support;

use perch_doc_compiler::PerchDocCompiler;
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::Env;

#[test]
fn the_compiler_hashes_the_canonical_recovery_text_and_binds_every_field() {
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let compiler = env.register(PerchDocCompiler, ());
    support::config_hash::check(&env, &compiler);
}
