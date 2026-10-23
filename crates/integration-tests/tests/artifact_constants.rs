//! The limits a wallet checks a document or program against before it
//! submits one, which no contract view reports, for the npm package
//! `@stellar-registry/perch-artifacts` (`packages/perch-artifacts/constants.json`).
//! Written from the crates' own constants (`PERCH_BLESS=1 cargo test --test
//! artifact_constants`), so a changed limit fails here until the file moves
//! with it.

use std::path::PathBuf;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packages/perch-artifacts/constants.json")
}

fn constants() -> serde_json::Value {
    serde_json::json!({
        "comment": "Written by crates/integration-tests/tests/artifact_constants.rs (PERCH_BLESS=1) from the crates' own constants.",
        "doc_compiler": {
            "MAX_DOC_SIGNERS": perch_doc_compiler::MAX_DOC_SIGNERS,
            "MAX_DOC_RULES": perch_doc_compiler::MAX_DOC_RULES,
            "MAX_DOC_CANONICAL_BYTES": perch_doc_compiler::MAX_DOC_CANONICAL_BYTES,
            "MAX_RULE_NAME_BYTES": perch_doc_compiler::MAX_RULE_NAME_BYTES,
        },
        "program": {
            "PROGRAM_VERSION": perch_program::PROGRAM_VERSION,
            "MAX_PROGRAM_LEN": perch_program::MAX_PROGRAM_LEN,
            "MAX_STACK_DEPTH": perch_program::MAX_STACK_DEPTH,
        },
    })
}

#[test]
fn the_packaged_constants_are_the_crates_own() {
    let want = serde_json::to_string_pretty(&constants()).unwrap() + "\n";
    if std::env::var("PERCH_BLESS").is_ok() {
        std::fs::write(path(), &want).unwrap();
    }
    let have = std::fs::read_to_string(path()).expect("PERCH_BLESS=1 writes the constants");
    assert_eq!(
        have, want,
        "packages/perch-artifacts/constants.json is stale: rerun with PERCH_BLESS=1"
    );
}
