//! Criterion 1 (drift): the committed artifact must equal what the generator
//! produces now. Runs under `cargo test --workspace` (CI's `rust` job), so a
//! change to perch-ir's constants or to the generator that is not followed by
//! `just schema` fails CI here.

use std::path::PathBuf;

fn committed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(perch_schema::CANONICAL_RELPATH)
}

#[test]
fn committed_schema_is_up_to_date() {
    let path = committed_path();
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let generated = perch_schema::policy_schema_json();
    assert_eq!(
        committed,
        generated,
        "{} is stale — run `just schema` to regenerate it",
        path.display(),
    );
}

#[test]
fn schema_declares_draft_2020_12_and_a_stable_id() {
    let schema = perch_schema::policy_schema();
    assert_eq!(schema["$schema"], perch_schema::SCHEMA_DIALECT);
    assert_eq!(schema["$id"], perch_schema::SCHEMA_ID);
    assert_eq!(schema["properties"]["version"]["const"], 1);
}
