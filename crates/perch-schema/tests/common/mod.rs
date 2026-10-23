//! Shared helpers for the schema test suites: load the real draft 2020-12
//! validator over the committed schema, and run perch-ir's own parser +
//! validator so each test compares the two at the applicable boundary.
//!
//! Each test binary includes this module and uses a different subset, so some
//! helpers look unused from any single one.
#![allow(dead_code)]

use std::path::PathBuf;

use jsonschema::Validator;
use serde_json::Value;

/// The workspace root (two levels up from this crate's manifest dir).
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// A validator built over the freshly generated schema. (The drift test
/// separately proves the committed file equals this, so the suites validate
/// against exactly the shipped contract.)
pub fn validator() -> Validator {
    jsonschema::validator_for(&perch_schema::policy_schema())
        .expect("the generated schema compiles as a draft 2020-12 validator")
}

/// Whether the schema accepts an already-parsed document value.
pub fn schema_accepts(v: &Validator, doc: &Value) -> bool {
    v.is_valid(doc)
}

/// What perch-ir's real parser + validator do with a document's JSON *text*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IrOutcome {
    /// `from_json` parsed the document (shape, tags, version, no unknown/null).
    pub parsed: bool,
    /// `from_json` parsed AND `validate` found no semantic violation.
    pub accepted: bool,
}

/// Run `from_json` then `validate` on raw JSON text.
pub fn ir_outcome(json_text: &str) -> IrOutcome {
    match perch_ir::from_json(json_text) {
        Ok(doc) => IrOutcome {
            parsed: true,
            accepted: perch_ir::validate(&doc).is_ok(),
        },
        Err(_) => IrOutcome {
            parsed: false,
            accepted: false,
        },
    }
}

/// `ir_outcome` for a document given as a parsed value (serialized back to
/// text first — perch-ir reads text). Not for duplicate-key cases, which a
/// `Value` cannot carry; those pass raw text to [`ir_outcome`] directly.
pub fn ir_outcome_of(doc: &Value) -> IrOutcome {
    ir_outcome(&serde_json::to_string(doc).expect("doc re-serializes"))
}
