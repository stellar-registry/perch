//! Fail-closed JSON parsing for policy documents.
//!
//! [`from_json`] is the only supported way to read a document from bytes.
//! It rejects, in order:
//!
//! 1. malformed JSON ([`ParseError::Json`]);
//! 2. a `version` field that is a number other than `1`
//!    ([`ParseError::UnsupportedVersion`]) — checked *before* the rest of the
//!    document is even looked at, so future-version documents get a precise
//!    error rather than a pile of unknown-field noise;
//! 3. any structural mismatch, including unknown fields anywhere in the tree,
//!    unknown enum tags, and **duplicate object keys** at any nesting level
//!    ([`ParseError::Json`]).
//!
//! Duplicate keys deserve a note: JSON parsers legitimately disagree on
//! whether the first or the last occurrence of a duplicated key wins, so a
//! document containing duplicates can display differently in a reviewer's
//! tooling than in the tool that canonicalizes and hashes it. That is a
//! content-aliasing vector, so the authoritative parse below goes through
//! serde's derived deserializer directly on the input text — which rejects
//! duplicate fields — rather than through a `serde_json::Value` (which would
//! silently collapse them last-wins).
//!
//! Parsing does **not** run semantic validation — call [`crate::validate()`] on
//! the result.

use crate::doc::PolicyDoc;
use std::fmt;

/// Error returned by [`from_json`].
#[derive(Debug)]
pub enum ParseError {
    /// The input is not valid JSON, or does not match the document schema
    /// (missing/unknown fields, wrong types, unknown enum tags, ...).
    Json(serde_json::Error),
    /// The document declares a numeric `version` other than `1`. Reported
    /// before any other schema check.
    UnsupportedVersion(u64),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Json(e) => write!(f, "invalid policy document JSON: {e}"),
            ParseError::UnsupportedVersion(v) => {
                write!(f, "unsupported policy document version {v} (expected 1)")
            }
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseError::Json(e) => Some(e),
            ParseError::UnsupportedVersion(_) => None,
        }
    }
}

/// Parse a policy document from JSON, fail-closed.
///
/// Unknown fields anywhere in the tree, unknown enum tags, duplicate object
/// keys at any nesting level, and any `version` other than `1` are rejected.
/// See the module docs for the precedence of the version check and the
/// rationale for rejecting duplicate keys.
///
/// # Errors
///
/// Returns [`ParseError::UnsupportedVersion`] for a numeric `version != 1`,
/// and [`ParseError::Json`] for every other syntax or schema violation.
pub fn from_json(input: &str) -> Result<PolicyDoc, ParseError> {
    let value: serde_json::Value = serde_json::from_str(input).map_err(ParseError::Json)?;
    // Distinct, early version check: only when `version` is present and
    // numeric. A missing or non-numeric version falls through to the typed
    // deserialization below, which reports it as a schema error.
    if let Some(v) = value.get("version") {
        if let Some(n) = v.as_u64() {
            if n != 1 {
                return Err(ParseError::UnsupportedVersion(n));
            }
        }
    }
    // The authoritative parse runs on the *input text*, not on `value`: a
    // `serde_json::Value` silently collapses duplicate object keys
    // (last-wins), while serde's derived deserializer rejects them with a
    // "duplicate field" error at every nesting level — including inside the
    // buffered content of internally tagged enums. See the module docs.
    serde_json::from_str(input).map_err(ParseError::Json)
}
