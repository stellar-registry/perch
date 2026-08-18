//! RFC 8785 (JCS) canonicalization and hashing for policy documents.
//!
//! Implements the JCS serialization rules for the *subset* of JSON a
//! [`PolicyDoc`] can produce. The deliberate subset restrictions are:
//!
//! - **Numbers**: every number in the model is a `u32`, so the ECMAScript
//!   number-serialization rules of RFC 8785 §3.2.2.3 collapse to plain decimal
//!   digits — no exponent, no decimal point, no negative zero. Pinned by test.
//! - **Object keys**: all keys are fixed ASCII field names, so the required
//!   UTF-16 code-unit ordering coincides with byte ordering. We still sort by
//!   UTF-16 code units explicitly, so this holds even if a non-ASCII key ever
//!   enters the model.
//! - **Nulls**: `Option` fields that are `None` are omitted entirely rather
//!   than serialized as `null`; the canonical form never contains `null`.
//! - **Strings**: escaped per RFC 8785 §3.2.2.2 — only `"`, `\`, and control
//!   characters are escaped (short forms `\b \t \n \f \r` where they exist,
//!   lowercase `\u00xx` otherwise); everything else, including non-ASCII, is
//!   emitted as literal UTF-8. Implemented directly (`write_json_string`), not
//!   delegated to `serde_json`, so the canonical form can never drift with a
//!   serializer version. Pinned by test.
//!
//! The authoritative, versioned definition of these bytes is `CANONICAL.md` at
//! the repo root; this module implements it, and [`CANON_VERSION`] tags the
//! format version.

use crate::doc::PolicyDoc;
#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Version of the canonical form implemented here, as defined by `CANONICAL.md`.
///
/// This is a format identifier, **not** part of the hash preimage: [`doc_hash`]
/// is `SHA-256` of the canonical bytes and contains no version marker. The
/// constant exists so that any change to the canonicalization rules is an
/// explicit, greppable, breaking event — bump it and re-freeze the conformance
/// vectors, never let the hash drift silently.
pub const CANON_VERSION: u32 = 1;

/// Serialize a document to its canonical JSON form (RFC 8785 for the subset
/// this model produces): keys sorted by UTF-16 code units, no insignificant
/// whitespace, integers as plain decimal, JCS string escaping.
///
/// Two structurally equal documents always canonicalize to identical bytes,
/// regardless of how they were constructed.
#[must_use]
pub fn canonical_json(doc: &PolicyDoc) -> String {
    let value = serde_json::to_value(doc)
        .expect("PolicyDoc serialization is infallible: string keys, no non-finite numbers");
    let mut out = String::new();
    write_value(&value, &mut out);
    out
}

/// SHA-256 of the canonical JSON bytes of `doc`. This is the document's
/// identity: what reviewers approve and what on-chain state commits to.
#[must_use]
pub fn doc_hash(doc: &PolicyDoc) -> [u8; 32] {
    Sha256::digest(canonical_json(doc).as_bytes()).into()
}

/// Lowercase hex encoding of [`doc_hash`].
#[must_use]
pub fn doc_hash_hex(doc: &PolicyDoc) -> String {
    hex::encode(doc_hash(doc))
}

/// Recursively write `value` in canonical form. `Null`/`Bool` are handled for
/// completeness but unreachable from a `PolicyDoc` (see module docs).
fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            // The model only contains u32s; anything else is a bug in this
            // crate, not bad user input (parsing already rejected it).
            let u = n
                .as_u64()
                .expect("PolicyDoc numbers are u32, always representable as u64");
            out.push_str(&u.to_string());
        }
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            // JCS: sort by UTF-16 code units of the raw (unescaped) key.
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (key, val)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_value(val, out);
            }
            out.push('}');
        }
    }
}

/// Write `s` as a canonical JSON string literal per RFC 8785 §3.2.2.2 — the
/// escaping table in `CANONICAL.md`. Implemented directly rather than delegated
/// to a JSON serializer whose output could change between versions (the Biscuit
/// canonicalization lesson): the bytes `doc_hash` commits to are defined here,
/// not inherited from `serde_json`.
fn write_json_string(s: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                // Remaining C0 control chars: lowercase `\u00xx` (high byte 00).
                let b = c as u32;
                out.push_str("\\u00");
                out.push(HEX[((b >> 4) & 0xf) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::write_value;
    use serde_json::{json, Value};

    fn canon(v: &Value) -> String {
        let mut out = String::new();
        write_value(v, &mut out);
        out
    }

    #[test]
    fn integers_are_plain_decimal() {
        assert_eq!(canon(&json!(0)), "0");
        assert_eq!(canon(&json!(1)), "1");
        assert_eq!(canon(&json!(u32::MAX)), "4294967295");
    }

    #[test]
    fn string_escaping_matches_jcs() {
        // Minimal escaping: quote and backslash.
        assert_eq!(canon(&json!("a\"b\\c")), r#""a\"b\\c""#);
        // Short-form escapes for the named control characters.
        assert_eq!(canon(&json!("\u{8}\t\n\u{c}\r")), r#""\b\t\n\f\r""#);
        // Other control characters: lowercase \u00xx.
        assert_eq!(canon(&json!("\u{1}\u{1f}")), "\"\\u0001\\u001f\"");
        // Non-ASCII passes through as literal UTF-8, never \u-escaped.
        assert_eq!(canon(&json!("é€😀")), "\"é€😀\"");
        // Forward slash is NOT escaped.
        assert_eq!(canon(&json!("a/b")), "\"a/b\"");
    }

    #[test]
    fn object_keys_sorted_no_whitespace() {
        let v = json!({"zeta": 1, "alpha": [1, 2], "beta": {"y": 1, "x": 2}});
        assert_eq!(
            canon(&v),
            r#"{"alpha":[1,2],"beta":{"x":2,"y":1},"zeta":1}"#
        );
    }

    #[test]
    fn escaper_matches_serde_json_across_the_subset() {
        // The hand-written escaper must be byte-identical to serde_json's string
        // escaping (what it replaced) across the whole reachable domain: every
        // ASCII code point incl. controls/quote/backslash/slash/DEL, plus a
        // spread of non-ASCII scalars. This is the guardrail that lets us stop
        // depending on the serializer without risking a hash drift.
        let mut sample: String = (0u8..=0x7f).map(|b| b as char).collect();
        sample.push_str("é€😀\u{a0}\u{feff}");
        let mut ours = String::new();
        super::write_json_string(&sample, &mut ours);
        assert_eq!(ours, serde_json::to_string(&sample).unwrap());
    }
}
