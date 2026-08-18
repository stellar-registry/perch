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
//!   emitted as literal UTF-8.
//!
//! The document is walked **directly** into these bytes — not via a
//! `serde_json::Value` or any other serializer whose output could drift with a
//! library version (the Biscuit canonicalization lesson), and not via anything
//! that would drag an `f64` into the on-chain wasm (see [`crate::parse`]). The
//! traversal builds a tiny float-free [`Cv`] value, and the emitter below is the
//! single authoritative definition of the bytes `doc_hash` commits to.
//!
//! The authoritative, versioned definition of these bytes is `CANONICAL.md` at
//! the repo root; this module implements it, and [`CANON_VERSION`] tags the
//! format version.

use crate::doc::{ArgPred, CapConstraint, PolicyDoc, Principals, Rule, Scope, SignerDecl};
#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

#[cfg(feature = "std")]
use sha2::{Digest, Sha256};

/// Version of the canonical form implemented here, as defined by `CANONICAL.md`.
///
/// This is a format identifier, **not** part of the hash preimage: [`doc_hash`]
/// is `SHA-256` of the canonical bytes and contains no version marker. The
/// constant exists so that any change to the canonicalization rules is an
/// explicit, greppable, breaking event — bump it and re-freeze the conformance
/// vectors, never let the hash drift silently.
pub const CANON_VERSION: u32 = 1;

/// A canonicalizable value — exactly the JSON shapes a [`PolicyDoc`] produces
/// and nothing else. Object keys are always fixed `&'static str` field names;
/// values borrow their strings from the document. Deliberately has no float
/// variant (the model has none, and one would taint the on-chain wasm).
enum Cv<'a> {
    Str(&'a str),
    U32(u32),
    Arr(Vec<Cv<'a>>),
    /// Members in source order; [`write_value`] sorts them per JCS.
    Obj(Vec<(&'static str, Cv<'a>)>),
}

/// Serialize a document to its canonical JSON form (RFC 8785 for the subset
/// this model produces): keys sorted by UTF-16 code units, no insignificant
/// whitespace, integers as plain decimal, JCS string escaping.
///
/// Two structurally equal documents always canonicalize to identical bytes,
/// regardless of how they were constructed.
#[must_use]
pub fn canonical_json(doc: &PolicyDoc) -> String {
    let mut out = String::new();
    write_value(&doc_to_cv(doc), &mut out);
    out
}

/// SHA-256 of the canonical JSON bytes of `doc`. This is the document's
/// identity: what reviewers approve and what on-chain state commits to.
///
/// `std`-only: it uses the `sha2` software implementation. On-chain, hash
/// [`canonical_json`]'s bytes with the host `env.crypto().sha256` instead — the
/// same digest for a fraction of the gas.
#[cfg(feature = "std")]
#[must_use]
pub fn doc_hash(doc: &PolicyDoc) -> [u8; 32] {
    Sha256::digest(canonical_json(doc).as_bytes()).into()
}

/// Lowercase hex encoding of [`doc_hash`]. `std`-only (see [`doc_hash`]).
#[cfg(feature = "std")]
#[must_use]
pub fn doc_hash_hex(doc: &PolicyDoc) -> String {
    hex::encode(doc_hash(doc))
}

// --- document → canonical value ----------------------------------------------
//
// Each builder pushes members in any order; `write_value` sorts object keys, so
// the traversal only has to be *complete* and *omit `None`s*, not ordered.

fn doc_to_cv(doc: &PolicyDoc) -> Cv<'_> {
    let mut o: Vec<(&'static str, Cv)> = Vec::new();
    o.push(("version", Cv::U32(doc.version)));
    if let Some(n) = &doc.network {
        o.push(("network", Cv::Str(n)));
    }
    o.push((
        "signers",
        Cv::Arr(doc.signers.iter().map(signer_to_cv).collect()),
    ));
    o.push(("rules", Cv::Arr(doc.rules.iter().map(rule_to_cv).collect())));
    Cv::Obj(o)
}

fn signer_to_cv(s: &SignerDecl) -> Cv<'_> {
    Cv::Obj(vec![
        ("id", Cv::Str(&s.id)),
        ("verifier", Cv::Str(&s.verifier)),
        ("key", Cv::Str(&s.key)),
    ])
}

fn rule_to_cv(r: &Rule) -> Cv<'_> {
    let mut o: Vec<(&'static str, Cv)> = Vec::new();
    o.push(("name", Cv::Str(&r.name)));
    o.push(("scope", scope_to_cv(&r.scope)));
    o.push(("principals", principals_to_cv(&r.principals)));
    if let Some(funcs) = &r.functions {
        o.push((
            "functions",
            Cv::Arr(funcs.iter().map(|f| Cv::Str(f)).collect()),
        ));
    }
    if let Some(args) = &r.args {
        o.push((
            "args",
            Cv::Arr(args.iter().map(arg_constraint_to_cv).collect()),
        ));
    }
    if let Some(nal) = r.not_after_ledger {
        o.push(("not-after-ledger", Cv::U32(nal)));
    }
    if let Some(cap) = &r.cap {
        o.push(("cap", cap_to_cv(cap)));
    }
    Cv::Obj(o)
}

fn scope_to_cv(scope: &Scope) -> Cv<'_> {
    match scope {
        Scope::Contract(c) => Cv::Obj(vec![
            ("type", Cv::Str("contract")),
            ("address", Cv::Str(&c.address)),
        ]),
        Scope::SelfAdmin(_) => Cv::Obj(vec![("type", Cv::Str("self-admin"))]),
    }
}

fn principals_to_cv(p: &Principals) -> Cv<'_> {
    match p {
        Principals::All(a) => Cv::Obj(vec![
            ("type", Cv::Str("all")),
            (
                "signers",
                Cv::Arr(a.signers.iter().map(|s| Cv::Str(s)).collect()),
            ),
        ]),
        Principals::SelfAuthenticating(s) => Cv::Obj(vec![
            ("type", Cv::Str("self-authenticating")),
            ("policy", Cv::Str(&s.policy)),
            ("install-param-hex", Cv::Str(&s.install_param_hex)),
            ("ack", Cv::Str(&s.ack)),
        ]),
    }
}

fn arg_constraint_to_cv(a: &crate::doc::ArgConstraint) -> Cv<'_> {
    Cv::Obj(vec![
        ("index", Cv::U32(a.index)),
        ("pred", pred_to_cv(&a.pred)),
    ])
}

fn pred_to_cv(pred: &ArgPred) -> Cv<'_> {
    match pred {
        ArgPred::IsSelf(_) => Cv::Obj(vec![("type", Cv::Str("is-self"))]),
        ArgPred::AddressEq(p) => Cv::Obj(vec![
            ("type", Cv::Str("address-eq")),
            ("address", Cv::Str(&p.address)),
        ]),
        ArgPred::StringIn(p) => Cv::Obj(vec![
            ("type", Cv::Str("string-in")),
            (
                "values",
                Cv::Arr(p.values.iter().map(|v| Cv::Str(v)).collect()),
            ),
        ]),
        ArgPred::StringPrefix(p) => Cv::Obj(vec![
            ("type", Cv::Str("string-prefix")),
            ("prefix", Cv::Str(&p.prefix)),
        ]),
        ArgPred::U32Eq(p) => Cv::Obj(vec![
            ("type", Cv::Str("u32-eq")),
            ("value", Cv::U32(p.value)),
        ]),
    }
}

fn cap_to_cv(cap: &CapConstraint) -> Cv<'_> {
    let mut o: Vec<(&'static str, Cv)> = Vec::new();
    if let Some(token) = &cap.token {
        o.push(("token", Cv::Str(token)));
    }
    // `limit` is a decimal *string* in the model (an i128 does not fit a JSON
    // number safely; see `CapConstraint`), so it canonicalizes as a string.
    o.push(("limit", Cv::Str(&cap.limit)));
    o.push(("period-ledgers", Cv::U32(cap.period_ledgers)));
    Cv::Obj(o)
}

// --- canonical value → bytes -------------------------------------------------

/// Recursively write `value` in canonical form.
fn write_value(value: &Cv, out: &mut String) {
    match value {
        Cv::Str(s) => write_json_string(s, out),
        Cv::U32(u) => out.push_str(&u.to_string()),
        Cv::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Cv::Obj(entries) => {
            let mut entries: Vec<&(&'static str, Cv)> = entries.iter().collect();
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
/// canonicalization lesson): the bytes `doc_hash` commits to are defined here.
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
    use super::{write_value, Cv};
    #[cfg(not(feature = "std"))]
    use alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    fn canon(v: &Cv) -> String {
        let mut out = String::new();
        write_value(v, &mut out);
        out
    }

    #[test]
    fn integers_are_plain_decimal() {
        assert_eq!(canon(&Cv::U32(0)), "0");
        assert_eq!(canon(&Cv::U32(1)), "1");
        assert_eq!(canon(&Cv::U32(u32::MAX)), "4294967295");
    }

    #[test]
    fn string_escaping_matches_jcs() {
        // Minimal escaping: quote and backslash.
        assert_eq!(canon(&Cv::Str("a\"b\\c")), r#""a\"b\\c""#);
        // Short-form escapes for the named control characters.
        assert_eq!(canon(&Cv::Str("\u{8}\t\n\u{c}\r")), r#""\b\t\n\f\r""#);
        // Other control characters: lowercase \u00xx.
        assert_eq!(canon(&Cv::Str("\u{1}\u{1f}")), "\"\\u0001\\u001f\"");
        // Non-ASCII passes through as literal UTF-8, never \u-escaped.
        assert_eq!(canon(&Cv::Str("é€😀")), "\"é€😀\"");
        // Forward slash is NOT escaped.
        assert_eq!(canon(&Cv::Str("a/b")), "\"a/b\"");
    }

    #[test]
    fn object_keys_sorted_no_whitespace() {
        let v = Cv::Obj(vec![
            ("zeta", Cv::U32(1)),
            ("alpha", Cv::Arr(vec![Cv::U32(1), Cv::U32(2)])),
            ("beta", Cv::Obj(vec![("y", Cv::U32(1)), ("x", Cv::U32(2))])),
        ]);
        assert_eq!(
            canon(&v),
            r#"{"alpha":[1,2],"beta":{"x":2,"y":1},"zeta":1}"#
        );
    }

    #[test]
    fn escaper_matches_the_jcs_table_over_all_ascii_and_non_ascii() {
        // The hand-written escaper must match RFC 8785 §3.2.2.2 (the table in
        // CANONICAL.md) across the whole reachable domain: every ASCII code
        // point incl. controls/quote/backslash/slash/DEL, plus a spread of
        // non-ASCII scalars. `reference` re-expresses the table independently of
        // `write_json_string` (a plain `{:04x}`, not its manual hex nibbles), so
        // a typo in either the range boundary or the hex digits is caught —
        // without depending on any JSON serializer.
        fn reference(c: char) -> String {
            match c {
                '"' => "\\\"".into(),
                '\\' => "\\\\".into(),
                '\u{8}' => "\\b".into(),
                '\t' => "\\t".into(),
                '\n' => "\\n".into(),
                '\u{c}' => "\\f".into(),
                '\r' => "\\r".into(),
                c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
                c => c.to_string(),
            }
        }
        let mut sample: Vec<char> = (0u8..=0x7f).map(|b| b as char).collect();
        sample.extend(['é', '€', '😀', '\u{a0}', '\u{feff}']);

        let mut expected = String::from("\"");
        for &c in &sample {
            expected.push_str(&reference(c));
        }
        expected.push('"');

        let s: String = sample.iter().collect();
        let mut ours = String::new();
        super::write_json_string(&s, &mut ours);
        assert_eq!(ours, expected);
    }
}
