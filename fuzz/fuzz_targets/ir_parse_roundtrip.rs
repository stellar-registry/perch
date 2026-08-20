//! Fuzz the trust root of the review workflow: `perch_ir::from_json` must
//! never panic on arbitrary input, and whenever it accepts a document, the
//! canonical form must re-parse to a document with identical canonical bytes
//! and identical doc_hash (idempotent canonicalization — the property behind
//! "what the reviewer approved is what the hash names").

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(doc) = perch_ir::from_json(s) else {
        return;
    };
    let canon = perch_ir::canonical_json(&doc);
    let doc2 = perch_ir::from_json(&canon).expect("canonical form must re-parse");
    assert_eq!(
        canon,
        perch_ir::canonical_json(&doc2),
        "canonicalization must be idempotent"
    );
    assert_eq!(
        perch_ir::doc_hash(&doc),
        perch_ir::doc_hash(&doc2),
        "canonical round-trip must preserve doc_hash"
    );
});
