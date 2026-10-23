//! Fuzz the trust root of the review workflow: `perch_ir::from_json` must
//! never panic on arbitrary input, and whenever it accepts a document, the
//! canonical form must re-parse to the same document with identical canonical
//! bytes and identical doc_hash (idempotent canonicalization — the property
//! behind "what the reviewer approved is what the hash names"). A document
//! with a `recovery` member must also carry exactly `recovery_canonical_json`
//! of it there, unchanged by the round trip (the text `config_hash` commits
//! to).
//!
//! `fuzz/dicts/ir_parse_roundtrip.dict` holds every key and tag of the
//! grammar, and the assurance job seeds the corpus with the
//! `testdata/ci-publish*.json` fixtures (recovery-enrolled ones included).

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
        doc, doc2,
        "the canonical form must parse back to the same document"
    );
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
    if let Some(r) = &doc.recovery {
        let member = perch_ir::recovery_canonical_json(r);
        assert!(
            canon.contains(&format!("\"recovery\":{member},\"rules\":")),
            "recovery_canonical_json must be the document's recovery member"
        );
        assert_eq!(
            Some(member),
            doc2.recovery
                .as_ref()
                .map(perch_ir::recovery_canonical_json),
            "canonical round-trip must preserve the recovery text"
        );
    }
});
