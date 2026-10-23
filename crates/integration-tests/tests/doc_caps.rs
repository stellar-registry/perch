//! The document caps (`docs/recovery/spec.md` §7.5) at their boundaries:
//! the compiler admits a document at every cap and refuses one past any of
//! them, and every rule name it admits OZ installs. The release-stack suite
//! measures the costliest document the caps admit against the budget
//! (`docs/recovery/budgets.md`, "Document caps").

use perch_doc_compiler::{
    DocCompilerError, MAX_DOC_CANONICAL_BYTES, MAX_DOC_RULES, MAX_DOC_SIGNERS, MAX_RULE_NAME_BYTES,
};
use perch_testkit::{Bootstrap, World, FIXTURE_NETWORK};
use soroban_sdk::{Address, Bytes};

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

fn strkey(a: &Address) -> String {
    let s = a.to_string();
    let mut buf = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).unwrap()
}

/// `signers` signers and `rules` rules (the admin rule first), the last
/// rule named `last_name`, and `padding` strings in a `string-in`
/// constraint to grow the canonical bytes.
fn doc(w: &World, signers: u32, rules: u32, last_name: &str, padding: usize) -> Bytes {
    let verifier = strkey(&w.verifier);
    let signers: Vec<String> = (0..signers)
        .map(|i| {
            format!(
                r#"{{"id":"s{i}","verifier":"{verifier}","key":"{}"}}"#,
                format!("{:02x}", i + 1).repeat(32)
            )
        })
        .collect();
    let mut all = vec![
        r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["s0"]}}"#
            .to_string(),
    ];
    for i in 1..rules {
        let name = if i == rules - 1 {
            last_name.to_string()
        } else {
            format!("r{i}")
        };
        let values: Vec<String> = (0..padding).map(|v| format!(r#""v{v:05}""#)).collect();
        let args = if i == 1 && padding > 0 {
            format!(
                r#","functions":["f"],"args":[{{"index":0,"pred":{{"type":"string-in","values":[{}]}}}}]"#,
                values.join(",")
            )
        } else {
            String::new()
        };
        all.push(format!(
            r#"{{"name":"{name}","scope":{{"type":"contract","address":"{verifier}"}},"principals":{{"type":"all","signers":["s0"]}}{args}}}"#
        ));
    }
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        all.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

fn too_large(w: &World, doc: &Bytes) -> bool {
    matches!(
        w.compiler_client().try_compile_doc(doc),
        Err(Ok(DocCompilerError::DocTooLarge))
    )
}

#[test]
fn a_document_at_every_count_cap_compiles_and_one_past_any_does_not() {
    let w = setup();
    let at_caps = doc(&w, MAX_DOC_SIGNERS, MAX_DOC_RULES, "last", 0);
    let compiled = w.compiler_client().compile_doc(&at_caps);
    assert_eq!(compiled.fingerprints.len(), MAX_DOC_SIGNERS);
    assert_eq!(compiled.rules.len(), MAX_DOC_RULES);
    assert!(too_large(
        &w,
        &doc(&w, MAX_DOC_SIGNERS + 1, MAX_DOC_RULES, "last", 0)
    ));
    assert!(too_large(
        &w,
        &doc(&w, MAX_DOC_SIGNERS, MAX_DOC_RULES + 1, "last", 0)
    ));
}

#[test]
fn the_byte_cap_counts_canonical_bytes() {
    let w = setup();
    let len = |padding| {
        perch_ir::canonical_json(
            &perch_ir::from_json(
                std::str::from_utf8(&doc(&w, 1, 2, "last", padding).to_alloc_vec()).unwrap(),
            )
            .unwrap(),
        )
        .len()
    };
    let fits = (1..)
        .take_while(|&p| len(p) <= MAX_DOC_CANONICAL_BYTES as usize)
        .last()
        .unwrap();
    assert!(w
        .compiler_client()
        .try_compile_doc(&doc(&w, 1, 2, "last", fits))
        .is_ok());
    assert!(too_large(&w, &doc(&w, 1, 2, "last", fits + 1)));
}

/// OZ refuses a context-rule name longer than its `MAX_NAME_SIZE` at
/// install, so a longer one compiling would make a published compromise
/// baseline impossible to restore.
#[test]
fn rule_names_are_capped_where_oz_caps_them() {
    let w = setup();
    let longest = "n".repeat(MAX_RULE_NAME_BYTES as usize);
    let installs = doc(&w, 1, 2, &longest, 0);
    w.account_client().apply_doc(&installs, &0, &None);
    assert!(too_large(
        &w,
        &doc(&w, 1, 2, &"n".repeat(MAX_RULE_NAME_BYTES as usize + 1), 0)
    ));
}
