//! The document caps (`docs/recovery/spec.md` §7.5) at their boundaries:
//! the compiler admits a document at every cap and refuses one past any of
//! them, and every rule name it admits OZ installs. An account document and
//! a grant document each have their own caps. The per-rule constraint
//! cap has the interpreter's local limit, with each exact root consuming one
//! additional constraint. The release-stack suite
//! measures the costliest document the caps admit against the budget
//! (`docs/recovery/budgets.md`, "Document caps" and "Grant-document caps").

use perch_doc_compiler::{
    doc_limits, grant_limits, DocCompilerError, DocLimits, MAX_DOC_CANONICAL_BYTES, MAX_DOC_RULES,
    MAX_DOC_SIGNERS, MAX_GRANT_CANONICAL_BYTES, MAX_GRANT_RULES, MAX_GRANT_SIGNERS,
    MAX_RULE_CONSTRAINTS, MAX_RULE_NAME_BYTES,
};
use perch_testkit::delta::strkey;
use perch_testkit::{Bootstrap, World, ED25519_VERIFIER_NAME, FIXTURE_NETWORK};
use soroban_sdk::Bytes;

fn setup() -> World {
    Bootstrap::native()
        .network(FIXTURE_NETWORK)
        .admin_ed25519([9u8; 32])
        .build()
}

/// `signers` signers and `rules` rules (the admin rule first), the last
/// rule named `last_name`, and `padding` strings in a `string-in`
/// constraint to grow the canonical bytes.
fn doc(w: &World, signers: u32, rules: u32, last_name: &str, padding: usize) -> Bytes {
    let verifier = strkey(&w.verifier);
    let signers: Vec<String> = (0..signers)
        .map(|i| {
            format!(
                r#"{{"id":"s{i}","verifier":"{verifier}","verifier-name":"{ED25519_VERIFIER_NAME}","key":"{}"}}"#,
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

/// A grant document (no self-admin rule, no recovery member): `signers`
/// signers and `rules` rules, each scoped to a contract and naming every
/// signer, with `padding` strings in a `string-in` constraint on rule 0.
fn grant_doc(w: &World, signers: u32, rules: u32, padding: usize) -> Bytes {
    let verifier = strkey(&w.verifier);
    let ids: Vec<String> = (0..signers).map(|i| format!(r#""s{i:02}""#)).collect();
    let decls: Vec<String> = (0..signers)
        .map(|i| {
            format!(
                r#"{{"id":"s{i:02}","verifier":"{verifier}","verifier-name":"{ED25519_VERIFIER_NAME}","key":"{}"}}"#,
                format!("{:02x}", i + 1).repeat(32)
            )
        })
        .collect();
    let rules: Vec<String> = (0..rules)
        .map(|k| {
            let args = if k == 0 && padding > 0 {
                let values: Vec<String> = (0..padding).map(|v| format!(r#""v{v:05}""#)).collect();
                format!(
                    r#","functions":["f"],"args":[{{"index":0,"pred":{{"type":"string-in","values":[{}]}}}}]"#,
                    values.join(",")
                )
            } else {
                String::new()
            };
            format!(
                r#"{{"name":"g{k}","scope":{{"type":"contract","address":"{verifier}"}},"principals":{{"type":"all","signers":[{}]}}{args}}}"#,
                ids.join(",")
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{}],"rules":[{}]}}"#,
        decls.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// The shortest spelling of a grant document of `rules` rules on `scope`,
/// each asking the one delegated signer `signer` (`a`): one-letter ids, rule
/// names `a`, ..., `z`, `ba`, ..., and `all` principals, so that the most
/// rules fit the byte cap.
fn dense_grant(env: &soroban_sdk::Env, scope: &str, signer: &str, rules: u32) -> Bytes {
    let name = |k: u32| {
        let letter = |n: u32| char::from(b'a' + n as u8);
        if k < 26 {
            letter(k).to_string()
        } else {
            format!("{}{}", letter(k / 26), letter(k % 26))
        }
    };
    let rules: Vec<String> = (0..rules)
        .map(|k| {
            format!(
                r#"{{"name":"{}","scope":{{"type":"contract","address":"{scope}"}},"principals":{{"type":"all","signers":["a"]}}}}"#,
                name(k)
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"a","address":"{signer}"}}],"rules":[{}]}}"#,
        rules.join(",")
    );
    Bytes::from_slice(env, json.as_bytes())
}

/// A grant document has its own caps, larger than an account document's:
/// the compiler admits one at each grant count cap and refuses one past
/// either, and still refuses an account document past its own caps, within
/// the grant caps. The two count caps are not reached in one document: the
/// rule cap is the most rules the byte cap holds, so the document at the
/// rule cap names one signer, and the one at the signer cap as many rules
/// naming every signer as the byte cap holds. Each document one past a cap
/// is within the byte cap, so the count cap is what refuses it.
#[test]
fn a_grant_document_at_every_grant_cap_compiles_and_one_past_any_does_not() {
    let w = setup();
    let canonical = |doc: &Bytes| {
        let json = std::str::from_utf8(&doc.to_alloc_vec())
            .unwrap()
            .to_string();
        perch_ir::canonical_json(&perch_ir::from_json(&json).unwrap()).len()
    };
    let within_bytes = |doc: &Bytes| canonical(doc) <= MAX_GRANT_CANONICAL_BYTES as usize;

    // The rule cap, with one signer, in the shortest spelling.
    let (scope, signer) = (strkey(&w.verifier), strkey(&w.compiler));
    let at_rules = dense_grant(&w.env, &scope, &signer, MAX_GRANT_RULES);
    let compiled = w.compiler_client().compile_doc(&at_rules);
    assert_eq!(compiled.rules.len(), MAX_GRANT_RULES);
    let past_rules = dense_grant(&w.env, &scope, &signer, MAX_GRANT_RULES + 1);
    assert!(within_bytes(&past_rules));
    assert!(too_large(&w, &past_rules));

    // The signer cap, every rule naming every signer, as many rules as fit.
    let fit = (1..=MAX_GRANT_RULES)
        .take_while(|&r| within_bytes(&grant_doc(&w, MAX_GRANT_SIGNERS, r, 0)))
        .last()
        .unwrap();
    let at_signers = grant_doc(&w, MAX_GRANT_SIGNERS, fit, 0);
    let compiled = w.compiler_client().compile_doc(&at_signers);
    assert_eq!(compiled.fingerprints.len(), MAX_GRANT_SIGNERS);
    assert!(compiled
        .rules
        .iter()
        .all(|r| r.signers.len() == MAX_GRANT_SIGNERS));
    let past_signers = grant_doc(&w, MAX_GRANT_SIGNERS + 1, 1, 0);
    assert!(within_bytes(&past_signers));
    assert!(too_large(&w, &past_signers));

    // An account document past its caps, within the grant caps.
    const { assert!(MAX_DOC_SIGNERS < MAX_GRANT_SIGNERS && MAX_DOC_RULES < MAX_GRANT_RULES) };
    assert!(too_large(
        &w,
        &doc(&w, MAX_DOC_SIGNERS, MAX_DOC_RULES + 1, "last", 0)
    ));
    assert!(too_large(
        &w,
        &doc(&w, MAX_DOC_SIGNERS + 1, MAX_DOC_RULES, "last", 0)
    ));
}

#[test]
fn the_grant_byte_cap_counts_canonical_bytes() {
    let w = setup();
    let len = |padding| {
        perch_ir::canonical_json(
            &perch_ir::from_json(
                std::str::from_utf8(&grant_doc(&w, 1, 1, padding).to_alloc_vec()).unwrap(),
            )
            .unwrap(),
        )
        .len()
    };
    let fits = (1..)
        .take_while(|&p| len(p) <= MAX_GRANT_CANONICAL_BYTES as usize)
        .last()
        .unwrap();
    assert!(w
        .compiler_client()
        .try_compile_doc(&grant_doc(&w, 1, 1, fits))
        .is_ok());
    assert!(too_large(&w, &grant_doc(&w, 1, 1, fits + 1)));
}

/// `limits` reports an account document's caps and `grant_limits` a grant
/// document's, in one format.
#[test]
fn the_compiler_reports_each_kinds_caps() {
    let w = setup();
    assert_eq!(w.compiler_client().limits(), DocLimits::V1(doc_limits()));
    assert_eq!(
        w.compiler_client().grant_limits(),
        DocLimits::V1(grant_limits())
    );
    assert_eq!(grant_limits().max_rule_name_bytes, MAX_RULE_NAME_BYTES);
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

/// A rule with `args` `is-self` argument constraints, and a function list
/// when `functions`.
fn constrained(w: &World, args: u32, functions: bool) -> Bytes {
    let verifier = strkey(&w.verifier);
    let preds: Vec<String> = (0..args)
        .map(|i| format!(r#"{{"index":{i},"pred":{{"type":"is-self"}}}}"#))
        .collect();
    let functions = if functions {
        r#","functions":["f"]"#
    } else {
        ""
    };
    let json = format!(
        r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"s0","verifier":"{verifier}","verifier-name":"{ED25519_VERIFIER_NAME}","key":"{key}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["s0"]}}}},{{"name":"r","scope":{{"type":"contract","address":"{verifier}"}},"principals":{{"type":"all","signers":["s0"]}}{functions},"args":[{}]}}]}}"#,
        preds.join(","),
        key = "01".repeat(32),
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// A rule at [`MAX_RULE_CONSTRAINTS`] compiles and one past it is refused,
/// counting a function list as one constraint; and the compiler accepts a
/// rule exactly when Perch's RPN lowering fits it in an interpreter program.
#[test]
fn the_constraint_cap_is_what_an_interpreter_program_holds() {
    let w = setup();
    let compiles = |args: u32, functions: bool| {
        let doc = constrained(&w, args, functions);
        let compiled = match w.compiler_client().try_compile_doc(&doc) {
            Ok(Ok(_)) => true,
            Err(Ok(DocCompilerError::DocCompile)) => false,
            other => panic!("{args} args: {other:?}"),
        };
        let program = perch_testkit::rpn::policies(&w.env, &doc).is_ok();
        assert_eq!(compiled, program, "{args} args, functions: {functions}");
        compiled
    };
    let cap = MAX_RULE_CONSTRAINTS;
    assert!(compiles(cap, false));
    assert!(!compiles(cap + 1, false));
    assert!(compiles(cap - 1, true));
    assert!(!compiles(cap, true));
}

#[test]
fn an_exact_root_consumes_one_constraint_at_the_boundary() {
    let w = setup();
    for functions in [false, true] {
        let at = MAX_RULE_CONSTRAINTS - 1 - u32::from(functions);
        for args in [at, at + 1] {
            let bytes = constrained(&w, args, functions).to_alloc_vec();
            let mut doc = perch_ir::from_json(std::str::from_utf8(&bytes).unwrap()).unwrap();
            doc.rules[1].auth_root = Some(perch_ir::AuthRoot {
                contract: strkey(&w.verifier),
                function: "guess".into(),
            });
            let canonical = perch_ir::canonical_json(&doc);
            assert!(canonical.len() <= MAX_DOC_CANONICAL_BYTES as usize);
            let result = w
                .compiler_client()
                .try_compile_doc(&Bytes::from_slice(&w.env, canonical.as_bytes()));
            if args == at {
                assert!(result
                    .unwrap()
                    .unwrap()
                    .rules
                    .get_unchecked(1)
                    .auth_root
                    .is_some());
            } else {
                assert!(matches!(result, Err(Ok(DocCompilerError::DocCompile))));
            }
        }
    }
}
