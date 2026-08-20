//! Executes the conformance table against the real evaluator and pins its
//! JSON serialization to `testdata/eval/eval-vectors.json` — the file the Lean
//! model replays. `UPDATE_GOLDEN=1` reblesses the JSON after an intentional
//! table change; the *expectations* are hand-authored in `src/lib.rs` and are
//! asserted even while blessing, so a semantics bug can never be frozen in.

use std::fs;
use std::path::PathBuf;

use perch_conformance::{cases, run, to_json, validation_error_name, verdict_name, AddrBook};
use soroban_sdk::Env;

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/eval/eval-vectors.json")
}

#[test]
fn every_case_matches_its_hand_authored_expectation() {
    let env = Env::default();
    let mut book = AddrBook::new();
    for c in cases() {
        let (valid, verdict) = run(&env, &mut book, &c);
        match (&c.expect_valid, &valid) {
            (Ok(()), Ok(())) => {}
            (Err(want), Err(got)) => assert_eq!(
                *want,
                validation_error_name(*got),
                "case `{}`: wrong validation error",
                c.name
            ),
            (want, got) => panic!(
                "case `{}`: expected validate {:?}, got {:?}",
                c.name, want, got
            ),
        }
        assert_eq!(
            verdict_name(c.expect_verdict),
            verdict_name(verdict),
            "case `{}` ({}): evaluator disagrees with the hand-authored verdict",
            c.name,
            c.pins
        );
    }
}

#[test]
fn case_names_are_unique() {
    let cs = cases();
    for (i, a) in cs.iter().enumerate() {
        for b in &cs[i + 1..] {
            assert_ne!(a.name, b.name, "duplicate case name");
        }
    }
}

#[test]
fn vectors_file_is_byte_stable() {
    let json = to_json(&cases());
    let path = vectors_path();
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().unwrap()).expect("create testdata/eval");
        fs::write(&path, &json).expect("write eval vectors");
    } else {
        let want = fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing {}; run `UPDATE_GOLDEN=1 cargo test -p perch-conformance`",
                path.display()
            )
        });
        assert_eq!(
            want, json,
            "eval-vectors.json is stale — rebless with UPDATE_GOLDEN=1 after reviewing the diff"
        );
    }
}
