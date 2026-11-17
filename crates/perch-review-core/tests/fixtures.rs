//! The npm wrapper's committed fixtures (`npm/test/fixtures.json`) hold the
//! native core's answers: every input, run through the byte interface here,
//! must give exactly the answer the file records. The npm tests run the
//! wasm builds on the same inputs, so the two builds answer alike.
//!
//! `perch-integration-tests` writes the file (`review_core_differential.rs`,
//! `write_npm_fixtures`) from gate cases the account itself decided; a
//! change to the core's answers fails here until the file is regenerated.

use base64::Engine as _;
use perch_review_core::envelope;
use serde_json::Value;

fn fixtures() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/npm/test/fixtures.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn check(kind: &str, run: fn(&[u8]) -> Vec<u8>) -> usize {
    let all = fixtures();
    let cases = all[kind].as_array().unwrap();
    assert!(!cases.is_empty(), "no {kind} fixtures");
    for f in cases {
        let input = base64::engine::general_purpose::STANDARD
            .decode(f["input"].as_str().unwrap())
            .unwrap();
        let got: Value = serde_json::from_slice(&run(&input)).unwrap();
        assert_eq!(got, f["output"], "{kind}: {}", f["name"]);
    }
    cases.len()
}

#[test]
fn the_native_core_gives_every_committed_answer() {
    let reviews = check("review", envelope::review);
    let witnesses = check("witness", envelope::witness);
    let budgets = check("budget", envelope::budget);
    println!("fixtures: {reviews} reviews, {witnesses} witnesses, {budgets} budgets");
}
