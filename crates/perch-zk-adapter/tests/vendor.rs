//! The vendored verifier and Noir Poseidon2 library are exactly the bytes
//! their NOTICE files describe. A hand edit anywhere under either directory
//! fails here, since both are security-critical third-party code (see
//! `vendor/ultrahonk-soroban-verifier/NOTICE`, `circuits/vendor/poseidon/NOTICE`).

use perch_zk_prover::fixture::sha256;
use perch_zk_prover::hex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn files(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            files(&p, base, out);
        } else {
            out.insert(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
        }
    }
}

fn check(rel: &str) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let pinned = std::fs::read_to_string(dir.join("CHECKSUMS.sha256")).unwrap();
    let mut listed = BTreeSet::new();
    for line in pinned.lines() {
        let (sum, name) = line.split_once("  ").expect("`<sha256>  <path>` lines");
        let got = hex(&sha256(&std::fs::read(dir.join(name)).unwrap()));
        assert_eq!(got.trim_start_matches("0x"), sum, "{rel}/{name} drifted");
        listed.insert(name.to_string());
    }
    let mut present = BTreeSet::new();
    files(&dir, &dir, &mut present);
    present.remove("CHECKSUMS.sha256");
    assert_eq!(present, listed, "{rel}: files added or removed");
}

#[test]
fn vendored_ultrahonk_verifier_is_unmodified() {
    check("vendor/ultrahonk-soroban-verifier");
}

#[test]
fn vendored_noir_poseidon_is_unmodified() {
    check("circuits/vendor/poseidon");
}
