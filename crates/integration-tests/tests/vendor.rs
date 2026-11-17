//! The vendored crates moved to soroban-sdk 29 (`vendor/<crate>/NOTICE`)
//! hold upstream's bytes except the delta each NOTICE documents: every file
//! other than `Cargo.toml` hashes to `UPSTREAM.sha256` once that delta is
//! reversed, and the directory holds nothing else but the NOTICE and the
//! hash list. (`vendor/ultrahonk-soroban-verifier` has its own, stricter
//! check in `crates/perch-zk-adapter/tests/vendor.rs`.)

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const VENDORED: [&str; 5] = [
    "soroban-sdk-tools",
    "soroban-poseidon",
    "soroban-flux",
    "admin-sep",
    "registry-traits",
];

/// Each documented source delta, as `(crate, file, upstream text, vendored
/// text)`: reversing it restores upstream's bytes.
const SOURCE_DELTA: [(&str, &str, &str, &str); 3] = [
    (
        "registry-traits",
        "src/registry/wasm.rs",
        "#[contracttype(export = false)]\n",
        "#[contracttype]\n",
    ),
    (
        "registry-traits",
        "src/registry/contract.rs",
        "deployer.deploy_v2(wasm_hash, args)",
        "deployer.deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm_hash), args)",
    ),
    (
        "registry-traits",
        "src/registry/contract.rs",
        "deployer.deploy_v2(wasm_hash, ())",
        "deployer.deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm_hash), ())",
    ),
];

fn files(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(root, &path, out);
        } else {
            let rel = path.strip_prefix(root).unwrap().to_str().unwrap();
            out.insert(rel.replace('\\', "/"));
        }
    }
}

fn upstream_bytes(krate: &str, name: &str, bytes: Vec<u8>) -> Vec<u8> {
    let mut text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return e.into_bytes(),
    };
    for (c, file, upstream, vendored) in SOURCE_DELTA {
        if c == krate && file == name {
            assert_eq!(
                text.matches(vendored).count(),
                1,
                "{krate}/{name}: the documented delta `{vendored}` is not there exactly once"
            );
            text = text.replace(vendored, upstream);
        }
    }
    text.into_bytes()
}

#[test]
fn vendored_crates_differ_from_upstream_only_by_their_documented_delta() {
    let vendor = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vendor");
    for krate in VENDORED {
        let dir = vendor.join(krate);
        let listed = std::fs::read_to_string(dir.join("UPSTREAM.sha256")).unwrap();
        let mut upstream = BTreeSet::new();
        for line in listed.lines() {
            let (sum, name) = line.split_once("  ").unwrap();
            upstream.insert(name.to_string());
            if name == "Cargo.toml" {
                continue;
            }
            let bytes = upstream_bytes(krate, name, std::fs::read(dir.join(name)).unwrap());
            assert_eq!(
                hex::encode(Sha256::digest(&bytes)),
                sum,
                "vendor/{krate}/{name}: differs from upstream beyond the documented delta"
            );
        }
        let mut present = BTreeSet::new();
        files(&dir, &dir, &mut present);
        let ours: BTreeSet<String> = ["NOTICE", "UPSTREAM.sha256"].map(String::from).into();
        let expected: BTreeSet<String> = upstream.union(&ours).cloned().collect();
        assert_eq!(present, expected, "vendor/{krate}: unexpected files");
    }
}
