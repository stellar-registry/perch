//! Documented circuit identities cannot drift from the committed VKs: the
//! generated table in docs/zk/measurements.md must equal what the manifest
//! produces, and no ZK doc may carry a 64-hex value (the shape of a
//! `circuit_id`) that is not one of the manifest's VK hashes.

use perch_zk_prover::{doc_block, splice_doc_block, DOC_BLOCK_BEGIN, DOC_BLOCK_END};
use std::path::PathBuf;

fn repo(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(p)
}

fn read(p: &str) -> String {
    std::fs::read_to_string(repo(p)).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn manifest() -> serde_json::Value {
    serde_json::from_str(&read("circuits/manifest.json")).unwrap()
}

#[test]
fn measurements_table_matches_the_manifest() {
    let doc = read("docs/zk/measurements.md");
    assert!(doc.contains(DOC_BLOCK_BEGIN) && doc.contains(DOC_BLOCK_END));
    assert_eq!(
        splice_doc_block(&doc, &doc_block(&manifest())).unwrap(),
        doc,
        "docs/zk/measurements.md is stale: run `just zk-artifacts`"
    );
}

#[test]
fn every_documented_circuit_id_is_a_committed_vk() {
    let vks: Vec<String> = manifest()["circuits"]
        .as_object()
        .unwrap()
        .values()
        .map(|c| {
            c["vk_sha256"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
                .to_string()
        })
        .collect();
    let mut docs: Vec<String> = std::fs::read_dir(repo("docs/zk"))
        .unwrap()
        .map(|e| format!("docs/zk/{}", e.unwrap().file_name().to_string_lossy()))
        .filter(|p| p.ends_with(".md"))
        .collect();
    docs.extend(["docs/recovery/budgets.md", "packages/perch-zk/README.md"].map(String::from));
    for p in docs {
        let text = read(&p);
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let run = bytes[i..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            if run == 64 {
                let hex = text[i..i + 64].to_ascii_lowercase();
                assert!(
                    vks.contains(&hex),
                    "{p}: {hex} is not a committed circuit_id"
                );
            }
            i += run.max(1);
        }
    }
}
