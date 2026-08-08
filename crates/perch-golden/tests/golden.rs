//! Golden-vector assertions for the perch wire format.
//!
//! `golden_vectors_are_byte_stable` pins each fixture's XDR against a
//! checked-in hex file and regenerates the shared manifest; run with
//! `UPDATE_GOLDEN=1` to (re)write the files after an intentional change.
//! `weighted_map_is_key_sorted` is the independent structural leg: it decodes
//! the weighted-threshold bytes back to an `ScVal` and asserts the signer map
//! is key-sorted by XDR — the divergence point a TS encoder must match.

use std::fs;
use std::path::PathBuf;

use perch_golden::fixtures;
use soroban_sdk::xdr::{Limits, ReadXdr, ScVal, WriteXdr};
use soroban_sdk::Env;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/golden")
}

fn manifest_json(fx: &[perch_golden::Fixture]) -> String {
    let mut out = String::from("[\n");
    for (i, f) in fx.iter().enumerate() {
        let name = f.name;
        let kind = f.kind;
        let hex_file = format!("{name}.xdr");
        let describe = f.describe;
        let comma = if i + 1 < fx.len() { "," } else { "" };
        out.push_str(&format!(
            "  {{ \"name\": {name:?}, \"kind\": {kind:?}, \"hex_file\": {hex_file:?}, \"describe\": {describe:?} }}{comma}\n"
        ));
    }
    out.push_str("]\n");
    out
}

#[test]
fn golden_vectors_are_byte_stable() {
    let env = Env::default();
    let fx = fixtures(&env);
    let dir = golden_dir();
    let blessing = std::env::var_os("UPDATE_GOLDEN").is_some();

    if blessing {
        fs::create_dir_all(&dir).expect("create testdata/golden");
    }

    for f in &fx {
        let hex = hex::encode(&f.bytes);
        let path = dir.join(format!("{}.xdr", f.name));
        if blessing {
            fs::write(&path, format!("{hex}\n")).expect("write golden");
        } else {
            let want = fs::read_to_string(&path).unwrap_or_else(|_| {
                panic!(
                    "missing golden {}; run `UPDATE_GOLDEN=1 cargo test -p perch-golden`",
                    path.display()
                )
            });
            assert_eq!(
                want.trim(),
                hex,
                "wire drift for fixture `{}` — the on-chain bytes changed",
                f.name
            );
        }
    }

    let manifest = manifest_json(&fx);
    let manifest_path = dir.join("manifest.json");
    if blessing {
        fs::write(&manifest_path, manifest).expect("write manifest");
    } else {
        let want = fs::read_to_string(&manifest_path).expect("missing manifest.json");
        assert_eq!(want, manifest, "manifest.json is stale");
    }
}

#[test]
fn weighted_map_is_key_sorted() {
    let env = Env::default();
    let fx = fixtures(&env);
    let weighted = fx
        .iter()
        .find(|f| f.name == "oz_weighted_threshold")
        .expect("weighted fixture present");

    // Decode the struct's XDR (a Map keyed by field-name Symbols). The only
    // Map-valued field is `signer_weights`, so find it structurally rather
    // than by symbol name.
    let sv = ScVal::from_xdr(&weighted.bytes, Limits::none()).expect("decode ScVal");
    let struct_map = match &sv {
        ScVal::Map(Some(m)) => m,
        _ => panic!("weighted params should encode as a struct Map"),
    };
    let signer_map = struct_map
        .0
        .iter()
        .find_map(|e| match &e.val {
            ScVal::Map(Some(m)) => Some(m),
            _ => None,
        })
        .expect("signer_weights map present");

    assert!(
        signer_map.0.len() >= 3,
        "sort-order fixture must have >= 3 entries, has {}",
        signer_map.0.len()
    );

    let mut prev: Option<Vec<u8>> = None;
    for entry in signer_map.0.iter() {
        let key_bytes = entry.key.to_xdr(Limits::none()).expect("encode key");
        if let Some(previous) = &prev {
            assert!(
                *previous < key_bytes,
                "signer map keys are not strictly ascending by XDR — cross-language encoders would diverge"
            );
        }
        prev = Some(key_bytes);
    }
}
