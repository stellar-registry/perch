//! The vendored verifier is upstream's audited code plus exactly the perch
//! delta its NOTICE lists, and the Noir Poseidon2 library is exactly the bytes
//! its NOTICE describes. A hand edit anywhere under either directory fails
//! here, since both are security-critical third-party code (see
//! `vendor/ultrahonk-soroban-verifier/NOTICE`, `circuits/vendor/poseidon/NOTICE`).

use perch_zk_prover::fixture::sha256;
use perch_zk_prover::hex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const VERIFIER: &str = "vendor/ultrahonk-soroban-verifier";

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

fn root(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

/// `(sha256, path)` lines of a `sha256sum`-style file.
fn sums(file: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(|line| {
            let (sum, name) = line.split_once("  ").expect("`<sha256>  <path>` lines");
            (sum.to_string(), name.to_string())
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(&sha256(bytes)).trim_start_matches("0x").to_string()
}

fn check(rel: &str) {
    let dir = root(rel);
    let mut listed = BTreeSet::new();
    for (sum, name) in sums(&dir.join("CHECKSUMS.sha256")) {
        let got = digest(&std::fs::read(dir.join(&name)).unwrap());
        assert_eq!(got, sum, "{rel}/{name} drifted");
        listed.insert(name);
    }
    let mut present = BTreeSet::new();
    files(&dir, &dir, &mut present);
    present.remove("CHECKSUMS.sha256");
    assert_eq!(present, listed, "{rel}: files added or removed");
}

/// `text` with exactly one `from` replaced by `to`.
fn undo(text: &str, from: &str, to: &str, file: &str) -> String {
    assert_eq!(
        text.matches(from).count(),
        1,
        "{file}: expected the perch delta `{from}` exactly once"
    );
    text.replacen(from, to, 1)
}

/// The upstream text of `file`: the vendored text with the perch delta that
/// `vendor/ultrahonk-soroban-verifier/NOTICE` lists reversed, edit by edit.
fn upstream_text(file: &str, text: &str) -> String {
    let unpub = |text: &str, fns: &[&str]| {
        fns.iter().fold(text.to_string(), |t, f| {
            undo(
                &t,
                &format!("pub(crate) fn {f}("),
                &format!("fn {f}("),
                file,
            )
        })
    };
    match file {
        "README.md" => {
            let end = "<!-- PERCH DELTA END -->\n\n";
            assert!(text.starts_with("<!-- PERCH DELTA BEGIN"), "{file}");
            let at = text.find(end).expect("README delta end marker");
            text[at + end.len()..].to_string()
        }
        "src/lib.rs" => {
            let t = undo(
                text,
                "// Perch delta: the UltraKeccakZKFlavor verifier (see NOTICE).\npub mod zk;\n",
                "",
                file,
            );
            undo(
                &t,
                "pub use zk::{UltraHonkZkVerifier, ZK_PROOF_BYTES, ZK_PROOF_FIELDS};\n",
                "",
                file,
            )
        }
        "src/transcript.rs" => {
            // `pub(crate)` pushes these two signatures past rustfmt's width,
            // so rustfmt (`cargo fmt --all` covers path dependencies) wraps
            // them; nothing else about them changed.
            let t = [
                "generate_gemini_r_challenge",
                "generate_shplonk_z_challenge",
            ]
            .iter()
            .fold(text.to_string(), |t, f| {
                undo(
                    &t,
                    &format!(
                        "pub(crate) fn {f}(\n    env: &Env,\n    proof: &Proof,\n    \
                             previous_challenge: Fr,\n) -> (Fr, Fr) {{"
                    ),
                    &format!(
                        "fn {f}(env: &Env, proof: &Proof, previous_challenge: Fr) -> (Fr, Fr) {{"
                    ),
                    file,
                )
            });
            unpub(
                &t,
                &[
                    "push_point",
                    "split_challenge",
                    "hash_to_fr",
                    "generate_relation_parameters_challenges",
                    "generate_alpha_challenges",
                    "generate_gate_challenges",
                ],
            )
        }
        "src/sumcheck.rs" => unpub(text, &["check_sum", "partially_evaluate_pow"]),
        "src/utils.rs" => unpub(text, &["point_err"]),
        "src/verifier.rs" => unpub(text, &["compute_public_input_delta"]),
        _ => text.to_string(),
    }
}

#[test]
fn vendored_ultrahonk_verifier_is_pinned() {
    check(VERIFIER);
}

/// Every upstream file, with the documented delta reversed, is upstream's
/// bytes: the audited code changed only where NOTICE says, and only as it
/// says (visibility, and the `zk` module's registration).
#[test]
fn vendored_ultrahonk_verifier_is_upstream_plus_the_documented_delta() {
    let dir = root(VERIFIER);
    let upstream = sums(&dir.join("UPSTREAM.sha256"));
    for (sum, name) in &upstream {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        assert_eq!(
            digest(upstream_text(name, &text).as_bytes()),
            *sum,
            "{VERIFIER}/{name}: differs from upstream beyond the documented delta"
        );
    }
    // Everything else is perch's: the delta's new file, and the vendoring
    // metadata NOTICE describes.
    let mut present = BTreeSet::new();
    files(&dir, &dir, &mut present);
    for (_, name) in &upstream {
        present.remove(name);
    }
    let ours: BTreeSet<String> = [
        "CHECKSUMS.sha256",
        "Cargo.toml",
        "NOTICE",
        "UPSTREAM.sha256",
        "src/zk.rs",
    ]
    .map(String::from)
    .into();
    assert_eq!(present, ours);
}

#[test]
fn vendored_noir_poseidon_is_unmodified() {
    check("circuits/vendor/poseidon");
}
