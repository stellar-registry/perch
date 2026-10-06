//! `perch-zk-fixtures`: regenerate or check Perch's ZK recovery artifacts.
//!
//! ```text
//! perch-zk-fixtures generate   compile the circuits; write the stripped ACIR
//!                              artifacts, the verification keys, one real proof
//!                              per fixture scenario, and circuits/manifest.json
//! perch-zk-fixtures check      rebuild all of the above and fail on any byte
//!                              that differs from what is committed
//! perch-zk-fixtures bench [N]  time witness generation and proving N times
//!                              (default 5) at every packaged depth, and write
//!                              one proof per depth to target/zk-bench/ for
//!                              the on-chain cost harness
//! ```
//!
//! Both need the pinned toolchain via `NARGO`/`BB` (`scripts/zk-toolchain.sh`
//! installs it without touching a global nargo/bb). Run from the repo root.

use perch_zk_prover::fixture::{
    field_tag, sha256, tag, Enrollment, Fixture, Statement, Subject, NETWORK_PASSPHRASE,
};
use perch_zk_prover::{
    commitment, doc_block, hex, host, prove, splice_doc_block, write_vk, Inputs, Toolchain, Tree,
    BB_VERSION, NARGO_VERSION,
};
use serde_json::{json, Value};
use soroban_sdk::Env;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const CIRCUITS: &str = "circuits";
const ARTIFACTS: &str = "circuits/artifacts";
const MANIFEST: &str = "circuits/manifest.json";
/// Carries a block generated from the manifest (`doc_block`).
const MEASUREMENTS_DOC: &str = "docs/zk/measurements.md";
const VK_DIR: &str = "crates/perch-zk-adapter/vk";
const FIXTURES: &str = "testdata/zk";
/// The npm package ships copies of the artifacts and manifest.
const TS_ARTIFACTS: &str = "packages/perch-zk/artifacts";
/// `(package, depth)`. Fixtures are proved against the release circuit only.
const PACKAGES: [(&str, u32); 2] = [("perch_zk_recovery", 32), ("perch_zk_recovery_d24", 24)];
const RELEASE: &str = "perch_zk_recovery";
/// The audited verifier this toolchain targets (see vendor/*/NOTICE).
const VERIFIER_SOURCE: &str =
    "NethermindEth/rs-soroban-ultrahonk@c2160987260284c656ffbdad8344210fc162b177";

/// Recovery terms every fixture's account enrolled with.
const EPOCH: u64 = 3;
const DELAY_LEDGERS: u32 = 120_960;
const EXPIRY_LEDGERS: u32 = 241_920;
const VALID_UNTIL: u32 = 2_000_000;

struct Scenario {
    name: &'static str,
    description: &'static str,
    subject: Subject,
    /// Prove the last slot of a full depth-32 tree (see `synthetic_prefix`).
    boundary: bool,
    /// Insertions after the proving leaf's neighbours, so the proof's root
    /// is newer than the `lost_key` fixture's.
    later_enrollments: u32,
}

fn attempt(attempt_id: u64, source: &str) -> (u64, String, String, String) {
    (
        attempt_id,
        hex(&tag(source)),
        hex(&tag(&format!("{source}-with-replacement"))),
        hex(&tag("replacement-set")),
    )
}

fn lost_key(attempt_id: u64) -> Subject {
    let (attempt_id, source_doc_hash, target_doc_hash, replacements_hash) =
        attempt(attempt_id, "applied-doc");
    Subject::LostKey {
        attempt_id,
        source_doc_hash,
        target_doc_hash,
        replacements_hash,
    }
}

fn statement(subject: Subject) -> Statement {
    Statement {
        network_passphrase: NETWORK_PASSPHRASE.into(),
        account_id: hex(&tag("account-a")),
        controller_id: hex(&tag("controller")),
        epoch: EPOCH,
        config_hash: hex(&tag("config-v1")),
        delay_ledgers: DELAY_LEDGERS,
        expiry_ledgers: EXPIRY_LEDGERS,
        valid_until_ledger: VALID_UNTIL,
        subject,
    }
}

fn scenarios(e: &Env) -> Vec<Scenario> {
    let (attempt_id, source_doc_hash, target_doc_hash, replacements_hash) =
        attempt(2, "baseline-doc");
    vec![
        Scenario {
            name: "lost_key",
            description: "Lost-key initiation evidence: the account's enrolled secret at index 1 of tree 0, between two other accounts' leaves.",
            subject: lost_key(1),
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "compromise",
            description: "Compromise initiation evidence, restoring the enrolled baseline.",
            subject: Subject::Compromise {
                attempt_id,
                source_doc_hash,
                target_doc_hash,
                replacements_hash,
            },
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "cancel",
            description: "Cancellation evidence naming attempt 1 by its initiation statement digest.",
            subject: Subject::Cancel {
                attempt_id: 1,
                attempt_statement: hex(&statement(lost_key(1)).digest(e)),
            },
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "reconfigure",
            description: "Protected reconfiguration evidence: replace configuration v1 with v2.",
            subject: Subject::ReconfigureSet {
                config_hash: hex(&tag("config-v2")),
            },
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "reconfigure_remove",
            description: "Protected reconfiguration evidence: remove recovery.",
            subject: Subject::ReconfigureRemove,
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "upgrade",
            description: "Protected upgrade evidence for one scheduled Wasm.",
            subject: Subject::Upgrade {
                request_id: 1,
                wasm_hash: hex(&tag("account-wasm-v2")),
            },
            boundary: false,
            later_enrollments: 0,
        },
        Scenario {
            name: "earlier_tree",
            description: "Lost-key initiation evidence for a leaf in the last slot (index 2^32-1) of a full depth-32 tree, proved after the pool rolled over to tree 1.",
            subject: lost_key(3),
            boundary: true,
            later_enrollments: 0,
        },
        Scenario {
            name: "later_root",
            description: "The lost_key evidence proved against the root after 129 further insertions. Both this root and lost_key's stay acceptable: the pool keeps every historical root.",
            subject: lost_key(1),
            boundary: false,
            later_enrollments: 129,
        },
    ]
}

fn build_fixture(e: &Env, s: Scenario) -> Fixture {
    let st = statement(s.subject);
    let digest = st.digest(e);
    let other = |n: &str| Enrollment {
        account_id: hex(&tag(&format!("account-{n}"))),
        enrollment_id: hex(&tag(&format!("enrollment-{n}"))),
        commitment: hex(&commitment(e, &field_tag(&format!("secret-{n}")))),
    };
    let mut f = Fixture {
        description: s.description.into(),
        pool_id: hex(&tag("pool")),
        account_id: st.account_id.clone(),
        enrollment_id: hex(&tag("enrollment-a")),
        statement: st,
        digest: hex(&digest),
        tree_id: 0,
        synthetic_prefix: 0,
        enrollments: vec![],
        leaf_index: 1,
        secret: hex(&field_tag("secret-a")),
        root: String::new(),
        nullifier: String::new(),
        statement_hash: String::new(),
    };
    let mine = f.own_enrollment(e);
    if s.boundary {
        f.synthetic_prefix = u64::from(u32::MAX);
        f.leaf_index = u64::from(u32::MAX);
        f.enrollments = vec![mine];
    } else {
        f.enrollments = vec![other("b"), mine, other("c")];
        f.enrollments
            .extend((0..s.later_enrollments).map(|i| other(&format!("later-{i}"))));
    }
    let inputs = f.inputs(e);
    f.root = hex(&inputs.root);
    f.nullifier = hex(&inputs.nullifier);
    f.statement_hash = hex(&inputs.statement_hash);
    f
}

fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|err| panic!("{cmd:?}: {err}"));
    assert!(status.success(), "{cmd:?} failed");
}

fn compile(tc: &Toolchain) {
    run(Command::new(&tc.nargo)
        .current_dir(CIRCUITS)
        .args(["compile", "--workspace"]));
}

/// The compiled program without its machine-specific debug info (`file_map`
/// holds absolute source paths): exactly what a prover needs, and identical
/// on every machine that compiles the same sources with the same nargo.
fn stripped_artifact(package: &str) -> Vec<u8> {
    let raw =
        std::fs::read(format!("{CIRCUITS}/target/{package}.json")).expect("compiled artifact");
    let full: Value = serde_json::from_slice(&raw).expect("artifact json");
    let mut out = serde_json::to_vec_pretty(&json!({
        "noir_version": full["noir_version"],
        "hash": full["hash"],
        "abi": full["abi"],
        "bytecode": full["bytecode"],
    }))
    .unwrap();
    out.push(b'\n');
    out
}

fn circuit_size(tc: &Toolchain, package: &str) -> u64 {
    let out = Command::new(&tc.bb)
        .args(["gates", "--scheme", "ultra_honk", "-b"])
        .arg(format!("{CIRCUITS}/target/{package}.json"))
        .output()
        .expect("bb gates");
    let v: Value = serde_json::from_slice(&out.stdout).expect("bb gates json");
    v["functions"][0]["circuit_size"]
        .as_u64()
        .expect("circuit_size")
}

fn source_hashes() -> BTreeMap<String, String> {
    fn walk(dir: &Path, out: &mut BTreeMap<String, String>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|d| d.unwrap().path())
            .collect();
        entries.sort();
        for p in entries {
            let name = p.file_name().unwrap().to_string_lossy();
            if p.is_dir() {
                if name != "target" && name != "artifacts" {
                    walk(&p, out);
                }
            } else if name.ends_with(".nr") || name == "Nargo.toml" {
                out.insert(
                    p.to_string_lossy().into_owned(),
                    hex(&sha256(&std::fs::read(&p).unwrap())),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(Path::new(CIRCUITS), &mut out);
    out
}

fn noirc_version(tc: &Toolchain) -> String {
    let out = Command::new(&tc.nargo).arg("--version").output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find(|l| l.starts_with("noirc version"))
        .unwrap_or_default()
        .to_string()
}

/// Everything `generate` writes, as `path -> bytes`, built in `work`.
fn build_all(tc: &Toolchain, work: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let e = host();
    compile(tc);
    let mut files = BTreeMap::new();
    let mut circuits = serde_json::Map::new();
    for (package, depth) in PACKAGES {
        let artifact = stripped_artifact(package);
        let vk =
            write_vk(tc, Path::new(CIRCUITS), package, &work.join(package)).expect("bb write_vk");
        let bytecode: Value = serde_json::from_slice(&artifact).unwrap();
        circuits.insert(
            package.into(),
            json!({
                "depth": depth,
                "public_inputs": ["root", "nullifier", "statement_hash"],
                "acir_bytecode_sha256": hex(&sha256(bytecode["bytecode"].as_str().unwrap().as_bytes())),
                "artifact": format!("{ARTIFACTS}/{package}.json"),
                "artifact_sha256": hex(&sha256(&artifact)),
                "vk": format!("{VK_DIR}/{package}.vk"),
                "vk_sha256": hex(&sha256(&vk)),
                "circuit_size": circuit_size(tc, package),
            }),
        );
        files.insert(
            PathBuf::from(format!("{TS_ARTIFACTS}/{package}.json")),
            artifact.clone(),
        );
        files.insert(
            PathBuf::from(format!("{ARTIFACTS}/{package}.json")),
            artifact,
        );
        files.insert(PathBuf::from(format!("{VK_DIR}/{package}.vk")), vk);
    }

    let mut fixtures = serde_json::Map::new();
    for s in scenarios(&e) {
        let name = s.name;
        let f = build_fixture(&e, s);
        let inputs = f.inputs(&e);
        let proof = prove(tc, Path::new(CIRCUITS), RELEASE, &inputs, &work.join(name))
            .unwrap_or_else(|err| panic!("proving {name}: {err}"));
        assert_eq!(
            proof.public_inputs,
            inputs.public_inputs(&e),
            "{name}: bb's public inputs differ from the host's"
        );
        let dir = PathBuf::from(format!("{FIXTURES}/{name}"));
        let mut fixture_json = serde_json::to_vec_pretty(&f).unwrap();
        fixture_json.push(b'\n');
        fixtures.insert(
            name.into(),
            json!({
                "action": format!("{:?}", f.statement.to_statement(&e).action()),
                "proof_sha256": hex(&sha256(&proof.proof)),
                "public_inputs_sha256": hex(&sha256(&proof.public_inputs)),
            }),
        );
        files.insert(dir.join("fixture.json"), fixture_json);
        files.insert(dir.join("proof"), proof.proof);
        files.insert(dir.join("public_inputs"), proof.public_inputs);
    }

    let manifest = json!({
        "toolchain": {
            "nargo": NARGO_VERSION,
            "noirc": noirc_version(tc),
            "bb": BB_VERSION,
            "bb_scheme": "ultra_honk --oracle_hash keccak (UltraKeccakFlavor, non-ZK)",
            "verifier": VERIFIER_SOURCE,
        },
        "sources": source_hashes(),
        "circuits": circuits,
        "fixtures": fixtures,
    });
    let doc = std::fs::read_to_string(MEASUREMENTS_DOC).expect("measurements doc");
    let doc = splice_doc_block(&doc, &doc_block(&manifest))
        .unwrap_or_else(|| panic!("{MEASUREMENTS_DOC} lost its generated-block markers"));
    files.insert(PathBuf::from(MEASUREMENTS_DOC), doc.into_bytes());
    let mut manifest = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest.push(b'\n');
    files.insert(
        PathBuf::from(format!("{TS_ARTIFACTS}/manifest.json")),
        manifest.clone(),
    );
    files.insert(PathBuf::from(MANIFEST), manifest);
    files
}

/// Proving cost at each packaged depth, for the same credential and
/// statement as the `lost_key` fixture.
fn bench(tc: &Toolchain, runs: usize, work: &Path) -> Value {
    let e = host();
    compile(tc);
    let f = build_fixture(
        &e,
        scenarios(&e)
            .into_iter()
            .find(|s| s.name == "lost_key")
            .unwrap(),
    );
    let leaves: Vec<_> = f
        .enrollments
        .iter()
        .map(|x| {
            perch_zk_prover::leaf_of_commitment(
                &e,
                &perch_zk_prover::fixture::h32(&x.account_id),
                &perch_zk_prover::fixture::h32(&x.enrollment_id),
                &perch_zk_prover::fixture::h32(&x.commitment),
            )
        })
        .collect();
    let mut out = serde_json::Map::new();
    for (package, depth) in PACKAGES {
        let inputs = Inputs::new(
            &e,
            perch_zk_prover::fixture::h32(&f.secret),
            perch_zk_prover::fixture::h32(&f.account_id),
            perch_zk_prover::fixture::h32(&f.enrollment_id),
            perch_zk_prover::fixture::h32(&f.digest),
            f.leaf_index,
            Tree::new(&e, depth, &leaves).path(f.leaf_index),
        );
        let mut execute = vec![];
        let mut prove_ms = vec![];
        let mut rss = vec![];
        let mut last = None;
        for i in 0..runs {
            let p = prove(
                tc,
                Path::new(CIRCUITS),
                package,
                &inputs,
                &work.join(format!("{package}-{i}")),
            )
            .unwrap_or_else(|err| panic!("proving {package}: {err}"));
            execute.push(p.execute_ms);
            prove_ms.push(p.prove_ms);
            rss.extend(p.prove_peak_rss_bytes);
            last = Some(p);
        }
        let p = last.expect("at least one run");
        let dir = PathBuf::from(format!("target/zk-bench/{package}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("proof"), &p.proof).unwrap();
        std::fs::write(dir.join("public_inputs"), &p.public_inputs).unwrap();
        // Nullifier and statement hash do not depend on the depth; the root does.
        let mut at_depth = f.clone();
        at_depth.root = hex(&inputs.root);
        std::fs::write(
            dir.join("fixture.json"),
            serde_json::to_vec_pretty(&at_depth).unwrap(),
        )
        .unwrap();
        let median = |v: &mut Vec<u128>| {
            v.sort_unstable();
            v[v.len() / 2]
        };
        out.insert(
            package.into(),
            json!({
                "depth": depth,
                "runs": runs,
                "nargo_execute_ms_median": median(&mut execute),
                "bb_prove_ms_median": median(&mut prove_ms),
                "bb_prove_peak_rss_bytes_max": rss.iter().max(),
                "proof_bytes": p.proof.len(),
                "root": hex(&inputs.root),
            }),
        );
    }
    Value::Object(out)
}

fn work_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("perch-zk-fixtures-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if !["generate", "check", "bench"].contains(&mode.as_str()) {
        eprintln!("usage: perch-zk-fixtures generate|check|bench [runs]");
        return ExitCode::from(2);
    }
    let tc = match Toolchain::from_env() {
        Ok(tc) => tc,
        Err(err) => {
            eprintln!("{err}\nrun scripts/zk-toolchain.sh and export the NARGO/BB it prints");
            return ExitCode::from(2);
        }
    };
    let work = work_dir();
    if mode == "bench" {
        let runs = std::env::args()
            .nth(2)
            .and_then(|n| n.parse().ok())
            .unwrap_or(5);
        let report = bench(&tc, runs, &work);
        let _ = std::fs::remove_dir_all(&work);
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
        return ExitCode::SUCCESS;
    }
    let files = build_all(&tc, &work);
    let _ = std::fs::remove_dir_all(&work);

    if mode == "generate" {
        for (path, bytes) in &files {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            println!("wrote {}", path.display());
        }
        return ExitCode::SUCCESS;
    }

    let mut drift = 0;
    for (path, bytes) in &files {
        match std::fs::read(path) {
            Ok(committed) if committed == *bytes => println!("ok    {}", path.display()),
            Ok(_) => {
                drift += 1;
                println!("DRIFT {}", path.display());
            }
            Err(_) => {
                drift += 1;
                println!("MISSING {}", path.display());
            }
        }
    }
    if drift > 0 {
        eprintln!("{drift} artifact(s) differ from a fresh build");
        return ExitCode::FAILURE;
    }
    println!("all artifacts reproduce byte-for-byte");
    ExitCode::SUCCESS
}
