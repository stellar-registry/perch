//! Native proof helpers for Perch ZK recovery.
//!
//! - [`IncrementalTree`] / [`PoolWitnessIndex`]: witnesses for a pool's
//!   trees, appended leaf by leaf (from the pool's `leaves` pages or its
//!   `LeafInserted` events) without materializing a tree; [`Tree`] is the
//!   in-memory convenience over a slice of leaves.
//! - [`Inputs`]: the full circuit input set for one proof, with the public
//!   values (`root`, `nullifier`, `statement_hash`) derived exactly as the
//!   contracts derive them.
//! - [`Toolchain`]/[`prove`]/[`verify`]: drives the pinned `nargo` and `bb`
//!   binaries to produce and check a real zero-knowledge UltraHonk proof, for
//!   fixtures and native tooling. Browser and Node proving live in
//!   `packages/perch-zk`.
//!
//! Hashing runs the Soroban host's own Poseidon2 permutation through an
//! in-process [`Env`], so a witness is computed by the same code the pool runs
//! on-chain rather than by a second Poseidon2 implementation.

use perch_recovery_interface::zk::{public_inputs, split_hi_lo, ZkStatementFields};
use perch_zk_primitives::Hasher;
use soroban_sdk::{BytesN, Env};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type Bytes32 = [u8; 32];

/// An `Env` for host-side hashing only, with metering disabled.
pub fn host() -> Env {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    e
}

pub(crate) fn bn(e: &Env, b: &Bytes32) -> BytesN<32> {
    BytesN::from_array(e, b)
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Parse `0x`-prefixed or bare hex into 32 bytes.
pub fn parse32(s: &str) -> Option<Bytes32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Recompute a root from a leaf, its index, and its sibling path — the
/// circuit's `merkle_root`.
pub fn root_from_path(e: &Env, leaf: &Bytes32, index: u64, siblings: &[Bytes32]) -> Bytes32 {
    let mut h = Hasher::new(e);
    let mut cur = bn(e, leaf);
    for (level, sib) in siblings.iter().enumerate() {
        cur = if (index >> level) & 1 == 0 {
            h.node(&cur, &bn(e, sib))
        } else {
            h.node(&bn(e, sib), &cur)
        };
    }
    cur.to_array()
}

/// Everything one proof needs. Raw 32-byte ids, not `Address`es, so the
/// fixture tool can pin arbitrary contract ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub root: Bytes32,
    pub nullifier: Bytes32,
    pub statement_hash: Bytes32,
    pub secret: Bytes32,
    pub account_id: Bytes32,
    pub enrollment_id: Bytes32,
    /// The recovery statement's 32-byte digest.
    pub digest: Bytes32,
    pub leaf_index: u64,
    pub siblings: Vec<Bytes32>,
}

impl Inputs {
    /// Derive the public values from the private ones. `siblings` is the
    /// path for `leaf_index` in the tree whose root the proof will name.
    pub fn new(
        e: &Env,
        secret: Bytes32,
        account_id: Bytes32,
        enrollment_id: Bytes32,
        digest: Bytes32,
        leaf_index: u64,
        siblings: Vec<Bytes32>,
    ) -> Self {
        let mut h = Hasher::new(e);
        let (acct, enr) = (bn(e, &account_id), bn(e, &enrollment_id));
        let inner = h.commitment(&bn(e, &secret));
        let leaf = h.leaf(&acct, &enr, &inner).to_array();
        let root = root_from_path(e, &leaf, leaf_index, &siblings);
        let fields = fields(&account_id, &enrollment_id, &digest);
        Self {
            root,
            nullifier: h.nullifier(&acct, &enr, &bn(e, &secret)).to_array(),
            statement_hash: h.statement_hash(&fields).to_array(),
            secret,
            account_id,
            enrollment_id,
            digest,
            leaf_index,
            siblings,
        }
    }

    /// The leaf these inputs prove membership of.
    pub fn leaf(&self, e: &Env) -> Bytes32 {
        leaf(e, &self.account_id, &self.enrollment_id, &self.secret)
    }

    /// `root || nullifier || statement_hash`, the verifier's public inputs.
    pub fn public_inputs(&self, e: &Env) -> Vec<u8> {
        let mut out = vec![0u8; 96];
        public_inputs(
            e,
            &bn(e, &self.root),
            &bn(e, &self.nullifier),
            &bn(e, &self.statement_hash),
        )
        .copy_into_slice(&mut out);
        out
    }

    /// The `Prover.toml` nargo reads, in the circuit's parameter names.
    pub fn prover_toml(&self) -> String {
        let f = fields(&self.account_id, &self.enrollment_id, &self.digest);
        let mut index = [0u8; 32];
        index[24..].copy_from_slice(&self.leaf_index.to_be_bytes());
        let siblings: Vec<String> = self
            .siblings
            .iter()
            .map(|s| format!("\"{}\"", hex(s)))
            .collect();
        let mut s = String::new();
        for (k, v) in [
            ("root", &self.root),
            ("nullifier", &self.nullifier),
            ("statement_hash", &self.statement_hash),
            ("secret", &self.secret),
            ("acct_hi", &f.account_hi),
            ("acct_lo", &f.account_lo),
            ("enr_hi", &f.enrollment_hi),
            ("enr_lo", &f.enrollment_lo),
            ("digest_hi", &f.digest_hi),
            ("digest_lo", &f.digest_lo),
            ("leaf_index", &index),
        ] {
            let _ = writeln!(s, "{k} = \"{}\"", hex(v));
        }
        let _ = writeln!(s, "siblings = [{}]", siblings.join(", "));
        s
    }
}

/// The circuit's account/enrollment/digest fields, split exactly as
/// `perch-recovery-interface::zk::zk_statement_fields` splits them.
pub fn fields(
    account_id: &Bytes32,
    enrollment_id: &Bytes32,
    digest: &Bytes32,
) -> ZkStatementFields {
    let (account_hi, account_lo) = split_hi_lo(account_id);
    let (enrollment_hi, enrollment_lo) = split_hi_lo(enrollment_id);
    let (digest_hi, digest_lo) = split_hi_lo(digest);
    ZkStatementFields {
        account_hi,
        account_lo,
        enrollment_hi,
        enrollment_lo,
        digest_hi,
        digest_lo,
    }
}

/// `H(DOM_LEAF, secret)`: the commitment a client enrolls.
pub fn commitment(e: &Env, secret: &Bytes32) -> Bytes32 {
    Hasher::new(e).commitment(&bn(e, secret)).to_array()
}

/// The leaf the pool stores for `secret` enrolled by `account_id` under
/// `enrollment_id`.
pub fn leaf(e: &Env, account_id: &Bytes32, enrollment_id: &Bytes32, secret: &Bytes32) -> Bytes32 {
    leaf_of_commitment(e, account_id, enrollment_id, &commitment(e, secret))
}

/// The leaf the pool stores for an enrolled `commitment`.
pub fn leaf_of_commitment(
    e: &Env,
    account_id: &Bytes32,
    enrollment_id: &Bytes32,
    commitment: &Bytes32,
) -> Bytes32 {
    Hasher::new(e)
        .leaf(
            &bn(e, account_id),
            &bn(e, enrollment_id),
            &bn(e, commitment),
        )
        .to_array()
}

/// The pinned proving toolchain. Proofs and verification keys must come
/// from these exact versions: the on-chain verifier parses bb 0.87.0's
/// `UltraKeccakZKFlavor` layout, and a proof from another bb version fails at
/// the pairing check rather than at parse time.
pub const NARGO_VERSION: &str = "1.0.0-beta.9";
pub const BB_VERSION: &str = "0.87.0";

pub struct Toolchain {
    pub nargo: PathBuf,
    pub bb: PathBuf,
}

fn first_line(bin: &Path, arg: &str) -> io::Result<String> {
    let out = Command::new(bin).arg(arg).output()?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string())
}

fn run(cmd: &mut Command) -> io::Result<()> {
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{cmd:?} failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

impl Toolchain {
    /// `NARGO`/`BB` from the environment (default: `nargo`/`bb` on `PATH`),
    /// refusing any version other than the pinned ones.
    pub fn from_env() -> io::Result<Self> {
        let tc = Self {
            nargo: std::env::var_os("NARGO").map_or_else(|| "nargo".into(), PathBuf::from),
            bb: std::env::var_os("BB").map_or_else(|| "bb".into(), PathBuf::from),
        };
        let nargo = first_line(&tc.nargo, "--version")?;
        if !nargo.contains(&format!("nargo version = {NARGO_VERSION}")) {
            return Err(io::Error::other(format!(
                "need nargo {NARGO_VERSION}, {} reports '{nargo}' (set NARGO)",
                tc.nargo.display()
            )));
        }
        let bb = first_line(&tc.bb, "--version")?;
        if bb.trim().trim_start_matches('v') != BB_VERSION {
            return Err(io::Error::other(format!(
                "need bb {BB_VERSION}, {} reports '{bb}' (set BB)",
                tc.bb.display()
            )));
        }
        Ok(tc)
    }
}

/// A proof and the public inputs bb committed it to.
pub struct Proof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    /// Wall time of witness generation (`nargo execute`) and proving
    /// (`bb prove`), and bb's peak resident memory when the platform's
    /// `/usr/bin/time` reports it.
    pub execute_ms: u128,
    pub prove_ms: u128,
    pub prove_peak_rss_bytes: Option<u64>,
}

/// Run `cmd` under `/usr/bin/time` (`-l` on macOS, `-v` on Linux) and return
/// the peak resident set size it reports, in bytes.
fn run_measured(cmd: &mut Command) -> io::Result<Option<u64>> {
    let time = Path::new("/usr/bin/time");
    if !time.exists() {
        run(cmd)?;
        return Ok(None);
    }
    let linux = cfg!(target_os = "linux");
    let mut timed = Command::new(time);
    timed.arg(if linux { "-v" } else { "-l" });
    timed.arg(cmd.get_program()).args(cmd.get_args());
    let out = timed.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{cmd:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let report = String::from_utf8_lossy(&out.stderr);
    Ok(report.lines().find_map(|l| {
        let l = l.trim();
        if linux {
            l.strip_prefix("Maximum resident set size (kbytes):")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(|kb| kb * 1024)
        } else {
            l.strip_suffix("maximum resident set size")
                .and_then(|v| v.trim().parse::<u64>().ok())
        }
    }))
}

/// The bb flags of the proving system the adapter verifies: UltraHonk with
/// the keccak transcript, zero-knowledge (`UltraKeccakZKFlavor`). The
/// verification key is the same with or without `--zk`, and `bb write_vk`
/// takes no `--zk`.
const BB_SCHEME: [&str; 4] = ["--scheme", "ultra_honk", "--oracle_hash", "keccak"];

/// Prove `inputs` against the compiled `package` of the Noir workspace at
/// `circuits` (`nargo compile --workspace` must have run). `work` receives
/// the witness and bb's outputs. Proofs are zero-knowledge and so randomized:
/// two proofs of the same witness differ.
pub fn prove(
    tc: &Toolchain,
    circuits: &Path,
    package: &str,
    inputs: &Inputs,
    work: &Path,
) -> io::Result<Proof> {
    prove_with(tc, circuits, package, inputs, work, true)
}

/// [`prove`], or with `zk = false` a deterministic non-ZK
/// (`UltraKeccakFlavor`) proof, which the adapter must refuse. Fixtures use
/// one to show that it does.
pub fn prove_with(
    tc: &Toolchain,
    circuits: &Path,
    package: &str,
    inputs: &Inputs,
    work: &Path,
    zk: bool,
) -> io::Result<Proof> {
    std::fs::create_dir_all(work)?;
    let work = work.canonicalize()?;
    let prover = work.join("Prover.toml");
    std::fs::write(&prover, inputs.prover_toml())?;
    let witness_name = format!("{package}-{}", std::process::id());
    let started = std::time::Instant::now();
    run(Command::new(&tc.nargo)
        .current_dir(circuits.join(package))
        .args(["execute", "--prover-name"])
        .arg(work.join("Prover"))
        .arg(&witness_name))?;
    let execute_ms = started.elapsed().as_millis();
    let target = circuits.join("target");
    let witness = target.join(format!("{witness_name}.gz"));
    let moved = work.join("witness.gz");
    std::fs::rename(&witness, &moved)?;
    let started = std::time::Instant::now();
    let prove_peak_rss_bytes = run_measured(
        Command::new(&tc.bb)
            .arg("prove")
            .args(BB_SCHEME)
            .args(zk.then_some("--zk"))
            .arg("-b")
            .arg(target.join(format!("{package}.json")))
            .arg("-w")
            .arg(&moved)
            .arg("-o")
            .arg(&work),
    )?;
    let prove_ms = started.elapsed().as_millis();
    Ok(Proof {
        proof: std::fs::read(work.join("proof"))?,
        public_inputs: std::fs::read(work.join("public_inputs"))?,
        execute_ms,
        prove_ms,
        prove_peak_rss_bytes,
    })
}

/// Write the verification key for `package` (`bb write_vk`) into `out_dir`.
pub fn write_vk(
    tc: &Toolchain,
    circuits: &Path,
    package: &str,
    out_dir: &Path,
) -> io::Result<Vec<u8>> {
    std::fs::create_dir_all(out_dir)?;
    run(Command::new(&tc.bb)
        .arg("write_vk")
        .args(BB_SCHEME)
        .arg("-b")
        .arg(circuits.join("target").join(format!("{package}.json")))
        .arg("-o")
        .arg(out_dir))?;
    std::fs::read(out_dir.join("vk"))
}

/// Whether `bb verify --zk` accepts `proof` for `public_inputs` under `vk`.
/// `work` receives the three files.
pub fn verify(
    tc: &Toolchain,
    vk: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
    work: &Path,
) -> io::Result<bool> {
    std::fs::create_dir_all(work)?;
    let (vk_path, proof_path, inputs_path) = (
        work.join("vk"),
        work.join("proof"),
        work.join("public_inputs"),
    );
    std::fs::write(&vk_path, vk)?;
    std::fs::write(&proof_path, proof)?;
    std::fs::write(&inputs_path, public_inputs)?;
    let out = Command::new(&tc.bb)
        .arg("verify")
        .args(BB_SCHEME)
        .arg("--zk")
        .arg("-k")
        .arg(&vk_path)
        .arg("-p")
        .arg(&proof_path)
        .arg("-i")
        .arg(&inputs_path)
        .output()?;
    Ok(out.status.success())
}

pub mod fixture;

/// Markers around the block of `docs/zk/measurements.md` generated from
/// `circuits/manifest.json`.
pub const DOC_BLOCK_BEGIN: &str =
    "<!-- BEGIN GENERATED from circuits/manifest.json by `perch-zk-fixtures generate`; do not edit -->";
pub const DOC_BLOCK_END: &str = "<!-- END GENERATED -->";

/// The circuit-identity table, generated from the manifest so documented
/// `circuit_id`s can never drift from the VKs the adapter compiles in.
pub fn doc_block(manifest: &serde_json::Value) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{DOC_BLOCK_BEGIN}");
    let _ = writeln!(
        s,
        "| Circuit | Depth | `circuit_id` (`sha256` of the VK) | Gates |"
    );
    let _ = writeln!(s, "| --- | --- | --- | --- |");
    let circuits = manifest["circuits"].as_object().expect("manifest circuits");
    for (name, c) in circuits {
        let vk = c["vk_sha256"].as_str().expect("vk_sha256");
        let _ = writeln!(
            s,
            "| `{name}` | {} | `{}` | {} |",
            c["depth"],
            vk.trim_start_matches("0x"),
            c["circuit_size"]
        );
    }
    let _ = write!(s, "{DOC_BLOCK_END}");
    s
}

/// `doc` with its generated block replaced by `block`.
pub fn splice_doc_block(doc: &str, block: &str) -> Option<String> {
    let begin = doc.find(DOC_BLOCK_BEGIN)?;
    let end = doc[begin..].find(DOC_BLOCK_END)? + begin + DOC_BLOCK_END.len();
    Some(format!("{}{block}{}", &doc[..begin], &doc[end..]))
}
pub mod tree;

pub use tree::{
    IncrementalTree, Insertion, MemoryNodeStore, MerklePath, NodeStore, PoolWitnessIndex, Tree,
    TreeState, CHUNK_LEVEL,
};

#[cfg(test)]
mod test;
