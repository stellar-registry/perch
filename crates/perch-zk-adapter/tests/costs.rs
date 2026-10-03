//! Metered resource costs of the compiled pool and adapter wasm, run under
//! the live per-transaction limits. These are the numbers recorded in
//! `docs/zk/measurements.md`.
//!
//! `#[ignore]`d because they need the wasm built first (`just zk-wasm`):
//!
//! ```text
//! just zk-wasm && cargo test -p perch-zk-adapter --test costs -- --ignored --nocapture
//! ```
//!
//! The depth-24 rows run only when `just zk-wasm` built the fallback
//! (`target/zk-d24/`) and `perch-zk-fixtures bench` wrote a depth-24 proof
//! (`target/zk-bench/perch_zk_recovery_d24/`).

use perch_recovery_interface::zk::{ProofVerifierClient, ZkAdapterClient, ZkBinding, ZkEvidence};
use perch_zk_pool::{PerchZkPoolClient, PoolKey, TreeState};
use perch_zk_primitives::ZERO_HASHES;
use perch_zk_prover::fixture::{address, h32, sha256, tag, Loaded, NETWORK_PASSPHRASE};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};
use std::path::{Path, PathBuf};

/// `tx_max_instructions` and `tx_memory_limit`, identical on testnet and
/// mainnet at protocol 29 (`stellar network settings`, 2026-10-03). The
/// testutils budget defaults to 100M instructions, which is not a network
/// limit; this raises it to the real one, so exceeding it fails the run.
const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn wasm(dir: &str, name: &str) -> Option<std::vec::Vec<u8>> {
    std::fs::read(
        root()
            .join(dir)
            .join("wasm32v1-none/release")
            .join(format!("{name}.wasm")),
    )
    .ok()
}

fn env() -> Env {
    let e = Env::default();
    e.cost_estimate()
        .budget()
        .reset_limits(TX_MAX_INSTRUCTIONS, TX_MEMORY_LIMIT);
    e.ledger()
        .set_network_id(sha256(NETWORK_PASSPHRASE.as_bytes()));
    e
}

fn report(label: &str, e: &Env) {
    let r = e.cost_estimate().resources();
    let fee = e.cost_estimate().fee();
    // Printed on its own line so `--nocapture` output stays one JSON object
    // per line.
    println!(
        "\n{{\"case\":\"{label}\",\"instructions\":{},\"instructions_pct_of_tx_limit\":{:.1},\"mem_bytes\":{},\"read_entries\":{},\"write_entries\":{},\"write_bytes\":{},\"events_bytes\":{},\"rent_ledger_bytes\":{},\"rent_bumps\":{},\"fee_resource_stroops\":{},\"fee_rent_stroops\":{}}}",
        r.instructions,
        r.instructions as f64 * 100.0 / TX_MAX_INSTRUCTIONS as f64,
        r.mem_bytes,
        r.memory_read_entries + r.disk_read_entries,
        r.write_entries,
        r.write_bytes,
        r.contract_events_size_bytes,
        r.persistent_rent_ledger_bytes,
        r.persistent_entry_rent_bumps,
        fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
        fee.persistent_entry_rent,
    );
    assert!(
        r.instructions as u64 <= TX_MAX_INSTRUCTIONS,
        "{label} exceeds tx_max_instructions"
    );
    assert!(
        r.mem_bytes as u64 <= TX_MEMORY_LIMIT,
        "{label} exceeds tx_memory_limit"
    );
}

fn enr(e: &Env, n: u64) -> BytesN<32> {
    let mut b = [0xee; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(e, &b)
}

fn commitment(e: &Env, n: u64) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(e, &perch_zk_prover::commitment(e, &b))
}

fn enroll_costs(target: &str, label: &str) {
    let Some(pool_wasm) = wasm(target, "perch_zk_pool") else {
        println!("skip {label}: no pool wasm under {target}/");
        return;
    };
    let e = env();
    e.mock_all_auths();
    let pool = e.register(pool_wasm.as_slice(), ());
    let client = PerchZkPoolClient::new(&e, &pool);
    let account = |n: u64| address(&e, &tag(&format!("bench-account-{n}")));

    client.rcv_insert(&account(0), &enr(&e, 0), &commitment(&e, 0));
    report(
        &format!("{label} rcv_insert: first leaf (opens the tree)"),
        &e,
    );
    for n in 1..=200 {
        client.rcv_insert(&account(n), &enr(&e, n), &commitment(&e, n));
    }
    client.rcv_insert(&account(201), &enr(&e, 201), &commitment(&e, 201));
    report(
        &format!("{label} rcv_insert: typical (tree already has 201 leaves)"),
        &e,
    );

    // Last slot of a full tree, then the first leaf of the next one.
    let depth = client.depth();
    let mut frontier = Vec::new(&e);
    for z in &ZERO_HASHES[..depth as usize] {
        frontier.push_back(BytesN::from_array(&e, z));
    }
    e.as_contract(&pool, || {
        e.storage().persistent().set(
            &PoolKey::Tree(0),
            &TreeState {
                size: (1u64 << depth) - 1,
                root: BytesN::from_array(&e, &ZERO_HASHES[depth as usize]),
                frontier,
            },
        );
    });
    client.rcv_insert(&account(300), &enr(&e, 300), &commitment(&e, 300));
    report(
        &format!("{label} rcv_insert: last slot (seals the tree)"),
        &e,
    );
    client.rcv_insert(&account(301), &enr(&e, 301), &commitment(&e, 301));
    report(
        &format!("{label} rcv_insert: first leaf after rollover"),
        &e,
    );
}

fn verify_costs(target: &str, fixture_dir: &Path, label: &str) {
    let (Some(pool_wasm), Some(adapter_wasm)) = (
        wasm(target, "perch_zk_pool"),
        wasm(target, "perch_zk_adapter"),
    ) else {
        println!("skip {label}: no wasm under {target}/");
        return;
    };
    let Ok(l) = Loaded::read(fixture_dir) else {
        println!("skip {label}: no proof in {}", fixture_dir.display());
        return;
    };
    let f = &l.fixture;
    let e = env();
    e.mock_all_auths();
    let pool: Address = address(&e, &h32(&f.pool_id));
    e.register_at(&pool, pool_wasm.as_slice(), ());
    let pool_client = PerchZkPoolClient::new(&e, &pool);
    for x in &f.enrollments {
        pool_client.rcv_insert(
            &address(&e, &h32(&x.account_id)),
            &BytesN::from_array(&e, &h32(&x.enrollment_id)),
            &BytesN::from_array(&e, &h32(&x.commitment)),
        );
    }
    let adapter = e.register(adapter_wasm.as_slice(), ());
    let client = ZkAdapterClient::new(&e, &adapter);
    let binding = ZkBinding {
        pool: pool.clone(),
        enrollment_id: BytesN::from_array(&e, &h32(&f.enrollment_id)),
        circuit_id: client.circuit_id(),
    };
    let evidence = ZkEvidence {
        tree_id: f.tree_id,
        root: BytesN::from_array(&e, &h32(&f.root)),
        nullifier: BytesN::from_array(&e, &h32(&f.nullifier)),
        proof: Bytes::from_slice(&e, &l.proof),
    };
    client.verify(&f.statement.to_statement(&e), &binding, &evidence);
    report(
        &format!("{label} adapter.verify (root check + statement hash + UltraHonk)"),
        &e,
    );

    ProofVerifierClient::new(&e, &adapter).verify_proof(
        &Bytes::from_slice(&e, &l.public_inputs),
        &Bytes::from_slice(&e, &l.proof),
    );
    report(
        &format!("{label} adapter.verify_proof (UltraHonk only)"),
        &e,
    );

    pool_client.is_known_root(&f.tree_id, &evidence.root);
    report(&format!("{label} pool.is_known_root"), &e);
}

#[test]
#[ignore = "needs `just zk-wasm`"]
fn depth_32() {
    enroll_costs("target", "d32");
    verify_costs("target", &root().join("testdata/zk/lost_key"), "d32");
}

#[test]
#[ignore = "needs `just zk-wasm` and `perch-zk-fixtures bench`"]
fn depth_24() {
    enroll_costs("target/zk-d24", "d24");
    verify_costs(
        "target/zk-d24",
        &root().join("target/zk-bench/perch_zk_recovery_d24"),
        "d24",
    );
}
