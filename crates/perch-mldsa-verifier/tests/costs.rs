//! Metered resource costs of the compiled verifier, against the network's
//! per-transaction limits and the budget rule's 75% of them
//! (`docs/recovery/budgets.md` §2). Metering accrues only to code running as
//! wasm, so this registers the release wasm.
//!
//! `#[ignore]`d because it needs the wasm built first:
//!
//! ```text
//! stellar contract build --package perch-mldsa-verifier
//! cargo test -p perch-mldsa-verifier --test costs -- --ignored --nocapture
//! ```
//!
//! `PERCH_MLDSA_WASM` names another build of it (the release asset, say).

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer};
use perch_mldsa_verifier::{key_commitment, MlDsaSigData, PerchMlDsaVerifierClient, SIG_CONTEXT};
use soroban_sdk::testutils::EnvTestConfig;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Bytes, BytesN, Env, Vec};

/// Protocol-29 per-transaction limits (`stellar network settings`,
/// 2026-10-03; identical on testnet and mainnet).
const TX_MAX_INSTRUCTIONS: u64 = 400_000_000;
const TX_MEMORY_LIMIT: u64 = 41_943_040;
const BUDGET_PCT: u64 = 75;

fn wasm() -> std::vec::Vec<u8> {
    let path = std::env::var("PERCH_MLDSA_WASM").unwrap_or_else(|_| {
        format!(
            "{}/../../target/wasm32v1-none/release/perch_mldsa_verifier.wasm",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!("no verifier wasm at {path} ({e}): stellar contract build --package perch-mldsa-verifier")
    })
}

struct Metered {
    env: Env,
    verifier: PerchMlDsaVerifierClient<'static>,
}

fn setup() -> Metered {
    // No snapshot: these runs register release wasm, and they are
    // measurements, not regression tests.
    let env = Env::new_with_config(EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    env.cost_estimate()
        .budget()
        .reset_limits(TX_MAX_INSTRUCTIONS, TX_MEMORY_LIMIT);
    let id = env.register(wasm().as_slice(), ());
    let verifier = PerchMlDsaVerifierClient::new(&env, &id);
    Metered { env, verifier }
}

/// One `{"case": ...}` JSON line with the last top-level call's resources,
/// asserted within the budget rule.
fn report(label: &str, e: &Env) {
    let r = e.cost_estimate().resources();
    println!(
        "\n{{\"case\":\"{label}\",\"instructions\":{},\"instructions_pct_of_tx_limit\":{:.1},\"mem_bytes\":{},\"mem_pct_of_tx_limit\":{:.1}}}",
        r.instructions,
        r.instructions as f64 * 100.0 / TX_MAX_INSTRUCTIONS as f64,
        r.mem_bytes,
        r.mem_bytes as f64 * 100.0 / TX_MEMORY_LIMIT as f64,
    );
    assert!(
        r.instructions as u64 * 100 <= TX_MAX_INSTRUCTIONS * BUDGET_PCT,
        "{label}: instructions over budget"
    );
    assert!(
        r.mem_bytes as u64 * 100 <= TX_MEMORY_LIMIT * BUDGET_PCT,
        "{label}: memory over budget"
    );
}

/// The signer key, and `sig_data` signing `payload` (`rnd` = `seed`).
fn signed(env: &Env, payload: &[u8; 32], seed: [u8; 32]) -> (BytesN<32>, Bytes) {
    let (pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[7; 32]);
    let signature = sk.try_sign_with_seed(&seed, payload, SIG_CONTEXT).unwrap();
    let public_key = Bytes::from_slice(env, &pk.into_bytes());
    let key_data = key_commitment(env, &public_key);
    let sig_data = MlDsaSigData {
        public_key,
        signature: Bytes::from_slice(env, &signature),
    }
    .to_xdr(env);
    (key_data, sig_data)
}

#[test]
#[ignore = "needs the wasm: stellar contract build --package perch-mldsa-verifier"]
fn verify_is_within_budget() {
    let m = setup();
    let payload = [0x42; 32];
    let message = Bytes::from_array(&m.env, &payload);
    // Signing draws a different number of rejection rounds per signature,
    // and so a different signature; verification does the same work for
    // each. A few signatures show that.
    for (i, seed) in [[0u8; 32], [1; 32], [2; 32]].into_iter().enumerate() {
        let (key_data, sig_data) = signed(&m.env, &payload, seed);
        assert!(m.verifier.verify(&message, &key_data, &sig_data));
        report(&format!("verify, valid signature {i}"), &m.env);
    }

    let (key_data, sig_data) = signed(&m.env, &payload, [0; 32]);
    let mut other = payload;
    other[0] ^= 1;
    assert!(!m
        .verifier
        .verify(&Bytes::from_array(&m.env, &other), &key_data, &sig_data));
    report("verify, signature over another payload", &m.env);

    let wrong_key = BytesN::from_array(&m.env, &[9; 32]);
    assert!(!m.verifier.verify(&message, &wrong_key, &sig_data));
    report("verify, key the commitment does not name", &m.env);
}

#[test]
#[ignore = "needs the wasm: stellar contract build --package perch-mldsa-verifier"]
fn canonicalization_is_within_budget() {
    let m = setup();
    let key = BytesN::from_array(&m.env, &[7; 32]);
    m.verifier.canonicalize_key(&key);
    report("canonicalize_key", &m.env);
    let keys = Vec::from_array(&m.env, [key.clone(), key.clone(), key.clone(), key]);
    m.verifier.batch_canonicalize_key(&keys);
    report("batch_canonicalize_key, 4 keys", &m.env);
}
