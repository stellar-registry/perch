//! `perch-testnet`: exercise a deployed perch stack on testnet and record
//! what every transaction cost.
//!
//! ```text
//! eval "$(scripts/zk-toolchain.sh)"
//! cargo run -p perch-testnet -- --manifest deployments/testnet.json \
//!     --out deployments/testnet-exercise.json
//! ```
//!
//! Every key is fresh for the run and funded by friendbot: the fee payer, the
//! G-account guardians, and the passkeys (software secp256r1 keys signing
//! real WebAuthn assertions). Accounts come from the deployed factory. Proofs
//! are real UltraHonk proofs from the pinned nargo/bb over the deployed
//! pool's on-chain leaves. Nothing is mocked: every transaction runs the
//! deployed wasm under enforcing authorization, and every refusal is a
//! simulation of the deployed wasm against live state.

mod chain;
mod scenarios;
mod world;

use anyhow::{Context, Result};
use clap::Parser;
use perch_deploy::keys::SeedKey;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId, Limits, WriteXdr,
};

use chain::Chain;
use world::{Stack, World};

type Scenario = fn(&World<'_>) -> Result<()>;

#[derive(Parser)]
#[command(name = "perch-testnet", about, version)]
struct Cli {
    /// The deployment manifest to exercise.
    #[arg(long, default_value = "deployments/testnet.json")]
    manifest: std::path::PathBuf,
    /// Where to write the report.
    #[arg(long, default_value = "deployments/testnet-exercise.json")]
    out: std::path::PathBuf,
    /// Run only these scenarios (comma-separated): zk-loss, combined,
    /// zk-protected, guardian-loss.
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
}

/// The native asset's contract id on `passphrase`'s network.
fn native_asset_contract(passphrase: &str) -> Result<String> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        contract_id_preimage: ContractIdPreimage::Asset(stellar_xdr::Asset::Native),
    });
    let id: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none())?).into();
    Ok(stellar_strkey::Contract(id).to_string().as_str().into())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&cli.manifest).with_context(|| format!("{}", cli.manifest.display()))?,
    )?;
    let passphrase = manifest["network_passphrase"]
        .as_str()
        .context("passphrase")?;
    let rpc_url = manifest["rpc_url"].as_str().context("rpc_url")?;
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .to_string();

    let payer = SeedKey::from_seed(Sha256::digest(format!("perch-testnet/{run}/payer")).into());
    let chain = Chain::new(rpc_url, passphrase, payer);
    chain.friendbot(&chain.payer.account())?;
    let stack = Stack::from_manifest(&manifest, native_asset_contract(passphrase)?)?;
    let w = World::new(&chain, stack, run.clone());
    let started_ledger = chain.latest_ledger()?;

    let all: [(&str, Scenario); 4] = [
        ("zk-loss", scenarios::zk_lost_key),
        ("combined", scenarios::combined_protected),
        ("zk-protected", scenarios::zk_protected_changes),
        ("guardian-loss", scenarios::guardian_loss),
    ];
    let mut failures = Vec::new();
    for (name, f) in all {
        if !cli.only.is_empty() && !cli.only.iter().any(|o| o == name) {
            continue;
        }
        if let Err(e) = f(&w) {
            eprintln!("!! {name} failed: {e:#}");
            failures.push(format!("{name}: {e:#}"));
        }
    }

    let proving: Vec<_> = w
        .proving
        .borrow()
        .iter()
        .map(|(x, p, rss)| serde_json::json!({"execute_ms": x, "prove_ms": p, "peak_rss_bytes": rss}))
        .collect();
    let accounts: Vec<_> = w
        .accounts
        .borrow()
        .iter()
        .map(|(label, address)| serde_json::json!({"label": label, "address": address}))
        .collect();
    let report = serde_json::json!({
        "schema": 1,
        "run": run,
        "manifest": cli.manifest,
        "manifest_commit": manifest["source"]["commit"],
        "network": manifest["network"],
        "ledgers": {"from": started_ledger, "to": chain.latest_ledger()?},
        "payer": chain.payer.account(),
        "limits": {
            "tx_max_instructions": 400_000_000u64,
            "tx_memory_limit": 41_943_040u64,
            "tx_max_disk_read_entries": 200,
            "tx_max_disk_read_bytes": 200_000,
            "tx_max_write_ledger_entries": 200,
            "tx_max_write_bytes": 132_096,
            "tx_max_size_bytes": 132_096,
            "source": "stellar network settings, testnet, 2026-10-03 (protocol 29)",
        },
        "accounts": accounts,
        "native_proving": proving,
        "failures": failures,
        "steps": *chain.steps.borrow(),
    });
    std::fs::write(&cli.out, serde_json::to_string_pretty(&report)? + "\n")?;
    eprintln!("\nwrote {}", cli.out.display());
    if !failures.is_empty() {
        anyhow::bail!("{} scenario(s) failed", failures.len());
    }
    Ok(())
}
