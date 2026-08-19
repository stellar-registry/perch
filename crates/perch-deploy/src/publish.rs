//! `publish`: idempotent CI publish to the registry. A read-only `fetch_hash`
//! preflight decides between no-op (same bytes already published), hard error
//! (same name+version, different bytes — a republish would be a supply-chain
//! smell), and proceeding with the CI-key-signed `publish` call.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stellar_xdr::ScVal;

use crate::keys::SeedKey;
use crate::rpc::Rpc;
use crate::tx::{simulate_read, AuthSpec, InvokeSpec, ReadOutcome};
use crate::{scv, tx};

#[derive(clap::Args)]
pub struct PublishArgs {
    #[arg(long)]
    pub wasm: PathBuf,
    #[arg(long)]
    pub wasm_name: String,
    /// The version string to publish under.
    #[arg(long)]
    pub binver: String,
    #[arg(long)]
    pub registry: String,
    /// The author smart account (C…) — the single address credential.
    #[arg(long)]
    pub author: String,
    /// The CI signer's verifier contract (C…) for an EXTERNAL signer. Omit
    /// when the CI signer is DELEGATED (CAP-0071): the key's own G-account is
    /// then the delegate, host-authenticated — no verifier involved.
    #[arg(long)]
    pub verifier: Option<String>,
    /// The account context rule the CI key signs under.
    #[arg(long)]
    pub rule_id: u32,
    /// Stop after simulation; print footprint and fee.
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, default_value = "publish-receipt.json")]
    pub receipt: PathBuf,
}

/// Registry `Error` discriminants (contracts/contracts/registry/src/error.rs —
/// `#[soroban_sdk_tools::scerr]` numbers variants positionally from 1; anchors:
/// #4 NoSuchContractDeployed observed live, #8/#11 pinned by cli publish tests).
const NO_SUCH_WASM_PUBLISHED: u32 = 1;
const NO_SUCH_VERSION: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum PreflightDecision {
    AlreadyPublished,
    Proceed,
    HashMismatch {
        onchain: [u8; 32],
    },
    /// The registry trapped with something OTHER than not-published — never
    /// publish through an error we don't understand.
    UnexpectedTrap,
}

/// Pure decision so the branches are testable offline. Only the two
/// "nothing published under this name/version" errors mean Proceed; any other
/// trap (or an unparseable error code) fails the preflight.
pub fn preflight_decision(outcome: &tx::ReadOutcome, local: &[u8; 32]) -> PreflightDecision {
    match outcome {
        tx::ReadOutcome::ContractError {
            code: Some(NO_SUCH_WASM_PUBLISHED | NO_SUCH_VERSION),
            ..
        } => PreflightDecision::Proceed,
        tx::ReadOutcome::ContractError { .. } => PreflightDecision::UnexpectedTrap,
        tx::ReadOutcome::Value(ScVal::Bytes(b)) => match <[u8; 32]>::try_from(b.as_slice()) {
            Ok(h) if h == *local => PreflightDecision::AlreadyPublished,
            Ok(h) => PreflightDecision::HashMismatch { onchain: h },
            Err(_) => PreflightDecision::UnexpectedTrap,
        },
        tx::ReadOutcome::Value(_) => PreflightDecision::UnexpectedTrap,
    }
}

#[derive(Serialize)]
struct Receipt<'a> {
    tx_hash: &'a str,
    wasm_hash: String,
    wasm_name: &'a str,
    version: &'a str,
    registry: &'a str,
    ledger: u32,
}

pub fn run(rpc: &Rpc, passphrase: &str, args: &PublishArgs) -> Result<()> {
    let wasm =
        std::fs::read(&args.wasm).with_context(|| format!("read wasm {}", args.wasm.display()))?;
    let local_hash: [u8; 32] = Sha256::digest(&wasm).into();

    let outcome = simulate_read(
        rpc,
        &args.registry,
        "fetch_hash",
        // Option<String>: Some(v) encodes as the inner value.
        vec![scv::string(&args.wasm_name)?, scv::string(&args.binver)?],
    )?;
    if let ReadOutcome::ContractError { code, message } = &outcome {
        println!("preflight: fetch_hash trapped (code {code:?}): {message}");
    }
    match preflight_decision(&outcome, &local_hash) {
        PreflightDecision::AlreadyPublished => {
            println!(
                "already published: {} {} = {}",
                args.wasm_name,
                args.binver,
                hex::encode(local_hash)
            );
            return Ok(());
        }
        PreflightDecision::HashMismatch { onchain } => bail!(
            "{} {} is already published with a DIFFERENT hash: on-chain {}, local {}",
            args.wasm_name,
            args.binver,
            hex::encode(onchain),
            hex::encode(local_hash)
        ),
        PreflightDecision::UnexpectedTrap => bail!(
            "preflight fetch_hash returned something other than 'not published' — refusing to \
             publish through an error we don't understand (see message above)"
        ),
        PreflightDecision::Proceed => {}
    }

    let key = SeedKey::from_env("PERCH_CI_KEY")?;
    let spec = InvokeSpec {
        contract: args.registry.clone(),
        func: "publish".to_string(),
        args: vec![
            scv::string(&args.wasm_name)?,
            scv::address(&args.author)?,
            scv::bytes(&wasm)?,
            scv::string(&args.binver)?,
        ],
    };
    let auth = AuthSpec {
        mode: match &args.verifier {
            Some(v) => tx::AuthMode::External {
                verifier: v.clone(),
            },
            None => tx::AuthMode::Delegated,
        },
        rule_id: args.rule_id,
        account: args.author.clone(),
    };
    let Some(submitted) = tx::run_signed(rpc, passphrase, &key, &auth, &spec, args.dry_run)? else {
        return Ok(()); // dry run
    };

    let receipt = Receipt {
        tx_hash: &submitted.tx_hash,
        wasm_hash: hex::encode(local_hash),
        wasm_name: &args.wasm_name,
        version: &args.binver,
        registry: &args.registry,
        ledger: submitted.ledger,
    };
    std::fs::write(&args.receipt, serde_json::to_string_pretty(&receipt)?)
        .with_context(|| format!("write receipt {}", args.receipt.display()))?;
    println!(
        "published {} {} in tx {} at ledger {} (receipt: {})",
        args.wasm_name,
        args.binver,
        submitted.tx_hash,
        submitted.ledger,
        args.receipt.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::ReadOutcome;

    fn trap(msg: &str) -> ReadOutcome {
        ReadOutcome::ContractError {
            code: tx::contract_error_code(msg),
            message: msg.to_string(),
        }
    }

    fn hash_value(h: [u8; 32]) -> ReadOutcome {
        ReadOutcome::Value(ScVal::Bytes(h.to_vec().try_into().unwrap()))
    }

    #[test]
    fn absent_wasm_proceeds() {
        // #1 NoSuchWasmPublished, #2 NoSuchVersion — the only Proceed traps.
        for msg in [
            "HostError: Error(Contract, #1)",
            "HostError: Error(Contract, #2)",
        ] {
            assert_eq!(
                preflight_decision(&trap(msg), &[1u8; 32]),
                PreflightDecision::Proceed,
                "{msg}"
            );
        }
    }

    #[test]
    fn other_traps_do_not_proceed() {
        // e.g. #11 HashAlreadyPublished, or an unparseable error string.
        for msg in [
            "HostError: Error(Contract, #11)",
            "HostError: Error(WasmVm, InvalidAction)",
        ] {
            assert_eq!(
                preflight_decision(&trap(msg), &[1u8; 32]),
                PreflightDecision::UnexpectedTrap,
                "{msg}"
            );
        }
    }

    #[test]
    fn same_hash_is_a_noop() {
        assert_eq!(
            preflight_decision(&hash_value([1u8; 32]), &[1u8; 32]),
            PreflightDecision::AlreadyPublished
        );
    }

    #[test]
    fn different_hash_is_an_error() {
        assert_eq!(
            preflight_decision(&hash_value([2u8; 32]), &[1u8; 32]),
            PreflightDecision::HashMismatch { onchain: [2u8; 32] }
        );
    }
}
