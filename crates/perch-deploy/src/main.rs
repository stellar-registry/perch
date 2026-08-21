//! perch-deploy: the interim signing shim for the perch smart-account
//! pipeline — it exists only because stellar-cli cannot yet sign OZ
//! smart-account approvals (AuthPayload selecting a rule id). `apply` submits
//! a policy document to the account's `apply_doc` signed by the admin key; CI
//! publishes wasm to the registry signed by the scoped CI key. Everything
//! else — and eventually all of this — is the stock `stellar` CLI. Key
//! material comes ONLY from PERCH_ADMIN_KEY / PERCH_CI_KEY env variables.

mod apply;
mod auth;
mod compose;
mod keys;
mod publish;
mod rpc;
mod scv;
mod tx;
mod verify;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use soroban_sdk::Env;

#[derive(Parser)]
#[command(name = "perch-deploy", about, version)]
struct Cli {
    /// Soroban RPC endpoint.
    #[arg(long, env = "STELLAR_RPC_URL", global = true)]
    rpc_url: Option<String>,
    /// Network passphrase (hashed into every signature).
    #[arg(long, env = "STELLAR_NETWORK_PASSPHRASE", global = true)]
    network_passphrase: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a PolicyDoc into the JSON worklist of add_context_rule calls.
    Compose {
        /// Path to the PolicyDoc JSON.
        #[arg(long)]
        doc: PathBuf,
        /// The smart account (C…) the rules apply to.
        #[arg(long)]
        account: String,
        /// The interpreter contract (C…) programs install into.
        #[arg(long)]
        interpreter: String,
        /// The interpreter's wasm hash (64 hex chars), pinned into the plan.
        #[arg(long)]
        interpreter_wasm_hash: String,
    },
    /// Apply a policy document whole: submit its JSON bytes to the account's
    /// `apply_doc` in one transaction, signed by PERCH_ADMIN_KEY selecting
    /// rule 0. The account verifies and swaps the entire rule set atomically.
    Apply {
        #[arg(long)]
        account: String,
        /// Path to the PolicyDoc JSON — the same file the review approved.
        #[arg(long)]
        doc: PathBuf,
        /// Stop after simulation; print footprint and fee.
        #[arg(long)]
        dry_run: bool,
    },
    /// Publish wasm to the registry, signed by PERCH_CI_KEY selecting --rule-id.
    Publish(publish::PublishArgs),
    /// Read-only check that the on-chain rules match a compose output.
    Verify {
        #[arg(long)]
        account: String,
        #[arg(long)]
        interpreter: String,
        #[arg(long)]
        rules: PathBuf,
    },
}

impl Cli {
    fn rpc(&self) -> Result<rpc::Rpc> {
        let url = self
            .rpc_url
            .as_deref()
            .context("--rpc-url or STELLAR_RPC_URL required")?;
        Ok(rpc::Rpc::new(url))
    }

    fn passphrase(&self) -> Result<&str> {
        self.network_passphrase
            .as_deref()
            .context("--network-passphrase or STELLAR_NETWORK_PASSPHRASE required")
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Cmd::Compose {
            doc,
            account,
            interpreter,
            interpreter_wasm_hash,
        } => {
            let doc_json = std::fs::read_to_string(doc)
                .with_context(|| format!("read doc {}", doc.display()))?;
            let env = Env::default();
            let out =
                compose::compose(&env, &doc_json, account, interpreter, interpreter_wasm_hash)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        Cmd::Apply {
            account,
            doc,
            dry_run,
        } => apply::run(&cli.rpc()?, cli.passphrase()?, account, doc, *dry_run),
        Cmd::Publish(args) => publish::run(&cli.rpc()?, cli.passphrase()?, args),
        Cmd::Verify {
            account,
            interpreter,
            rules,
        } => verify::run(&cli.rpc()?, account, interpreter, rules),
    }
}
