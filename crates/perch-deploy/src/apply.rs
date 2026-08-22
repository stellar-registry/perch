//! `apply`: submit a policy document's JSON bytes to the account's
//! `apply_doc` in one signed transaction. The account does all the real
//! verification on-chain — parse, validate, network binding, compile,
//! anti-brick check, atomic whole-rule-set swap — this command only
//! pre-flights locally for a better error message, prints the canonical
//! `doc_hash` the reviewer approved, and signs the admin's approval
//! (PERCH_ADMIN_KEY selecting rule 0 — the one thing the stock stellar CLI
//! cannot sign yet).

use anyhow::{bail, Context, Result};
use stellar_xdr::{ScBytes, ScVal};

use crate::keys::SeedKey;
use crate::rpc::Rpc;
use crate::tx::{simulate_read, AuthSpec, InvokeSpec, ReadOutcome};
use crate::{scv, tx};

/// The verifier address of the on-chain rule-0 `Signer::External` whose key is
/// `pubkey`. Reads `get_context_rule(0)` — the same storage `__check_auth`
/// validates against.
fn onchain_rule0_verifier(rpc: &Rpc, account: &str, pubkey: &[u8; 32]) -> Result<String> {
    let rule = match simulate_read(rpc, account, "get_context_rule", vec![ScVal::U32(0)])? {
        ReadOutcome::Value(ScVal::Map(Some(m))) => m,
        ReadOutcome::Value(other) => bail!("get_context_rule(0) returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => {
            bail!("get_context_rule(0) trapped — is the account deployed? {message}")
        }
    };
    let ScVal::Vec(Some(signers)) =
        scv::map_get(&rule, "signers").context("rule 0 has no signers field")?
    else {
        bail!("rule 0 signers field is not a vec");
    };
    for signer in signers.iter() {
        // Signer::External = Vec[Sym("External"), Address(verifier), Bytes(key)]
        let ScVal::Vec(Some(parts)) = signer else {
            continue;
        };
        let mut it = parts.iter();
        let (Some(ScVal::Symbol(tag)), Some(verifier), Some(ScVal::Bytes(key))) =
            (it.next(), it.next(), it.next())
        else {
            continue;
        };
        if tag.to_utf8_string_lossy() == "External" && key.as_slice() == pubkey {
            return scv::address_to_string(verifier);
        }
    }
    bail!("PERCH_ADMIN_KEY's public key matches no External signer on the ON-CHAIN rule 0")
}

pub fn run(
    rpc: &Rpc,
    passphrase: &str,
    account: &str,
    doc_path: &std::path::Path,
    dry_run: bool,
) -> Result<()> {
    let doc_json = std::fs::read_to_string(doc_path)
        .with_context(|| format!("read {}", doc_path.display()))?;

    // Local pre-flight for operator-grade error messages; the account
    // re-verifies everything fail-closed on-chain.
    let doc = perch_ir::from_json(&doc_json)
        .map_err(|e| anyhow::anyhow!("document does not parse: {e:?}"))?;
    if let Err(errors) = perch_ir::validate(&doc) {
        bail!("document is invalid: {errors:?}");
    }
    match &doc.network {
        Some(net) if net == passphrase => {}
        Some(net) => bail!(
            "document names network {net:?} but this connection targets {passphrase:?} — \
             the account would reject it (WrongNetwork)"
        ),
        None => bail!("document names no network; apply_doc requires one (WrongNetwork)"),
    }
    let doc_hash = perch_ir::doc_hash_hex(&doc);
    println!("canonical doc_hash: {doc_hash}");

    // Only the document bytes: the account resolves the compiler + interpreter
    // itself through its pinned stateless registry.
    let args = vec![ScVal::Bytes(ScBytes(
        doc_json
            .clone()
            .into_bytes()
            .try_into()
            .context("document too large for an ScVal bytes value")?,
    ))];

    let key = SeedKey::from_env("PERCH_ADMIN_KEY")?;
    let verifier = onchain_rule0_verifier(rpc, account, &key.public)?;

    let spec = InvokeSpec {
        contract: account.to_string(),
        func: "apply_doc".to_string(),
        args,
    };
    let auth_spec = AuthSpec {
        mode: tx::AuthMode::External { verifier },
        rule_id: 0,
        account: account.to_string(),
    };
    if let Some(submitted) = tx::run_signed(rpc, passphrase, &key, &auth_spec, &spec, dry_run)? {
        println!(
            "applied document {doc_hash} in tx {} at ledger {}",
            submitted.tx_hash, submitted.ledger
        );
        println!(
            "confirm with the stock CLI: stellar contract invoke --id {account} -- \
             applied_doc_hash"
        );
    }
    Ok(())
}
