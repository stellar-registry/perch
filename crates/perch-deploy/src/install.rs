//! `install-rule`: turn one compose apply entry into a signed
//! `add_context_rule` call on the account. The auth entry is signed with
//! PERCH_ADMIN_KEY selecting rule 0 — the admin key must therefore *be* one of
//! rule 0's registered signers ON CHAIN, which is what `__check_auth` will
//! actually consult (fail-closed: a wrong key errors here, not in the
//! transaction; the compose file is only warned about, never trusted).

use anyhow::{bail, Context, Result};
use stellar_xdr::{Limits, ReadXdr, ScVal};

use crate::compose::{ComposeOutput, SignerJson};
use crate::keys::SeedKey;
use crate::rpc::Rpc;
use crate::tx::{simulate_read, AuthSpec, InvokeSpec, ReadOutcome};
use crate::{auth, scv, tx};

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
    rules_path: &std::path::Path,
    rule_name: &str,
    dry_run: bool,
) -> Result<()> {
    let compose: ComposeOutput = serde_json::from_str(
        &std::fs::read_to_string(rules_path)
            .with_context(|| format!("read {}", rules_path.display()))?,
    )
    .context("parse compose output")?;
    if compose.account != account {
        bail!(
            "--account {} does not match the compose output's account {}",
            account,
            compose.account
        );
    }
    if compose
        .genesis_rule
        .as_ref()
        .is_some_and(|r| r.name == rule_name)
    {
        bail!("rule '{rule_name}' is satisfied at genesis by the constructor; nothing to install");
    }
    let entry = compose
        .apply
        .iter()
        .find(|r| r.name == rule_name)
        .with_context(|| format!("no apply rule named '{rule_name}' in compose output"))?;
    if entry.cap.is_some() {
        bail!(
            "rule '{rule_name}' carries a cumulative cap; attaching OZ spending_limit is not \
             supported by perch-deploy yet"
        );
    }

    // add_context_rule(context_type, name, valid_until, signers, policies)
    let context_type = auth::call_contract_context(&entry.context_type.call_contract)?;
    let name = scv::string(&entry.name)?;
    let valid_until = entry.valid_until.map_or(ScVal::Void, ScVal::U32);
    let signers = scv::vec(
        entry
            .signers
            .iter()
            .map(|s| match s {
                SignerJson::External { verifier, key_hex } => {
                    let key = hex::decode(key_hex)
                        .with_context(|| format!("signer key for '{}' is not hex", entry.name))?;
                    auth::external_signer(verifier, &key)
                }
                SignerJson::Delegated { address } => auth::delegated_signer(address),
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    let policies = match &entry.install {
        Some(i) => scv::map(vec![(
            scv::address(&compose.interpreter)?,
            ScVal::from_xdr_base64(&i.scval_base64, Limits::none())?,
        )])?,
        None => scv::map(vec![])?,
    };

    let key = SeedKey::from_env("PERCH_ADMIN_KEY")?;
    let verifier = onchain_rule0_verifier(rpc, account, &key.public)?;
    // The compose file is advisory here: warn on divergence, trust the chain.
    if let Some(genesis) = &compose.genesis_rule {
        let my_key_hex = hex::encode(key.public);
        let matching = genesis.signers.iter().find_map(|s| match s {
            SignerJson::External { verifier, key_hex } if *key_hex == my_key_hex => Some(verifier),
            _ => None,
        });
        match matching {
            None => eprintln!(
                "warning: PERCH_ADMIN_KEY is not among the compose file's genesis-rule external \
                 signers (chain and doc disagree — consider re-running compose)"
            ),
            Some(v) if *v != verifier => {
                eprintln!("warning: compose genesis verifier {v} != on-chain verifier {verifier}")
            }
            Some(_) => {}
        }
    }

    let spec = InvokeSpec {
        contract: account.to_string(),
        func: "add_context_rule".to_string(),
        args: vec![context_type, name, valid_until, signers, policies],
    };
    let auth_spec = AuthSpec {
        mode: tx::AuthMode::External { verifier },
        rule_id: 0,
        account: account.to_string(),
    };
    if let Some(submitted) = tx::run_signed(rpc, passphrase, &key, &auth_spec, &spec, dry_run)? {
        println!(
            "installed rule '{}' (expected id {}) in tx {} at ledger {}",
            entry.name, entry.expected_rule_id, submitted.tx_hash, submitted.ledger
        );
        println!("run `perch-deploy verify` to confirm the assigned rule id");
    }
    Ok(())
}
