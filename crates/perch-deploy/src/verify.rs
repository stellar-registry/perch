//! `verify`: read-only reconciliation of the on-chain account against a
//! compose output. Each expected rule (genesis + applied) must exist with the
//! matching context type and name, and every interpreter-attached rule's
//! stored program must carry the compose doc_hash. Everything runs through
//! simulation — no keys, no writes. One simulate_read per check (2N+1 round
//! trips) is deliberate: batching via getLedgerEntries would mean replicating
//! OZ's storage-key encoding, which is more fragile than a handful of
//! sequential reads in a bootstrap-only tool.

use anyhow::{bail, Context, Result};
use stellar_xdr::{ScMap, ScVal};

use crate::compose::{parse_hash32, ComposeOutput, RuleEntry};
use crate::rpc::Rpc;
use crate::tx::{simulate_read, ReadOutcome};
use crate::{auth, scv};

struct Row {
    rule_id: u32,
    name: String,
    check: &'static str,
    /// `None` = OK; `Some(reason)` = mismatch.
    mismatch: Option<String>,
}

fn rule_mismatch(map: &ScMap, expected: &RuleEntry) -> Result<Option<String>> {
    let want_name = scv::string(&expected.name)?;
    let want_ctx = auth::call_contract_context(&expected.context_type.call_contract)?;
    let name_ok = scv::map_get(map, "name") == Some(&want_name);
    let ctx_ok = scv::map_get(map, "context_type") == Some(&want_ctx);
    Ok(match (ctx_ok, name_ok) {
        (true, true) => None,
        (false, true) => Some("context_type mismatch".to_string()),
        (true, false) => Some("name mismatch".to_string()),
        (false, false) => Some("context_type + name mismatch".to_string()),
    })
}

fn check_rule(rpc: &Rpc, account: &str, expected: &RuleEntry) -> Result<Row> {
    let mismatch = match simulate_read(
        rpc,
        account,
        "get_context_rule",
        vec![ScVal::U32(expected.expected_rule_id)],
    )? {
        ReadOutcome::ContractError { .. } => Some("MISSING".to_string()),
        ReadOutcome::Value(ScVal::Map(Some(m))) => rule_mismatch(&m, expected)?,
        ReadOutcome::Value(other) => Some(format!("unexpected shape: {other:?}")),
    };
    Ok(Row {
        rule_id: expected.expected_rule_id,
        name: expected.name.clone(),
        check: "context+name",
        mismatch,
    })
}

fn check_program(
    rpc: &Rpc,
    account: &str,
    interpreter: &str,
    doc_hash_hex: &str,
    expected: &RuleEntry,
) -> Result<Row> {
    let outcome = simulate_read(
        rpc,
        interpreter,
        "get_program",
        vec![
            scv::address(account)?,
            ScVal::U32(expected.expected_rule_id),
        ],
    )?;
    let mismatch = match outcome {
        ReadOutcome::ContractError { message, .. } => {
            Some(format!("get_program trapped: {message}"))
        }
        // Option<InstallParams>: None encodes as Void.
        ReadOutcome::Value(ScVal::Void) => Some("no program installed".to_string()),
        ReadOutcome::Value(ScVal::Map(Some(m))) => {
            let want = scv::bytes(&parse_hash32(doc_hash_hex).context("compose doc_hash")?)?;
            if scv::map_get(&m, "doc_hash") == Some(&want) {
                None
            } else {
                Some("doc_hash mismatch".to_string())
            }
        }
        ReadOutcome::Value(other) => Some(format!("unexpected shape: {other:?}")),
    };
    Ok(Row {
        rule_id: expected.expected_rule_id,
        name: expected.name.clone(),
        check: "program hash",
        mismatch,
    })
}

pub fn run(
    rpc: &Rpc,
    account: &str,
    interpreter: &str,
    rules_path: &std::path::Path,
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
    if compose.interpreter != interpreter {
        bail!(
            "--interpreter {} does not match the compose output's interpreter {}",
            interpreter,
            compose.interpreter
        );
    }

    let count = match simulate_read(rpc, account, "get_context_rules_count", vec![])? {
        ReadOutcome::Value(ScVal::U32(n)) => n,
        ReadOutcome::Value(other) => bail!("get_context_rules_count returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => {
            bail!("get_context_rules_count trapped: {message}")
        }
    };

    let mut rows = Vec::new();
    for expected in compose.genesis_rule.iter().chain(compose.apply.iter()) {
        rows.push(check_rule(rpc, account, expected)?);
        if expected.install.is_some() {
            rows.push(check_program(
                rpc,
                account,
                interpreter,
                &compose.doc_hash,
                expected,
            )?);
        }
    }

    println!("{:<6} {:<24} {:<14} status", "rule", "name", "check");
    for row in &rows {
        println!(
            "{:<6} {:<24} {:<14} {}",
            row.rule_id,
            row.name,
            row.check,
            row.mismatch.as_deref().unwrap_or("OK")
        );
    }
    let expected_rules = usize::from(compose.genesis_rule.is_some()) + compose.apply.len();
    println!("on-chain rule count: {count} (expected at least {expected_rules})");

    if rows.iter().any(|r| r.mismatch.is_some()) {
        bail!("verification failed");
    }
    println!("verification OK");
    Ok(())
}
