//! `verify`: read-only reconciliation of the on-chain account against a
//! compose output. The headline check is a single read — the account's
//! `applied_doc_hash` must equal the compose `doc_hash` (installed ==
//! reviewed). Then every composed rule must exist on chain, matched **by
//! name** (rule ids are assigned at apply time and shift across re-applies),
//! with the matching context type; every interpreter-attached rule's stored
//! program must carry the doc_hash; and the on-chain rule count must equal
//! the document's exactly — `apply_doc` replaces the whole set, so a leftover
//! rule is a detected mismatch, not a mystery. Everything runs through
//! simulation — no keys, no writes.

use anyhow::{bail, Context, Result};
use stellar_xdr::{ScMap, ScVal};

use crate::compose::{parse_hash32, ComposeOutput, RuleEntry};
use crate::rpc::Rpc;
use crate::tx::{simulate_read, ReadOutcome};
use crate::{auth, scv};

struct Row {
    /// Actual on-chain rule id, if the rule was found.
    rule_id: Option<u32>,
    name: String,
    check: &'static str,
    /// `None` = OK; `Some(reason)` = mismatch.
    mismatch: Option<String>,
}

fn fmt_id(id: Option<u32>) -> String {
    id.map_or_else(|| "—".to_string(), |i| i.to_string())
}

/// Probe rule ids upward until all `count` live rules are found. Ids are
/// sparse after `apply_doc` replaces the set; the ceiling bounds the scan.
fn scan_rules(rpc: &Rpc, account: &str) -> Result<Vec<(u32, ScMap)>> {
    let count = match simulate_read(rpc, account, "get_context_rules_count", vec![])? {
        ReadOutcome::Value(ScVal::U32(n)) => n,
        ReadOutcome::Value(other) => bail!("get_context_rules_count returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => {
            bail!("get_context_rules_count trapped: {message}")
        }
    };
    let ceiling = count.saturating_mul(8).saturating_add(64);
    let mut found = Vec::new();
    let mut id = 0u32;
    while (found.len() as u32) < count && id < ceiling {
        if let ReadOutcome::Value(ScVal::Map(Some(m))) =
            simulate_read(rpc, account, "get_context_rule", vec![ScVal::U32(id)])?
        {
            found.push((id, m));
        }
        id += 1;
    }
    if (found.len() as u32) < count {
        bail!(
            "found only {} of {count} rules within the id probe ceiling {ceiling}",
            found.len()
        );
    }
    Ok(found)
}

/// The applied document hash stored by `apply_doc` (`Option<BytesN<32>>`:
/// `None` encodes as Void).
fn check_applied_hash(rpc: &Rpc, account: &str, doc_hash_hex: &str) -> Result<Row> {
    let want = scv::bytes(&parse_hash32(doc_hash_hex).context("compose doc_hash")?)?;
    let mismatch = match simulate_read(rpc, account, "applied_doc_hash", vec![])? {
        ReadOutcome::Value(ScVal::Void) => Some("no document applied".to_string()),
        ReadOutcome::Value(v) if v == want => None,
        ReadOutcome::Value(other) => Some(format!("applied hash differs: {other:?}")),
        ReadOutcome::ContractError { message, .. } => {
            Some(format!("applied_doc_hash trapped: {message}"))
        }
    };
    Ok(Row {
        rule_id: None,
        name: "(document)".to_string(),
        check: "applied hash",
        mismatch,
    })
}

fn check_program(
    rpc: &Rpc,
    account: &str,
    interpreter: &str,
    doc_hash_hex: &str,
    name: &str,
    rule_id: u32,
) -> Result<Row> {
    let outcome = simulate_read(
        rpc,
        interpreter,
        "get_program",
        vec![scv::address(account)?, ScVal::U32(rule_id)],
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
        rule_id: Some(rule_id),
        name: name.to_string(),
        check: "program hash",
        mismatch,
    })
}

/// Find a composed rule on chain by name and compare its context type.
fn check_rule(onchain: &[(u32, ScMap)], expected: &RuleEntry) -> Result<(Row, Option<u32>)> {
    let want_name = scv::string(&expected.name)?;
    let want_ctx = auth::call_contract_context(&expected.context_type.call_contract)?;
    let found = onchain
        .iter()
        .find(|(_, m)| scv::map_get(m, "name") == Some(&want_name));
    let (rule_id, mismatch) = match found {
        None => (None, Some("MISSING".to_string())),
        Some((id, m)) => {
            let ctx_ok = scv::map_get(m, "context_type") == Some(&want_ctx);
            (
                Some(*id),
                (!ctx_ok).then(|| "context_type mismatch".to_string()),
            )
        }
    };
    Ok((
        Row {
            rule_id,
            name: expected.name.clone(),
            check: "context+name",
            mismatch,
        },
        rule_id,
    ))
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

    let mut rows = vec![check_applied_hash(rpc, account, &compose.doc_hash)?];

    let onchain = scan_rules(rpc, account)?;
    for expected in compose.genesis_rule.iter().chain(compose.apply.iter()) {
        let (row, rule_id) = check_rule(&onchain, expected)?;
        rows.push(row);
        if expected.install.is_some() {
            rows.push(match rule_id {
                Some(id) => check_program(
                    rpc,
                    account,
                    interpreter,
                    &compose.doc_hash,
                    &expected.name,
                    id,
                )?,
                None => Row {
                    rule_id: None,
                    name: expected.name.clone(),
                    check: "program hash",
                    mismatch: Some("rule missing; program unchecked".to_string()),
                },
            });
        }
    }

    // apply_doc replaces the whole set: the document's rules are exactly the
    // account's rules. A count mismatch means a leftover or a missing rule.
    let expected_rules = usize::from(compose.genesis_rule.is_some()) + compose.apply.len();
    rows.push(Row {
        rule_id: None,
        name: "(rule count)".to_string(),
        check: "exact count",
        mismatch: (onchain.len() != expected_rules)
            .then(|| format!("on-chain {} != document {}", onchain.len(), expected_rules)),
    });

    println!("{:<6} {:<24} {:<14} status", "rule", "name", "check");
    for row in &rows {
        println!(
            "{:<6} {:<24} {:<14} {}",
            fmt_id(row.rule_id),
            row.name,
            row.check,
            row.mismatch.as_deref().unwrap_or("OK")
        );
    }

    if rows.iter().any(|r| r.mismatch.is_some()) {
        bail!("verification failed");
    }
    println!("verification OK: installed == reviewed");
    Ok(())
}
