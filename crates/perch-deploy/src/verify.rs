//! `verify`: read-only reconciliation of the on-chain account against a
//! compose output. The headline check is a single read — the account's
//! `applied_doc_hash` must equal the compose `doc_hash` (installed ==
//! reviewed). Then every composed rule must exist on chain, matched **by
//! name** in the account's `configuration()` snapshot (rule ids are
//! assigned when a rule is added and kept while it is edited in place), with
//! the matching context type. Every rule's stored rule-eval rule (the
//! account's `rule_set()`, aligned with its installed rules) must equal the
//! composed one: the rule `__check_auth` decides that rule's authorizations
//! with is the rule the reviewed document lowers to. The on-chain rule
//! count, and the stored set's length, must equal the document's exactly —
//! `apply_doc` brings the rule set to the document's, so a leftover rule is a
//! detected mismatch, not a mystery. Every read must belong to the
//! snapshot's configuration revision, which is read again at the end.
//! Everything runs through simulation — no keys, no writes.

use anyhow::{bail, Context, Result};
use stellar_xdr::{Limits, ReadXdr, ScMap, ScVal};

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

/// The account's configuration snapshot (`configuration()`): its revision
/// and every installed rule with its OZ id, read at one ledger. Rules are
/// found by name in it, never by probing ids.
pub(crate) fn read_configuration(rpc: &Rpc, account: &str) -> Result<(u64, Vec<(u32, ScMap)>)> {
    let m = match simulate_read(rpc, account, "configuration", vec![])? {
        ReadOutcome::Value(ScVal::Map(Some(m))) => m,
        ReadOutcome::Value(other) => bail!("configuration returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => bail!("configuration trapped: {message}"),
    };
    let Some(ScVal::U64(revision)) = scv::map_get(&m, "revision") else {
        bail!("configuration has no revision");
    };
    let Some(ScVal::Vec(Some(rules))) = scv::map_get(&m, "rules") else {
        bail!("configuration has no rules");
    };
    let mut found = Vec::new();
    for rule in rules.iter() {
        let ScVal::Map(Some(r)) = rule else {
            bail!("configuration rule is not a map: {rule:?}");
        };
        let Some(ScVal::U32(id)) = scv::map_get(r, "id") else {
            bail!("configuration rule has no id");
        };
        found.push((*id, r.clone()));
    }
    Ok((*revision, found))
}

/// The account's configuration revision (`revision()`).
fn read_revision(rpc: &Rpc, account: &str) -> Result<u64> {
    match simulate_read(rpc, account, "revision", vec![])? {
        ReadOutcome::Value(ScVal::U64(r)) => Ok(r),
        ReadOutcome::Value(other) => bail!("revision returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => bail!("revision trapped: {message}"),
    }
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

/// The account's stored rule-eval rules (`rule_set()`), aligned with its
/// installed rules.
fn read_rule_set(rpc: &Rpc, account: &str) -> Result<Vec<ScVal>> {
    match simulate_read(rpc, account, "rule_set", vec![])? {
        ReadOutcome::Value(ScVal::Vec(Some(rules))) => Ok(rules.to_vec()),
        ReadOutcome::Value(other) => bail!("rule_set returned {other:?}"),
        ReadOutcome::ContractError { message, .. } => bail!("rule_set trapped: {message}"),
    }
}

/// The rule stored for the installed rule at `index` must be exactly the
/// composed one.
fn check_stored(stored: &[ScVal], expected: &RuleEntry, index: usize, rule_id: u32) -> Result<Row> {
    let want = ScVal::from_xdr_base64(&expected.rule.scval_base64, Limits::none())
        .context("compose stored rule")?;
    let mismatch = match stored.get(index) {
        None => Some("no stored rule".to_string()),
        Some(found) if *found == want => None,
        Some(_) => Some("stored rule differs".to_string()),
    };
    Ok(Row {
        rule_id: Some(rule_id),
        name: expected.name.clone(),
        check: "stored rule",
        mismatch,
    })
}

/// Find a composed rule on chain by name and compare its context type.
/// Returns its index among the installed rules and its id when found.
fn check_rule(
    onchain: &[(u32, ScMap)],
    expected: &RuleEntry,
) -> Result<(Row, Option<(usize, u32)>)> {
    let want_name = scv::string(&expected.name)?;
    let want_ctx = auth::call_contract_context(&expected.context_type.call_contract)?;
    let found = onchain
        .iter()
        .enumerate()
        .find(|(_, (_, m))| scv::map_get(m, "name") == Some(&want_name));
    let (at, mismatch) = match found {
        None => (None, Some("MISSING".to_string())),
        Some((i, (id, m))) => {
            let ctx_ok = scv::map_get(m, "context_type") == Some(&want_ctx);
            (
                Some((i, *id)),
                (!ctx_ok).then(|| "context_type mismatch".to_string()),
            )
        }
    };
    Ok((
        Row {
            rule_id: at.map(|(_, id)| id),
            name: expected.name.clone(),
            check: "context+name",
            mismatch,
        },
        at,
    ))
}

pub fn run(rpc: &Rpc, account: &str, rules_path: &std::path::Path) -> Result<()> {
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

    // Every read below must belong to the snapshot's revision: it is
    // checked again once they are done.
    let (revision, onchain) = read_configuration(rpc, account)?;
    let stored = read_rule_set(rpc, account)?;
    let mut rows = vec![check_applied_hash(rpc, account, &compose.doc_hash)?];

    for expected in compose.genesis_rule.iter().chain(compose.apply.iter()) {
        let (row, at) = check_rule(&onchain, expected)?;
        rows.push(row);
        rows.push(match at {
            Some((index, id)) => check_stored(&stored, expected, index, id)?,
            None => Row {
                rule_id: None,
                name: expected.name.clone(),
                check: "stored rule",
                mismatch: Some("rule missing; stored rule unchecked".to_string()),
            },
        });
    }

    // apply_doc brings the rule set to the document's: the document's rules
    // are exactly the account's rules. A count mismatch means a leftover or a
    // missing rule.
    let expected_rules = usize::from(compose.genesis_rule.is_some()) + compose.apply.len();
    rows.push(Row {
        rule_id: None,
        name: "(rule count)".to_string(),
        check: "exact count",
        mismatch: (onchain.len() != expected_rules)
            .then(|| format!("on-chain {} != document {}", onchain.len(), expected_rules)),
    });
    // The stored set is aligned with the installed rules; an account with
    // none is one OZ's policies still decide, which the reviewed rules do
    // not describe.
    rows.push(Row {
        rule_id: None,
        name: "(rule set)".to_string(),
        check: "aligned",
        mismatch: (stored.len() != onchain.len()).then(|| {
            format!(
                "{} stored rules for {} installed rules",
                stored.len(),
                onchain.len()
            )
        }),
    });

    let after = read_revision(rpc, account)?;
    if after != revision {
        bail!("the account changed while it was read (revision {revision} -> {after}); rerun");
    }

    println!("revision {revision}");
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
