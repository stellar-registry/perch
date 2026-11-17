//! `compose`: PolicyDoc → a reviewable JSON expansion of the rules the
//! document lowers to on one account. The account applies the document
//! directly (`apply_doc` — see the `apply` subcommand), so this output is a
//! review artifact and `verify`'s expectation file, not an install worklist.
//! Each rule carries the rule-eval rule the account stores for it and
//! decides its authorizations with (`rule_eval::lower` of the document's
//! model, as the account's `rule_set()` holds it). The self-admin rule lands
//! in `genesis_rule` (the constructor satisfies it at genesis; `apply_doc`
//! re-creates it on every apply); rule ids here are doc-order and advisory —
//! actual ids are assigned at apply time, and `verify` matches by name.

use anyhow::{anyhow, bail, Context, Result};
use perch_ir::{Principals, Scope, SignerMethod};
use perch_rule_eval::convert::Addresses;
use perch_rule_eval::StoredRule;
use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Env};
use stellar_xdr::{Limits, ReadXdr, ScVal, WriteXdr};

#[derive(Serialize, Deserialize)]
pub struct ComposeOutput {
    pub doc_hash: String,
    pub account: String,
    /// The single self-admin rule, satisfied by the account constructor at
    /// genesis and re-created by every `apply_doc`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub genesis_rule: Option<RuleEntry>,
    pub apply: Vec<RuleEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct RuleEntry {
    /// Doc-order index — advisory only. Actual ids are assigned at apply
    /// time; `verify` matches rules by name and reports the real ids.
    pub expected_rule_id: u32,
    pub name: String,
    pub context_type: ContextTypeJson,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<u32>,
    pub signers: Vec<SignerJson>,
    /// The rule-eval rule the account stores for this rule.
    pub rule: StoredRuleJson,
}

/// Every rule in this pipeline scopes to `CallContract` (self-admin resolves
/// to the account's own address at compose time).
#[derive(Serialize, Deserialize)]
pub struct ContextTypeJson {
    pub call_contract: String,
}

/// Externally-tagged JSON so the reviewable output is explicit about how
/// each signer authenticates.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerJson {
    External { verifier: String, key_hex: String },
    Delegated { address: String },
}

/// A `perch_rule_eval::StoredRule`, in both machine (base64 ScVal XDR — what
/// `verify` compares with the account's `rule_set()` entry) and reviewable
/// (serde_json ScVal) form.
#[derive(Serialize, Deserialize)]
pub struct StoredRuleJson {
    pub scval_base64: String,
    pub scval_json: serde_json::Value,
}

pub fn parse_hash32(hex64: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex64.trim()).context("hash is not hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("hash must be 32 bytes (64 hex chars), got {}", bytes.len()))
}

/// The StoredRule contracttype ScVal — `ToXdr` bytes ARE the ScVal XDR.
pub fn stored_scval(env: &Env, rule: &StoredRule) -> Result<ScVal> {
    let bytes: Vec<u8> = rule.clone().to_xdr(env).iter().collect();
    Ok(ScVal::from_xdr(bytes, Limits::none())?)
}

fn rule_entry(
    env: &Env,
    expected_rule_id: u32,
    doc: &perch_ir::PolicyDoc,
    rule: &perch_ir::Rule,
    stored: &StoredRule,
    call_contract: &str,
) -> Result<RuleEntry> {
    let ids = match &rule.principals {
        Principals::All(p) => &p.signers,
        Principals::Threshold(p) => &p.signers,
        Principals::SelfAuthenticating(_) => bail!("rule '{}' is self-authenticating", rule.name),
    };
    let mut signers = Vec::new();
    for id in ids {
        let decl = doc
            .signers
            .iter()
            .find(|s| &s.id == id)
            .ok_or_else(|| anyhow!("rule '{}' names no declared signer '{id}'", rule.name))?;
        signers.push(match &decl.method {
            SignerMethod::External { verifier, key } => SignerJson::External {
                verifier: verifier.clone(),
                key_hex: key.clone(),
            },
            SignerMethod::Delegated { address } => SignerJson::Delegated {
                address: address.clone(),
            },
        });
    }
    let scval = stored_scval(env, stored)?;
    Ok(RuleEntry {
        expected_rule_id,
        name: rule.name.clone(),
        context_type: ContextTypeJson {
            call_contract: call_contract.to_string(),
        },
        valid_until: stored.valid_until,
        signers,
        rule: StoredRuleJson {
            scval_base64: scval.to_xdr_base64(Limits::none())?,
            scval_json: serde_json::to_value(&scval)?,
        },
    })
}

pub fn compose(env: &Env, doc_json: &str, account: &str) -> Result<ComposeOutput> {
    let doc = perch_ir::from_json(doc_json).map_err(|e| anyhow!("doc parse failed: {e:?}"))?;
    perch_ir::validate(&doc).map_err(|errs| anyhow!("doc validation failed: {errs:?}"))?;
    crate::scv::contract(account).context("--account")?;

    // The account's own conversion: the document's model, read through
    // soroban-facade, lowered by rule-eval, and each rule converted back to
    // the host form the account stores.
    let model = perch_rule_eval::model_of(env, &doc).map_err(|e| anyhow!("model: {e:?}"))?;
    let mut known = Addresses::default();
    let me = known
        .read(env, &Address::from_str(env, account))
        .context("the account's address")?;
    let model = perch_rule_eval::doc_of_in(env, &model, &mut known)
        .context("soroban-facade cannot read the document's model")?;
    let lowered = rule_eval::lower(&model, &me);

    let mut genesis_rule = None;
    let mut apply = Vec::new();
    for (rule, lowered) in doc.rules.iter().zip(&lowered) {
        let stored = StoredRule::from_rule_in(env, lowered, &known)
            .ok_or_else(|| anyhow!("rule '{}' has no stored form", rule.name))?;
        match &rule.scope {
            Scope::SelfAdmin(_) => {
                // The constructor installs rule 0 asking every signer for
                // every function; a self-admin rule with a constraint could
                // never be genesis-satisfied.
                let constraint_free = matches!(rule.principals, Principals::All(_))
                    && rule.functions.is_none()
                    && rule.args.is_none()
                    && rule.cap.is_none();
                if !constraint_free {
                    bail!(
                        "self-admin rule '{}' has constraints; the constructor cannot satisfy it",
                        rule.name
                    );
                }
                if genesis_rule.is_some() {
                    bail!("constructor installs exactly one self-admin rule; document has more");
                }
                genesis_rule = Some(rule_entry(env, 0, &doc, rule, &stored, account)?);
            }
            Scope::Contract(c) => {
                let id = apply.len() as u32 + 1;
                apply.push(rule_entry(env, id, &doc, rule, &stored, &c.address)?);
            }
        }
    }

    Ok(ComposeOutput {
        doc_hash: perch_ir::doc_hash_hex(&doc),
        account: account.to_string(),
        genesis_rule,
        apply,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_DOC_HASH: &str =
        "27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98";
    const DUMMY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

    fn fixture() -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/ci-publish.json");
        std::fs::read_to_string(p).expect("read ci-publish.json")
    }

    fn stored(entry: &RuleEntry) -> StoredRule {
        use soroban_sdk::xdr::FromXdr;
        let env = Env::default();
        let scval = ScVal::from_xdr_base64(&entry.rule.scval_base64, Limits::none()).unwrap();
        let xdr = soroban_sdk::Bytes::from_slice(
            &env,
            &WriteXdr::to_xdr(&scval, Limits::none()).unwrap(),
        );
        StoredRule::from_xdr(&env, &xdr).unwrap()
    }

    #[test]
    fn compose_skips_self_admin_and_freezes_doc_hash() {
        let env = Env::default();
        let out = compose(&env, &fixture(), DUMMY).unwrap();

        assert_eq!(out.doc_hash, FIXTURE_DOC_HASH);
        // admin is genesis-satisfied, never an apply entry.
        let genesis = out.genesis_rule.as_ref().expect("one genesis rule");
        assert_eq!(genesis.name, "admin");
        assert_eq!(genesis.expected_rule_id, 0);
        assert_eq!(genesis.context_type.call_contract, DUMMY);
        let admin = stored(genesis);
        assert!(admin.conds.is_empty() && admin.cap.is_empty());
        assert_eq!(admin.threshold, admin.signers.len());

        assert_eq!(out.apply.len(), 1);
        let ci = &out.apply[0];
        assert_eq!(ci.name, "ci-publish");
        assert_eq!(ci.expected_rule_id, 1);
        // not-after-ledger 55000000 lowers to the inclusive valid_until 54999999.
        assert_eq!(ci.valid_until, Some(54_999_999));
        assert_eq!(ci.signers.len(), 1);
        let rule = stored(ci);
        assert_eq!(rule.valid_until, Some(54_999_999));
        assert_eq!(rule.threshold, 1);
    }

    /// The composed rule is what the account stores: rule-eval's lowering of
    /// the document's model on the account, through the same conversions.
    #[test]
    fn composed_rules_are_the_lowering_of_the_model() {
        let env = Env::default();
        let out = compose(&env, &fixture(), DUMMY).unwrap();
        let doc = perch_ir::from_json(&fixture()).unwrap();
        let model = perch_rule_eval::model_of(&env, &doc).unwrap();
        let me = perch_rule_eval::convert::address(&env, &Address::from_str(&env, DUMMY)).unwrap();
        let lowered = rule_eval::lower(&perch_rule_eval::doc_of(&env, &model).unwrap(), &me);
        let entries: Vec<&RuleEntry> = out.genesis_rule.iter().chain(&out.apply).collect();
        assert_eq!(entries.len(), lowered.len());
        for (entry, rule) in entries.into_iter().zip(&lowered) {
            assert_eq!(
                stored(entry),
                StoredRule::from_rule(&env, rule).unwrap(),
                "{}",
                entry.name
            );
        }
    }

    #[test]
    fn stored_rule_round_trips_through_serde_json() {
        let env = Env::default();
        let out = compose(&env, &fixture(), DUMMY).unwrap();
        let entry = &out.apply[0];
        let scval = ScVal::from_xdr_base64(&entry.rule.scval_base64, Limits::none()).unwrap();
        let original = WriteXdr::to_xdr(&scval, Limits::none()).unwrap();
        let back: ScVal = serde_json::from_value(entry.rule.scval_json.clone()).unwrap();
        // Fully qualified: soroban's env-based `ToXdr` also matches `.to_xdr`
        // on ScVal under testutils.
        let reserialized = WriteXdr::to_xdr(&back, Limits::none()).unwrap();
        assert_eq!(reserialized, original);
    }
}
