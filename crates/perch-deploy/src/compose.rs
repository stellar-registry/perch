//! `compose`: PolicyDoc → the JSON worklist of `add_context_rule` calls.
//! The self-admin rule is *not* emitted as an apply entry — the account
//! constructor already installed it as rule 0, and re-adding would duplicate
//! the rule and shift every subsequent id. It lands in `genesis_rule` so
//! `verify` can still check it on chain.

use anyhow::{anyhow, bail, Context, Result};
use perch_compile::{CapSpec, CompileConfig, LoweredRule, ScopeSpec, SignerSpec};
use perch_program::InstallParams;
use serde::{Deserialize, Serialize};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{BytesN, Env};
use stellar_xdr::{Limits, ReadXdr, ScVal, WriteXdr};

#[derive(Serialize, Deserialize)]
pub struct ComposeOutput {
    pub doc_hash: String,
    pub account: String,
    pub interpreter: String,
    pub interpreter_wasm_hash: String,
    /// The single self-admin rule, satisfied by the account constructor as
    /// rule 0; `verify` checks it, `install-rule` refuses it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub genesis_rule: Option<RuleEntry>,
    pub apply: Vec<RuleEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct RuleEntry {
    pub expected_rule_id: u32,
    pub name: String,
    pub context_type: ContextTypeJson,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub valid_until: Option<u32>,
    pub signers: Vec<SignerJson>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub install: Option<InstallJson>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cap: Option<CapJson>,
}

/// Every rule in this pipeline scopes to `CallContract` (self-admin resolves
/// to the account's own address at compose time).
#[derive(Serialize, Deserialize)]
pub struct ContextTypeJson {
    pub call_contract: String,
}

/// Mirrors [`SignerSpec`]: externally-tagged JSON so the reviewable output is
/// explicit about how each signer authenticates.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerJson {
    External { verifier: String, key_hex: String },
    Delegated { address: String },
}

/// The interpreter's InstallParams, in both machine (base64 ScVal XDR — what
/// `install-rule` submits) and reviewable (serde_json ScVal) form.
#[derive(Serialize, Deserialize)]
pub struct InstallJson {
    pub scval_base64: String,
    pub scval_json: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct CapJson {
    pub token: Option<String>,
    /// i128 as a decimal string — JSON numbers cannot carry it.
    pub limit: String,
    pub period_ledgers: u32,
}

pub fn parse_hash32(hex64: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex64.trim()).context("hash is not hex")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("hash must be 32 bytes (64 hex chars), got {}", bytes.len()))
}

/// The InstallParams contracttype ScVal — `ToXdr` bytes ARE the ScVal XDR.
pub fn install_scval(env: &Env, install: &InstallParams) -> Result<ScVal> {
    let bytes: Vec<u8> = install.clone().to_xdr(env).iter().collect();
    Ok(ScVal::from_xdr(bytes, Limits::none())?)
}

fn rule_entry(
    env: &Env,
    expected_rule_id: u32,
    rule: &LoweredRule,
    call_contract: &str,
) -> Result<RuleEntry> {
    let install = match &rule.install {
        None => None,
        Some(ip) => {
            let scval = install_scval(env, ip)?;
            Some(InstallJson {
                scval_base64: scval.to_xdr_base64(Limits::none())?,
                scval_json: serde_json::to_value(&scval)?,
            })
        }
    };
    Ok(RuleEntry {
        expected_rule_id,
        name: rule.name.clone(),
        context_type: ContextTypeJson {
            call_contract: call_contract.to_string(),
        },
        valid_until: rule.valid_until,
        signers: rule
            .signers
            .iter()
            .map(|s| match s {
                SignerSpec::External { verifier, key_hex } => SignerJson::External {
                    verifier: verifier.clone(),
                    key_hex: key_hex.clone(),
                },
                SignerSpec::Delegated { address } => SignerJson::Delegated {
                    address: address.clone(),
                },
            })
            .collect(),
        install,
        cap: rule.cap.as_ref().map(|c: &CapSpec| CapJson {
            token: c.token.clone(),
            limit: c.limit.to_string(),
            period_ledgers: c.period_ledgers,
        }),
    })
}

pub fn compose(
    env: &Env,
    doc_json: &str,
    account: &str,
    interpreter: &str,
    interpreter_wasm_hash_hex: &str,
) -> Result<ComposeOutput> {
    let doc = perch_ir::from_json(doc_json).map_err(|e| anyhow!("doc parse failed: {e:?}"))?;
    perch_ir::validate(&doc).map_err(|errs| anyhow!("doc validation failed: {errs:?}"))?;

    let wasm_hash = parse_hash32(interpreter_wasm_hash_hex)?;
    let cfg = CompileConfig {
        interpreter_wasm_hash: BytesN::from_array(env, &wasm_hash),
    };
    let plan = perch_compile::compile(env, &doc, &cfg).map_err(|e| anyhow!("compile: {e:?}"))?;
    // Fail-closed gate: never emit attachments for a plan that has diverged
    // from the reviewed document.
    perch_compile::verify_plan_matches_doc(env, &doc, &plan)
        .map_err(|e| anyhow!("plan/doc divergence: {e:?}"))?;

    let mut genesis_rule = None;
    let mut apply = Vec::new();
    for rule in &plan.rules {
        match &rule.scope {
            ScopeSpec::SelfAdmin => {
                // The constructor installs rule 0 policy-free; a self-admin rule
                // carrying a program or cap could never be genesis-satisfied.
                if rule.install.is_some() || rule.cap.is_some() {
                    bail!(
                        "self-admin rule '{}' has constraints; the constructor cannot satisfy it",
                        rule.name
                    );
                }
                if genesis_rule.is_some() {
                    bail!("constructor installs exactly one self-admin rule; document has more");
                }
                genesis_rule = Some(rule_entry(env, 0, rule, account)?);
            }
            ScopeSpec::Contract(addr) => {
                let id = apply.len() as u32 + 1;
                apply.push(rule_entry(env, id, rule, addr)?);
            }
        }
    }

    Ok(ComposeOutput {
        doc_hash: perch_ir::doc_hash_hex(&doc),
        account: account.to_string(),
        interpreter: interpreter.to_string(),
        interpreter_wasm_hash: interpreter_wasm_hash_hex.to_string(),
        genesis_rule,
        apply,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_DOC_HASH: &str =
        "38c7ae56e602adbd318d08b92c664106fde77f3f08b7457ed8203f0d2d27ab0d";
    const DUMMY: &str = "CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL";

    fn fixture() -> String {
        let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../testdata/ci-publish.json");
        std::fs::read_to_string(p).expect("read ci-publish.json")
    }

    #[test]
    fn compose_skips_self_admin_and_freezes_doc_hash() {
        let env = Env::default();
        let out = compose(&env, &fixture(), DUMMY, DUMMY, &"ab".repeat(32)).unwrap();

        assert_eq!(out.doc_hash, FIXTURE_DOC_HASH);
        // admin-root is genesis-satisfied, never an apply entry.
        let genesis = out.genesis_rule.as_ref().expect("one genesis rule");
        assert_eq!(genesis.name, "admin-root");
        assert_eq!(genesis.expected_rule_id, 0);
        assert_eq!(genesis.context_type.call_contract, DUMMY);
        assert!(genesis.install.is_none());

        assert_eq!(out.apply.len(), 1);
        let ci = &out.apply[0];
        assert_eq!(ci.name, "ci-publish");
        assert_eq!(ci.expected_rule_id, 1);
        // not-after-ledger 55000000 lowers to the inclusive valid_until 54999999.
        assert_eq!(ci.valid_until, Some(54_999_999));
        assert!(ci.install.is_some());
        assert_eq!(ci.signers.len(), 1);
    }

    #[test]
    fn install_params_round_trip_through_serde_json() {
        let env = Env::default();
        let doc = perch_ir::from_json(&fixture()).unwrap();
        let cfg = CompileConfig {
            interpreter_wasm_hash: BytesN::from_array(&env, &[0xab; 32]),
        };
        let plan = perch_compile::compile(&env, &doc, &cfg).unwrap();
        let install = plan.rules[1].install.as_ref().expect("ci-publish installs");

        let original: Vec<u8> = install.clone().to_xdr(&env).iter().collect();
        let scval = ScVal::from_xdr(original.clone(), Limits::none()).unwrap();
        let json = serde_json::to_value(&scval).unwrap();
        let back: ScVal = serde_json::from_value(json).unwrap();
        // Fully qualified: soroban's env-based `ToXdr` also matches `.to_xdr`
        // on ScVal under testutils.
        let reserialized = WriteXdr::to_xdr(&back, Limits::none()).unwrap();
        assert_eq!(reserialized, original);
    }
}
