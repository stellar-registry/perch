//! Hand-rolled JSON-RPC over ureq for the five soroban-rpc methods this tool
//! needs. Deliberately not stellar-rpc-client: five methods by hand keep
//! sdk/client version skew out of the build.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use stellar_xdr::{
    AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, Uint256,
    WriteXdr,
};

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

/// The subset of a simulateTransaction response the flows consume. `error` is
/// carried (not bailed on) because the publish preflight *expects* a contract
/// error on an unpublished name.
pub struct Simulation {
    pub error: Option<String>,
    pub transaction_data: Option<String>,
    pub min_resource_fee: u64,
    pub auth: Vec<String>,
    pub result_xdr: Option<String>,
    /// Every simulateTransaction response carries the current ledger — reuse it
    /// for signature expirations instead of a separate getLatestLedger call.
    pub latest_ledger: u32,
}

pub enum TxStatus {
    NotFound,
    Success { ledger: u32 },
    Failed { result_xdr: String },
}

impl Rpc {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(30))
                .build(),
        }
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .agent
            .post(&self.url)
            .send_json(body)
            .with_context(|| format!("rpc {method} request failed"))?
            .into_json()
            .with_context(|| format!("rpc {method} returned non-JSON"))?;
        if let Some(err) = resp.get("error") {
            bail!("rpc {method} error: {err}");
        }
        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow!("rpc {method}: response has no result"))
    }

    /// Current sequence number of a classic G-account (the fee payer).
    pub fn account_seq(&self, pubkey: &[u8; 32]) -> Result<i64> {
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*pubkey))),
        });
        let key_b64 = key.to_xdr_base64(Limits::none())?;
        let r = self.call("getLedgerEntries", json!({ "keys": [key_b64] }))?;
        let entry_xdr = r
            .get("entries")
            .and_then(Value::as_array)
            .and_then(|es| es.first())
            .and_then(|e| e.get("xdr"))
            .and_then(Value::as_str)
            .context("fee-payer account not found on network (fund it first)")?;
        match LedgerEntryData::from_xdr_base64(entry_xdr, Limits::none())? {
            LedgerEntryData::Account(a) => Ok(a.seq_num.0),
            other => bail!("getLedgerEntries: expected an account entry, got {other:?}"),
        }
    }

    pub fn simulate(&self, envelope_b64: &str) -> Result<Simulation> {
        let r = self.call(
            "simulateTransaction",
            json!({ "transaction": envelope_b64 }),
        )?;
        let first_result = r
            .get("results")
            .and_then(Value::as_array)
            .and_then(|a| a.first());
        Ok(Simulation {
            error: r.get("error").and_then(Value::as_str).map(String::from),
            transaction_data: r
                .get("transactionData")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from),
            min_resource_fee: r
                .get("minResourceFee")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            auth: first_result
                .and_then(|res| res.get("auth"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            result_xdr: first_result
                .and_then(|res| res.get("xdr"))
                .and_then(Value::as_str)
                .map(String::from),
            latest_ledger: r
                .get("latestLedger")
                .and_then(Value::as_u64)
                .map(|s| s as u32)
                .context("simulateTransaction: missing latestLedger")?,
        })
    }

    /// Returns the tx hash on acceptance; bails on immediate rejection.
    pub fn send(&self, envelope_b64: &str) -> Result<String> {
        let r = self.call("sendTransaction", json!({ "transaction": envelope_b64 }))?;
        let status = r.get("status").and_then(Value::as_str).unwrap_or("");
        if status == "ERROR" {
            bail!(
                "sendTransaction rejected: {}",
                r.get("errorResultXdr")
                    .and_then(Value::as_str)
                    .unwrap_or("(no errorResultXdr)")
            );
        }
        r.get("hash")
            .and_then(Value::as_str)
            .map(String::from)
            .context("sendTransaction: missing hash")
    }

    pub fn get_transaction(&self, hash_hex: &str) -> Result<TxStatus> {
        let r = self.call("getTransaction", json!({ "hash": hash_hex }))?;
        match r.get("status").and_then(Value::as_str) {
            Some("SUCCESS") => Ok(TxStatus::Success {
                ledger: r.get("ledger").and_then(Value::as_u64).unwrap_or(0) as u32,
            }),
            Some("FAILED") => Ok(TxStatus::Failed {
                result_xdr: r
                    .get("resultXdr")
                    .and_then(Value::as_str)
                    .unwrap_or("(no resultXdr)")
                    .to_string(),
            }),
            _ => Ok(TxStatus::NotFound),
        }
    }
}
