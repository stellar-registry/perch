//! One network connection: build an invocation, simulate it in recording
//! mode, sign every address-credential entry the simulation asks for (a
//! passkey through an account rule, an account's recovery rule, or a
//! G-account's own key), re-simulate under enforcing authorization, submit,
//! and record what it cost.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::Signer as _;
use perch_deploy::keys::SeedKey;
use perch_deploy::rpc::{Rpc, TxStatus};
use perch_deploy::tx::{
    build_tx, contract_error_code, envelope_b64, set_auth, sign_envelope, InvokeSpec,
};
use perch_deploy::{auth, scv};
use perch_testkit::passkey::{sig_data, SoftPasskey};
use serde::Serialize;
use sha2::Digest as _;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{map, vec, Address, Bytes, Env, IntoVal, TryFromVal, Val};
use stellar_accounts::smart_account::{AuthPayload, Signer};
use stellar_xdr::{
    AccountId, Limits, PublicKey, ReadXdr, ScAddress, ScVal, SorobanAuthorizationEntry,
    SorobanCredentials, SorobanTransactionData, TransactionExt, TransactionResult, Uint256,
};

/// Who satisfies one address-credential entry.
pub enum Auth<'a> {
    /// The account authorizes through `rule`, signed by its passkey.
    Passkey {
        account: &'a str,
        webauthn: &'a str,
        key: &'a SoftPasskey,
        rule: u32,
    },
    /// Anyone selects the account's zero-signer recovery rule.
    RecoveryRule { account: &'a str, rule: u32 },
    /// A G-account signs its own entry.
    Account(&'a SeedKey),
}

/// One measured step of the exercise.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Step {
    pub scenario: String,
    pub label: String,
    /// `ok`, or `refused` for a step that must fail.
    pub outcome: String,
    pub tx_hash: Option<String>,
    pub ledger: Option<u32>,
    pub error: Option<String>,
    pub error_code: Option<u32>,
    /// The contract error an account's `__check_auth` failed with, from the
    /// host's diagnostics ("failed account authentication with error").
    pub auth_error_code: Option<u32>,
    /// Which simulation refused: `recording` (the contract refused before
    /// any signature mattered) or `enforcing` (with every entry signed).
    pub refused_in: Option<String>,
    pub instructions: Option<u64>,
    pub mem_bytes: Option<u64>,
    pub read_entries: Option<u32>,
    pub write_entries: Option<u32>,
    pub disk_read_bytes: Option<u32>,
    pub write_bytes: Option<u32>,
    pub tx_size_bytes: Option<usize>,
    pub resource_fee_stroops: Option<i64>,
    pub fee_charged_stroops: Option<i64>,
    pub latency_ms: Option<u128>,
}

/// Which simulation produced a refusal, carried as a prefix on its message.
const RECORDING: &str = "[recording] ";
const ENFORCING: &str = "[enforcing] ";

pub struct Receipt {
    pub value: ScVal,
}

/// Where a transaction's auth entries come from.
pub enum Entries {
    /// A recording-mode simulation's templates.
    Recorded,
    /// One entry for this address over exactly the root call.
    Root(String),
}

pub struct Chain {
    pub rpc: Rpc,
    pub passphrase: String,
    /// Host-side encoding, hashing, and the statement digest.
    pub env: Env,
    pub payer: SeedKey,
    pub steps: RefCell<Vec<Step>>,
    pub scenario: RefCell<String>,
    nonce: std::cell::Cell<u64>,
}

impl Chain {
    pub fn new(rpc_url: &str, passphrase: &str, payer: SeedKey) -> Self {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let network_id = auth::network_id(passphrase);
        env.ledger().with_mut(|l| l.network_id = network_id);
        Self {
            rpc: Rpc::new(rpc_url),
            passphrase: passphrase.to_string(),
            env,
            payer,
            steps: RefCell::new(Vec::new()),
            scenario: RefCell::new(String::new()),
            nonce: std::cell::Cell::new(0),
        }
    }

    pub fn begin_scenario(&self, name: &str) {
        eprintln!("\n=== {name}");
        *self.scenario.borrow_mut() = name.to_string();
    }

    // --- encoding --------------------------------------------------------

    pub fn sc<T: IntoVal<Env, Val>>(&self, v: T) -> ScVal {
        let val: Val = v.into_val(&self.env);
        ScVal::try_from_val(&self.env, &val).expect("ScVal")
    }

    pub fn decode<T: TryFromVal<Env, Val>>(&self, v: &ScVal) -> Result<T> {
        let val = Val::try_from_val(&self.env, v).map_err(|e| anyhow!("decode Val: {e:?}"))?;
        T::try_from_val(&self.env, &val).map_err(|_| anyhow!("decode {v:?}"))
    }

    pub fn address(&self, strkey: &str) -> Address {
        Address::from_str(&self.env, strkey)
    }

    // --- reads -----------------------------------------------------------

    pub fn read(&self, contract: &str, func: &str, args: Vec<ScVal>) -> Result<ScVal> {
        match perch_deploy::tx::simulate_read(&self.rpc, contract, func, args)? {
            perch_deploy::tx::ReadOutcome::Value(v) => Ok(v),
            perch_deploy::tx::ReadOutcome::ContractError { message, .. } => {
                bail!("{func} refused: {}", first_line(&message))
            }
        }
    }

    pub fn read_as<T: TryFromVal<Env, Val>>(
        &self,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
    ) -> Result<T> {
        self.decode(&self.read(contract, func, args)?)
    }

    pub fn latest_ledger(&self) -> Result<u32> {
        self.rpc.latest_ledger()
    }

    pub fn wait_for_ledger(&self, ledger: u32) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let now = self.latest_ledger()?;
            if now >= ledger {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for ledger {ledger} (at {now})");
            }
            eprintln!("  waiting for ledger {ledger} (at {now})");
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    // --- writes ----------------------------------------------------------

    /// Simulate and sign. `Err` carries the refusal message: a contract or
    /// auth error in either simulation.
    fn prepare(
        &self,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
        auths: &[Auth<'_>],
        entries: Entries,
    ) -> Result<
        std::result::Result<(stellar_xdr::Transaction, perch_deploy::rpc::Simulation), String>,
    > {
        let spec = InvokeSpec {
            contract: contract.to_string(),
            func: func.to_string(),
            args: args.clone(),
        };
        let seq = self.rpc.account_seq(&self.payer.public)?;
        let mut tx = build_tx(self.payer.public, seq + 1, &spec)?;
        let templates = match entries {
            Entries::Recorded => {
                let sim1 = self.rpc.simulate(&envelope_b64(&tx)?)?;
                if let Some(e) = sim1.error {
                    return Ok(Err(format!("{RECORDING}{e}")));
                }
                sim1.auth
                    .iter()
                    .map(|b64| SorobanAuthorizationEntry::from_xdr_base64(b64, Limits::none()))
                    .collect::<std::result::Result<Vec<_>, _>>()?
            }
            Entries::Root(address) => std::vec![self.root_entry(&address, contract, func, args)?],
        };
        let expiration = self.latest_ledger()? + 100;
        let mut entries = Vec::new();
        for mut entry in templates {
            if matches!(entry.credentials, SorobanCredentials::Address(_)) {
                self.sign_entry(&mut entry, expiration, auths)?;
            }
            entries.push(entry);
        }
        set_auth(&mut tx, entries)?;
        let sim2 = self.rpc.simulate(&envelope_b64(&tx)?)?;
        if let Some(e) = sim2.error {
            return Ok(Err(format!("{ENFORCING}{e}")));
        }
        let td = sim2
            .transaction_data
            .clone()
            .context("simulation returned no transactionData")?;
        let data = SorobanTransactionData::from_xdr_base64(&td, Limits::none())?;
        let fee = 100u64 + (sim2.min_resource_fee * 125).div_ceil(100);
        tx.fee = u32::try_from(fee).context("fee overflows u32")?;
        tx.ext = TransactionExt::V1(data);
        Ok(Ok((tx, sim2)))
    }

    /// `address`'s authorization of exactly the root call, with a fresh
    /// nonce: what a client builds itself when recording-mode simulation
    /// cannot produce the entry (a recovery completion only succeeds once the
    /// controller's `enforce` has run inside `__check_auth`, which recording
    /// mode skips).
    fn root_entry(
        &self,
        address: &str,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
    ) -> Result<SorobanAuthorizationEntry> {
        use stellar_xdr::{
            InvokeContractArgs, ScSymbol, SorobanAddressCredentials, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation,
        };
        let n = self.nonce.get() + 1;
        self.nonce.set(n);
        let nonce = i64::from_be_bytes(
            sha2::Sha256::digest(format!("{}/{n}", self.payer.account()).as_bytes())[..8]
                .try_into()
                .expect("8 bytes"),
        ) & i64::MAX;
        Ok(SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: scv::contract(address)?,
                nonce,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: scv::contract(contract)?,
                    function_name: ScSymbol(func.try_into()?),
                    args: args.try_into()?,
                }),
                sub_invocations: Default::default(),
            },
        })
    }

    fn sign_entry(
        &self,
        entry: &mut SorobanAuthorizationEntry,
        expiration: u32,
        auths: &[Auth<'_>],
    ) -> Result<()> {
        let invocation = entry.root_invocation.clone();
        let SorobanCredentials::Address(creds) = &mut entry.credentials else {
            unreachable!("checked by the caller");
        };
        creds.signature_expiration_ledger = expiration;
        let payload =
            auth::signature_payload(&self.passphrase, creds.nonce, expiration, &invocation)?;
        let signer = auths
            .iter()
            .find(|a| auth_address(a).is_ok_and(|addr| addr == creds.address))
            .with_context(|| format!("no signer for auth entry {:?}", creds.address))?;
        creds.signature = match signer {
            Auth::Passkey {
                webauthn,
                key,
                rule,
                ..
            } => {
                let digest = auth::oz_auth_digest(&payload, &[*rule])?;
                let signer = Signer::External(
                    self.address(webauthn),
                    Bytes::from_slice(&self.env, &key.key_data()),
                );
                self.sc(AuthPayload {
                    signers: map![
                        &self.env,
                        (signer, sig_data(&self.env, &key.assert(&digest)))
                    ],
                    context_rule_ids: vec![&self.env, *rule],
                })
            }
            Auth::RecoveryRule { rule, .. } => self.sc(AuthPayload {
                signers: soroban_sdk::Map::new(&self.env),
                context_rule_ids: vec![&self.env, *rule],
            }),
            Auth::Account(key) => {
                let sig = key.signing.sign(&payload).to_bytes();
                auth::account_signature_scval(&key.public, &sig)?
            }
        };
        Ok(())
    }

    fn record(&self, mut step: Step) {
        step.scenario = self.scenario.borrow().clone();
        let fee = step
            .fee_charged_stroops
            .map(|f| format!(" fee {f}"))
            .unwrap_or_default();
        match step.outcome.as_str() {
            "ok" => eprintln!(
                "  ok       {}: {} insns{fee} ({})",
                step.label,
                step.instructions.unwrap_or(0),
                step.tx_hash.as_deref().unwrap_or("-")
            ),
            _ => eprintln!(
                "  refused  {}: {}",
                step.label,
                step.error.as_deref().unwrap_or("-")
            ),
        }
        self.steps.borrow_mut().push(step);
    }

    /// Submit `contract.func(args)` and wait for success.
    pub fn call(
        &self,
        label: &str,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
        auths: &[Auth<'_>],
    ) -> Result<Receipt> {
        self.call_with(label, contract, func, args, auths, Entries::Recorded)
    }

    pub fn call_with(
        &self,
        label: &str,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
        auths: &[Auth<'_>],
        entries: Entries,
    ) -> Result<Receipt> {
        let (tx, sim) = self
            .prepare(contract, func, args, auths, entries)?
            .map_err(|e| anyhow!("{label}: refused in simulation: {}", first_line(&e)))?;
        let (envelope, hash) = sign_envelope(&tx, &self.passphrase, &self.payer)?;
        let started = Instant::now();
        let sent = self.rpc.send(&envelope)?;
        if sent != hash {
            eprintln!("warning: rpc tx hash {sent} != local {hash}");
        }
        let deadline = started + Duration::from_secs(90);
        let (ledger, result_xdr) = loop {
            match self.rpc.get_transaction(&sent)? {
                TxStatus::Success { ledger, result_xdr } => break (ledger, result_xdr),
                TxStatus::Failed { result_xdr } => bail!("{label}: tx {sent} FAILED: {result_xdr}"),
                TxStatus::NotFound if Instant::now() > deadline => {
                    bail!("{label}: timed out waiting for {sent}")
                }
                TxStatus::NotFound => std::thread::sleep(Duration::from_millis(1500)),
            }
        };
        let latency_ms = started.elapsed().as_millis();
        let fee_charged = TransactionResult::from_xdr_base64(&result_xdr, Limits::none())
            .map(|r| r.fee_charged)
            .ok();
        let mut step = resources(&tx, &sim);
        step.label = label.to_string();
        step.outcome = "ok".into();
        step.tx_hash = Some(sent);
        step.ledger = Some(ledger);
        step.fee_charged_stroops = fee_charged;
        step.latency_ms = Some(latency_ms);
        step.tx_size_bytes = Some(envelope_len(&envelope));
        self.record(step);
        let value = match &sim.result_xdr {
            Some(x) => ScVal::from_xdr_base64(x, Limits::none())?,
            None => ScVal::Void,
        };
        Ok(Receipt { value })
    }

    /// `contract.func(args)` must be refused, under enforcing authorization
    /// with the given signers. With `code`, the refusal must carry exactly
    /// that contract error. Nothing is submitted.
    pub fn refused(
        &self,
        label: &str,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
        auths: &[Auth<'_>],
        code: Option<u32>,
    ) -> Result<()> {
        self.refused_with(label, contract, func, args, auths, code, Entries::Recorded)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn refused_with(
        &self,
        label: &str,
        contract: &str,
        func: &str,
        args: Vec<ScVal>,
        auths: &[Auth<'_>],
        code: Option<u32>,
        entries: Entries,
    ) -> Result<()> {
        match self.prepare(contract, func, args, auths, entries)? {
            Ok(_) => bail!("{label}: expected a refusal, but it simulates successfully"),
            Err(e) => {
                let (refused_in, e) = match e.strip_prefix(RECORDING) {
                    Some(rest) => ("recording", rest.to_string()),
                    None => (
                        "enforcing",
                        e.strip_prefix(ENFORCING).unwrap_or(&e).to_string(),
                    ),
                };
                if std::env::var_os("PERCH_TESTNET_VERBOSE").is_some() {
                    eprintln!("    [{refused_in}] {e}");
                }
                let got = contract_error_code(&e);
                if let Some(want) = code {
                    if got != Some(want) {
                        bail!(
                            "{label}: refused with {got:?}, expected #{want}: {}",
                            first_line(&e)
                        );
                    }
                }
                self.record(Step {
                    label: label.to_string(),
                    outcome: "refused".into(),
                    error: Some(first_line(&e)),
                    error_code: got,
                    auth_error_code: auth_error_code(&e),
                    refused_in: Some(refused_in.to_string()),
                    ..Step::default()
                });
                Ok(())
            }
        }
    }

    /// Fund a G-account through friendbot.
    pub fn friendbot(&self, account: &str) -> Result<()> {
        ureq::get(&format!("https://friendbot.stellar.org?addr={account}"))
            .call()
            .with_context(|| format!("friendbot {account}"))?;
        Ok(())
    }
}

fn auth_address(a: &Auth<'_>) -> Result<ScAddress> {
    match a {
        Auth::Passkey { account, .. } | Auth::RecoveryRule { account, .. } => {
            scv::contract(account)
        }
        Auth::Account(key) => Ok(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(key.public)),
        ))),
    }
}

fn resources(tx: &stellar_xdr::Transaction, sim: &perch_deploy::rpc::Simulation) -> Step {
    let TransactionExt::V1(data) = &tx.ext else {
        return Step::default();
    };
    let r = &data.resources;
    Step {
        instructions: sim.cpu_insns.or(Some(u64::from(r.instructions))),
        mem_bytes: sim.mem_bytes,
        read_entries: Some((r.footprint.read_only.len() + r.footprint.read_write.len()) as u32),
        write_entries: Some(r.footprint.read_write.len() as u32),
        disk_read_bytes: Some(r.disk_read_bytes),
        write_bytes: Some(r.write_bytes),
        resource_fee_stroops: Some(data.resource_fee),
        ..Step::default()
    }
}

fn envelope_len(b64: &str) -> usize {
    b64.len() / 4 * 3 - b64.chars().rev().take_while(|c| *c == '=').count()
}

pub fn first_line(s: &str) -> String {
    let s = s.trim();
    let line = s.lines().next().unwrap_or(s);
    // The interesting part of a host error is its `Error(...)` code.
    match s.find("Error(") {
        Some(i) if !line.contains("Error(") => {
            let rest = &s[i..];
            rest[..rest.find(')').map_or(rest.len(), |j| j + 1)].to_string()
        }
        _ => line.chars().take(240).collect(),
    }
}

/// The code in the host's "failed account authentication with error",
/// account, Error(Contract, #N) diagnostic.
pub fn auth_error_code(message: &str) -> Option<u32> {
    let line = message
        .lines()
        .find(|l| l.contains("failed account authentication with error"))?;
    contract_error_code(line)
}
