//! The write path: build one InvokeHostFunction transaction, capture the smart
//! account's auth entry from simulation, sign it with the OZ digest, then
//! re-simulate — the signed auth runs verifier + policy cross-calls, so the
//! first simulation's footprint is insufficient — and sign/send/poll.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    DecoratedSignature, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, Preconditions, ReadXdr, ScSymbol, ScVal,
    SequenceNumber, Signature, SignatureHint, SorobanAuthorizationEntry, SorobanCredentials,
    SorobanTransactionData, Transaction, TransactionEnvelope, TransactionExt,
    TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::keys::SeedKey;
use crate::rpc::{Rpc, TxStatus};
use crate::{auth, scv};

/// One contract invocation: `contract.func(args)`.
pub struct InvokeSpec {
    pub contract: String,
    pub func: String,
    pub args: Vec<ScVal>,
}

/// How the smart account's auth entry is satisfied.
pub enum AuthMode {
    /// OZ `Signer::External`: sign the rule-id-bound digest, verified by the
    /// given verifier contract.
    External { verifier: String },
    /// CAP-0071 `Signer::Delegated`: the signing key's own G-account is the
    /// delegate; the host authenticates its classic signature inside the
    /// account's single `AddressWithDelegates` entry.
    Delegated,
}

/// How to satisfy the smart account's auth entry: in which mode, selecting
/// which context rule, for which account address. The signing key is
/// `run_signed`'s single key — it signs both the auth entry and the fee
/// envelope (a future fee-payer split would add a second key here).
pub struct AuthSpec {
    pub mode: AuthMode,
    pub rule_id: u32,
    /// The smart account expected to be the (single) address credential.
    pub account: String,
}

pub struct Submitted {
    pub tx_hash: String,
    pub ledger: u32,
}

fn build_tx(source_pubkey: [u8; 32], seq: i64, spec: &InvokeSpec) -> Result<Transaction> {
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: scv::contract(&spec.contract)?,
                function_name: ScSymbol(spec.func.as_str().try_into()?),
                args: spec.args.clone().try_into()?,
            }),
            auth: Default::default(),
        }),
    };
    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_pubkey)),
        fee: 100,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into()?,
        ext: TransactionExt::V0,
    })
}

fn set_auth(tx: &mut Transaction, auth: Vec<SorobanAuthorizationEntry>) -> Result<()> {
    let ops = tx.operations.to_vec();
    let mut op = ops.into_iter().next().context("transaction has no op")?;
    let OperationBody::InvokeHostFunction(ref mut ihf) = op.body else {
        bail!("operation is not InvokeHostFunction");
    };
    ihf.auth = auth.try_into()?;
    tx.operations = vec![op].try_into()?;
    Ok(())
}

fn envelope_b64(tx: &Transaction) -> Result<String> {
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: Default::default(),
    });
    Ok(envelope.to_xdr_base64(Limits::none())?)
}

/// Sign the envelope with the fee payer. Returns (envelope base64, tx hash hex)
/// — the hash is sha256 of the TransactionSignaturePayload, i.e. the network's
/// transaction id.
fn sign_envelope(tx: &Transaction, passphrase: &str, payer: &SeedKey) -> Result<(String, String)> {
    let payload = TransactionSignaturePayload {
        network_id: stellar_xdr::Hash(auth::network_id(passphrase)),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    let hash: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none())?).into();
    let sig = payer.signing.sign(&hash).to_bytes();
    let decorated = DecoratedSignature {
        hint: SignatureHint(payer.public[28..32].try_into().expect("4 bytes")),
        signature: Signature(sig.to_vec().try_into()?),
    };
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: vec![decorated].try_into()?,
    });
    Ok((envelope.to_xdr_base64(Limits::none())?, hex::encode(hash)))
}

/// The full signed write flow. Returns `None` on `--dry-run` (stops after the
/// second simulation), `Some(Submitted)` once the network reports SUCCESS.
pub fn run_signed(
    rpc: &Rpc,
    passphrase: &str,
    payer: &SeedKey,
    auth_spec: &AuthSpec,
    spec: &InvokeSpec,
    dry_run: bool,
) -> Result<Option<Submitted>> {
    let seq = rpc
        .account_seq(&payer.public)
        .with_context(|| format!("fee payer {}", payer.account()))?;
    let mut tx = build_tx(payer.public, seq + 1, spec)?;

    let sim1 = rpc.simulate(&envelope_b64(&tx)?)?;
    if let Some(e) = sim1.error {
        bail!("simulation failed: {e}");
    }

    // Exactly one address-credential entry, and it must be the smart account.
    // Source-account credential entries (if any) pass through untouched.
    let mut address_entries = Vec::new();
    let mut source_entries = Vec::new();
    for b64 in &sim1.auth {
        let entry = SorobanAuthorizationEntry::from_xdr_base64(b64, Limits::none())?;
        match entry.credentials {
            SorobanCredentials::Address(_) => address_entries.push(entry),
            SorobanCredentials::SourceAccount => source_entries.push(entry),
            // Recording-mode simulation never runs __check_auth, so it always
            // emits plain Address credential templates — WE build the CAP-71
            // AddressWithDelegates form from them (sign_delegated_auth_entry).
            // A pre-formed CAP-71 entry coming back from simulation would mean
            // an RPC behavior change; fail loudly rather than mis-sign.
            SorobanCredentials::AddressV2(_) | SorobanCredentials::AddressWithDelegates(_) => {
                bail!("unexpected CAP-71 credential entry in simulation output")
            }
        }
    }
    if address_entries.len() != 1 {
        bail!(
            "expected exactly one address-credential auth entry, got {}",
            address_entries.len()
        );
    }
    let mut entry = address_entries.pop().expect("len checked");
    let expected_addr = scv::contract(&auth_spec.account)?;
    if let SorobanCredentials::Address(c) = &entry.credentials {
        if c.address != expected_addr {
            bail!(
                "auth entry credential {:?} is not the smart account {}",
                c.address,
                auth_spec.account
            );
        }
    }

    let expiration = sim1.latest_ledger + 120;
    match &auth_spec.mode {
        AuthMode::External { verifier } => auth::sign_auth_entry(
            &mut entry,
            passphrase,
            expiration,
            payer,
            verifier,
            auth_spec.rule_id,
        )?,
        AuthMode::Delegated => auth::sign_delegated_auth_entry(
            &mut entry,
            passphrase,
            expiration,
            payer,
            auth_spec.rule_id,
        )?,
    }

    let mut auth_entries = vec![entry];
    auth_entries.extend(source_entries);
    set_auth(&mut tx, auth_entries)?;

    // Re-simulate with the signed auth: verifier + policy cross-calls inflate
    // the footprint, so only THIS simulation's resources are trustworthy.
    let sim2 = rpc.simulate(&envelope_b64(&tx)?)?;
    if let Some(e) = sim2.error {
        bail!("re-simulation with signed auth failed: {e}");
    }
    let td = sim2
        .transaction_data
        .context("re-simulation returned no transactionData")?;
    let soroban_data = SorobanTransactionData::from_xdr_base64(&td, Limits::none())?;
    // 15% headroom over the simulated resource fee, rounded up.
    let fee = 100u64 + (sim2.min_resource_fee * 115).div_ceil(100);
    tx.fee = u32::try_from(fee).context("computed fee overflows u32")?;
    tx.ext = TransactionExt::V1(soroban_data.clone());

    if dry_run {
        println!("footprint: {:?}", soroban_data.resources.footprint);
        println!(
            "fee: {} stroops (min resource fee {})",
            tx.fee, sim2.min_resource_fee
        );
        println!("DRY RUN OK");
        return Ok(None);
    }

    let (envelope, local_hash) = sign_envelope(&tx, passphrase, payer)?;
    let hash = rpc.send(&envelope)?;
    if hash != local_hash {
        eprintln!("warning: rpc tx hash {hash} != locally computed {local_hash}");
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match rpc.get_transaction(&hash)? {
            TxStatus::Success { ledger } => {
                return Ok(Some(Submitted {
                    tx_hash: hash,
                    ledger,
                }))
            }
            TxStatus::Failed { result_xdr } => bail!("transaction {hash} FAILED: {result_xdr}"),
            TxStatus::NotFound => {
                if Instant::now() >= deadline {
                    bail!("timed out waiting for transaction {hash}");
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

/// Outcome of a read-only simulation: a value, or a *contract* error (which
/// callers like the publish preflight treat as data, not failure). `code` is
/// the `#N` from the host's `Error(Contract, #N)` rendering — callers that
/// branch on specific contract errors MUST match the code, not just the fact
/// of a trap.
pub enum ReadOutcome {
    Value(ScVal),
    ContractError { code: Option<u32>, message: String },
}

/// Extract N from the host error rendering `… Error(Contract, #N) …`.
pub fn contract_error_code(message: &str) -> Option<u32> {
    let (_, rest) = message.split_once("Error(Contract, #")?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Simulate `contract.func(args)` read-only. The source is the all-zero
/// G-account: simulation needs a well-formed envelope, not a funded account.
pub fn simulate_read(
    rpc: &Rpc,
    contract: &str,
    func: &str,
    args: Vec<ScVal>,
) -> Result<ReadOutcome> {
    let spec = InvokeSpec {
        contract: contract.to_string(),
        func: func.to_string(),
        args,
    };
    let tx = build_tx([0u8; 32], 0, &spec)?;
    let sim = rpc.simulate(&envelope_b64(&tx)?)?;
    if let Some(e) = sim.error {
        if e.contains("Error(Contract") {
            return Ok(ReadOutcome::ContractError {
                code: contract_error_code(&e),
                message: e,
            });
        }
        bail!("read simulation of {func} failed: {e}");
    }
    let xdr = sim
        .result_xdr
        .with_context(|| format!("read simulation of {func} returned no result"))?;
    Ok(ReadOutcome::Value(ScVal::from_xdr_base64(
        &xdr,
        Limits::none(),
    )?))
}
