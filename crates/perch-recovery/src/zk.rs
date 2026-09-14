//! Generic ZK verifier adapter: the statement a proof must bind, and the
//! cross-contract interface any verifier implementation satisfies.
//!
//! This module deliberately carries **no circuit**. Per the authoritative
//! decision record §5.4, proof-system portability is an interface goal, not
//! a requirement to ship or validate a specific circuit in this stage — see
//! `docs/recovery/controller-governance.md`'s "ZK adapter scope" section.
//! What this module fixes is the *statement* a proof must be over: every
//! recovery-specific public fact, bound the same way regardless of which
//! proof system a given verifier implements.

use crate::types::Action;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, Vec};

/// A domain-separation tag, so a statement can never be confused with a hash
/// computed for an unrelated purpose (`doc_hash`, `config_hash`, ...) even if
/// the byte lengths happened to coincide.
const STATEMENT_DOMAIN: &str = "perch-recovery-statement-v1";

fn action_tag(action: &Action) -> u8 {
    match action {
        Action::LostKey => 0,
        Action::Compromise => 1,
        Action::Cancel => 2,
        Action::Reconfigure => 3,
    }
}

/// The statement a recovery proof must be over: network, account, and
/// controller identity; the action being authorized; the enrolled
/// configuration's own content hash (so a proof cannot outlive a
/// reconfiguration — see `contract.rs`'s reconfigure-evidence handling); the
/// target document's hash for `LostKey`/`Compromise` (zero for `Cancel`,
/// which identifies its attempt by id instead, per §2.2); the attempt's
/// nonce; and the enrolled timelock. Binding all of this in one hash means a
/// proof for one account/action/config/target/attempt can never be replayed
/// for another — every field the follow-up review §5.3 names for a proposal
/// commitment is present.
#[allow(clippy::too_many_arguments)]
pub fn statement(
    e: &Env,
    account: &Address,
    controller: &Address,
    action: &Action,
    config_hash: &BytesN<32>,
    target_doc_hash: Option<&BytesN<32>>,
    attempt_id: u64,
    delay_ledgers: u32,
) -> BytesN<32> {
    let mut buf = Bytes::from_slice(e, STATEMENT_DOMAIN.as_bytes());
    buf.append(&Bytes::from_slice(e, &e.ledger().network_id().to_array()));
    buf.append(&account.to_xdr(e));
    buf.append(&controller.to_xdr(e));
    buf.push_back(action_tag(action));
    buf.append(&Bytes::from_slice(e, &config_hash.to_array()));
    match target_doc_hash {
        Some(h) => buf.append(&Bytes::from_slice(e, &h.to_array())),
        None => buf.append(&Bytes::from_slice(e, &[0u8; 32])),
    }
    buf.append(&Bytes::from_slice(e, &attempt_id.to_be_bytes()));
    buf.append(&Bytes::from_slice(e, &delay_ledgers.to_be_bytes()));
    e.crypto().sha256(&buf).to_bytes()
}

/// Cross-contract interface a ZK verifier instance implements. Deliberately
/// minimal and proof-system-agnostic: the controller computes `statement`
/// itself from its own stored attempt/config (never trusting a
/// caller-supplied statement — see `contract.rs`'s `submit_zk_proof`), and
/// treats `verify_proof`'s result as the only fact it needs.
///
/// `nullifier` is the prover-revealed nullifier the circuit derives from its
/// secret; the controller tracks spent nullifiers itself (globally, across
/// accounts — see `storage.rs`), so a verifier need not. `pool`, present only
/// for schemes that prove membership of a secret in a set, is opaque to the
/// controller: it is passed through unchanged from the enrolled
/// `ZkVerifierConfig.pool`, and interpreting it is entirely the verifier's
/// concern.
#[allow(unused)]
#[soroban_sdk::contractclient(name = "ZkVerifierClient")]
pub trait ZkVerifierInterface {
    fn verify_proof(
        e: &Env,
        statement: BytesN<32>,
        nullifier: BytesN<32>,
        proof: Bytes,
        pool: Vec<Address>,
    ) -> bool;
}
