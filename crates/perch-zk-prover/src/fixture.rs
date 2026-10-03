//! The committed proof fixtures under `testdata/zk/`: their on-disk format,
//! and how to rebuild the state each one was proved against.
//!
//! Each fixture directory holds `fixture.json` (a [`Fixture`]), `proof` (the
//! raw UltraHonk proof), and `public_inputs` (`root || nullifier ||
//! statement_hash`). `perch-zk-fixtures generate` writes them; contract tests
//! replay `enrollments` into a real pool registered at `pool_id`, rebuild the
//! [`RecoveryStatement`] from `statement`, and verify `proof`.

use crate::{commitment, leaf, parse32, Bytes32, Inputs, Tree};
use perch_recovery_interface::statement::{
    AttemptSubject, CancelSubject, ConfigBinding, ConfigChange, RecoveryStatement,
    StatementSubject, StatementTiming, UpgradeSubject,
};
use perch_zk_primitives::ZERO_HASHES;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{FromXdr, ToXdr};
use soroban_sdk::{Address, Bytes, BytesN, Env};
use std::path::Path;

pub const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";

pub fn sha256(data: &[u8]) -> Bytes32 {
    Sha256::digest(data).into()
}

/// A fixture constant: `sha256("perch-zk-fixture/<label>")`.
pub fn tag(label: &str) -> Bytes32 {
    sha256(format!("perch-zk-fixture/{label}").as_bytes())
}

/// A canonical field element derived from `label` (top three bits cleared,
/// so below `2^253 < r`). Used for secrets.
pub fn field_tag(label: &str) -> Bytes32 {
    let mut b = tag(label);
    b[0] &= 0x1f;
    b
}

/// The contract address with raw id `id`: `ScAddress::Contract(id)` as XDR,
/// decoded by the host.
pub fn address(e: &Env, id: &Bytes32) -> Address {
    let mut xdr = [0u8; 40];
    xdr[..8].copy_from_slice(&[0, 0, 0, 18, 0, 0, 0, 1]);
    xdr[8..].copy_from_slice(id);
    let addr = Address::from_xdr(e, &Bytes::from_array(e, &xdr)).expect("contract address xdr");
    debug_assert_eq!(addr.clone().to_xdr(e).len(), 40);
    addr
}

pub fn h32(s: &str) -> Bytes32 {
    parse32(s).unwrap_or_else(|| panic!("bad 32-byte hex {s}"))
}

fn b(e: &Env, s: &str) -> BytesN<32> {
    BytesN::from_array(e, &h32(s))
}

/// One enrollment, in insertion order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Enrollment {
    pub account_id: String,
    pub enrollment_id: String,
    pub commitment: String,
}

/// [`StatementSubject`], serializable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Subject {
    LostKey {
        attempt_id: u64,
        source_doc_hash: String,
        target_doc_hash: String,
        replacements_hash: String,
    },
    Compromise {
        attempt_id: u64,
        source_doc_hash: String,
        target_doc_hash: String,
        replacements_hash: String,
    },
    Cancel {
        attempt_id: u64,
        attempt_statement: String,
    },
    ReconfigureSet {
        config_hash: String,
    },
    ReconfigureRemove,
    Upgrade {
        request_id: u64,
        wasm_hash: String,
    },
}

/// [`RecoveryStatement`], serializable, with raw contract ids.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Statement {
    pub network_passphrase: String,
    pub account_id: String,
    pub controller_id: String,
    pub epoch: u64,
    pub config_hash: String,
    pub delay_ledgers: u32,
    pub expiry_ledgers: u32,
    pub valid_until_ledger: u32,
    pub subject: Subject,
}

impl Statement {
    pub fn to_statement(&self, e: &Env) -> RecoveryStatement {
        let attempt = |attempt_id: &u64, src: &str, tgt: &str, rep: &str| AttemptSubject {
            attempt_id: *attempt_id,
            source_doc_hash: b(e, src),
            target_doc_hash: b(e, tgt),
            replacements_hash: b(e, rep),
        };
        let subject = match &self.subject {
            Subject::LostKey {
                attempt_id,
                source_doc_hash,
                target_doc_hash,
                replacements_hash,
            } => StatementSubject::LostKey(attempt(
                attempt_id,
                source_doc_hash,
                target_doc_hash,
                replacements_hash,
            )),
            Subject::Compromise {
                attempt_id,
                source_doc_hash,
                target_doc_hash,
                replacements_hash,
            } => StatementSubject::Compromise(attempt(
                attempt_id,
                source_doc_hash,
                target_doc_hash,
                replacements_hash,
            )),
            Subject::Cancel {
                attempt_id,
                attempt_statement,
            } => StatementSubject::Cancel(CancelSubject {
                attempt_id: *attempt_id,
                attempt_statement: b(e, attempt_statement),
            }),
            Subject::ReconfigureSet { config_hash } => {
                StatementSubject::Reconfigure(ConfigChange::Set(b(e, config_hash)))
            }
            Subject::ReconfigureRemove => StatementSubject::Reconfigure(ConfigChange::Remove),
            Subject::Upgrade {
                request_id,
                wasm_hash,
            } => StatementSubject::Upgrade(UpgradeSubject {
                request_id: *request_id,
                wasm_hash: b(e, wasm_hash),
            }),
        };
        RecoveryStatement {
            network_id: BytesN::from_array(e, &sha256(self.network_passphrase.as_bytes())),
            account: address(e, &h32(&self.account_id)),
            controller: address(e, &h32(&self.controller_id)),
            config: ConfigBinding {
                epoch: self.epoch,
                config_hash: b(e, &self.config_hash),
            },
            timing: StatementTiming {
                delay_ledgers: self.delay_ledgers,
                expiry_ledgers: self.expiry_ledgers,
                valid_until_ledger: self.valid_until_ledger,
            },
            subject,
        }
    }

    /// `RecoveryStatement::digest`.
    pub fn digest(&self, e: &Env) -> Bytes32 {
        self.to_statement(e)
            .digest(e)
            .expect("fixture statements use contract addresses")
            .to_array()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    pub description: String,
    pub pool_id: String,
    pub account_id: String,
    pub enrollment_id: String,
    pub statement: Statement,
    /// `statement`'s digest, as the controller computes it.
    pub digest: String,
    pub tree_id: u32,
    /// Empty slots in front of `enrollments` in tree `tree_id`: the pool's
    /// frontier starts as all-empty subtrees at this size. Non-zero only for
    /// the depth-32 boundary scenario, which real inserts cannot reach.
    pub synthetic_prefix: u64,
    pub enrollments: Vec<Enrollment>,
    pub leaf_index: u64,
    pub secret: String,
    pub root: String,
    pub nullifier: String,
    pub statement_hash: String,
}

/// A fixture with its proof artifacts.
pub struct Loaded {
    pub fixture: Fixture,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

impl Loaded {
    pub fn read(dir: &Path) -> std::io::Result<Self> {
        let fixture = serde_json::from_slice(&std::fs::read(dir.join("fixture.json"))?)
            .map_err(std::io::Error::other)?;
        Ok(Self {
            fixture,
            proof: std::fs::read(dir.join("proof"))?,
            public_inputs: std::fs::read(dir.join("public_inputs"))?,
        })
    }
}

impl Fixture {
    /// The proof inputs this fixture describes, recomputed from its private
    /// fields and enrollment history.
    pub fn inputs(&self, e: &Env) -> Inputs {
        let leaves: Vec<Bytes32> = self
            .enrollments
            .iter()
            .map(|x| {
                crate::leaf_of_commitment(
                    e,
                    &h32(&x.account_id),
                    &h32(&x.enrollment_id),
                    &h32(&x.commitment),
                )
            })
            .collect();
        let siblings = if self.synthetic_prefix == 0 {
            Tree::new(e, 32, &leaves).path(self.leaf_index)
        } else {
            // Every earlier slot is empty and the leaf is the right child at
            // every level: each sibling is that level's empty subtree.
            assert_eq!(leaves.len(), 1);
            assert_eq!(self.leaf_index, self.synthetic_prefix);
            ZERO_HASHES[..32].to_vec()
        };
        Inputs::new(
            e,
            h32(&self.secret),
            h32(&self.account_id),
            h32(&self.enrollment_id),
            h32(&self.digest),
            self.leaf_index,
            siblings,
        )
    }

    /// The enrollment this fixture's secret made.
    pub fn own_enrollment(&self, e: &Env) -> Enrollment {
        Enrollment {
            account_id: self.account_id.clone(),
            enrollment_id: self.enrollment_id.clone(),
            commitment: crate::hex(&commitment(e, &h32(&self.secret))),
        }
    }

    /// The leaf this fixture's secret is stored as.
    pub fn leaf(&self, e: &Env) -> Bytes32 {
        leaf(
            e,
            &h32(&self.account_id),
            &h32(&self.enrollment_id),
            &h32(&self.secret),
        )
    }
}
