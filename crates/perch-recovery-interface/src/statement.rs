//! The one recovery statement: what every piece of recovery evidence — a
//! guardian's signature or a ZK proof, for any action — is bound to.
//!
//! A statement names the network, the account, the controller instance, the
//! enrolled configuration (by epoch and content hash), the timing terms, and
//! an action-specific subject. Its canonical encoding
//! ([`RecoveryStatement::encode`]) is fixed-width per action and specified
//! byte-for-byte in `docs/recovery/statement.md`; its digest
//! ([`RecoveryStatement::digest`]) is what a guardian authorizes
//! (`require_auth_for_args((digest,))`) and what the ZK circuit binds (see
//! [`crate::zk::zk_statement_fields`]). Both factors therefore commit to the
//! identical statement, which is how `Combined` mode guarantees the proof and
//! the guardian quorum approved the same proposal.
//!
//! Timing is in native ledger-sequence counts throughout. There is no
//! seconds field and no seconds-to-ledgers conversion anywhere in the
//! statement (see `docs/recovery/spec.md` §4).

use crate::encode::contract_id;
use crate::zk::ZkEvidence;
use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};
use soroban_sdk_tools::scerr;

/// Domain tag every encoding starts with. A statement digest can never
/// collide with a document hash, a configuration hash, a credential
/// fingerprint, or an OZ auth digest, because none of those preimages start
/// with these bytes.
pub const STATEMENT_DOMAIN: &[u8; 24] = b"perch/recovery/statement";

/// Encoding version. Version 1 was `perch-recovery`'s pre-spec
/// `zk::statement` (`"perch-recovery-statement-v1"`, a different prefix,
/// no epoch, no freshness bound); nothing produced under it verifies under
/// this one.
pub const STATEMENT_VERSION: u8 = 2;

/// The action domain a statement authorizes. Evidence for one action never
/// satisfies another: the action code is the encoding's 26th byte and selects
/// the subject layout, so two statements that differ only in action have
/// different digests (and different encoded lengths for most pairs).
///
/// The numeric codes are part of the wire format.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RecoveryAction {
    /// Lost-key recovery: replace designated credentials in an agreed
    /// snapshot of the current document.
    LostKey = 1,
    /// Compromise recovery: restore the enrolled baseline, with designated
    /// credentials replaced.
    Compromise = 2,
    /// Cancel one identified attempt.
    Cancel = 3,
    /// Change or remove the enrolled recovery configuration (the evidence a
    /// `Protected` account needs in addition to owner authorization).
    Reconfigure = 4,
    /// Approve one scheduled account upgrade (the evidence a `Protected`
    /// account needs in addition to owner authorization).
    Upgrade = 5,
}

/// Everything encoding a statement or its parts can refuse.
#[scerr]
pub enum StatementError {
    /// `account` is not a contract (`C...`) address.
    AccountNotContract,
    /// `controller` is not a contract (`C...`) address.
    ControllerNotContract,
    /// A credential names an address shape the recovery stack does not
    /// accept (muxed, claimable-balance, liquidity-pool, ...).
    UnsupportedAddress,
    /// A replacement set's signer ids are not strictly ascending (sorted,
    /// no duplicates), so it has no single canonical encoding.
    ReplacementsNotCanonical,
    /// A replacement set replaces nothing.
    EmptyReplacements,
    /// The current ledger is past the statement's `valid_until_ledger`.
    EvidenceExpired,
    /// `valid_until_ledger` reaches further past the current ledger than the
    /// enrolled `expiry_ledgers` allows.
    EvidenceWindowTooLong,
}

/// The enrolled configuration a statement is evaluated against.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigBinding {
    /// The controller's per-account configuration epoch. It increments on
    /// every enrollment, reconfiguration, removal, and completed recovery, so
    /// evidence produced under one epoch is dead under every later one.
    pub epoch: u64,
    /// `sha256` of the canonical JSON of the enrolled document's `recovery`
    /// section (`docs/recovery/spec.md` §3.2). Binds
    /// the whole configuration: profile, mode, guardians, quorum, ZK
    /// adapter/pool/enrollment, controller, baseline, replaceable signer
    /// ids, and timing.
    pub config_hash: BytesN<32>,
}

/// Timing terms, all in ledger-sequence units.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementTiming {
    /// The enrolled `delay-ledgers`: ledgers between an attempt becoming
    /// authorized and becoming completable.
    pub delay_ledgers: u32,
    /// The enrolled `expiry-ledgers`: the evidence window for a collecting
    /// attempt, the completion window for an authorized one, and the upper
    /// bound on how far ahead `valid_until_ledger` may reach.
    pub expiry_ledgers: u32,
    /// The last ledger sequence (inclusive) at which this evidence may be
    /// accepted. For `LostKey`/`Compromise` it is the attempt's evidence
    /// deadline, fixed by the controller; for every other action the
    /// evidence provider chooses it, within `expiry_ledgers` of submission.
    pub valid_until_ledger: u32,
}

/// The subject of a `LostKey` or `Compromise` attempt.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptSubject {
    /// The controller-assigned, per-account, never-reused attempt id.
    pub attempt_id: u64,
    /// `LostKey`: the canonical hash of the account's applied document when
    /// the attempt began (the agreed snapshot). `Compromise`: the enrolled
    /// baseline's canonical hash.
    pub source_doc_hash: BytesN<32>,
    /// The canonical hash of the target document, derived on-chain from
    /// the source and the replacement set — never caller-chosen.
    pub target_doc_hash: BytesN<32>,
    /// [`crate::credential::ReplacementSet::hash`] of the declared
    /// replacements.
    pub replacements_hash: BytesN<32>,
}

/// The subject of a `Cancel` statement.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelSubject {
    /// The attempt being cancelled.
    pub attempt_id: u64,
    /// That attempt's own initiation statement digest, so cancellation
    /// evidence names exactly one proposal, not just an id.
    pub attempt_statement: BytesN<32>,
}

/// What a `Reconfigure` statement changes the enrolled configuration to.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigChange {
    /// Remove recovery from the account.
    Remove,
    /// Replace the configuration with the one whose
    /// [`ConfigBinding::config_hash`] is this value (which may name a
    /// different controller instance).
    Set(BytesN<32>),
}

/// The subject of an `Upgrade` statement.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpgradeSubject {
    /// The account's per-account, never-reused upgrade request id.
    pub request_id: u64,
    /// The exact Wasm hash the account would run after the upgrade.
    pub wasm_hash: BytesN<32>,
}

/// The action-specific part of a statement. The variant determines
/// [`RecoveryStatement::action`]; there is no separate action field that
/// could disagree with it.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementSubject {
    LostKey(AttemptSubject),
    Compromise(AttemptSubject),
    Cancel(CancelSubject),
    Reconfigure(ConfigChange),
    Upgrade(UpgradeSubject),
}

/// The one recovery statement. See the module docs.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryStatement {
    /// The network id (`sha256` of the network passphrase), as
    /// `Env::ledger().network_id()` returns it.
    pub network_id: BytesN<32>,
    /// The recovering account. Must be a contract address.
    pub account: Address,
    /// The controller instance evaluating the evidence (for `Reconfigure`,
    /// the currently adopted one, even when the change adopts another).
    /// Must be a contract address.
    pub controller: Address,
    pub config: ConfigBinding,
    pub timing: StatementTiming,
    pub subject: StatementSubject,
}

/// Evidence submitted alongside a statement the controller reconstructs
/// itself (the caller never supplies the statement). Which parts are
/// required depends on the enrolled mode — see `docs/recovery/spec.md` §5.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryEvidence {
    /// For actions whose freshness bound the evidence provider chooses
    /// (`Cancel`, `Reconfigure`, `Upgrade`): the `valid_until_ledger` every
    /// guardian signed and the proof binds. Ignored for `LostKey`/
    /// `Compromise`, whose bound is the attempt's evidence deadline.
    pub valid_until_ledger: u32,
    /// Guardians, each of whom must authorize
    /// `require_auth_for_args((digest,))` for this exact statement in the
    /// same transaction. Duplicates and non-members are not counted.
    pub guardians: Vec<Address>,
    /// Zero or one ZK proof. A `Vec` rather than an `Option` because
    /// `#[contracttype]` cannot derive `Option<CustomStruct>` fields.
    pub zk: Vec<ZkEvidence>,
}

/// Fixed prefix length: domain (24) + version (1) + action (1) + network
/// (32) + account (32) + controller (32) + epoch (8) + config hash (32) +
/// delay (4) + expiry (4) + valid-until (4).
pub const STATEMENT_PREFIX_LEN: u32 = 174;

impl RecoveryStatement {
    /// The action domain, derived from the subject.
    pub fn action(&self) -> RecoveryAction {
        match &self.subject {
            StatementSubject::LostKey(_) => RecoveryAction::LostKey,
            StatementSubject::Compromise(_) => RecoveryAction::Compromise,
            StatementSubject::Cancel(_) => RecoveryAction::Cancel,
            StatementSubject::Reconfigure(_) => RecoveryAction::Reconfigure,
            StatementSubject::Upgrade(_) => RecoveryAction::Upgrade,
        }
    }

    /// The canonical encoding (`docs/recovery/statement.md`). Every field is
    /// fixed-width and big-endian, and the action byte precedes and selects
    /// the subject layout, so the encoding is injective without length
    /// prefixes.
    pub fn encode(&self, e: &Env) -> Result<Bytes, StatementError> {
        let account = contract_id(e, &self.account).ok_or(StatementError::AccountNotContract)?;
        let controller =
            contract_id(e, &self.controller).ok_or(StatementError::ControllerNotContract)?;

        let mut out = Bytes::from_slice(e, STATEMENT_DOMAIN);
        out.push_back(STATEMENT_VERSION);
        out.push_back(self.action() as u32 as u8);
        out.extend_from_array(&self.network_id.to_array());
        out.extend_from_array(&account);
        out.extend_from_array(&controller);
        out.extend_from_array(&self.config.epoch.to_be_bytes());
        out.extend_from_array(&self.config.config_hash.to_array());
        out.extend_from_array(&self.timing.delay_ledgers.to_be_bytes());
        out.extend_from_array(&self.timing.expiry_ledgers.to_be_bytes());
        out.extend_from_array(&self.timing.valid_until_ledger.to_be_bytes());

        match &self.subject {
            StatementSubject::LostKey(s) | StatementSubject::Compromise(s) => {
                out.extend_from_array(&s.attempt_id.to_be_bytes());
                out.extend_from_array(&s.source_doc_hash.to_array());
                out.extend_from_array(&s.target_doc_hash.to_array());
                out.extend_from_array(&s.replacements_hash.to_array());
            }
            StatementSubject::Cancel(s) => {
                out.extend_from_array(&s.attempt_id.to_be_bytes());
                out.extend_from_array(&s.attempt_statement.to_array());
            }
            StatementSubject::Reconfigure(ConfigChange::Remove) => {
                out.push_back(0);
                out.extend_from_array(&[0u8; 32]);
            }
            StatementSubject::Reconfigure(ConfigChange::Set(h)) => {
                out.push_back(1);
                out.extend_from_array(&h.to_array());
            }
            StatementSubject::Upgrade(s) => {
                out.extend_from_array(&s.request_id.to_be_bytes());
                out.extend_from_array(&s.wasm_hash.to_array());
            }
        }
        Ok(out)
    }

    /// `sha256(encode())`: what guardians authorize and the circuit binds.
    pub fn digest(&self, e: &Env) -> Result<BytesN<32>, StatementError> {
        Ok(e.crypto().sha256(&self.encode(e)?).to_bytes())
    }

    /// Freshness (`docs/recovery/spec.md` §4): evidence
    /// is acceptable at ledger `now` only while `now <= valid_until_ledger`,
    /// and only if `valid_until_ledger` reaches no more than
    /// `expiry_ledgers` past `now` — so an evidence provider cannot mint a
    /// standing approval that outlives the account's own recovery window.
    pub fn check_fresh(&self, now: u32) -> Result<(), StatementError> {
        let until = self.timing.valid_until_ledger;
        if now > until {
            return Err(StatementError::EvidenceExpired);
        }
        if until - now > self.timing.expiry_ledgers {
            return Err(StatementError::EvidenceWindowTooLong);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
