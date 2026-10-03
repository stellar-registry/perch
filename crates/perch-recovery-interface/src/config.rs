//! The compiled recovery configuration (`docs/recovery/spec.md` §3): the
//! wire form of a document's `recovery` member that the doc compiler emits,
//! the account passes to its controller's `rcv_sync`, and the controller
//! stores.
//!
//! It lives here, not in `perch-doc-compiler`, so the controller, the
//! account, and the compiler all agree on one definition without any of them
//! depending on another deployable's crate.

use crate::statement::{ConfigBinding, StatementTiming};
use crate::zk::ZkBinding;
use soroban_sdk::{contracttype, Address, BytesN, String, Vec};

/// Who may change the recovery configuration, and whether an authorized
/// attempt freezes ordinary activity (spec §2, §9).
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryProfile {
    /// Owner authorization alone reconfigures; activity continues while an
    /// attempt is authorized; the owner can always cancel.
    Loss,
    /// Reconfiguration and upgrades also need the enrolled condition; an
    /// authorized attempt freezes the account.
    Protected,
}

/// The guardian factor.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledGuardianSet {
    /// Guardian addresses (`G...` or `C...`), never the account itself.
    pub guardians: Vec<Address>,
    /// `1 <= quorum <= guardians.len()`.
    pub quorum: u32,
}

/// The ZK factor (spec §3.1, §3.4).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledZkFactor {
    /// The constructorless ZK adapter the controller calls.
    pub adapter: Address,
    /// `sha256` of the adapter's verification key; must equal the adapter's
    /// `circuit_id()`.
    pub circuit_id: BytesN<32>,
    /// The membership pool roots are accepted from.
    pub pool: Address,
    /// The current credential's id, bound into its leaf and nullifier.
    pub enrollment_id: BytesN<32>,
    /// The current credential's inner commitment, `Poseidon2(DOM_LEAF,
    /// secret)`, from which the account inserts the leaf.
    pub commitment: BytesN<32>,
}

impl CompiledZkFactor {
    /// What the adapter checks a proof against.
    pub fn binding(&self) -> ZkBinding {
        ZkBinding {
            pool: self.pool.clone(),
            enrollment_id: self.enrollment_id.clone(),
            circuit_id: self.circuit_id.clone(),
        }
    }
}

/// Which factors a statement needs.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompiledRecoveryMode {
    GuardianOnly(CompiledGuardianSet),
    ZkOnly(CompiledZkFactor),
    Combined(CompiledGuardianSet, CompiledZkFactor),
}

/// A compiled `recovery` member.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRecoveryConfig {
    /// `sha256("perch/recovery/config" || canonical JSON of the recovery
    /// member)`, computed by the doc compiler (spec §3.2). Configuration
    /// identity: two compiled configurations with the same `config_hash` are
    /// the same configuration.
    pub config_hash: BytesN<32>,
    pub profile: RecoveryProfile,
    pub mode: CompiledRecoveryMode,
    /// The adopted controller instance.
    pub controller: Address,
    /// The enrolled baseline's canonical document hash, if compromise
    /// recovery is enrolled.
    pub baseline: Option<BytesN<32>>,
    /// Signer ids (not credential fingerprints) a recovery may replace, so
    /// rotating a key does not change the configuration (#92).
    pub replaceable: Vec<String>,
    pub delay_ledgers: u32,
    pub expiry_ledgers: u32,
    pub max_cancels: u32,
}

impl CompiledRecoveryConfig {
    /// The guardian factor, if the mode has one.
    pub fn guardians(&self) -> Option<&CompiledGuardianSet> {
        match &self.mode {
            CompiledRecoveryMode::GuardianOnly(g) | CompiledRecoveryMode::Combined(g, _) => Some(g),
            CompiledRecoveryMode::ZkOnly(_) => None,
        }
    }

    /// The ZK factor, if the mode has one.
    pub fn zk(&self) -> Option<&CompiledZkFactor> {
        match &self.mode {
            CompiledRecoveryMode::ZkOnly(z) | CompiledRecoveryMode::Combined(_, z) => Some(z),
            CompiledRecoveryMode::GuardianOnly(_) => None,
        }
    }

    /// The configuration a statement binds at `epoch`.
    pub fn binding(&self, epoch: u64) -> ConfigBinding {
        ConfigBinding {
            epoch,
            config_hash: self.config_hash.clone(),
        }
    }

    /// The statement timing terms for evidence valid through
    /// `valid_until_ledger`.
    pub fn timing(&self, valid_until_ledger: u32) -> StatementTiming {
        StatementTiming {
            delay_ledgers: self.delay_ledgers,
            expiry_ledgers: self.expiry_ledgers,
            valid_until_ledger,
        }
    }
}

/// Spec §3.4: across one `apply_doc`, the ZK factor either stays entirely
/// unchanged or carries a new enrollment id. Adding or removing the factor
/// is always allowed here (whether the change itself is authorized is
/// §10's question).
pub fn zk_factor_transition_ok(
    old: Option<&CompiledZkFactor>,
    new: Option<&CompiledZkFactor>,
) -> bool {
    match (old, new) {
        (Some(a), Some(b)) => a == b || a.enrollment_id != b.enrollment_id,
        _ => true,
    }
}

/// Spec §14.2: the leaf the account must insert when applying `new` over
/// `old`, i.e. exactly when the enrollment id changes. Returns the factor
/// whose `(pool, enrollment_id, commitment)` to insert.
pub fn leaf_to_insert<'a>(
    old: Option<&CompiledZkFactor>,
    new: Option<&'a CompiledZkFactor>,
) -> Option<&'a CompiledZkFactor> {
    let new = new?;
    match old {
        Some(o) if o.enrollment_id == new.enrollment_id => None,
        _ => Some(new),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Env};

    fn factor(e: &Env, pool: &Address, id: u8, commitment: u8) -> CompiledZkFactor {
        CompiledZkFactor {
            adapter: Address::generate(e),
            circuit_id: BytesN::from_array(e, &[0xc1; 32]),
            pool: pool.clone(),
            enrollment_id: BytesN::from_array(e, &[id; 32]),
            commitment: BytesN::from_array(e, &[commitment; 32]),
        }
    }

    #[test]
    fn zk_factor_changes_need_a_new_enrollment_id() {
        let e = Env::default();
        let pool = Address::generate(&e);
        let a = factor(&e, &pool, 1, 1);
        let mut same_id_new_pool = a.clone();
        same_id_new_pool.pool = Address::generate(&e);
        let mut same_id_new_commitment = a.clone();
        same_id_new_commitment.commitment = BytesN::from_array(&e, &[2; 32]);
        let rotated = factor(&e, &Address::generate(&e), 2, 2);

        assert!(zk_factor_transition_ok(Some(&a), Some(&a)));
        assert!(zk_factor_transition_ok(Some(&a), Some(&rotated)));
        assert!(!zk_factor_transition_ok(Some(&a), Some(&same_id_new_pool)));
        assert!(!zk_factor_transition_ok(
            Some(&a),
            Some(&same_id_new_commitment)
        ));
        assert!(zk_factor_transition_ok(None, Some(&a)));
        assert!(zk_factor_transition_ok(Some(&a), None));
    }

    #[test]
    fn a_leaf_is_inserted_exactly_when_the_enrollment_id_changes() {
        let e = Env::default();
        let pool = Address::generate(&e);
        let a = factor(&e, &pool, 1, 1);
        let b = factor(&e, &pool, 2, 2);
        assert_eq!(leaf_to_insert(None, Some(&a)), Some(&a));
        assert_eq!(leaf_to_insert(Some(&a), Some(&b)), Some(&b));
        assert_eq!(leaf_to_insert(Some(&a), Some(&a)), None);
        assert_eq!(leaf_to_insert(Some(&a), None), None);
        assert_eq!(leaf_to_insert(None, None), None);
    }

    #[test]
    fn accessors_follow_the_mode() {
        let e = Env::default();
        let g = CompiledGuardianSet {
            guardians: vec![&e, Address::generate(&e)],
            quorum: 1,
        };
        let z = factor(&e, &Address::generate(&e), 1, 1);
        let mut cfg = CompiledRecoveryConfig {
            config_hash: BytesN::from_array(&e, &[9; 32]),
            profile: RecoveryProfile::Protected,
            mode: CompiledRecoveryMode::GuardianOnly(g.clone()),
            controller: Address::generate(&e),
            baseline: None,
            replaceable: vec![&e, String::from_str(&e, "admin")],
            delay_ledgers: 10,
            expiry_ledgers: 20,
            max_cancels: 3,
        };
        assert_eq!(cfg.guardians(), Some(&g));
        assert_eq!(cfg.zk(), None);
        cfg.mode = CompiledRecoveryMode::ZkOnly(z.clone());
        assert_eq!(cfg.guardians(), None);
        assert_eq!(cfg.zk().map(|z| z.binding()), Some(z.binding()));
        cfg.mode = CompiledRecoveryMode::Combined(g.clone(), z.clone());
        assert!(cfg.guardians().is_some() && cfg.zk().is_some());

        let b = cfg.binding(4);
        assert_eq!((b.epoch, b.config_hash), (4, cfg.config_hash.clone()));
        let t = cfg.timing(99);
        assert_eq!(
            (t.delay_ledgers, t.expiry_ledgers, t.valid_until_ledger),
            (10, 20, 99)
        );
    }
}
