use super::*;
use soroban_sdk::testutils::Address as _;

const ACCOUNT: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
const CONTROLLER: &str = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";

fn b32(e: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(e, &[byte; 32])
}

fn attempt(e: &Env) -> AttemptSubject {
    AttemptSubject {
        attempt_id: 3,
        source_doc_hash: b32(e, 0x22),
        target_doc_hash: b32(e, 0x33),
        replacements_hash: b32(e, 0x44),
    }
}

fn base(e: &Env, subject: StatementSubject) -> RecoveryStatement {
    RecoveryStatement {
        network_id: b32(e, 0x01),
        account: Address::from_str(e, ACCOUNT),
        controller: Address::from_str(e, CONTROLLER),
        config: ConfigBinding {
            epoch: 7,
            config_hash: b32(e, 0x11),
        },
        timing: StatementTiming {
            delay_ledgers: 17_280,
            expiry_ledgers: 120_960,
            valid_until_ledger: 1_000_000,
        },
        subject,
    }
}

fn one_of_each(e: &Env) -> [RecoveryStatement; 6] {
    [
        base(e, StatementSubject::LostKey(attempt(e))),
        base(e, StatementSubject::Compromise(attempt(e))),
        base(
            e,
            StatementSubject::Cancel(CancelSubject {
                attempt_id: 3,
                attempt_statement: b32(e, 0x55),
            }),
        ),
        base(
            e,
            StatementSubject::Reconfigure(ConfigChange::Set(b32(e, 0x66))),
        ),
        base(e, StatementSubject::Reconfigure(ConfigChange::Remove)),
        base(
            e,
            StatementSubject::Upgrade(UpgradeSubject {
                request_id: 9,
                wasm_hash: b32(e, 0x77),
            }),
        ),
    ]
}

#[test]
fn encoded_length_is_fixed_per_action() {
    let e = Env::default();
    let lens: [u32; 6] = one_of_each(&e).map(|s| s.encode(&e).unwrap().len());
    assert_eq!(lens, [278, 278, 214, 207, 207, 214]);
    for s in one_of_each(&e) {
        assert!(s.encode(&e).unwrap().len() > STATEMENT_PREFIX_LEN);
    }
}

#[test]
fn encoding_starts_with_domain_version_and_action() {
    let e = Env::default();
    for s in one_of_each(&e) {
        let enc = s.encode(&e).unwrap();
        let mut head = [0u8; 26];
        enc.slice(0..26).copy_into_slice(&mut head);
        assert_eq!(&head[..24], STATEMENT_DOMAIN);
        assert_eq!(head[24], STATEMENT_VERSION);
        assert_eq!(head[25] as u32, s.action() as u32);
    }
}

/// The property guardian signatures and ZK proofs rely on: the digest moves
/// with every field, so evidence for one statement can't be replayed for a
/// statement that differs anywhere.
#[test]
fn every_field_changes_the_digest() {
    let e = Env::default();
    let s = base(&e, StatementSubject::LostKey(attempt(&e)));
    let d = s.digest(&e).unwrap();

    let mut variants: soroban_sdk::Vec<RecoveryStatement> = soroban_sdk::Vec::new(&e);
    let mut v = s.clone();
    v.network_id = b32(&e, 0x02);
    variants.push_back(v);
    let mut v = s.clone();
    v.account = Address::generate(&e);
    variants.push_back(v);
    let mut v = s.clone();
    v.controller = Address::generate(&e);
    variants.push_back(v);
    let mut v = s.clone();
    v.config.epoch = 8;
    variants.push_back(v);
    let mut v = s.clone();
    v.config.config_hash = b32(&e, 0x12);
    variants.push_back(v);
    let mut v = s.clone();
    v.timing.delay_ledgers += 1;
    variants.push_back(v);
    let mut v = s.clone();
    v.timing.expiry_ledgers += 1;
    variants.push_back(v);
    let mut v = s.clone();
    v.timing.valid_until_ledger += 1;
    variants.push_back(v);
    for (field, byte) in [(0, 0u8), (1, 0x23), (2, 0x34), (3, 0x45)] {
        let mut a = attempt(&e);
        match field {
            0 => a.attempt_id = 4,
            1 => a.source_doc_hash = b32(&e, byte),
            2 => a.target_doc_hash = b32(&e, byte),
            _ => a.replacements_hash = b32(&e, byte),
        }
        let mut v = s.clone();
        v.subject = StatementSubject::LostKey(a);
        variants.push_back(v);
    }
    assert_eq!(variants.len(), 12);
    for v in variants.iter() {
        assert_ne!(d, v.digest(&e).unwrap());
    }
}

#[test]
fn actions_are_domain_separated() {
    let e = Env::default();
    let digests = one_of_each(&e).map(|s| s.digest(&e).unwrap());
    for i in 0..digests.len() {
        for j in (i + 1)..digests.len() {
            assert_ne!(digests[i], digests[j], "statements {i} and {j} collide");
        }
    }
    // The pair that differs *only* in the action byte.
    let lost = base(&e, StatementSubject::LostKey(attempt(&e)));
    let comp = base(&e, StatementSubject::Compromise(attempt(&e)));
    assert_eq!(
        lost.encode(&e).unwrap().len(),
        comp.encode(&e).unwrap().len()
    );
    assert_ne!(lost.digest(&e).unwrap(), comp.digest(&e).unwrap());
}

#[test]
fn removal_is_distinct_from_setting_an_all_zero_hash() {
    let e = Env::default();
    let remove = base(&e, StatementSubject::Reconfigure(ConfigChange::Remove));
    let zero = base(
        &e,
        StatementSubject::Reconfigure(ConfigChange::Set(b32(&e, 0))),
    );
    assert_ne!(remove.digest(&e).unwrap(), zero.digest(&e).unwrap());
}

#[test]
fn cancel_binds_the_attempt_statement_not_just_its_id() {
    let e = Env::default();
    let a = base(
        &e,
        StatementSubject::Cancel(CancelSubject {
            attempt_id: 3,
            attempt_statement: b32(&e, 0x55),
        }),
    );
    let b = base(
        &e,
        StatementSubject::Cancel(CancelSubject {
            attempt_id: 3,
            attempt_statement: b32(&e, 0x56),
        }),
    );
    assert_ne!(a.digest(&e).unwrap(), b.digest(&e).unwrap());
}

#[test]
fn account_and_controller_must_be_contracts() {
    let e = Env::default();
    let g = Address::from_str(
        &e,
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
    );
    let mut s = base(&e, StatementSubject::LostKey(attempt(&e)));
    s.account = g.clone();
    assert_eq!(s.digest(&e), Err(StatementError::AccountNotContract));
    let mut s = base(&e, StatementSubject::LostKey(attempt(&e)));
    s.controller = g;
    assert_eq!(s.digest(&e), Err(StatementError::ControllerNotContract));
}

#[test]
fn provider_chosen_freshness_is_bounded_by_the_expiry_window() {
    let e = Env::default();
    for subject in [
        StatementSubject::Reconfigure(ConfigChange::Remove),
        StatementSubject::Upgrade(UpgradeSubject {
            request_id: 1,
            wasm_hash: b32(&e, 9),
        }),
    ] {
        let mut s = base(&e, subject);
        s.timing.expiry_ledgers = 100;
        s.timing.valid_until_ledger = 1_000;

        // Accepted from `valid_until - expiry` through `valid_until` inclusive.
        assert_eq!(s.check_fresh(1_000), Ok(()));
        assert_eq!(s.check_fresh(900), Ok(()));
        assert_eq!(s.check_fresh(1_001), Err(StatementError::EvidenceExpired));
        assert_eq!(
            s.check_fresh(899),
            Err(StatementError::EvidenceWindowTooLong)
        );
    }
}

#[test]
fn attempt_bound_freshness_is_only_the_controller_fixed_deadline() {
    // A cancellation's bound is the attempt's last possible live ledger,
    // which can sit further out than one expiry window; guardians who sign
    // early must still be counted.
    let e = Env::default();
    for subject in [
        StatementSubject::LostKey(attempt(&e)),
        StatementSubject::Cancel(CancelSubject {
            attempt_id: 3,
            attempt_statement: b32(&e, 0x55),
        }),
    ] {
        let mut s = base(&e, subject);
        s.timing.expiry_ledgers = 100;
        s.timing.valid_until_ledger = 1_000;
        assert_eq!(s.check_fresh(1), Ok(()));
        assert_eq!(s.check_fresh(1_000), Ok(()));
        assert_eq!(s.check_fresh(1_001), Err(StatementError::EvidenceExpired));
    }
}

#[test]
fn action_codes_are_the_wire_values() {
    assert_eq!(RecoveryAction::LostKey as u32, 1);
    assert_eq!(RecoveryAction::Compromise as u32, 2);
    assert_eq!(RecoveryAction::Cancel as u32, 3);
    assert_eq!(RecoveryAction::Reconfigure as u32, 4);
    assert_eq!(RecoveryAction::Upgrade as u32, 5);
}
