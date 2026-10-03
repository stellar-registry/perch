//! Recovery-configuration schema tests: the `ci-publish-recovery{,-combined}`
//! golden fixtures (canonical form + doc_hash, mirrored in
//! `packages/perch-js/test/parity.test.ts`), and semantic validation of
//! [`perch_ir::RecoveryConfig`]. See `CANONICAL.md` and `docs/recovery/`.

mod common;

use common::{assert_accepts, assert_rejects, base_doc};
use perch_ir::recovery::{derive_target, DeriveAction, DeriveError, Replacement, ZkRotation};
use perch_ir::{
    canonical_json, doc_hash_hex, from_json, recovery_canonical_json, validate, BaselineCommitment,
    GuardianSet, RecoveryConfig, RecoveryMode, RecoveryProfile, SignerMethod, ValidationError,
    ZkFactor,
};
use std::fs;
use std::path::PathBuf;

fn testdata(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name)
}

fn read(name: &str) -> String {
    fs::read_to_string(testdata(name)).unwrap_or_else(|e| panic!("reading testdata/{name}: {e}"))
}

const RECOVERY_HASH_HEX: &str = "d348912f20a15189922d12a06e00a68498bef4f16c8c7e2eeaa919dae9d060b0";
const RECOVERY_COMBINED_HASH_HEX: &str =
    "91ca693d888c0f77ad354e92a6a91cc316e202448b65637e2c59ecc3edf6f63c";

#[test]
fn guardian_only_fixture_parses_validates_and_matches_committed_files() {
    let doc = from_json(&read("ci-publish-recovery.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    let recovery = doc.recovery.as_ref().expect("fixture must enroll recovery");
    assert_eq!(recovery.profile, RecoveryProfile::Protected);
    assert!(matches!(recovery.mode, RecoveryMode::GuardianOnly(_)));
    assert!(recovery.baseline.is_some());
    assert_eq!(recovery.replaceable, ["admin".to_string()]);

    let committed = read("ci-publish-recovery.canonical.json");
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));

    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish-recovery.doc-hash").trim());
    assert_eq!(hash, RECOVERY_HASH_HEX);

    // Round-trip: the canonical form parses back to the same document.
    let reparsed = from_json(&canonical_json(&doc)).expect("canonical form must parse");
    assert_eq!(doc, reparsed);
}

#[test]
fn combined_mode_fixture_parses_validates_and_matches_committed_files() {
    let doc = from_json(&read("ci-publish-recovery-combined.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    let recovery = doc.recovery.as_ref().expect("fixture must enroll recovery");
    assert_eq!(recovery.profile, RecoveryProfile::Loss);
    assert!(matches!(recovery.mode, RecoveryMode::Combined(_, _)));
    // Loss profile with no baseline: lost-key recovery only.
    assert!(recovery.baseline.is_none());

    let committed = read("ci-publish-recovery-combined.canonical.json");
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));

    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish-recovery-combined.doc-hash").trim());
    assert_eq!(hash, RECOVERY_COMBINED_HASH_HEX);
}

/// A minimal, valid guardian-only recovery config referencing `base_doc()`'s
/// single "admin" signer.
fn guardian_only_recovery() -> RecoveryConfig {
    RecoveryConfig {
        profile: RecoveryProfile::Loss,
        mode: RecoveryMode::GuardianOnly(GuardianSet {
            guardians: vec![
                "GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH".into(),
                "GASP3KHU7JDP23WQINN5DDWC6BYMJ4MFBRLXBPGRAS3EX726YY67JISR".into(),
            ],
            quorum: 1,
        }),
        controller: "CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF".into(),
        baseline: None,
        replaceable: vec!["admin".into()],
        delay_ledgers: 100,
        expiry_ledgers: 1000,
        max_cancels: 3,
    }
}

const ADAPTER: &str = "CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ";
const POOL: &str = "CDGGTZJDHAPV3S5LD36GAETRHWZ6ASCEZ5YRH7O5JOK3WXW55RRHOLL5";
const CIRCUIT: &str = "21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb";
const ENROLLMENT: &str = "6f0d1c2b3a49586776859483a2b1c0dfeefdfcfbfaf9f8f7f6f5f4f3f2f1f0e1";
const COMMITMENT: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff0";

fn zk_factor() -> ZkFactor {
    ZkFactor {
        adapter: ADAPTER.into(),
        circuit_id: CIRCUIT.into(),
        pool: POOL.into(),
        enrollment_id: ENROLLMENT.into(),
        commitment: COMMITMENT.into(),
    }
}

#[test]
fn accepts_minimal_guardian_only_recovery() {
    let mut doc = base_doc();
    doc.recovery = Some(guardian_only_recovery());
    assert_accepts(&doc);
}

#[test]
fn accepts_zk_only_recovery_with_no_guardian_field_at_all() {
    // Guardian-only requires no ZK machinery; symmetrically, zk-only carries
    // no guardian field to leave unset.
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::ZkOnly(zk_factor());
    doc.recovery = Some(r);
    assert_accepts(&doc);
}

#[test]
fn accepts_baseline_pointing_at_a_different_documents_hash() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.baseline = Some(BaselineCommitment {
        doc_hash: "27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98".into(),
    });
    doc.recovery = Some(r);
    assert_accepts(&doc);
}

#[test]
fn rejects_empty_replaceable() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.replaceable = vec![];
    doc.recovery = Some(r);
    assert_rejects(&doc, &ValidationError::EmptyRecoveryReplaceable);
}

#[test]
fn rejects_duplicate_replaceable() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.replaceable = vec!["admin".into(), "admin".into()];
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::DuplicateRecoveryReplaceable { id: "admin".into() },
    );
}

#[test]
fn rejects_replaceable_referencing_undeclared_signer() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.replaceable = vec!["nobody".into()];
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::UnknownRecoveryReplaceableRef {
            id: "nobody".into(),
        },
    );
}

#[test]
fn rejects_zero_delay_expiry_and_max_cancels() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.delay_ledgers = 0;
    doc.recovery = Some(r);
    assert_rejects(&doc, &ValidationError::ZeroRecoveryDelayLedgers);

    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.expiry_ledgers = 0;
    doc.recovery = Some(r);
    assert_rejects(&doc, &ValidationError::ZeroRecoveryExpiryLedgers);

    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.max_cancels = 0;
    doc.recovery = Some(r);
    assert_rejects(&doc, &ValidationError::ZeroRecoveryMaxCancels);
}

#[test]
fn rejects_malformed_controller_address() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.controller = "not-an-address".into();
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidRecoveryController {
            address: "not-an-address".into(),
        },
    );
}

#[test]
fn rejects_malformed_baseline_doc_hash() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.baseline = Some(BaselineCommitment {
        doc_hash: "not-hex".into(),
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidBaselineDocHash {
            doc_hash: "not-hex".into(),
        },
    );
}

#[test]
fn rejects_empty_guardian_set() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::GuardianOnly(GuardianSet {
        guardians: vec![],
        quorum: 1,
    });
    doc.recovery = Some(r);
    assert_rejects(&doc, &ValidationError::EmptyGuardianSet);
}

#[test]
fn rejects_duplicate_guardian() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    let addr = "GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH";
    r.mode = RecoveryMode::GuardianOnly(GuardianSet {
        guardians: vec![addr.into(), addr.into()],
        quorum: 1,
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::DuplicateGuardian {
            address: addr.into(),
        },
    );
}

#[test]
fn rejects_guardian_quorum_out_of_range() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::GuardianOnly(GuardianSet {
        guardians: vec!["GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH".into()],
        quorum: 0,
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidGuardianQuorum { quorum: 0, n: 1 },
    );

    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::GuardianOnly(GuardianSet {
        guardians: vec!["GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH".into()],
        quorum: 2,
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidGuardianQuorum { quorum: 2, n: 1 },
    );
}

fn rejects_zk(mutate: impl FnOnce(&mut ZkFactor), expected: ValidationError) {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    let mut z = zk_factor();
    mutate(&mut z);
    r.mode = RecoveryMode::ZkOnly(z);
    doc.recovery = Some(r);
    assert_rejects(&doc, &expected);
}

#[test]
fn rejects_malformed_zk_fields() {
    rejects_zk(
        |z| z.adapter = "not-an-address".into(),
        ValidationError::InvalidRecoveryAdapter {
            address: "not-an-address".into(),
        },
    );
    rejects_zk(
        |z| z.pool = "not-an-address".into(),
        ValidationError::InvalidRecoveryPool {
            address: "not-an-address".into(),
        },
    );
    // Circuit and enrollment ids are exactly 32 bytes of lowercase hex: a
    // shorter id or an uppercase spelling would give one value two
    // configuration hashes.
    for bad in ["abcd", &CIRCUIT.to_uppercase()] {
        rejects_zk(
            |z| z.circuit_id = bad.into(),
            ValidationError::InvalidCircuitId {
                circuit_id: bad.into(),
            },
        );
        rejects_zk(
            |z| z.enrollment_id = bad.into(),
            ValidationError::InvalidEnrollmentId {
                enrollment_id: bad.into(),
            },
        );
    }
}

#[test]
fn rejects_non_canonical_commitments() {
    // r itself and anything above it would verify as a smaller element.
    let modulus = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    let above = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for bad in [modulus, above, "0a1b"] {
        rejects_zk(
            |z| z.commitment = bad.into(),
            ValidationError::InvalidCommitment {
                commitment: bad.into(),
            },
        );
    }
    // r - 1 is the largest canonical element.
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    let mut z = zk_factor();
    z.commitment = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000".into();
    r.mode = RecoveryMode::ZkOnly(z);
    doc.recovery = Some(r);
    assert_accepts(&doc);
}

#[test]
fn rules_scoped_to_the_zk_adapter_or_pool_are_refused_but_the_controller_is_not() {
    let combined = from_json(&read("ci-publish-recovery-combined.json")).unwrap();
    for (target, refused) in [
        (ADAPTER, true),
        (POOL, true),
        (
            "CC5QACNC45UM2FLTKPXD2TME7647YHUPF4PGHQBFRP26PHHDQ6LWAPBF",
            false,
        ),
    ] {
        let mut doc = combined.clone();
        doc.rules[1].scope = perch_ir::Scope::contract(target);
        doc.rules[1].args = None;
        if refused {
            assert_rejects(
                &doc,
                &ValidationError::RuleScopedToRecoveryContract {
                    rule: "ci-publish".into(),
                    address: target.into(),
                },
            );
        } else {
            assert_accepts(&doc);
        }
    }
}

#[test]
fn pending_activity_is_no_longer_part_of_the_schema() {
    let json = read("ci-publish-recovery.json").replace(
        "\"max-cancels\": 3",
        "\"max-cancels\": 3,\n    \"pending-activity\": \"freeze\"",
    );
    assert!(from_json(&json).is_err());
}

#[test]
fn recovery_canonical_json_is_the_members_slice_of_the_document() {
    let doc = from_json(&read("ci-publish-recovery-combined.json")).unwrap();
    let member = recovery_canonical_json(doc.recovery.as_ref().unwrap());
    let whole = canonical_json(&doc);
    assert!(
        whole.contains(&format!("\"recovery\":{member}")),
        "{member}"
    );
}

/// Key rotation is not reconfiguration (spec §3.2, perch #92): changing a
/// replaceable signer's key leaves the recovery member's text unchanged.
#[test]
fn rotating_a_signer_key_leaves_the_recovery_text_unchanged() {
    let doc = from_json(&read("ci-publish-recovery.json")).unwrap();
    let mut rotated = doc.clone();
    if let SignerMethod::External { key, .. } = &mut rotated.signers[0].method {
        *key = "04".to_string() + &"11".repeat(64);
    }
    assert_ne!(canonical_json(&doc), canonical_json(&rotated));
    assert_eq!(
        recovery_canonical_json(doc.recovery.as_ref().unwrap()),
        recovery_canonical_json(rotated.recovery.as_ref().unwrap())
    );
}

// --- target derivation (spec §7.3) -------------------------------------------

fn external(verifier: &str, key: &str) -> SignerMethod {
    SignerMethod::External {
        verifier: verifier.into(),
        key: key.into(),
    }
}

fn replacement(id: &str, method: SignerMethod) -> Replacement {
    Replacement {
        signer_id: id.into(),
        method,
    }
}

fn recovery_doc() -> perch_ir::PolicyDoc {
    from_json(&read("ci-publish-recovery.json")).unwrap()
}

const NEW_ADMIN_KEY: &str = "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn lost_key_target_is_the_source_with_exactly_the_declared_replacement() {
    let source = recovery_doc();
    let verifier = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
    let target = derive_target(
        &source,
        &source,
        DeriveAction::LostKey,
        &[replacement("admin", external(verifier, NEW_ADMIN_KEY))],
        None,
    )
    .unwrap();
    validate(&target).unwrap();
    let mut expected = source.clone();
    expected.signers[0].method = external(verifier, NEW_ADMIN_KEY);
    assert_eq!(target, expected);
}

#[test]
fn lost_key_requires_a_replacement_and_compromise_does_not() {
    let source = recovery_doc();
    assert_eq!(
        derive_target(&source, &source, DeriveAction::LostKey, &[], None),
        Err(DeriveError::EmptyReplacements)
    );
    assert_eq!(
        derive_target(&source, &source, DeriveAction::Compromise, &[], None),
        Ok(source)
    );
}

#[test]
fn only_replaceable_declared_signers_of_the_same_kind_may_change() {
    let source = recovery_doc();
    let admin_verifier = "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN";
    let ci_verifier = "CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG";
    let derive =
        |r: Vec<Replacement>| derive_target(&source, &source, DeriveAction::LostKey, &r, None);
    assert_eq!(
        derive(vec![replacement("ci", external(ci_verifier, CI_KEY))]),
        Err(DeriveError::NotReplaceable { id: "ci".into() })
    );
    // Same kind, different verifier: routing the slot through another
    // verifier is refused.
    assert_eq!(
        derive(vec![replacement("admin", external(ci_verifier, CI_KEY))]),
        Err(DeriveError::KindMismatch { id: "admin".into() })
    );
    assert_eq!(
        derive(vec![replacement(
            "admin",
            SignerMethod::Delegated {
                address: "GALZMP2YGMVP6N57D2E6YVKMK3AONEOSC3F2RAXPOAKRIQVTSHJOOBVH".into()
            }
        )]),
        Err(DeriveError::KindMismatch { id: "admin".into() })
    );
    assert_eq!(
        derive(vec![
            replacement("admin", external(admin_verifier, NEW_ADMIN_KEY)),
            replacement("admin", external(admin_verifier, NEW_ADMIN_KEY)),
        ]),
        Err(DeriveError::NotCanonical)
    );
}

const CI_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn compromise_keeps_the_current_recovery_member_not_the_baselines() {
    let current = recovery_doc();
    let mut baseline = from_json(&read("ci-publish.json")).unwrap();
    // The baseline's own recovery member, if any, is ignored.
    let mut stale = current.recovery.clone().unwrap();
    stale.max_cancels = 99;
    baseline.recovery = Some(stale);
    let target = derive_target(&baseline, &current, DeriveAction::Compromise, &[], None).unwrap();
    assert_eq!(target.recovery, current.recovery);
    assert_eq!(target.rules, baseline.rules);
    assert_eq!(target.signers, baseline.signers);
}

#[test]
fn zk_rotation_is_required_exactly_for_zk_modes_and_must_be_fresh() {
    let guardian = recovery_doc();
    let rotation = ZkRotation {
        enrollment_id: "11".repeat(32),
        commitment: "0b".repeat(32),
    };
    let admin = replacement(
        "admin",
        external(
            "CD4IF75DNQJKCT35PAJAQDPW3K337EK6SJZDMQEVLXAH65K7ZVZMLXYN",
            NEW_ADMIN_KEY,
        ),
    );
    assert_eq!(
        derive_target(
            &guardian,
            &guardian,
            DeriveAction::LostKey,
            core::slice::from_ref(&admin),
            Some(&rotation)
        ),
        Err(DeriveError::ZkEnrollmentMismatch)
    );

    let combined = from_json(&read("ci-publish-recovery-combined.json")).unwrap();
    let derive = |zk: Option<&ZkRotation>| {
        derive_target(
            &combined,
            &combined,
            DeriveAction::LostKey,
            core::slice::from_ref(&admin),
            zk,
        )
    };
    assert_eq!(derive(None), Err(DeriveError::ZkEnrollmentMismatch));
    let reuse = ZkRotation {
        enrollment_id: ENROLLMENT.into(),
        commitment: "0b".repeat(32),
    };
    assert_eq!(derive(Some(&reuse)), Err(DeriveError::ZkEnrollmentMismatch));

    let target = derive(Some(&rotation)).unwrap();
    validate(&target).unwrap();
    let RecoveryMode::Combined(_, z) = &target.recovery.as_ref().unwrap().mode else {
        panic!("mode changed");
    };
    assert_eq!(z.enrollment_id, rotation.enrollment_id);
    assert_eq!(z.commitment, rotation.commitment);
    assert_eq!(z.adapter, ADAPTER);
}

#[test]
fn recovery_absent_documents_hash_exactly_as_before_this_field_existed() {
    // The load-bearing regression: base_doc() (no `recovery`) must canonicalize
    // with no "recovery" key at all, and its hash must be unaffected — this is
    // the same document every other perch-ir test already exercises, so this
    // just makes the guarantee explicit and named.
    let doc = base_doc();
    let canon = canonical_json(&doc);
    assert!(!canon.contains("recovery"), "{canon}");
}
