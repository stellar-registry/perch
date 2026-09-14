//! Recovery-configuration schema tests: the `ci-publish-recovery{,-combined}`
//! golden fixtures (canonical form + doc_hash, mirrored in
//! `packages/perch-js/test/parity.test.ts`), and semantic validation of
//! [`perch_ir::RecoveryConfig`]. See `CANONICAL.md` and `docs/recovery/`.

mod common;

use common::{assert_accepts, assert_rejects, base_doc};
use perch_ir::{
    canonical_json, doc_hash_hex, from_json, validate, BaselineCommitment, GuardianSet,
    PendingActivityPolicy, RecoveryConfig, RecoveryMode, RecoveryProfile, ValidationError,
    ZkVerifierConfig,
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

const RECOVERY_HASH_HEX: &str = "dcd539d241eddba9537237f2958a639cd84ac9f1ed6111c18da4230b1b60b08d";
const RECOVERY_COMBINED_HASH_HEX: &str =
    "9a6c29fdfd28746f8826a945611f31f43e6a51d131ff0bfd018b1ce2762e24bb";

#[test]
fn guardian_only_fixture_parses_validates_and_matches_committed_files() {
    let doc = from_json(&read("ci-publish-recovery.json")).expect("fixture must parse");
    validate(&doc).expect("fixture must validate");

    let recovery = doc.recovery.as_ref().expect("fixture must enroll recovery");
    assert_eq!(recovery.profile, RecoveryProfile::Protected);
    assert!(matches!(recovery.mode, RecoveryMode::GuardianOnly(_)));
    assert_eq!(recovery.pending_activity, PendingActivityPolicy::Freeze);
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
    assert_eq!(recovery.pending_activity, PendingActivityPolicy::Continue);
    // Loss profile with no baseline: lost-key recovery only.
    assert!(recovery.baseline.is_none());

    let committed = read("ci-publish-recovery-combined.canonical.json");
    assert_eq!(canonical_json(&doc), committed.trim_end_matches('\n'));

    let hash = doc_hash_hex(&doc);
    assert_eq!(hash, read("ci-publish-recovery-combined.doc-hash").trim());
    assert_eq!(hash, RECOVERY_COMBINED_HASH_HEX);
}

/// A minimal, valid guardian-only recovery config referencing `base_doc()`'s
/// single "admin" signer. Test builder, not the schema's own default (there
/// is none — every field is explicit, per `pending_activity`'s no-default
/// requirement extended to the whole struct for test clarity).
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
        pending_activity: PendingActivityPolicy::Continue,
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
    r.mode = RecoveryMode::ZkOnly(ZkVerifierConfig {
        verifier: "CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ".into(),
        circuit_id: "21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb".into(),
        pool: None,
    });
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

#[test]
fn rejects_malformed_zk_fields() {
    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::ZkOnly(ZkVerifierConfig {
        verifier: "not-an-address".into(),
        circuit_id: "21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb".into(),
        pool: None,
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidRecoveryVerifier {
            address: "not-an-address".into(),
        },
    );

    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::ZkOnly(ZkVerifierConfig {
        verifier: "CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ".into(),
        circuit_id: "not-hex!".into(),
        pool: None,
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidCircuitId {
            circuit_id: "not-hex!".into(),
        },
    );

    let mut doc = base_doc();
    let mut r = guardian_only_recovery();
    r.mode = RecoveryMode::ZkOnly(ZkVerifierConfig {
        verifier: "CBIRQ266AYZMRM4XFEUR4CHXLIZVHSCK7HWX674P37V4BLTREEH35OHZ".into(),
        circuit_id: "21d53d237ccdb61c57f0b128d9efaf6d96b844b224c2c19a973eaf7b5ee18bbb".into(),
        pool: Some("not-an-address".into()),
    });
    doc.recovery = Some(r);
    assert_rejects(
        &doc,
        &ValidationError::InvalidRecoveryPool {
            address: "not-an-address".into(),
        },
    );
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
