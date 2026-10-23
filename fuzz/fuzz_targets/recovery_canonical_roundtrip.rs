//! Fuzz the recovery member's canonical form, the text `config_hash` commits
//! to: for ANY `RecoveryConfig` (every profile, mode, and baseline shape,
//! arbitrary strings including control characters and non-ASCII, arbitrary
//! `u32`s), `recovery_canonical_json` is deterministic, is exactly the
//! document's `recovery` member, parses back to the same configuration, and
//! changes whenever one field changes. The Rust-side counterpart of the Lean
//! model's `pRecovery_rt` / `emitRecovery_injective`.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use perch_ir::{
    BaselineCommitment, GuardianSet, PolicyDoc, RecoveryConfig, RecoveryMode, RecoveryProfile,
    ZkFactor,
};

#[derive(Arbitrary, Debug, Clone)]
struct AGuardians {
    guardians: Vec<String>,
    quorum: u32,
}

#[derive(Arbitrary, Debug, Clone)]
struct AZk {
    adapter: String,
    circuit_id: String,
    pool: String,
    enrollment_id: String,
    commitment: String,
}

#[derive(Arbitrary, Debug, Clone)]
enum AMode {
    GuardianOnly(AGuardians),
    ZkOnly(AZk),
    Combined(AGuardians, AZk),
}

#[derive(Arbitrary, Debug, Clone)]
struct ARecovery {
    protected: bool,
    mode: AMode,
    controller: String,
    baseline: Option<String>,
    replaceable: Vec<String>,
    delay_ledgers: u32,
    expiry_ledgers: u32,
    max_cancels: u32,
}

/// One field of a configuration, replaced: the neighbour whose canonical text
/// must differ whenever the configuration does.
#[derive(Arbitrary, Debug)]
enum Edit {
    Profile,
    Mode(AMode),
    Controller(String),
    Baseline(Option<String>),
    Replaceable(Vec<String>),
    DelayLedgers(u32),
    ExpiryLedgers(u32),
    MaxCancels(u32),
}

#[derive(Arbitrary, Debug)]
struct Case {
    network: Option<String>,
    recovery: ARecovery,
    edit: Edit,
}

fn guardians(g: AGuardians) -> GuardianSet {
    GuardianSet {
        guardians: g.guardians,
        quorum: g.quorum,
    }
}

fn zk(z: AZk) -> ZkFactor {
    ZkFactor {
        adapter: z.adapter,
        circuit_id: z.circuit_id,
        pool: z.pool,
        enrollment_id: z.enrollment_id,
        commitment: z.commitment,
    }
}

fn mode(m: AMode) -> RecoveryMode {
    match m {
        AMode::GuardianOnly(g) => RecoveryMode::GuardianOnly(guardians(g)),
        AMode::ZkOnly(z) => RecoveryMode::ZkOnly(zk(z)),
        AMode::Combined(g, z) => RecoveryMode::Combined(guardians(g), zk(z)),
    }
}

fn recovery(a: ARecovery) -> RecoveryConfig {
    RecoveryConfig {
        profile: if a.protected {
            RecoveryProfile::Protected
        } else {
            RecoveryProfile::Loss
        },
        mode: mode(a.mode),
        controller: a.controller,
        baseline: a.baseline.map(|doc_hash| BaselineCommitment { doc_hash }),
        replaceable: a.replaceable,
        delay_ledgers: a.delay_ledgers,
        expiry_ledgers: a.expiry_ledgers,
        max_cancels: a.max_cancels,
    }
}

fn edited(mut a: ARecovery, edit: Edit) -> ARecovery {
    match edit {
        Edit::Profile => a.protected = !a.protected,
        Edit::Mode(m) => a.mode = m,
        Edit::Controller(c) => a.controller = c,
        Edit::Baseline(b) => a.baseline = b,
        Edit::Replaceable(r) => a.replaceable = r,
        Edit::DelayLedgers(n) => a.delay_ledgers = n,
        Edit::ExpiryLedgers(n) => a.expiry_ledgers = n,
        Edit::MaxCancels(n) => a.max_cancels = n,
    }
    a
}

fuzz_target!(|case: Case| {
    let r = recovery(case.recovery.clone());
    let member = perch_ir::recovery_canonical_json(&r);
    assert_eq!(
        member,
        perch_ir::recovery_canonical_json(&r.clone()),
        "recovery_canonical_json must be deterministic"
    );

    let doc = PolicyDoc {
        version: 1,
        network: case.network,
        signers: Vec::new(),
        rules: Vec::new(),
        recovery: Some(r.clone()),
    };
    let canon = perch_ir::canonical_json(&doc);
    assert!(
        canon.contains(&format!("\"recovery\":{member},\"rules\":")),
        "recovery_canonical_json must be the document's recovery member"
    );
    let reparsed = perch_ir::from_json(&canon).expect("canonical form must re-parse");
    assert_eq!(
        reparsed, doc,
        "the canonical form must parse back to the same document"
    );

    let r2 = recovery(edited(case.recovery, case.edit));
    if r2 != r {
        assert_ne!(
            member,
            perch_ir::recovery_canonical_json(&r2),
            "distinct configurations must have distinct canonical text"
        );
    }
});
