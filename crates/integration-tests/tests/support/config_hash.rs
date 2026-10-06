//! `config_hash` against an independent computation (spec §3.2).
//!
//! The Lean model proves `"perch/recovery/config" || recovery_canonical_json`
//! injective (`configPreimage_injective`); this checks that a doc compiler
//! actually hashes that preimage. For each committed recovery-member fixture
//! (`testdata/recovery/config-*.canonical.json`, one per mode) the compiler's
//! `config_hash` must equal `sha256(domain || fixture bytes)` computed here
//! with `sha2`, and changing any one configuration field must change it (to
//! the same independent hash of the changed text). Changing the document
//! outside the `recovery` member must not.

use perch_doc_compiler::PerchDocCompilerClient;
use perch_ir::{GuardianSet, PolicyDoc, RecoveryConfig, RecoveryMode, RecoveryProfile, ZkFactor};
use perch_testkit::FIXTURE_NETWORK;
use sha2::{Digest, Sha256};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Bytes, Env};
use std::collections::BTreeMap;
use std::format;
use std::path::PathBuf;
use std::string::{String, ToString};
use std::vec::Vec;

use super::strkey;

/// `CONFIG_DOMAIN` in `perch-doc-compiler`, restated from the spec.
const CONFIG_DOMAIN: &[u8] = b"perch/recovery/config";

/// The committed recovery-member fixtures, one per mode.
const FIXTURES: [&str; 3] = ["config-guardian-only", "config-zk-only", "config-combined"];

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/recovery")
        .join(format!("{name}.canonical.json"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .trim_end_matches('\n')
        .to_string()
}

fn expected(recovery_text: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONFIG_DOMAIN);
    h.update(recovery_text.as_bytes());
    h.finalize().into()
}

/// Run `compile_doc` and return `(config_hash, doc_hash)`.
fn compile(e: &Env, compiler: &Address, label: &str, json: &str) -> ([u8; 32], [u8; 32]) {
    let compiled = PerchDocCompilerClient::new(e, compiler)
        .try_compile_doc(&Bytes::from_slice(e, json.as_bytes()))
        .unwrap_or_else(|err| panic!("{label}: compile_doc refused the document: {err:?}"))
        .unwrap();
    assert_eq!(compiled.recovery.len(), 1, "{label}");
    (
        compiled.recovery.get(0).unwrap().config_hash.to_array(),
        compiled.doc_hash.to_array(),
    )
}

/// The last hex digit of `s`, changed: still 64 lowercase hex characters, and
/// a commitment below the BN254 modulus stays below it.
fn other_hex(s: &str) -> String {
    let mut out = s.to_string();
    let last = out.pop().unwrap();
    out.push(if last == 'f' { 'e' } else { 'f' });
    out
}

fn guardian_set(m: &mut RecoveryConfig) -> &mut GuardianSet {
    match &mut m.mode {
        RecoveryMode::GuardianOnly(g) | RecoveryMode::Combined(g, _) => g,
        RecoveryMode::ZkOnly(_) => unreachable!(),
    }
}

fn zk_factor(m: &mut RecoveryConfig) -> &mut ZkFactor {
    match &mut m.mode {
        RecoveryMode::ZkOnly(z) | RecoveryMode::Combined(_, z) => z,
        RecoveryMode::GuardianOnly(_) => unreachable!(),
    }
}

/// Every single-field change of `r` that still compiles, by field name.
fn mutations(
    e: &Env,
    r: &RecoveryConfig,
    guardians: &GuardianSet,
    zk: &ZkFactor,
) -> Vec<(String, RecoveryConfig)> {
    let other_contract = || strkey(&Address::generate(e));
    let mut out: Vec<(String, RecoveryConfig)> = Vec::new();
    let mut add = |label: &str, f: &dyn Fn(&mut RecoveryConfig)| {
        let mut m = r.clone();
        f(&mut m);
        assert_ne!(&m, r, "{label}: the mutation changed nothing");
        out.push((label.to_string(), m));
    };

    add("profile", &|m| {
        m.profile = match m.profile {
            RecoveryProfile::Loss => RecoveryProfile::Protected,
            RecoveryProfile::Protected => RecoveryProfile::Loss,
        }
    });
    let controller = other_contract();
    add("controller", &|m| m.controller = controller.clone());
    match &r.baseline {
        Some(b) => {
            add("baseline removed", &|m| m.baseline = None);
            let other = other_hex(&b.doc_hash);
            add("baseline doc-hash", &|m| {
                m.baseline.as_mut().unwrap().doc_hash = other.clone()
            });
        }
        None => add("baseline added", &|m| {
            m.baseline = Some(perch_ir::BaselineCommitment {
                doc_hash: "27cb38ef07bd8e4f86f07bef4d9272c070c2d9f05063d4c1ad1d4769b1d74a98".into(),
            })
        }),
    }
    add("replaceable", &|m| {
        m.replaceable = std::vec!["admin".into(), "backup".into()]
    });
    add("delay-ledgers", &|m| m.delay_ledgers += 1);
    add("expiry-ledgers", &|m| m.expiry_ledgers += 1);
    add("max-cancels", &|m| m.max_cancels += 1);

    let has_guardians = !matches!(r.mode, RecoveryMode::ZkOnly(_));
    let has_zk = !matches!(r.mode, RecoveryMode::GuardianOnly(_));
    if has_guardians {
        add("guardians: one fewer", &|m| {
            let g = guardian_set(m);
            g.guardians.pop();
            g.quorum = g.quorum.min(g.guardians.len() as u32);
        });
        let replacement = other_contract();
        add("guardians: one replaced", &|m| {
            guardian_set(m).guardians[0] = replacement.clone()
        });
        add("quorum", &|m| {
            let g = guardian_set(m);
            g.quorum = if (g.quorum as usize) < g.guardians.len() {
                g.quorum + 1
            } else {
                g.quorum - 1
            };
        });
    }
    if has_zk {
        let (adapter, pool) = (other_contract(), other_contract());
        add("adapter", &|m| zk_factor(m).adapter = adapter.clone());
        add("circuit-id", &|m| {
            let z = zk_factor(m);
            z.circuit_id = other_hex(&z.circuit_id)
        });
        add("pool", &|m| zk_factor(m).pool = pool.clone());
        add("enrollment-id", &|m| {
            let z = zk_factor(m);
            z.enrollment_id = other_hex(&z.enrollment_id)
        });
        add("commitment", &|m| {
            let z = zk_factor(m);
            z.commitment = other_hex(&z.commitment)
        });
    }

    let modes = [
        (
            "mode: guardian-only",
            RecoveryMode::GuardianOnly(guardians.clone()),
        ),
        ("mode: zk-only", RecoveryMode::ZkOnly(zk.clone())),
        (
            "mode: combined",
            RecoveryMode::Combined(guardians.clone(), zk.clone()),
        ),
    ];
    for (label, mode) in modes {
        if core::mem::discriminant(&mode) != core::mem::discriminant(&r.mode) {
            add(label, &|m| m.mode = mode.clone());
        }
    }
    out
}

/// Check `compiler` (a registered `PerchDocCompiler`, native or wasm) against
/// every fixture and every single-field mutation of it.
pub fn check(e: &Env, compiler: &Address) {
    let network_id: [u8; 32] = Sha256::digest(FIXTURE_NETWORK.as_bytes()).into();
    e.ledger().with_mut(|l| l.network_id = network_id);

    // Two delegated signers: the fixtures' replaceable `admin`, and `backup`
    // for the replaceable-set mutation. Delegated, so compiling calls no
    // verifier contract.
    let admin = strkey(&Address::generate(e));
    let backup = strkey(&Address::generate(e));
    let doc_around = |admin: &str, recovery_text: &str| {
        format!(
            r#"{{"version":1,"network":"{FIXTURE_NETWORK}","signers":[{{"id":"admin","address":"{admin}"}},{{"id":"backup","address":"{backup}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}}],"recovery":{recovery_text}}}"#
        )
    };
    let config = |name: &str| -> RecoveryConfig {
        perch_ir::from_json(&doc_around(&admin, &fixture(name)))
            .unwrap_or_else(|err| panic!("{name}: {err:?}"))
            .recovery
            .unwrap()
    };
    let RecoveryMode::GuardianOnly(guardians) = config("config-guardian-only").mode else {
        panic!("config-guardian-only is not guardian-only");
    };
    let RecoveryMode::Combined(_, zk) = config("config-combined").mode else {
        panic!("config-combined is not combined");
    };

    for name in FIXTURES {
        let text = fixture(name);
        let json = doc_around(&admin, &text);
        let (base, doc_hash) = compile(e, compiler, name, &json);
        assert_eq!(
            base,
            expected(&text),
            "{name}: config_hash is not sha256(\"perch/recovery/config\" || the fixture)"
        );

        // Outside the recovery member: a new document, the same configuration.
        let rotated = strkey(&Address::generate(e));
        let (same, other_doc) = compile(e, compiler, name, &doc_around(&rotated, &text));
        assert_eq!(same, base, "{name}: rotating a signer changed config_hash");
        assert_ne!(
            other_doc, doc_hash,
            "{name}: rotating a signer kept doc_hash"
        );

        // Every single-field change: the hash moves, to the independent value.
        let doc: PolicyDoc = perch_ir::from_json(&json).unwrap();
        let r = doc.recovery.clone().unwrap();
        let mut seen: BTreeMap<[u8; 32], String> = BTreeMap::new();
        seen.insert(base, "the fixture".into());
        for (field, m) in mutations(e, &r, &guardians, &zk) {
            let label = format!("{name}, {field}");
            let mut mutated = doc.clone();
            mutated.recovery = Some(m.clone());
            let (hash, _) = compile(e, compiler, &label, &perch_ir::canonical_json(&mutated));
            assert_eq!(
                hash,
                expected(&perch_ir::recovery_canonical_json(&m)),
                "{label}: config_hash is not the domain-separated hash of the recovery text"
            );
            if let Some(prev) = seen.insert(hash, field.clone()) {
                panic!("{label}: config_hash equals that of {prev}");
            }
        }
    }
}
