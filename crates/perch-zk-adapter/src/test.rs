//! Real-proof tests: every proof here is a zero-knowledge proof generated
//! by `perch-zk-fixtures` with the pinned nargo/bb toolchain against the
//! committed circuit (or, for `proof.bbjs`, by bb.js), and is verified by the
//! adapter's `UltraKeccakZKFlavor` verifier with the committed VK, through the
//! controller's own client (`perch-recovery-interface`'s `ZkAdapterClient`).
//! Nothing is mocked except account authorization for `rcv_insert` (the
//! pool's own authorization is tested in perch-zk-pool). The verifier delta's
//! own tests are in `tests/zk_verifier.rs`.

extern crate std;

use crate::{PerchZkAdapter, PerchZkAdapterClient, CIRCUIT_DEPTH};
use perch_recovery_interface::statement::{ConfigChange, StatementSubject};
use perch_recovery_interface::zk::{
    ProofVerifierClient, ProofVerifierError, ZkAdapterClient, ZkAdapterError, ZkBinding,
    ZkEvidence, BN254_SCALAR_MODULUS,
};
use perch_recovery_interface::RecoveryStatement;
use perch_zk_pool::{PerchZkPool, PerchZkPoolClient, PoolKey, TreeState};
use perch_zk_primitives::ZERO_HASHES;
use perch_zk_prover::fixture::{
    address, field_tag, h32, sha256, tag, Enrollment, Loaded, NETWORK_PASSPHRASE,
};
use perch_zk_prover::{commitment, Bytes32};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, TryFromVal, Val, Vec};
use std::path::PathBuf;

fn load(name: &str) -> Loaded {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/zk")
        .join(name);
    Loaded::read(&dir).unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

struct World {
    e: Env,
    adapter: ZkAdapterClient<'static>,
    pool: Address,
    pool_client: PerchZkPoolClient<'static>,
}

impl World {
    /// A pool at the fixture's address, filled with the fixture's
    /// enrollments in order, and a fresh adapter.
    fn new(l: &Loaded) -> Self {
        let f = &l.fixture;
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        e.ledger()
            .set_network_id(sha256(NETWORK_PASSPHRASE.as_bytes()));
        e.mock_all_auths();
        let pool = address(&e, &h32(&f.pool_id));
        e.register_at(&pool, PerchZkPool, ());
        let pool_client = PerchZkPoolClient::new(&e, &pool);
        if f.synthetic_prefix > 0 {
            let mut frontier = Vec::new(&e);
            for z in &ZERO_HASHES[..32] {
                frontier.push_back(BytesN::from_array(&e, z));
            }
            e.as_contract(&pool, || {
                e.storage().persistent().set(
                    &PoolKey::Tree(f.tree_id),
                    &TreeState {
                        size: f.synthetic_prefix,
                        root: BytesN::from_array(&e, &ZERO_HASHES[32]),
                        frontier,
                    },
                );
            });
        }
        let adapter = ZkAdapterClient::new(&e, &e.register(PerchZkAdapter, ()));
        let w = Self {
            e,
            adapter,
            pool,
            pool_client,
        };
        w.enroll_all(&f.enrollments);
        w
    }

    fn enroll_all(&self, enrollments: &[Enrollment]) {
        for x in enrollments {
            self.pool_client.rcv_insert(
                &address(&self.e, &h32(&x.account_id)),
                &self.b32(&h32(&x.enrollment_id)),
                &self.b32(&h32(&x.commitment)),
            );
        }
    }

    fn b32(&self, b: &Bytes32) -> BytesN<32> {
        BytesN::from_array(&self.e, b)
    }

    fn statement(&self, l: &Loaded) -> RecoveryStatement {
        l.fixture.statement.to_statement(&self.e)
    }

    fn binding(&self, l: &Loaded) -> ZkBinding {
        ZkBinding {
            pool: self.pool.clone(),
            enrollment_id: self.b32(&h32(&l.fixture.enrollment_id)),
            circuit_id: self.adapter.circuit_id(),
        }
    }

    fn evidence(&self, l: &Loaded) -> ZkEvidence {
        ZkEvidence {
            tree_id: l.fixture.tree_id,
            root: self.b32(&h32(&l.fixture.root)),
            nullifier: self.b32(&h32(&l.fixture.nullifier)),
            proof: Bytes::from_slice(&self.e, &l.proof),
        }
    }

    fn check(
        &self,
        statement: &RecoveryStatement,
        binding: &ZkBinding,
        evidence: &ZkEvidence,
    ) -> Result<(), ZkAdapterError> {
        match self.adapter.try_verify(statement, binding, evidence) {
            Ok(Ok(())) => Ok(()),
            Err(Ok(err)) => Err(err),
            other => panic!("unexpected host-level result {other:?}"),
        }
    }

    /// Verify `l` exactly as its fixture declares.
    fn verify(&self, l: &Loaded) -> Result<(), ZkAdapterError> {
        self.check(&self.statement(l), &self.binding(l), &self.evidence(l))
    }
}

const ACTIONS: [&str; 6] = [
    "lost_key",
    "compromise",
    "cancel",
    "reconfigure",
    "reconfigure_remove",
    "upgrade",
];

/// One real proof per supported ZK action — including both reconfiguration
/// forms and upgrade approval — each over the statement the controller
/// builds for that action, verifies against a real pool.
#[test]
fn every_action_has_a_real_proof_that_verifies() {
    for name in ACTIONS {
        let l = load(name);
        let f = &l.fixture;
        let w = World::new(&l);
        let s = w.statement(&l);
        assert_eq!(s.digest(&w.e).unwrap().to_array(), h32(&f.digest), "{name}");
        let mut pis = h32(&f.root).to_vec();
        pis.extend_from_slice(&h32(&f.nullifier));
        pis.extend_from_slice(&h32(&f.statement_hash));
        assert_eq!(l.public_inputs, pis, "{name}: public inputs");
        assert_eq!(w.verify(&l), Ok(()), "{name}");
    }
    let actions: std::vec::Vec<_> = ACTIONS
        .iter()
        .map(|n| {
            let l = load(n);
            l.fixture.statement.to_statement(&Env::default()).subject
        })
        .collect();
    assert!(matches!(
        actions[3],
        StatementSubject::Reconfigure(ConfigChange::Set(_))
    ));
    assert!(matches!(
        actions[4],
        StatementSubject::Reconfigure(ConfigChange::Remove)
    ));
    assert!(matches!(actions[5], StatementSubject::Upgrade(_)));
}

/// Changing any statement field invalidates the evidence: the proof binds
/// the whole statement through its digest.
#[test]
fn evidence_is_bound_to_every_statement_field() {
    let l = load("lost_key");
    let w = World::new(&l);
    let base = w.statement(&l);
    let other = w.b32(&tag("something-else"));
    type Change = fn(&mut RecoveryStatement, &BytesN<32>, &Env);
    let changes: [(&str, Change); 11] = [
        ("network", |s, o, _| s.network_id = o.clone()),
        ("controller", |s, _, e| {
            s.controller = address(e, &tag("controller-2"))
        }),
        ("epoch", |s, _, _| s.config.epoch += 1),
        ("config", |s, o, _| s.config.config_hash = o.clone()),
        ("delay", |s, _, _| s.timing.delay_ledgers += 1),
        ("expiry", |s, _, _| s.timing.expiry_ledgers += 1),
        ("valid until", |s, _, _| s.timing.valid_until_ledger += 1),
        ("attempt", |s, _, _| {
            if let StatementSubject::LostKey(a) = &mut s.subject {
                a.attempt_id += 1;
            }
        }),
        ("source", |s, o, _| {
            if let StatementSubject::LostKey(a) = &mut s.subject {
                a.source_doc_hash = o.clone();
            }
        }),
        ("target", |s, o, _| {
            if let StatementSubject::LostKey(a) = &mut s.subject {
                a.target_doc_hash = o.clone();
            }
        }),
        ("replacements", |s, o, _| {
            if let StatementSubject::LostKey(a) = &mut s.subject {
                a.replacements_hash = o.clone();
            }
        }),
    ];
    for (what, change) in changes {
        let mut s = base.clone();
        change(&mut s, &other, &w.e);
        assert_ne!(s, base, "{what} changes the statement");
        assert_eq!(
            w.check(&s, &w.binding(&l), &w.evidence(&l)),
            Err(ZkAdapterError::ProofRejected),
            "{what}"
        );
    }
}

/// Evidence for one action never serves another, in either direction, even
/// for the same account, enrollment, and secret.
#[test]
fn evidence_for_one_action_cannot_serve_another() {
    let all: std::vec::Vec<Loaded> = ACTIONS.iter().map(|n| load(n)).collect();
    let w = World::new(&all[0]);
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            let want = if i == j {
                Ok(())
            } else {
                Err(ZkAdapterError::ProofRejected)
            };
            assert_eq!(
                w.check(&w.statement(b), &w.binding(a), &w.evidence(a)),
                want,
                "{} evidence for a {} statement",
                ACTIONS[i],
                ACTIONS[j]
            );
        }
    }
}

/// A proof for one account never authorizes another, a leaf enrolled under
/// one enrollment id never satisfies a binding to another (the account's own
/// newer enrollment included), and the nullifier is the one the secret
/// determines.
#[test]
fn evidence_is_bound_to_its_account_enrollment_and_nullifier() {
    let l = load("lost_key");
    let w = World::new(&l);

    let mut other_account = w.statement(&l);
    other_account.account = address(&w.e, &tag("account-b"));
    assert_eq!(
        w.check(&other_account, &w.binding(&l), &w.evidence(&l)),
        Err(ZkAdapterError::ProofRejected)
    );

    // The account enrolls a fresh credential and its configuration moves to
    // it: evidence from the old enrollment is dead.
    let newer = w.b32(&tag("enrollment-a-2"));
    w.pool_client.rcv_insert(
        &address(&w.e, &h32(&l.fixture.account_id)),
        &newer,
        &w.b32(&commitment(&w.e, &field_tag("secret-a-2"))),
    );
    let mut rebound = w.binding(&l);
    rebound.enrollment_id = newer;
    assert_eq!(
        w.check(&w.statement(&l), &rebound, &w.evidence(&l)),
        Err(ZkAdapterError::ProofRejected)
    );

    let mut other_nullifier = w.evidence(&l);
    let mut n = h32(&l.fixture.nullifier);
    n[31] ^= 1;
    other_nullifier.nullifier = w.b32(&n);
    assert_eq!(
        w.check(&w.statement(&l), &w.binding(&l), &other_nullifier),
        Err(ZkAdapterError::ProofRejected)
    );
}

/// Root acceptance is bound to the enrolled pool and the named tree, and an
/// unreachable pool fails closed.
#[test]
fn root_must_be_retained_by_the_enrolled_pool_for_the_named_tree() {
    let l = load("lost_key");
    let w = World::new(&l);
    let (s, b) = (w.statement(&l), w.binding(&l));

    let mut wrong_tree = w.evidence(&l);
    wrong_tree.tree_id = 1;
    assert_eq!(
        w.check(&s, &b, &wrong_tree),
        Err(ZkAdapterError::UnknownRoot)
    );

    let mut fabricated = w.evidence(&l);
    let mut root = tag("not-a-root");
    root[0] &= 0x1f;
    fabricated.root = w.b32(&root);
    assert_eq!(
        w.check(&s, &b, &fabricated),
        Err(ZkAdapterError::UnknownRoot)
    );

    // A pool that never saw these enrollments.
    let mut elsewhere = b.clone();
    elsewhere.pool = w.e.register(PerchZkPool, ());
    assert_eq!(
        w.check(&s, &elsewhere, &w.evidence(&l)),
        Err(ZkAdapterError::UnknownRoot)
    );

    // Something that is not a pool at all.
    let mut not_a_pool = b.clone();
    not_a_pool.pool = w.adapter.address.clone();
    assert_eq!(
        w.check(&s, &not_a_pool, &w.evidence(&l)),
        Err(ZkAdapterError::PoolUnavailable)
    );
}

/// Every root a tree has ever had stays acceptable: insertions after a
/// proof was built never invalidate it, so nobody can race a victim's
/// evidence out of the pool. A proof against a later root verifies too.
#[test]
fn evidence_against_an_older_root_survives_later_insertions() {
    let old = load("lost_key");
    let later = load("later_root");
    let prior = old.fixture.enrollments.len();
    assert_eq!(later.fixture.enrollments.len(), prior + 129);
    assert_ne!(old.fixture.root, later.fixture.root);
    let w = World::new(&old);
    assert_eq!(w.verify(&old), Ok(()));

    w.enroll_all(&later.fixture.enrollments[prior..]);
    assert_eq!(w.verify(&old), Ok(()));
    assert_eq!(w.verify(&later), Ok(()));
}

/// The real depth-32 boundary: a leaf in the last slot of a full tree stays
/// provable after the pool has rolled over and kept enrolling elsewhere.
#[test]
fn leaf_in_a_full_earlier_tree_stays_provable_after_rollover() {
    let l = load("earlier_tree");
    let w = World::new(&l);
    let info = w.pool_client.tree(&0);
    assert!(info.sealed);
    assert_eq!(info.root, w.b32(&h32(&l.fixture.root)));
    assert_eq!(w.pool_client.current_tree(), 1);

    let mut later = load("lost_key").fixture.enrollments;
    later.retain(|x| x.account_id != l.fixture.account_id);
    w.enroll_all(&later);
    assert_eq!(w.pool_client.tree(&1).size, 2);
    assert_eq!(w.verify(&l), Ok(()));
}

#[test]
fn malformed_and_mismatched_inputs_are_refused_before_verification() {
    let l = load("lost_key");
    let w = World::new(&l);
    let (s, b, ev) = (w.statement(&l), w.binding(&l), w.evidence(&l));

    let mut other_circuit = b.clone();
    other_circuit.circuit_id = w.b32(&tag("another-circuit"));
    assert_eq!(
        w.check(&s, &other_circuit, &ev),
        Err(ZkAdapterError::CircuitMismatch)
    );

    let mut g_account = s.clone();
    g_account.account = Address::from_str(
        &w.e,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    assert_eq!(
        w.check(&g_account, &b, &ev),
        Err(ZkAdapterError::InvalidStatement)
    );

    let mut big_nullifier = ev.clone();
    big_nullifier.nullifier = w.b32(&BN254_SCALAR_MODULUS);
    assert_eq!(
        w.check(&s, &b, &big_nullifier),
        Err(ZkAdapterError::NonCanonicalField)
    );
    let mut big_root = ev.clone();
    big_root.root = w.b32(&[0xff; 32]);
    assert_eq!(
        w.check(&s, &b, &big_root),
        Err(ZkAdapterError::NonCanonicalField)
    );

    let mut short = ev.clone();
    short.proof = ev.proof.slice(..ev.proof.len() - 32);
    assert_eq!(w.check(&s, &b, &short), Err(ZkAdapterError::MalformedProof));
}

/// The browser prover's output (bb.js, committed by `packages/perch-zk`'s
/// tests) verifies through the adapter like the CLI's, though the two proofs
/// of the same statement differ: ZK proofs are randomized.
#[test]
fn browser_prover_proofs_verify() {
    let l = load("lost_key");
    let w = World::new(&l);
    let bbjs = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/zk/lost_key/proof.bbjs"),
    )
    .unwrap();
    assert_ne!(bbjs, l.proof);
    let mut ev = w.evidence(&l);
    ev.proof = Bytes::from_slice(&w.e, &bbjs);
    assert_eq!(w.check(&w.statement(&l), &w.binding(&l), &ev), Ok(()));
}

/// A valid non-ZK proof of the same statement (which would reveal
/// witness-dependent data) is refused, by both entry points.
#[test]
fn non_zk_proofs_are_refused() {
    let l = load("lost_key");
    let w = World::new(&l);
    let non_zk = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/zk/lost_key/proof.non-zk"),
    )
    .unwrap();
    let mut ev = w.evidence(&l);
    ev.proof = Bytes::from_slice(&w.e, &non_zk);
    assert_eq!(
        w.check(&w.statement(&l), &w.binding(&l), &ev),
        Err(ZkAdapterError::MalformedProof)
    );
    let v = ProofVerifierClient::new(&w.e, &w.adapter.address);
    assert_eq!(
        v.try_verify_proof(&Bytes::from_slice(&w.e, &l.public_inputs), &ev.proof),
        Err(Ok(ProofVerifierError::ProofParseError))
    );
}

#[test]
fn tampered_proofs_are_rejected() {
    let l = load("lost_key");
    let w = World::new(&l);
    // A wire commitment, a sumcheck univariate, a Libra evaluation, and the
    // final KZG opening: early, middle, and late in the proof.
    for at in [600usize, 7000, 15_900, l.proof.len() - 10] {
        let mut proof = l.proof.clone();
        proof[at] ^= 0x01;
        let mut ev = w.evidence(&l);
        ev.proof = Bytes::from_slice(&w.e, &proof);
        assert_eq!(
            w.check(&w.statement(&l), &w.binding(&l), &ev),
            Err(ZkAdapterError::ProofRejected),
            "byte {at}"
        );
    }
}

/// The adapter keeps no state: the same evidence verifies every time.
/// Refusing a replay of identical evidence is the controller's job (it
/// reserves and spends nullifiers and consumes attempts); what the adapter
/// guarantees is that evidence cannot be redirected to any other statement,
/// account, enrollment, pool, or tree (the tests above).
#[test]
fn verification_is_stateless() {
    let l = load("cancel");
    let w = World::new(&l);
    assert_eq!(w.verify(&l), Ok(()));
    assert_eq!(w.verify(&l), Ok(()));
}

/// `verify` writes no contract state. Its one ledger effect is the pool's
/// `is_known_root` extending the matched `Root` entry's TTL (so a root a
/// recovery relies on stays live), which the submitter pays for and which a
/// simulation's footprint must include. Every other entry, and every
/// entry's value, is unchanged.
#[test]
fn verification_only_extends_the_matched_roots_ttl() {
    let l = load("lost_key");
    let w = World::new(&l);
    // Age the entries so an extension is visible, staying inside every
    // entry's TTL (the test host restores, and so rewrites, archived ones).
    w.e.ledger().with_mut(|li| li.sequence_number += 1_000);
    let entries = |w: &World| {
        w.e.to_ledger_snapshot()
            .ledger_entries
            .into_iter()
            .map(|(k, (v, ttl))| (*k, (*v, ttl)))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = entries(&w);
    assert_eq!(w.verify(&l), Ok(()));
    let after = entries(&w);

    assert_eq!(
        before.keys().collect::<std::vec::Vec<_>>(),
        after.keys().collect::<std::vec::Vec<_>>(),
        "verify created or removed a ledger entry"
    );
    let changed: std::vec::Vec<_> = before
        .iter()
        .filter(|(k, v)| after[*k] != **v)
        .map(|(k, _)| k)
        .collect();
    let root: Val = PoolKey::Root(l.fixture.tree_id, w.b32(&h32(&l.fixture.root))).into_val(&w.e);
    let root_key =
        soroban_sdk::xdr::LedgerKey::ContractData(soroban_sdk::xdr::LedgerKeyContractData {
            contract: (&w.pool).into(),
            key: soroban_sdk::xdr::ScVal::try_from_val(&w.e, &root).unwrap(),
            durability: soroban_sdk::xdr::ContractDataDurability::Persistent,
        });
    assert_eq!(
        changed,
        [&root_key],
        "verify changed something besides the root's TTL"
    );
    let (entry_before, ttl_before) = &before[&root_key];
    let (entry_after, ttl_after) = &after[&root_key];
    assert_eq!(entry_before, entry_after, "the root entry's value changed");
    assert!(ttl_after > ttl_before, "the root's TTL was not extended");
}

/// The raw verifier entry point (`ProofVerifierInterface`) checks a proof
/// against caller-assembled public inputs, with Nido's error codes.
#[test]
fn raw_verifier_entry_point() {
    let l = load("upgrade");
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    let v = ProofVerifierClient::new(&e, &e.register(PerchZkAdapter, ()));
    let pis = Bytes::from_slice(&e, &l.public_inputs);
    let proof = Bytes::from_slice(&e, &l.proof);
    v.verify_proof(&pis, &proof);

    let mut other = l.public_inputs.clone();
    other[95] ^= 1;
    assert_eq!(
        v.try_verify_proof(&Bytes::from_slice(&e, &other), &proof),
        Err(Ok(ProofVerifierError::VerificationFailed))
    );
    assert_eq!(
        v.try_verify_proof(&pis, &proof.slice(..100)),
        Err(Ok(ProofVerifierError::ProofParseError))
    );
}

#[test]
fn verification_key_identity_matches_the_manifest() {
    let e = Env::default();
    let a = PerchZkAdapterClient::new(&e, &e.register(PerchZkAdapter, ()));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../circuits/manifest.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let entry = &manifest["circuits"]["perch_zk_recovery"];
    let want = h32(entry["vk_sha256"].as_str().unwrap());
    assert_eq!(a.circuit_id().to_array(), want);
    assert_eq!(e.crypto().sha256(&a.vk()).to_array(), want);
    assert_eq!(a.tree_depth(), CIRCUIT_DEPTH);
    assert_eq!(entry["depth"].as_u64(), Some(u64::from(CIRCUIT_DEPTH)));
    assert_eq!(CIRCUIT_DEPTH, perch_zk_pool::TREE_DEPTH);
    assert!(ultrahonk_soroban_verifier::UltraHonkZkVerifier::new(&e, &a.vk()).is_ok());
}
