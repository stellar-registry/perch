use super::*;
use crate::statement::{AttemptSubject, ConfigBinding, StatementSubject, StatementTiming};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, U256};

fn u256(e: &Env, x: &[u8; 32]) -> U256 {
    U256::from_be_bytes(e, &Bytes::from_array(e, x))
}

#[test]
fn domain_tags_are_sha256_of_their_labels_mod_r() {
    let e = Env::default();
    let r = u256(&e, &BN254_SCALAR_MODULUS);
    for (label, tag) in [
        (DOM_LEAF_LABEL, DOM_LEAF),
        (DOM_BIND_LABEL, DOM_BIND),
        (DOM_NULLIFIER_LABEL, DOM_NULLIFIER),
        (DOM_AUTH_LABEL, DOM_AUTH),
    ] {
        let h = e
            .crypto()
            .sha256(&Bytes::from_slice(&e, label.as_bytes()))
            .to_bytes()
            .to_array();
        assert_eq!(u256(&e, &h).rem_euclid(&r), u256(&e, &tag), "{label}");
        assert!(is_canonical_field(&tag), "{label}");
    }
}

#[test]
fn canonical_field_is_strictly_below_r() {
    let mut r_minus_1 = BN254_SCALAR_MODULUS;
    r_minus_1[31] -= 1;
    let mut r_plus_1 = BN254_SCALAR_MODULUS;
    r_plus_1[31] += 1;
    assert!(is_canonical_field(&[0u8; 32]));
    assert!(is_canonical_field(&r_minus_1));
    assert!(!is_canonical_field(&BN254_SCALAR_MODULUS));
    assert!(!is_canonical_field(&r_plus_1));
    assert!(!is_canonical_field(&[0xff; 32]));
}

#[test]
fn split_is_two_zero_extended_halves() {
    let mut x = [0u8; 32];
    for (i, b) in x.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    let (hi, lo) = split_hi_lo(&x);
    assert_eq!(&hi[..16], &[0u8; 16]);
    assert_eq!(&lo[..16], &[0u8; 16]);
    assert_eq!(&hi[16..], &x[..16]);
    assert_eq!(&lo[16..], &x[16..]);
    assert!(is_canonical_field(&hi) && is_canonical_field(&lo));
}

fn statement(e: &Env, account: Address) -> RecoveryStatement {
    RecoveryStatement {
        network_id: e.ledger().network_id(),
        account,
        controller: Address::generate(e),
        config: ConfigBinding {
            epoch: 1,
            config_hash: BytesN::from_array(e, &[1; 32]),
        },
        timing: StatementTiming {
            delay_ledgers: 10,
            expiry_ledgers: 20,
            valid_until_ledger: 30,
        },
        subject: StatementSubject::LostKey(AttemptSubject {
            attempt_id: 0,
            source_doc_hash: BytesN::from_array(e, &[2; 32]),
            target_doc_hash: BytesN::from_array(e, &[3; 32]),
            replacements_hash: BytesN::from_array(e, &[4; 32]),
        }),
    }
}

#[test]
fn projection_carries_account_enrollment_and_digest() {
    let e = Env::default();
    let account = Address::generate(&e);
    let s = statement(&e, account.clone());
    let enrollment = BytesN::from_array(&e, &[9; 32]);
    let f = zk_statement_fields(&e, &s, &enrollment).unwrap();

    let id = crate::encode::contract_id(&e, &account).unwrap();
    assert_eq!((f.account_hi, f.account_lo), split_hi_lo(&id));
    assert_eq!((f.enrollment_hi, f.enrollment_lo), split_hi_lo(&[9; 32]));
    assert_eq!(
        (f.digest_hi, f.digest_lo),
        split_hi_lo(&s.digest(&e).unwrap().to_array())
    );
    let pre = f.auth_preimage();
    assert_eq!(pre[0], DOM_AUTH);
    assert!(pre.iter().all(is_canonical_field));

    // A different enrollment id is a different projection: a leaf enrolled
    // under any other id cannot satisfy this binding.
    let g = zk_statement_fields(&e, &s, &BytesN::from_array(&e, &[8; 32])).unwrap();
    assert_ne!(f, g);
}

#[test]
fn projection_refuses_a_non_contract_account() {
    let e = Env::default();
    let g = Address::from_str(
        &e,
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
    );
    let s = statement(&e, g);
    assert_eq!(
        zk_statement_fields(&e, &s, &BytesN::from_array(&e, &[0; 32])),
        Err(StatementError::AccountNotContract)
    );
}

#[test]
fn public_inputs_are_root_nullifier_statement_hash() {
    let e = Env::default();
    let pi = public_inputs(
        &e,
        &BytesN::from_array(&e, &[1; 32]),
        &BytesN::from_array(&e, &[2; 32]),
        &BytesN::from_array(&e, &[3; 32]),
    );
    assert_eq!(pi.len(), PUBLIC_INPUTS_LEN);
    let mut buf = [0u8; 96];
    pi.copy_into_slice(&mut buf);
    assert_eq!(&buf[..32], &[1; 32]);
    assert_eq!(&buf[32..64], &[2; 32]);
    assert_eq!(&buf[64..], &[3; 32]);
}

// A stand-in adapter exercising the interface end to end through the
// generated client: it checks the circuit binding and field canonicality the
// way the spec requires, accepts only a proof equal to the statement digest
// (a deterministic placeholder for "the proof verifies"), and surfaces
// refusals as typed `ZkAdapterError`s across the contract boundary.
#[contract]
struct StandInAdapter;

const STAND_IN_CIRCUIT: [u8; 32] = [0xc1; 32];

#[contractimpl]
impl StandInAdapter {
    pub fn circuit_id(e: &Env) -> BytesN<32> {
        BytesN::from_array(e, &STAND_IN_CIRCUIT)
    }

    pub fn tree_depth() -> u32 {
        32
    }

    pub fn verify(
        e: &Env,
        statement: RecoveryStatement,
        binding: ZkBinding,
        evidence: ZkEvidence,
    ) -> Result<(), ZkAdapterError> {
        if binding.circuit_id.to_array() != STAND_IN_CIRCUIT {
            return Err(ZkAdapterError::CircuitMismatch);
        }
        if !is_canonical_field(&evidence.root.to_array())
            || !is_canonical_field(&evidence.nullifier.to_array())
        {
            return Err(ZkAdapterError::NonCanonicalField);
        }
        let fields = zk_statement_fields(e, &statement, &binding.enrollment_id)
            .map_err(|_| ZkAdapterError::InvalidStatement)?;
        let mut expected = Bytes::new(e);
        for f in fields.auth_preimage() {
            expected.extend_from_array(&f);
        }
        if evidence.proof != expected {
            return Err(ZkAdapterError::ProofRejected);
        }
        Ok(())
    }
}

#[test]
fn adapter_interface_round_trips_through_the_generated_client() {
    let e = Env::default();
    let adapter = e.register(StandInAdapter, ());
    let client = ZkAdapterClient::new(&e, &adapter);
    assert_eq!(client.circuit_id().to_array(), STAND_IN_CIRCUIT);
    assert_eq!(client.tree_depth(), 32);

    let s = statement(&e, Address::generate(&e));
    let binding = ZkBinding {
        pool: Address::generate(&e),
        enrollment_id: BytesN::from_array(&e, &[9; 32]),
        circuit_id: BytesN::from_array(&e, &STAND_IN_CIRCUIT),
    };
    let fields = zk_statement_fields(&e, &s, &binding.enrollment_id).unwrap();
    let mut proof = Bytes::new(&e);
    for f in fields.auth_preimage() {
        proof.extend_from_array(&f);
    }
    let evidence = ZkEvidence {
        tree_id: 0,
        root: BytesN::from_array(&e, &[0; 32]),
        nullifier: BytesN::from_array(&e, &[0; 32]),
        proof,
    };
    client.verify(&s, &binding, &evidence);

    // The same proof for a statement that differs in one field is refused.
    let mut other = s.clone();
    other.config.epoch += 1;
    assert_eq!(
        client.try_verify(&other, &binding, &evidence),
        Err(Ok(ZkAdapterError::ProofRejected))
    );

    let mut wrong_circuit = binding.clone();
    wrong_circuit.circuit_id = BytesN::from_array(&e, &[0; 32]);
    assert_eq!(
        client.try_verify(&s, &wrong_circuit, &evidence),
        Err(Ok(ZkAdapterError::CircuitMismatch))
    );

    let mut non_canonical = evidence.clone();
    non_canonical.nullifier = BytesN::from_array(&e, &BN254_SCALAR_MODULUS);
    assert_eq!(
        client.try_verify(&s, &binding, &non_canonical),
        Err(Ok(ZkAdapterError::NonCanonicalField))
    );
}
