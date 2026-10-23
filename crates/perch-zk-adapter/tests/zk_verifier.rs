//! Tests of the perch ZK delta to the vendored verifier
//! (`vendor/ultrahonk-soroban-verifier/src/zk.rs`, `UltraKeccakZKFlavor`),
//! against the committed real proofs. Upstream's own tests need fixtures that
//! are not vendored, so the delta's tests live here.
//!
//! - every committed ZK proof (bb CLI and bb.js) verifies, and they are
//!   randomized;
//! - a valid non-ZK proof of the same statement is refused, as is one
//!   re-encoded in the ZK layout;
//! - malformed ZK proofs are refused: lengths, non-canonical encodings,
//!   off-curve points, padding, and every ZK-only field tampered;
//! - each ZK check rejects on its own with the transcript held fixed;
//! - the constants are what bb uses.

use soroban_sdk::{Bytes, Env};
use std::path::PathBuf;
use ultrahonk_soroban_verifier::field::Fr;
use ultrahonk_soroban_verifier::types::G1Point;
use ultrahonk_soroban_verifier::zk::{
    check_libra_evaluations_consistency, load_zk_proof, verify_zk_shplemini, verify_zk_sumcheck,
    ZkProof, ZkTranscript, NUM_SMALL_IPA_EVALUATIONS, SUBGROUP_GENERATOR,
    SUBGROUP_GENERATOR_INVERSE, SUBGROUP_SIZE, ZK_BARYCENTRIC_DENOMINATORS,
    ZK_BATCHED_RELATION_PARTIAL_LENGTH, ZK_PROOF_BYTES,
};
use ultrahonk_soroban_verifier::{UltraHonkVerifier, UltraHonkZkVerifier, VerifyError};

const FIXTURES: [&str; 8] = [
    "lost_key",
    "compromise",
    "cancel",
    "reconfigure",
    "reconfigure_remove",
    "upgrade",
    "earlier_tree",
    "later_root",
];

/// Byte offsets of the ZK-only fields in a 507-field proof (bb 0.87.0
/// `ultra_keccak_zk_flavor.hpp`), and of the shared fields around them.
mod at {
    pub const LIBRA_CONCATENATION: usize = 512 + 8 * 128;
    pub const LIBRA_SUM: usize = LIBRA_CONCATENATION + 128;
    pub const UNIVARIATES: usize = LIBRA_SUM + 32;
    pub const EVALUATIONS: usize = UNIVARIATES + 28 * 9 * 32;
    pub const LIBRA_EVALUATION: usize = EVALUATIONS + 40 * 32;
    pub const LIBRA_GRAND_SUM: usize = LIBRA_EVALUATION + 32;
    pub const LIBRA_QUOTIENT: usize = LIBRA_GRAND_SUM + 128;
    pub const MASKING_POLY: usize = LIBRA_QUOTIENT + 128;
    pub const MASKING_EVAL: usize = MASKING_POLY + 128;
    pub const FOLDS: usize = MASKING_EVAL + 32;
    pub const GEMINI_EVALS: usize = FOLDS + 27 * 128;
    pub const LIBRA_POLY_EVALS: usize = GEMINI_EVALS + 28 * 32;
    pub const SHPLONK_Q: usize = LIBRA_POLY_EVALS + 4 * 32;
    pub const END: usize = SHPLONK_Q + 2 * 128;

    /// Evaluation `c` of sumcheck round `r`.
    pub const fn univariate(r: usize, c: usize) -> usize {
        UNIVARIATES + (r * 9 + c) * 32
    }

    /// The ZK-only commitments.
    pub const COMMITMENTS: [usize; 4] = [
        LIBRA_CONCATENATION,
        LIBRA_GRAND_SUM,
        LIBRA_QUOTIENT,
        MASKING_POLY,
    ];
}

/// log₂ of the release circuit's size (`vk` header).
const LOG_N: usize = 14;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(repo(rel)).unwrap_or_else(|err| panic!("{rel}: {err}"))
}

struct Case {
    e: Env,
    v: UltraHonkZkVerifier,
    proof: Vec<u8>,
    public_inputs: Bytes,
}

impl Case {
    fn new(name: &str) -> Self {
        let e = Env::default();
        e.cost_estimate().budget().reset_unlimited();
        let vk = Bytes::from_slice(&e, &read("crates/perch-zk-adapter/vk/perch_zk_recovery.vk"));
        let v = UltraHonkZkVerifier::new(&e, &vk).unwrap();
        assert_eq!(v.get_vk().log_circuit_size as usize, LOG_N);
        let public_inputs =
            Bytes::from_slice(&e, &read(&format!("testdata/zk/{name}/public_inputs")));
        Self {
            proof: read(&format!("testdata/zk/{name}/proof")),
            e,
            v,
            public_inputs,
        }
    }

    fn verify(&self, proof: &[u8]) -> Result<(), VerifyError> {
        self.v
            .verify(&Bytes::from_slice(&self.e, proof), &self.public_inputs)
    }

    fn parsed(&self) -> (ZkProof, ZkTranscript) {
        let proof = load_zk_proof(&self.e, &Bytes::from_slice(&self.e, &self.proof)).unwrap();
        let t = self.v.transcript(&proof, &self.public_inputs).unwrap();
        (proof, t)
    }

    fn fr(&self, v: u64) -> Fr {
        Fr::from_u64(&self.e, v)
    }
}

/// `proof` with the 32-byte word at `at` replaced.
fn with_word(proof: &[u8], at: usize, word: [u8; 32]) -> Vec<u8> {
    let mut p = proof.to_vec();
    p[at..at + 32].copy_from_slice(&word);
    p
}

/// `proof` with the canonical scalar at `at` changed by one.
fn nudged(proof: &[u8], at: usize) -> Vec<u8> {
    let mut p = proof.to_vec();
    p[at + 31] ^= 1;
    p
}

/// The 128-byte limb encoding of the G1 generator `(1, 2)`.
fn generator_limbs() -> [u8; 128] {
    let mut g = [0u8; 128];
    g[31] = 1;
    g[95] = 2;
    g
}

const SCALAR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[test]
fn every_committed_zk_proof_verifies_and_proofs_are_randomized() {
    for name in FIXTURES {
        let c = Case::new(name);
        assert_eq!(c.proof.len(), ZK_PROOF_BYTES, "{name}");
        c.verify(&c.proof)
            .unwrap_or_else(|err| panic!("{name}: {err:?}"));
    }
    // bb.js (the browser prover) proved the same statement as the CLI; the
    // two proofs differ and both verify.
    let c = Case::new("lost_key");
    let bbjs = read("testdata/zk/lost_key/proof.bbjs");
    assert_ne!(bbjs, c.proof);
    c.verify(&bbjs).unwrap();
}

#[test]
fn the_layout_is_bbs() {
    assert_eq!(at::END, ZK_PROOF_BYTES);
    assert_eq!(ZK_PROOF_BYTES, 507 * 32);
    let c = Case::new("lost_key");
    let (p, _) = c.parsed();
    let word = |o: usize| -> [u8; 32] { c.proof[o..o + 32].try_into().unwrap() };
    assert_eq!(p.libra_sum.to_bytes(), word(at::LIBRA_SUM));
    assert_eq!(p.libra_evaluation.to_bytes(), word(at::LIBRA_EVALUATION));
    assert_eq!(p.gemini_masking_eval.to_bytes(), word(at::MASKING_EVAL));
    for r in [0, LOG_N - 1, LOG_N, 27] {
        for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            assert_eq!(
                p.sumcheck_univariates[r][i].to_bytes(),
                word(at::univariate(r, i))
            );
        }
    }
    for i in 0..NUM_SMALL_IPA_EVALUATIONS {
        assert_eq!(
            p.libra_poly_evals[i].to_bytes(),
            word(at::LIBRA_POLY_EVALS + 32 * i)
        );
    }
    assert_eq!(
        p.base.sumcheck_evaluations[0].to_bytes(),
        word(at::EVALUATIONS)
    );
    assert_eq!(
        p.base.gemini_a_evaluations[0].to_bytes(),
        word(at::GEMINI_EVALS)
    );
    // The honest prover's padding: zero univariates and Gemini evaluations
    // past log n.
    for r in LOG_N..28 {
        for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            assert_eq!(word(at::univariate(r, i)), [0; 32]);
        }
        assert_eq!(word(at::GEMINI_EVALS + 32 * r), [0; 32]);
    }
}

#[test]
fn non_zk_proofs_are_refused() {
    let c = Case::new("lost_key");
    let non_zk = read("testdata/zk/lost_key/proof.non-zk");
    // It is a valid proof of the same statement, for the audited non-ZK
    // verifier and the same key ...
    let vk = Bytes::from_slice(
        &c.e,
        &read("crates/perch-zk-adapter/vk/perch_zk_recovery.vk"),
    );
    UltraHonkVerifier::new(&c.e, &vk)
        .unwrap()
        .verify(&Bytes::from_slice(&c.e, &non_zk), &c.public_inputs)
        .unwrap();
    // ... which the ZK verifier refuses by length,
    assert!(matches!(c.verify(&non_zk), Err(VerifyError::InvalidInput)));
    // and refuses re-encoded in the ZK layout with no masking (zero Libra
    // values, identity commitments, each round's ninth evaluation zero).
    let mut reencoded = vec![0u8; ZK_PROOF_BYTES];
    reencoded[..at::LIBRA_CONCATENATION].copy_from_slice(&non_zk[..512 + 8 * 128]);
    let non_zk_univariates = 512 + 8 * 128;
    for r in 0..28 {
        for i in 0..8 {
            let from = non_zk_univariates + (r * 8 + i) * 32;
            reencoded[at::univariate(r, i)..at::univariate(r, i) + 32]
                .copy_from_slice(&non_zk[from..from + 32]);
        }
    }
    let non_zk_evaluations = non_zk_univariates + 28 * 8 * 32;
    reencoded[at::EVALUATIONS..at::LIBRA_EVALUATION]
        .copy_from_slice(&non_zk[non_zk_evaluations..non_zk_evaluations + 40 * 32]);
    let non_zk_folds = non_zk_evaluations + 40 * 32;
    reencoded[at::FOLDS..at::LIBRA_POLY_EVALS]
        .copy_from_slice(&non_zk[non_zk_folds..non_zk_folds + 27 * 128 + 28 * 32]);
    reencoded[at::SHPLONK_Q..].copy_from_slice(&non_zk[non_zk.len() - 256..]);
    assert!(c.verify(&reencoded).is_err());
}

#[test]
fn malformed_zk_proofs_are_refused_at_parse_time() {
    let c = Case::new("lost_key");
    let invalid = |p: &[u8], what: &str| {
        assert!(
            matches!(c.verify(p), Err(VerifyError::InvalidInput)),
            "{what}"
        );
    };
    invalid(&[], "empty");
    invalid(&c.proof[..ZK_PROOF_BYTES - 32], "one field short");
    invalid(&c.proof[..ZK_PROOF_BYTES - 1], "one byte short");
    invalid(&[c.proof.as_slice(), &[0; 32]].concat(), "one field long");

    for (field, o) in [
        ("libra sum", at::LIBRA_SUM),
        ("ninth evaluation of round 0", at::univariate(0, 8)),
        ("libra evaluation", at::LIBRA_EVALUATION),
        ("masking evaluation", at::MASKING_EVAL),
        ("libra poly evaluation 0", at::LIBRA_POLY_EVALS),
        ("libra poly evaluation 3", at::LIBRA_POLY_EVALS + 96),
    ] {
        invalid(
            &with_word(&c.proof, o, SCALAR_MODULUS),
            &format!("non-canonical {field}"),
        );
    }
    for o in at::COMMITMENTS {
        // x_lo carries bits above 2^136.
        let mut p = c.proof.clone();
        p[o] = 1;
        invalid(&p, &format!("non-canonical limb at {o}"));
        // In range, off the curve.
        let mut p = c.proof.clone();
        p[o + 64 + 31] ^= 1;
        invalid(&p, &format!("off-curve point at {o}"));
    }
    let mut one = [0u8; 32];
    one[31] = 1;
    invalid(
        &with_word(&c.proof, at::GEMINI_EVALS + 32 * LOG_N, one),
        "non-zero Gemini padding",
    );
}

#[test]
fn every_zk_only_field_is_bound() {
    let c = Case::new("lost_key");
    let rejected = |p: &[u8], what: &str| {
        assert!(
            matches!(
                c.verify(p),
                Err(VerifyError::SumcheckFailed | VerifyError::ShplonkFailed)
            ),
            "{what} was not rejected by the checks"
        );
    };
    let mut scalars = vec![
        ("libra sum", at::LIBRA_SUM),
        ("libra evaluation", at::LIBRA_EVALUATION),
        ("masking evaluation", at::MASKING_EVAL),
        ("ninth evaluation of round 0", at::univariate(0, 8)),
        (
            "ninth evaluation of the last real round",
            at::univariate(LOG_N - 1, 8),
        ),
        // Padded rounds are bound through the transcript and the Libra check.
        ("an evaluation of a padded round", at::univariate(20, 3)),
    ];
    for i in 0..NUM_SMALL_IPA_EVALUATIONS {
        scalars.push(("a libra poly evaluation", at::LIBRA_POLY_EVALS + 32 * i));
    }
    for (what, o) in scalars {
        rejected(&nudged(&c.proof, o), what);
    }
    for o in at::COMMITMENTS {
        let mut p = c.proof.clone();
        p[o..o + 128].copy_from_slice(&generator_limbs());
        rejected(&p, &format!("commitment at {o} replaced"));
    }
}

/// Each ZK addition is load-bearing on its own: with the honest transcript
/// held fixed, changing only what one check reads makes that check fail.
#[test]
fn each_zk_check_rejects_on_its_own() {
    let c = Case::new("lost_key");
    let e = &c.e;
    let vk = c.v.get_vk();
    let (p, t) = c.parsed();
    let one = c.fr(1);
    verify_zk_sumcheck(e, &p, &t, vk).unwrap();
    let consistency = |p: &ZkProof, t: &ZkTranscript| {
        check_libra_evaluations_consistency(
            e,
            &p.libra_poly_evals,
            &t.base.gemini_r,
            &t.base.sumcheck_u_challenges,
            &p.libra_evaluation,
        )
    };
    consistency(&p, &t).unwrap();
    verify_zk_shplemini(e, &p, vk, &t).unwrap();

    // Sumcheck: the Libra-corrected target, the ninth evaluation, and the
    // Libra-corrected final value.
    let mut q = p.clone();
    q.libra_sum = &q.libra_sum + &one;
    assert!(verify_zk_sumcheck(e, &q, &t, vk).is_err(), "libra sum");
    let mut u = t.clone();
    u.libra_challenge = &u.libra_challenge + &one;
    assert!(
        verify_zk_sumcheck(e, &p, &u, vk).is_err(),
        "libra challenge"
    );
    let mut q = p.clone();
    q.sumcheck_univariates[3][8] = &q.sumcheck_univariates[3][8] + &one;
    assert!(
        verify_zk_sumcheck(e, &q, &t, vk).is_err(),
        "ninth evaluation"
    );
    let mut q = p.clone();
    q.libra_evaluation = &q.libra_evaluation + &one;
    assert!(
        verify_zk_sumcheck(e, &q, &t, vk).is_err(),
        "claimed evaluation"
    );

    // The small-subgroup IPA identity.
    assert!(consistency(&q, &t).is_err(), "claimed evaluation (IPA)");
    for i in 0..NUM_SMALL_IPA_EVALUATIONS {
        let mut q = p.clone();
        q.libra_poly_evals[i] = &q.libra_poly_evals[i] + &one;
        assert!(consistency(&q, &t).is_err(), "libra poly evaluation {i}");
        assert!(verify_zk_shplemini(e, &q, vk, &t).is_err(), "opening {i}");
    }
    let mut u = t.clone();
    u.base.sumcheck_u_challenges[27] = &u.base.sumcheck_u_challenges[27] + &one;
    assert!(consistency(&p, &u).is_err(), "padded round's challenge");
    for r in [Fr::from_array(e, &SUBGROUP_GENERATOR), one.clone()] {
        let mut u = t.clone();
        u.base.gemini_r = r;
        assert_eq!(
            consistency(&p, &u),
            Err("zk: Gemini challenge is in the small subgroup")
        );
    }

    // Shplemini: the masking polynomial and each Libra commitment are opened.
    let mut q = p.clone();
    q.gemini_masking_eval = &q.gemini_masking_eval + &one;
    assert!(
        verify_zk_shplemini(e, &q, vk, &t).is_err(),
        "masking evaluation"
    );
    let mut q = p.clone();
    q.gemini_masking_poly = G1Point::generator(e);
    assert!(
        verify_zk_shplemini(e, &q, vk, &t).is_err(),
        "masking commitment"
    );
    for i in 0..3 {
        let mut q = p.clone();
        q.libra_commitments[i] = G1Point::generator(e);
        assert!(
            verify_zk_shplemini(e, &q, vk, &t).is_err(),
            "libra commitment {i}"
        );
    }
}

#[test]
fn constants_are_bbs() {
    let e = Env::default();
    let g = Fr::from_array(&e, &SUBGROUP_GENERATOR);
    let g_inv = Fr::from_array(&e, &SUBGROUP_GENERATOR_INVERSE);
    let one = Fr::one(&e);
    assert_eq!(SUBGROUP_SIZE, 256);
    assert_eq!(g.pow(SUBGROUP_SIZE as u64), one);
    assert_ne!(
        g.pow(SUBGROUP_SIZE as u64 / 2),
        one,
        "g has order exactly 256"
    );
    assert_eq!(&g * &g_inv, one);
    // Nine-point barycentric denominators dᵢ = ∏_{j≠i} (i − j).
    for (i, d) in ZK_BARYCENTRIC_DENOMINATORS.iter().enumerate() {
        let want: i64 = (0..ZK_BATCHED_RELATION_PARTIAL_LENGTH as i64)
            .filter(|&j| j != i as i64)
            .map(|j| i as i64 - j)
            .product();
        assert_eq!(*d, want, "d{i}");
    }
}
