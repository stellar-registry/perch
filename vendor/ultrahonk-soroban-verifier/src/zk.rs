//! PERCH DELTA: this file is not part of the audited upstream.
//!
//! Zero-knowledge flavor: Barretenberg v0.87.0 `UltraKeccakZKFlavor`
//! (`bb prove --scheme ultra_honk --oracle_hash keccak --zk`, bb.js
//! `{ keccakZK: true }`), added by perch on top of the audited non-ZK verifier
//! at the upstream commit NOTICE names. This file holds all of the new
//! verification logic. The audited files change only in visibility, so this
//! file can reuse their helpers (see NOTICE, "Perch delta"). It is unaudited
//! until the delta audit that `docs/zk/README.md` lists as an open release
//! criterion.
//!
//! The ZK flavor shares the non-ZK flavor's circuit, verification key,
//! relations, and Oink rounds. Where it differs, the code below is marked
//! `ZK:`. Every unmarked step calls, or copies line for line, the audited
//! non-ZK step of the same number:
//!
//! - Proof layout: 507 fields, not 456. A ZK proof adds three Libra
//!   commitments, the Libra sum, the Libra claimed evaluation, and four
//!   small-subgroup IPA evaluations. It also adds the Gemini masking
//!   polynomial's commitment and evaluation. Its sumcheck round univariates
//!   carry nine evaluations, not eight.
//! - Transcript: a Libra challenge follows the gate challenges, and each
//!   sumcheck round absorbs nine values. ρ also absorbs the Libra claimed
//!   evaluation, two Libra commitments, and the masking polynomial. ν also
//!   absorbs the four Libra evaluations.
//! - Sumcheck: the target starts at `libra_sum · libra_challenge`. The final
//!   relation value is scaled by the row-disabling polynomial, then corrected
//!   by `libra_evaluation · libra_challenge`.
//! - Shplemini: the masking polynomial is batched at ρ⁰, which moves the
//!   sumcheck evaluations to ρ¹…ρ⁴⁰. The three Libra commitments are opened
//!   at `r` and `g·r` with ν⁵⁸…ν⁶¹, and the small-subgroup IPA consistency
//!   check must hold.
//!
//! BB reference (v0.87.0), all under `barretenberg/cpp/src/barretenberg/`:
//!   - `stdlib_circuit_builders/ultra_keccak_zk_flavor.hpp`
//!     (`PROOF_LENGTH_WITHOUT_PUB_INPUTS`, `Transcript::deserialize_full_transcript`)
//!   - `sumcheck/sumcheck.hpp::SumcheckVerifier::verify` (`Flavor::HasZK` branches)
//!   - `polynomials/row_disabling_polynomial.hpp::RowDisablingPolynomial::evaluate_at_challenge`
//!   - `commitment_schemes/shplonk/shplemini.hpp::ShpleminiVerifier_::compute_batch_opening_claim`
//!     (`has_zk` branches) and `::add_zk_data`
//!   - `commitment_schemes/small_subgroup_ipa/small_subgroup_ipa.hpp::SmallSubgroupIPAVerifier::check_libra_evaluations_consistency`
//!   - `ecc/curves/bn254/bn254.hpp` (`SUBGROUP_SIZE`, `subgroup_generator`, `LIBRA_UNIVARIATES_LENGTH`)
//!   - `dsl/acir_proofs/honk_zk_contract.hpp`: bb's generated ZK Solidity
//!     verifier, which runs the same algorithm over the same fixed layout and
//!     is the closest line-by-line reference for this file.

use crate::{
    ec::{g1_msm, pairing_check},
    field::{batch_inverse, Fr},
    relations::accumulate_relation_evaluations,
    sumcheck::{check_sum, partially_evaluate_pow},
    transcript::{
        generate_alpha_challenges, generate_gate_challenges, generate_gemini_r_challenge,
        generate_relation_parameters_challenges, generate_shplonk_z_challenge, hash_to_fr,
        push_point, split_challenge,
    },
    types::{
        G1Point, Proof, Transcript, VerificationKey, BATCHED_RELATION_PARTIAL_LENGTH,
        CONST_PROOF_SIZE_LOG_N, NUMBER_OF_ENTITIES, NUMBER_UNSHIFTED, PAIRING_POINTS_SIZE,
    },
    utils::{
        load_vk_from_bytes, point_err, read_bytes, try_fr_word32, try_g1_at,
        validate_gemini_padding, validate_public_inputs_canonical,
    },
    verifier::{UltraHonkVerifier, VerifyError, VkLoadError},
};
use core::array;
use core::array::repeat;
use core::ops::Neg;
use soroban_sdk::{Bytes, Env};

/// ZK: evaluations per sumcheck round univariate, one more than the non-ZK
/// flavor's. It is also the length of the Libra univariates.
///
/// BB: `ultra_keccak_zk_flavor.hpp` (`BATCHED_RELATION_PARTIAL_LENGTH`),
/// `bn254.hpp` (`LIBRA_UNIVARIATES_LENGTH`)
pub const ZK_BATCHED_RELATION_PARTIAL_LENGTH: usize = BATCHED_RELATION_PARTIAL_LENGTH + 1;
/// Libra concatenation, grand-sum, and quotient commitments.
pub const NUM_LIBRA_COMMITMENTS: usize = 3;
/// Small-subgroup IPA evaluations: the concatenation at `r`, the grand sum at
/// `g·r` and at `r`, and the quotient at `r`.
pub const NUM_SMALL_IPA_EVALUATIONS: usize = 4;
/// Order of the multiplicative subgroup `H` that the Libra polynomials are
/// interpolated over. BB: `bn254.hpp::SUBGROUP_SIZE`.
pub const SUBGROUP_SIZE: usize = 256;
/// Shplonk claims reserved for interleaving. This flavor does not
/// interleave, but bb still offsets the Libra claims' powers of ν by them.
/// BB: `shplemini.hpp` (`NUM_INTERLEAVING_CLAIMS`)
const NUM_INTERLEAVING_CLAIMS: usize = 2;

/// Fields in a ZK proof: bb's `PROOF_LENGTH_WITHOUT_PUB_INPUTS` (491) plus
/// the 16-field pairing-point object.
pub const ZK_PROOF_FIELDS: usize = 507;
pub const ZK_PROOF_BYTES: usize = ZK_PROOF_FIELDS * 32;

/// Generator `g` of `H`, a primitive 256th root of unity in BN254's scalar
/// field: `5^((r − 1)/256)`, i.e. `ω^(2^20)` for the field's `2^28`-th root of
/// unity `ω = 5^((r − 1)/2^28)`. BB: `bn254.hpp::subgroup_generator`
pub const SUBGROUP_GENERATOR: [u8; 32] = [
    0x07, 0xb0, 0xc5, 0x61, 0xa6, 0x14, 0x84, 0x04, 0xf0, 0x86, 0x20, 0x4a, 0x9f, 0x36, 0xff, 0xb0,
    0x61, 0x79, 0x42, 0x54, 0x67, 0x50, 0xf2, 0x30, 0xc8, 0x93, 0x61, 0x91, 0x74, 0xa5, 0x7a, 0x76,
];
/// `g⁻¹`. BB: `bn254.hpp::subgroup_generator_inverse`
pub const SUBGROUP_GENERATOR_INVERSE: [u8; 32] = [
    0x20, 0x4b, 0xd3, 0x27, 0x74, 0x22, 0xfa, 0xd3, 0x64, 0x75, 0x1a, 0xd9, 0x38, 0xe2, 0xb5, 0xe6,
    0xa5, 0x4c, 0xf8, 0xc6, 0x87, 0x12, 0x84, 0x8a, 0x69, 0x2c, 0x55, 0x3d, 0x03, 0x29, 0xf5, 0xd6,
];

/// Barycentric Lagrange denominators over the domain `0..9`:
/// `dᵢ = ∏_{j≠i} (i − j)`. This is the nine-point analogue of the non-ZK
/// flavor's `sumcheck.rs::BARY_BYTES`, and the same values as
/// `honk_zk_contract.hpp`'s `BARYCENTRIC_LAGRANGE_DENOMINATORS`.
pub const ZK_BARYCENTRIC_DENOMINATORS: [i64; ZK_BATCHED_RELATION_PARTIAL_LENGTH] =
    [40320, -5040, 1440, -720, 576, -720, 1440, -5040, 40320];

/// Byte sizes of the ZK proof layout, in order; they must sum to
/// `ZK_PROOF_BYTES`.
const PAIRING_OBJ_BYTES: usize = PAIRING_POINTS_SIZE * 32;
/// w1, w2, w3, lookup_read_counts, lookup_read_tags, w4, lookup_inverses,
/// z_perm, then ZK: the Libra concatenation commitment.
const PROOF_HEAD_G1_BYTES: usize = 9 * 128;
const ZK_SUMCHECK_UNIV_BYTES: usize =
    CONST_PROOF_SIZE_LOG_N * ZK_BATCHED_RELATION_PARTIAL_LENGTH * 32;
const SUMCHECK_EVAL_BYTES: usize = NUMBER_OF_ENTITIES * 32;
const GEMINI_FOLD_COMMS_BYTES: usize = (CONST_PROOF_SIZE_LOG_N - 1) * 128;
const GEMINI_A_EVAL_BYTES: usize = CONST_PROOF_SIZE_LOG_N * 32;
const LIBRA_POLY_EVAL_BYTES: usize = NUM_SMALL_IPA_EVALUATIONS * 32;

const _: () = assert!(
    PAIRING_OBJ_BYTES
        + PROOF_HEAD_G1_BYTES
        + 32 // Libra sum
        + ZK_SUMCHECK_UNIV_BYTES
        + SUMCHECK_EVAL_BYTES
        + 32 // Libra claimed evaluation
        + 2 * 128 // Libra grand-sum and quotient commitments
        + 128 // Gemini masking commitment
        + 32 // Gemini masking evaluation
        + GEMINI_FOLD_COMMS_BYTES
        + GEMINI_A_EVAL_BYTES
        + LIBRA_POLY_EVAL_BYTES
        + 2 * 128 // Shplonk Q, KZG quotient
        == ZK_PROOF_BYTES
);

/// A parsed ZK proof.
///
/// `base` holds every message the two flavors share, so the audited
/// transcript rounds that read only those messages (η/β/γ, α, Gemini `r`,
/// Shplonk `z`) and `validate_gemini_padding` run on it unchanged.
/// `base.sumcheck_univariates` is left zero and never read: a ZK round has
/// nine evaluations, which are in [`ZkProof::sumcheck_univariates`].
#[derive(Clone, Debug)]
pub struct ZkProof {
    pub base: Proof,
    /// Concatenation `[G]`, grand sum `[A]`, quotient `[Q]`.
    pub libra_commitments: [G1Point; NUM_LIBRA_COMMITMENTS],
    pub libra_sum: Fr,
    pub sumcheck_univariates: [[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    pub libra_evaluation: Fr,
    pub gemini_masking_poly: G1Point,
    pub gemini_masking_eval: Fr,
    /// `G(r)`, `A(g·r)`, `A(r)`, `Q(r)`.
    pub libra_poly_evals: [Fr; NUM_SMALL_IPA_EVALUATIONS],
}

/// ZK challenges. `base.sumcheck_u_challenges`, `base.rho`, and
/// `base.shplonk_nu` come from the ZK rounds, and every other field from the
/// shared ones.
#[derive(Clone, Debug)]
pub struct ZkTranscript {
    pub base: Transcript,
    pub libra_challenge: Fr,
}

fn next_fr(env: &Env, bytes: &Bytes, boundary: &mut u32) -> Result<Fr, &'static str> {
    try_fr_word32(env, &read_bytes::<32>(bytes, boundary), 0)
}

fn next_g1(env: &Env, bytes: &Bytes, boundary: &mut u32) -> Result<G1Point, &'static str> {
    try_g1_at(env, &read_bytes::<128>(bytes, boundary), 0).map_err(point_err)
}

/// ZK: deserialize a ZK proof. Each element is decoded exactly as
/// `utils::load_proof` decodes it: scalars must be canonical, and G1 points
/// must have canonical limbs, in-range coordinates, and lie on the curve. Only
/// the layout differs.
///
/// BB: `ultra_keccak_zk_flavor.hpp::Transcript::deserialize_full_transcript`;
/// `honk_zk_contract.hpp::ZKTranscriptLib::loadProof`
pub fn load_zk_proof(env: &Env, proof_bytes: &Bytes) -> Result<ZkProof, &'static str> {
    if proof_bytes.len() as usize != ZK_PROOF_BYTES {
        return Err("zk proof bytes length mismatch");
    }
    let mut boundary = 0u32;

    // 0) pairing point object
    let ppo = read_bytes::<PAIRING_OBJ_BYTES>(proof_bytes, &mut boundary);
    let mut pairing_point_object = Fr::zero_array::<PAIRING_POINTS_SIZE>(env);
    for (i, slot) in pairing_point_object.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &ppo, i)?;
    }

    // 1–4) eight witness commitments, then ZK: the Libra concatenation commitment
    let g1_head = read_bytes::<PROOF_HEAD_G1_BYTES>(proof_bytes, &mut boundary);
    let w1 = try_g1_at(env, &g1_head, 0).map_err(point_err)?;
    let w2 = try_g1_at(env, &g1_head, 1).map_err(point_err)?;
    let w3 = try_g1_at(env, &g1_head, 2).map_err(point_err)?;
    let lookup_read_counts = try_g1_at(env, &g1_head, 3).map_err(point_err)?;
    let lookup_read_tags = try_g1_at(env, &g1_head, 4).map_err(point_err)?;
    let w4 = try_g1_at(env, &g1_head, 5).map_err(point_err)?;
    let lookup_inverses = try_g1_at(env, &g1_head, 6).map_err(point_err)?;
    let z_perm = try_g1_at(env, &g1_head, 7).map_err(point_err)?;
    let libra_concatenation = try_g1_at(env, &g1_head, 8).map_err(point_err)?;

    // ZK: Libra sum
    let libra_sum = next_fr(env, proof_bytes, &mut boundary)?;

    // 5) ZK: sumcheck univariates, nine evaluations per round (row-major)
    let su = read_bytes::<ZK_SUMCHECK_UNIV_BYTES>(proof_bytes, &mut boundary);
    let mut sumcheck_univariates: [[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH];
        CONST_PROOF_SIZE_LOG_N] = array::from_fn(|_| Fr::zero_array(env));
    for (r, row) in sumcheck_univariates.iter_mut().enumerate() {
        for (c, cell) in row.iter_mut().enumerate() {
            *cell = try_fr_word32(env, &su, r * ZK_BATCHED_RELATION_PARTIAL_LENGTH + c)?;
        }
    }

    // 6) sumcheck evaluations
    let se = read_bytes::<SUMCHECK_EVAL_BYTES>(proof_bytes, &mut boundary);
    let mut sumcheck_evaluations = Fr::zero_array::<NUMBER_OF_ENTITIES>(env);
    for (i, slot) in sumcheck_evaluations.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &se, i)?;
    }

    // ZK: Libra claimed evaluation, grand-sum and quotient commitments, Gemini
    // masking commitment and evaluation
    let libra_evaluation = next_fr(env, proof_bytes, &mut boundary)?;
    let libra_grand_sum = next_g1(env, proof_bytes, &mut boundary)?;
    let libra_quotient = next_g1(env, proof_bytes, &mut boundary)?;
    let gemini_masking_poly = next_g1(env, proof_bytes, &mut boundary)?;
    let gemini_masking_eval = next_fr(env, proof_bytes, &mut boundary)?;

    // 7) Gemini fold commitments
    let gf = read_bytes::<GEMINI_FOLD_COMMS_BYTES>(proof_bytes, &mut boundary);
    let mut gemini_fold_comms: [G1Point; CONST_PROOF_SIZE_LOG_N - 1] =
        array::from_fn(|_| G1Point::infinity(env));
    for (i, slot) in gemini_fold_comms.iter_mut().enumerate() {
        *slot = try_g1_at(env, &gf, i).map_err(point_err)?;
    }

    // 8) Gemini evaluations
    let ga = read_bytes::<GEMINI_A_EVAL_BYTES>(proof_bytes, &mut boundary);
    let mut gemini_a_evaluations = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for (i, slot) in gemini_a_evaluations.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &ga, i)?;
    }

    // ZK: small-subgroup IPA evaluations
    let le = read_bytes::<LIBRA_POLY_EVAL_BYTES>(proof_bytes, &mut boundary);
    let mut libra_poly_evals = Fr::zero_array::<NUM_SMALL_IPA_EVALUATIONS>(env);
    for (i, slot) in libra_poly_evals.iter_mut().enumerate() {
        *slot = try_fr_word32(env, &le, i)?;
    }

    // 9) Shplonk Q, KZG quotient
    let shplonk_q = next_g1(env, proof_bytes, &mut boundary)?;
    let kzg_quotient = next_g1(env, proof_bytes, &mut boundary)?;

    debug_assert_eq!(boundary as usize, ZK_PROOF_BYTES);

    Ok(ZkProof {
        base: Proof {
            pairing_point_object,
            w1,
            w2,
            w3,
            w4,
            lookup_read_counts,
            lookup_read_tags,
            lookup_inverses,
            z_perm,
            sumcheck_univariates: array::from_fn(|_| Fr::zero_array(env)),
            sumcheck_evaluations,
            gemini_fold_comms,
            gemini_a_evaluations,
            shplonk_q,
            kzg_quotient,
        },
        libra_commitments: [libra_concatenation, libra_grand_sum, libra_quotient],
        libra_sum,
        sumcheck_univariates,
        libra_evaluation,
        gemini_masking_poly,
        gemini_masking_eval,
        libra_poly_evals,
    })
}

/// ZK: the Libra challenge, from the Libra concatenation commitment and the
/// Libra sum.
///
/// BB: `sumcheck.hpp::SumcheckVerifier::verify` (`"Libra:Sum"`,
/// `"Libra:Challenge"`); `honk_zk_contract.hpp::generateLibraChallenge`
fn generate_libra_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    push_point(&mut data, &proof.libra_commitments[0]);
    data.extend_from_slice(&proof.libra_sum.to_bytes());
    let next_previous_challenge = hash_to_fr(&data);
    let libra_challenge = split_challenge(&next_previous_challenge).0;
    (libra_challenge, next_previous_challenge)
}

/// ZK: `transcript.rs::generate_sumcheck_challenges` over nine-evaluation
/// univariates.
fn generate_zk_sumcheck_challenges(
    env: &Env,
    proof: &ZkProof,
    previous_challenge: Fr,
) -> ([Fr; CONST_PROOF_SIZE_LOG_N], Fr) {
    let mut next_previous_challenge = previous_challenge;
    let mut sumcheck_challenges = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    for (r, challenge) in sumcheck_challenges.iter_mut().enumerate() {
        let mut data = Bytes::new(env);
        data.extend_from_slice(&next_previous_challenge.to_bytes());
        for c in proof.sumcheck_univariates[r].iter() {
            data.extend_from_slice(&c.to_bytes());
        }
        next_previous_challenge = hash_to_fr(&data);
        *challenge = split_challenge(&next_previous_challenge).0;
    }
    (sumcheck_challenges, next_previous_challenge)
}

/// ZK: `transcript.rs::generate_rho_challenge`, which here also absorbs the
/// Libra claimed evaluation, the Libra grand-sum and quotient commitments,
/// and the Gemini masking commitment and evaluation.
///
/// BB: `shplemini.hpp` (`"Gemini:masking_poly_comm"`, `"Gemini:masking_poly_eval"`,
/// then `"rho"`); `honk_zk_contract.hpp::generateRhoChallenge`
fn generate_zk_rho_challenge(env: &Env, proof: &ZkProof, previous_challenge: Fr) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for e in proof.base.sumcheck_evaluations.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    data.extend_from_slice(&proof.libra_evaluation.to_bytes());
    push_point(&mut data, &proof.libra_commitments[1]);
    push_point(&mut data, &proof.libra_commitments[2]);
    push_point(&mut data, &proof.gemini_masking_poly);
    data.extend_from_slice(&proof.gemini_masking_eval.to_bytes());
    let next_previous_challenge = hash_to_fr(&data);
    let rho = split_challenge(&next_previous_challenge).0;
    (rho, next_previous_challenge)
}

/// ZK: `transcript.rs::generate_shplonk_nu_challenge`, which here also
/// absorbs the four small-subgroup IPA evaluations.
///
/// BB: `shplemini.hpp` (`"Libra:concatenation_eval"` … `"Libra:quotient_eval"`,
/// then `"Shplonk:nu"`); `honk_zk_contract.hpp::generateShplonkNuChallenge`
fn generate_zk_shplonk_nu_challenge(
    env: &Env,
    proof: &ZkProof,
    previous_challenge: Fr,
) -> (Fr, Fr) {
    let mut data = Bytes::new(env);
    data.extend_from_slice(&previous_challenge.to_bytes());
    for a in proof.base.gemini_a_evaluations.iter() {
        data.extend_from_slice(&a.to_bytes());
    }
    for e in proof.libra_poly_evals.iter() {
        data.extend_from_slice(&e.to_bytes());
    }
    let next_previous_challenge = hash_to_fr(&data);
    let shplonk_nu = split_challenge(&next_previous_challenge).0;
    (shplonk_nu, next_previous_challenge)
}

/// Every Fiat–Shamir challenge of a ZK proof, in the order of
/// `transcript.rs::generate_transcript`, with the Libra challenge between
/// steps 3 and 4.
///
/// BB: `honk_zk_contract.hpp::ZKTranscriptLib::generateTranscript`
pub fn generate_zk_transcript(
    env: &Env,
    proof: &ZkProof,
    public_inputs: &Bytes,
    circuit_size: u64,
    public_inputs_size: u64,
    pub_inputs_offset: u64,
) -> ZkTranscript {
    // 1) eta/beta/gamma (shared messages only)
    let (rp, previous_challenge) = generate_relation_parameters_challenges(
        env,
        &proof.base,
        public_inputs,
        circuit_size,
        public_inputs_size,
        pub_inputs_offset,
    );

    // 2) alphas (shared messages only)
    let (alphas, previous_challenge) =
        generate_alpha_challenges(env, previous_challenge, &proof.base);

    // 3) gate challenges
    let (gate_chals, previous_challenge) = generate_gate_challenges(env, previous_challenge);

    // ZK: Libra challenge
    let (libra_challenge, previous_challenge) =
        generate_libra_challenge(env, proof, previous_challenge);

    // 4) ZK: sumcheck challenges
    let (u_chals, previous_challenge) =
        generate_zk_sumcheck_challenges(env, proof, previous_challenge);

    // 5) ZK: rho
    let (rho, previous_challenge) = generate_zk_rho_challenge(env, proof, previous_challenge);

    // 6) gemini_r (shared messages only)
    let (gemini_r, previous_challenge) =
        generate_gemini_r_challenge(env, &proof.base, previous_challenge);

    // 7) ZK: shplonk_nu
    let (shplonk_nu, previous_challenge) =
        generate_zk_shplonk_nu_challenge(env, proof, previous_challenge);

    // 8) shplonk_z (shared messages only)
    let (shplonk_z, _previous_challenge) =
        generate_shplonk_z_challenge(env, &proof.base, previous_challenge);

    ZkTranscript {
        base: Transcript {
            rel_params: rp,
            alphas,
            gate_challenges: gate_chals,
            sumcheck_u_challenges: u_chals,
            rho,
            gemini_r,
            shplonk_nu,
            shplonk_z,
        },
        libra_challenge,
    }
}

/// ZK: `sumcheck.rs::compute_next_target_sum` over the nine-point domain
/// `0..9`, with the same domain-point short circuit and batch inversion.
fn compute_next_target_sum_zk(
    round_univariate: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    round_challenge: &Fr,
    barycentric_denominators: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    point_indices: &[Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH],
    one: &Fr,
    zero: &Fr,
) -> Result<Fr, &'static str> {
    for (point, univariate) in point_indices.iter().zip(round_univariate.iter()) {
        if round_challenge == point {
            return Ok(univariate.clone());
        }
    }

    let mut denoms: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = array::from_fn(|_| zero.clone());
    let mut b_poly = one.clone();
    for i in 0..ZK_BATCHED_RELATION_PARTIAL_LENGTH {
        let diff = round_challenge - &point_indices[i];
        b_poly = b_poly * &diff;
        denoms[i] = &barycentric_denominators[i] * &diff;
    }

    let mut inv_denoms: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = array::from_fn(|_| zero.clone());
    batch_inverse(&denoms, &mut inv_denoms)
        .map_err(|_| "zk sumcheck: barycentric denominator is zero")?;

    let mut acc = zero.clone();
    for (univariate, inv_denom) in round_univariate.iter().zip(inv_denoms.iter()) {
        acc = acc + (univariate * inv_denom);
    }

    Ok(b_poly * acc)
}

/// ZK sumcheck: `sumcheck.rs::verify_sumcheck` with the three ZK changes.
///
/// BB: `sumcheck/sumcheck.hpp::SumcheckVerifier::verify` (`Flavor::HasZK`);
/// `honk_zk_contract.hpp::verifySumcheck`
pub fn verify_zk_sumcheck(
    env: &Env,
    proof: &ZkProof,
    tp: &ZkTranscript,
    vk: &VerificationKey,
) -> Result<(), &'static str> {
    let log_n = vk.log_circuit_size as usize;
    if log_n == 0 || log_n > CONST_PROOF_SIZE_LOG_N {
        return Err("zk sumcheck: log_circuit_size out of range");
    }
    let t = &tp.base;
    let zero = Fr::zero(env);
    let one = Fr::one(env);
    let barycentric_denominators: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] = array::from_fn(|i| {
        let d = ZK_BARYCENTRIC_DENOMINATORS[i];
        let magnitude = Fr::from_u64(env, d.unsigned_abs());
        if d < 0 {
            -magnitude
        } else {
            magnitude
        }
    });
    let point_indices: [Fr; ZK_BATCHED_RELATION_PARTIAL_LENGTH] =
        array::from_fn(|i| Fr::from_u64(env, i as u64));

    // ZK: the target is corrected by the Libra masking polynomial's sum over
    // the hypercube.
    let mut round_target = &proof.libra_sum * &tp.libra_challenge;
    let mut pow_partial_evaluation = one.clone();

    // 1) Each round sum check and next target/pow calculation
    for round in 0..log_n {
        let round_univariate = &proof.sumcheck_univariates[round];

        if !check_sum(round_univariate, round_target) {
            return Err("round failed");
        }

        let round_challenge = t.sumcheck_u_challenges[round].clone();
        round_target = compute_next_target_sum_zk(
            round_univariate,
            &round_challenge,
            &barycentric_denominators,
            &point_indices,
            &one,
            &zero,
        )?;
        pow_partial_evaluation = partially_evaluate_pow(
            &one,
            t.gate_challenges[round].clone(),
            pow_partial_evaluation,
            round_challenge,
        );
    }

    // 2) Final relation summation
    let grand_honk_relation_sum = accumulate_relation_evaluations(
        env,
        &proof.base.sumcheck_evaluations,
        &t.rel_params,
        &t.alphas,
        pow_partial_evaluation,
    );

    // ZK: scale by the row-disabling polynomial `1 − ∏_{i=2}^{log_n−1} uᵢ`
    // (zero on the disabled rows that hold the prover's masking values), then
    // add the Libra claimed evaluation's contribution.
    // BB: `row_disabling_polynomial.hpp::evaluate_at_challenge`
    let mut disabled = one.clone();
    for u in t.sumcheck_u_challenges.iter().take(log_n).skip(2) {
        disabled = disabled * u;
    }
    let full_honk_purported_value = grand_honk_relation_sum * (&one - &disabled)
        + &(&proof.libra_evaluation * &tp.libra_challenge);

    if full_honk_purported_value == round_target {
        Ok(())
    } else {
        Err("zk sumcheck final mismatch")
    }
}

/// ZK: the small-subgroup IPA consistency check. It ties the Libra claimed
/// evaluation to the four Libra evaluations opened at `r` and `g·r`:
///
/// `L₁(r)·A(r) + (r − g⁻¹)·(A(g·r) − A(r) − G(r)·F(r)) + L_|H|(r)·(A(r) − s) − Z_H(r)·Q(r) = 0`
///
/// Here `F` is the challenge polynomial built from the sumcheck challenges,
/// `s` is the claimed evaluation, and `Z_H(X) = X²⁵⁶ − 1`. It also refuses a
/// Gemini challenge `r` that falls in `H`, where the barycentric formula is
/// undefined.
///
/// BB: `small_subgroup_ipa.hpp::SmallSubgroupIPAVerifier::check_libra_evaluations_consistency`,
/// `::check_consistency`, `::compute_batched_barycentric_evaluations`, and
/// `compute_challenge_polynomial_coeffs`; `honk_zk_contract.hpp::checkEvalsConsistency`
pub fn check_libra_evaluations_consistency(
    env: &Env,
    libra_poly_evals: &[Fr; NUM_SMALL_IPA_EVALUATIONS],
    gemini_r: &Fr,
    u_challenges: &[Fr; CONST_PROOF_SIZE_LOG_N],
    libra_evaluation: &Fr,
) -> Result<(), &'static str> {
    let one = Fr::one(env);
    let vanishing_poly_eval = gemini_r.pow(SUBGROUP_SIZE as u64) - &one;
    if vanishing_poly_eval.is_zero() {
        return Err("zk: Gemini challenge is in the small subgroup");
    }

    // F in the Lagrange basis over H: 1, then (1, uᵢ, uᵢ², …, uᵢ⁸) for every
    // round i, including the padded rounds; the last three entries stay zero.
    let mut challenge_poly_lagrange = Fr::zero_array::<SUBGROUP_SIZE>(env);
    challenge_poly_lagrange[0] = one.clone();
    for (round, u) in u_challenges.iter().enumerate() {
        let start = 1 + ZK_BATCHED_RELATION_PARTIAL_LENGTH * round;
        challenge_poly_lagrange[start] = one.clone();
        for idx in start + 1..start + ZK_BATCHED_RELATION_PARTIAL_LENGTH {
            challenge_poly_lagrange[idx] = &challenge_poly_lagrange[idx - 1] * u;
        }
    }

    // Lagrange denominators r·g⁻ⁱ − 1, inverted together. None is zero:
    // r·g⁻ⁱ = 1 only for r in H, refused above. (bb multiplies g⁻ⁱ by r each
    // time; a running r·g⁻ⁱ gives the same values with half the products.)
    let g_inv = Fr::from_array(env, &SUBGROUP_GENERATOR_INVERSE);
    let mut denominators = Fr::zero_array::<SUBGROUP_SIZE>(env);
    let mut r_times_root_power = gemini_r.clone();
    for d in denominators.iter_mut() {
        *d = &r_times_root_power - &one;
        r_times_root_power = r_times_root_power * &g_inv;
    }
    let mut inverted = Fr::zero_array::<SUBGROUP_SIZE>(env);
    batch_inverse(&denominators, &mut inverted)
        .map_err(|_| "zk: small-subgroup Lagrange denominator is zero")?;

    // (r²⁵⁶ − 1) / 256 scales F(r), L₁(r), and L_|H|(r) alike.
    let numerator = &vanishing_poly_eval * &Fr::from_u64(env, SUBGROUP_SIZE as u64).inverse();
    let mut challenge_poly_eval = Fr::zero(env);
    for (c, inv) in challenge_poly_lagrange.iter().zip(inverted.iter()) {
        challenge_poly_eval = challenge_poly_eval + &(c * inv);
    }
    let challenge_poly_eval = challenge_poly_eval * &numerator;
    let lagrange_first = &inverted[0] * &numerator;
    let lagrange_last = &inverted[SUBGROUP_SIZE - 1] * &numerator;

    let [concatenated_at_r, grand_sum_shifted_eval, grand_sum_eval, quotient_eval] =
        libra_poly_evals;
    let mut diff = &lagrange_first * grand_sum_eval;
    diff = diff
        + &((gemini_r - &g_inv)
            * &(grand_sum_shifted_eval
                - grand_sum_eval
                - &(concatenated_at_r * &challenge_poly_eval)));
    diff = diff + &(&lagrange_last * &(grand_sum_eval - libra_evaluation))
        - &(&vanishing_poly_eval * quotient_eval);

    if diff.is_zero() {
        Ok(())
    } else {
        Err("zk: Libra evaluations are inconsistent")
    }
}

/// ZK Shplemini: `shplemini.rs::verify_shplemini` with the Gemini masking
/// polynomial and the Libra opening claims added to the same MSM, plus the
/// small-subgroup IPA consistency check. Step numbers match the audited
/// function's.
///
/// BB: `shplemini.hpp::ShpleminiVerifier_::compute_batch_opening_claim`
/// (`has_zk`) and `::add_zk_data`; `honk_zk_contract.hpp::verifyShplemini`
pub fn verify_zk_shplemini(
    env: &Env,
    proof: &ZkProof,
    vk: &VerificationKey,
    tp: &ZkTranscript,
) -> Result<(), &'static str> {
    let log_n = vk.log_circuit_size as usize;
    if log_n == 0 || log_n > CONST_PROOF_SIZE_LOG_N {
        return Err("zk shplemini: log_circuit_size out of range");
    }
    let t = &tp.base;
    let p = &proof.base;

    // 1) r^{2^i}
    let one = Fr::one(env);
    let two = Fr::from_u64(env, 2);
    let mut r_pows = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    r_pows[0] = t.gemini_r.clone();
    for i in 1..log_n {
        r_pows[i] = &r_pows[i - 1] * &r_pows[i - 1];
    }

    // The audited batch of inversions, laid out as in `verify_shplemini`,
    // plus ZK: z − g·r, last (the Libra claims at r reuse 1/(z − r) = [0]).
    const MAX_BATCH: usize = 3 * CONST_PROOF_SIZE_LOG_N + 2;
    let batch_size = 3 + log_n + 2 * (log_n - 1) + 1;
    let mut to_invert = Fr::zero_array::<MAX_BATCH>(env);
    let mut inverted = Fr::zero_array::<MAX_BATCH>(env);

    to_invert[0] = &t.shplonk_z - &r_pows[0];
    to_invert[1] = &t.shplonk_z + &r_pows[0];
    to_invert[2] = t.gemini_r.clone();

    for j in (1..=log_n).rev() {
        let u = &t.sumcheck_u_challenges[j - 1];
        to_invert[3 + (log_n - j)] = &r_pows[j - 1] * &(&one - u) + u;
    }

    let further_base = 3 + log_n;
    for j in 1..log_n {
        to_invert[further_base + 2 * (j - 1)] = &t.shplonk_z - &r_pows[j];
        to_invert[further_base + 2 * (j - 1) + 1] = &t.shplonk_z + &r_pows[j];
    }

    let libra_shifted_idx = batch_size - 1;
    let g = Fr::from_array(env, &SUBGROUP_GENERATOR);
    to_invert[libra_shifted_idx] = &t.shplonk_z - &(&g * &t.gemini_r);

    batch_inverse(&to_invert[..batch_size], &mut inverted[..batch_size]).map_err(|_| {
        "zk shplemini: batch inversion failed (zero denominator in shplonk/gemini/fold/libra)"
    })?;

    if inverted[..batch_size].iter().any(|x| x.is_zero()) {
        return Err("zk shplemini: batch inversion produced zero result");
    }

    let pos0 = inverted[0].clone();
    let neg0 = inverted[1].clone();
    let gemini_r_inv = inverted[2].clone();

    // 2) allocate arrays. The audited layout, with ZK: the masking polynomial
    // after Q, and the three Libra commitments after the fold commitments:
    //   [0]       = shplonk_Q
    //   [1]       = ZK: Gemini masking polynomial
    //   [2..=28]  = VK precomputed (27)
    //   [29..=33] = proof wires w1,w2,w3,w4,z_perm (merged shifted scalars)
    //   [34..=36] = proof lookup_inverses, read_counts, read_tags
    //   [37..=63] = gemini_fold_comms (27)
    //   [64..=66] = ZK: Libra concatenation, grand sum, quotient
    //   [67]      = generator with const_acc scalar
    //   [68]      = kzg_quotient with scalar z
    const TOTAL: usize =
        1 + 1 + NUMBER_UNSHIFTED + (CONST_PROOF_SIZE_LOG_N - 1) + NUM_LIBRA_COMMITMENTS + 1 + 1;
    let mut scalars = Fr::zero_array::<TOTAL>(env);
    let mut coms = repeat::<G1Point, TOTAL>(G1Point::infinity(env));

    // 3) compute shplonk weights
    let unshifted = &t.shplonk_nu * &neg0 + &pos0;
    let shifted = gemini_r_inv * (&pos0 - &(&t.shplonk_nu * &neg0));
    let neg_unshifted = -&unshifted;
    let neg_shifted = -&shifted;
    // 4) shplonk_Q
    scalars[0] = one.clone();
    coms[0] = p.shplonk_q.clone();

    // ZK: the masking polynomial is batched at ρ⁰.
    scalars[1] = neg_unshifted.clone();
    coms[1] = proof.gemini_masking_poly.clone();

    // 5) weight sumcheck evals. ZK: they start at ρ¹, and the batched
    // evaluation starts from the masking polynomial's evaluation.
    let mut rho_pow = t.rho.clone();
    let mut eval_acc = proof.gemini_masking_eval.clone();
    let mut eval_scalars = Fr::zero_array::<NUMBER_OF_ENTITIES>(env);
    for (idx, eval) in p
        .sumcheck_evaluations
        .iter()
        .take(NUMBER_OF_ENTITIES)
        .enumerate()
    {
        let scalar = if idx < NUMBER_UNSHIFTED {
            neg_unshifted.clone()
        } else {
            neg_shifted.clone()
        } * &rho_pow;
        eval_scalars[idx] = scalar;
        eval_acc = eval_acc + &(eval * &rho_pow);
        rho_pow = rho_pow * &t.rho;
    }

    for (unshifted, shifted) in [(27, 35), (28, 36), (29, 37), (30, 38), (31, 39)] {
        eval_scalars[unshifted] = eval_scalars[unshifted].clone() + eval_scalars[shifted].clone();
    }

    // 6) load VK & proof (deduplicated), one slot later than the audited
    // layout (ZK: after the masking polynomial)
    {
        let mut j = 2;
        macro_rules! push_vk {
            ($($field:ident),+ $(,)?) => {
                $(
                    coms[j] = vk.$field.clone();
                    scalars[j] = eval_scalars[j - 2].clone();
                    j += 1;
                )+
            };
        }
        push_vk![
            qm,
            qc,
            ql,
            qr,
            qo,
            q4,
            q_lookup,
            q_arith,
            q_delta_range,
            q_elliptic,
            q_aux,
            q_poseidon2_external,
            q_poseidon2_internal,
            s1,
            s2,
            s3,
            s4,
            id1,
            id2,
            id3,
            id4,
            t1,
            t2,
            t3,
            t4,
            lagrange_first,
            lagrange_last
        ];

        for (com, eval_idx) in [
            (&p.w1, 27),
            (&p.w2, 28),
            (&p.w3, 29),
            (&p.w4, 30),
            (&p.z_perm, 31),
            (&p.lookup_inverses, 32),
            (&p.lookup_read_counts, 33),
            (&p.lookup_read_tags, 34),
        ] {
            coms[j] = com.clone();
            scalars[j] = eval_scalars[eval_idx].clone();
            j += 1;
        }
        debug_assert_eq!(j, 2 + NUMBER_UNSHIFTED);
    }

    // 7) folding rounds
    let mut fold_pos = Fr::zero_array::<CONST_PROOF_SIZE_LOG_N>(env);
    let mut cur = eval_acc;
    for j in (1..=log_n).rev() {
        let r2 = &r_pows[j - 1];
        let u = &t.sumcheck_u_challenges[j - 1];
        let fold_lin = r2 * &(&one - u) - u;
        let num = r2 * &cur * &two - &(&p.gemini_a_evaluations[j - 1] * &fold_lin);
        let den_inv = inverted[3 + (log_n - j)].clone();
        cur = num * &den_inv;
        fold_pos[j - 1] = cur.clone();
    }
    // 8) accumulate constant term
    let nu_sq = &t.shplonk_nu * &t.shplonk_nu;
    let mut const_acc =
        &fold_pos[0] * &pos0 + &(&p.gemini_a_evaluations[0] * &t.shplonk_nu * &neg0);
    let mut v_pow = nu_sq.clone();
    // 9) further folding + commit
    let base = 2 + NUMBER_UNSHIFTED;
    for j in 1..log_n {
        let pos_inv = inverted[further_base + 2 * (j - 1)].clone();
        let neg_inv = inverted[further_base + 2 * (j - 1) + 1].clone();
        let sp = &v_pow * &pos_inv;
        let sn = &v_pow * &t.shplonk_nu * &neg_inv;

        scalars[base + j - 1] = -(&sp + &sn);
        const_acc = const_acc + &(&p.gemini_a_evaluations[j] * &sn) + &(&fold_pos[j] * &sp);

        v_pow = v_pow * &nu_sq;

        coms[base + j - 1] = p.gemini_fold_comms[j - 1].clone();
    }

    coms[((log_n - 1) + base)..((CONST_PROOF_SIZE_LOG_N - 1) + base)]
        .clone_from_slice(&p.gemini_fold_comms[(log_n - 1)..(CONST_PROOF_SIZE_LOG_N - 1)]);

    // ZK: the Libra opening claims G(r), A(g·r), A(r), Q(r), batched with
    // ν^(2·CONST_PROOF_SIZE_LOG_N + NUM_INTERLEAVING_CLAIMS + i), i = 0..4.
    // The exponent counts every Gemini slot, dummy rounds included, so it
    // does not depend on log_n. Both grand-sum claims open [A], so their
    // scalars are summed.
    // BB: `shplemini.hpp::add_zk_data`
    let libra_base = base + (CONST_PROOF_SIZE_LOG_N - 1);
    let libra_denominators = [
        pos0.clone(),
        inverted[libra_shifted_idx].clone(),
        pos0.clone(),
        pos0.clone(),
    ];
    let mut nu_pow = t
        .shplonk_nu
        .pow((2 * CONST_PROOF_SIZE_LOG_N + NUM_INTERLEAVING_CLAIMS) as u64);
    let mut libra_scalars = Fr::zero_array::<NUM_SMALL_IPA_EVALUATIONS>(env);
    for i in 0..NUM_SMALL_IPA_EVALUATIONS {
        let scaling_factor = &libra_denominators[i] * &nu_pow;
        const_acc = const_acc + &(&scaling_factor * &proof.libra_poly_evals[i]);
        libra_scalars[i] = scaling_factor.neg();
        nu_pow = nu_pow * &t.shplonk_nu;
    }
    coms[libra_base] = proof.libra_commitments[0].clone();
    scalars[libra_base] = libra_scalars[0].clone();
    coms[libra_base + 1] = proof.libra_commitments[1].clone();
    scalars[libra_base + 1] = &libra_scalars[1] + &libra_scalars[2];
    coms[libra_base + 2] = proof.libra_commitments[2].clone();
    scalars[libra_base + 2] = libra_scalars[3].clone();

    // ZK: the Libra evaluations must be consistent with the claimed evaluation.
    check_libra_evaluations_consistency(
        env,
        &proof.libra_poly_evals,
        &t.gemini_r,
        &t.sumcheck_u_challenges,
        &proof.libra_evaluation,
    )?;

    // 10) add generator
    let one_idx = libra_base + NUM_LIBRA_COMMITMENTS;
    coms[one_idx] = G1Point::generator(env);
    scalars[one_idx] = const_acc;

    // 11) add quotient
    let q_idx = one_idx + 1;
    debug_assert_eq!(q_idx, TOTAL - 1);
    coms[q_idx] = p.kzg_quotient.clone();
    scalars[q_idx] = t.shplonk_z.clone();

    // 12) MSM + pairing
    let p0 = g1_msm(env, &coms, &scalars)?;
    let p1 = p.kzg_quotient.0.clone().neg();
    if pairing_check(env, &p0, &p1) {
        Ok(())
    } else {
        Err("Shplonk pairing check failed")
    }
}

/// Verifier for `UltraKeccakZKFlavor` proofs: [`UltraHonkVerifier`] for the
/// zero-knowledge flavor. The verification key is the same one the non-ZK
/// flavor uses (`bb write_vk --scheme ultra_honk --oracle_hash keccak`), and it
/// is parsed and validated by the audited `load_vk_from_bytes`.
pub struct UltraHonkZkVerifier {
    env: Env,
    vk: VerificationKey,
}

impl UltraHonkZkVerifier {
    pub fn new(env: &Env, vk_bytes: &Bytes) -> Result<Self, VkLoadError> {
        load_vk_from_bytes(env, vk_bytes).map(|vk| Self {
            env: env.clone(),
            vk,
        })
    }

    pub fn get_vk(&self) -> &VerificationKey {
        &self.vk
    }

    /// Verify a ZK proof against the loaded key: `UltraHonkVerifier::verify`'s
    /// seven steps, with steps 1, 4, 6, and 7 in their ZK form.
    ///
    /// BB: `ultra_verifier.cpp::UltraVerifier_<UltraKeccakZKFlavor>::verify_proof`
    pub fn verify(
        &self,
        proof_bytes: &Bytes,
        public_inputs_bytes: &Bytes,
    ) -> Result<(), VerifyError> {
        let env = &self.env;
        // 1) ZK: parse the ZK layout
        let proof = load_zk_proof(env, proof_bytes).map_err(|_| VerifyError::InvalidInput)?;

        // 2)–5)
        let t = self.transcript(&proof, public_inputs_bytes)?;

        // 6) ZK: sum-check
        verify_zk_sumcheck(env, &proof, &t, &self.vk).map_err(|_| VerifyError::SumcheckFailed)?;

        // 7) ZK: Shplemini (Gemini + Shplonk + KZG) and the Libra consistency check
        verify_zk_shplemini(env, &proof, &self.vk, &t).map_err(|_| VerifyError::ShplonkFailed)?;

        Ok(())
    }

    /// Steps 2–5 of [`Self::verify`] for a parsed proof: the padding and
    /// public-input checks, then every challenge and the public-input delta.
    /// Exposed so tests can run steps 6 and 7 against a fixed transcript.
    pub fn transcript(
        &self,
        proof: &ZkProof,
        public_inputs_bytes: &Bytes,
    ) -> Result<ZkTranscript, VerifyError> {
        let env = &self.env;
        // 2) reject non-canonical padding in the unused Gemini evaluation slots
        validate_gemini_padding(&proof.base, self.vk.log_circuit_size as usize)
            .map_err(|_| VerifyError::InvalidInput)?;

        // 3) validate public inputs (alignment, canonical encodings, count vs VK)
        if !public_inputs_bytes.len().is_multiple_of(32) {
            return Err(VerifyError::InvalidInput);
        }
        validate_public_inputs_canonical(public_inputs_bytes)
            .map_err(|_| VerifyError::InvalidInput)?;
        let provided = (public_inputs_bytes.len() / 32) as u64;
        let expected = self
            .vk
            .public_inputs_size
            .checked_sub(PAIRING_POINTS_SIZE as u64)
            .ok_or(VerifyError::InvalidInput)?;
        if expected != provided {
            return Err(VerifyError::InvalidInput);
        }

        // 4) ZK: Fiat–Shamir transcript
        let pis_total = provided + PAIRING_POINTS_SIZE as u64;
        let pub_inputs_offset = self.vk.pub_inputs_offset;
        let mut t = generate_zk_transcript(
            env,
            proof,
            public_inputs_bytes,
            self.vk.circuit_size,
            pis_total,
            pub_inputs_offset,
        );

        // 5) Public delta
        t.base.rel_params.public_inputs_delta = UltraHonkVerifier::compute_public_input_delta(
            env,
            public_inputs_bytes,
            &proof.base.pairing_point_object,
            &t.base.rel_params.beta,
            &t.base.rel_params.gamma,
            pub_inputs_offset,
            self.vk.circuit_size,
        )
        .map_err(|_| VerifyError::InvalidInput)?;

        Ok(t)
    }
}
