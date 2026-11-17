use crate::{
    poseidon2::{
        params::{
            get_mat_diag_bls12_381_t_2, get_mat_diag_bls12_381_t_3, get_mat_diag_bls12_381_t_4,
            get_mat_diag_bn254_t_2, get_mat_diag_bn254_t_3, get_mat_diag_bn254_t_4,
            get_rc_bls12_381_t_2, get_rc_bls12_381_t_3, get_rc_bls12_381_t_4, get_rc_bn254_t_2,
            get_rc_bn254_t_3, get_rc_bn254_t_4, SBOX_D,
        },
        Poseidon2Sponge,
    },
    poseidon2_hash,
};
use soroban_sdk::{
    bytesn,
    crypto::{bls12_381::Bls12381Fr, bn254::Bn254Fr},
    vec, Env, Symbol, U256,
};

// This test matches barretenberg test case for hashing 4 inputs: https://github.com/AztecProtocol/aztec-packages/blob/b95e36c6c1a5a84ba488c720189102ecbb052d2c/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2.test.cpp#L34
#[test]
fn test_poseidon2_hash() {
    let env = Env::default();

    // Input: 4 identical field elements
    let unreduced_input = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789
        )
        .into(),
    );
    let input_value = Bn254Fr::from_u256(unreduced_input).to_u256();
    let inputs = vec![
        &env,
        input_value.clone(),
        input_value.clone(),
        input_value.clone(),
        input_value,
    ];

    // Expected output from Aztec's implementation
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2f43a0f83b51a6f5fc839dea0ecec74947637802a579fa9841930a25a0bcec11
        )
        .into(),
    );

    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env); // t=4, rate=3 matches noir
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation() {
    let env = Env::default();

    // Input: 4 identical field elements
    let input_value = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789
        )
        .into(),
    );
    let input = vec![
        &env,
        input_value.clone(),
        input_value.clone(),
        input_value.clone(),
        input_value,
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 4;
    let m_diag = get_mat_diag_bn254_t_4(&env);
    let rc = get_rc_bn254_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output (full state after permutation)
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x2bf1eaf87f7d27e8dc4056e9af975985bccc89077a21891d6c7b6ccce0631f95
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0c01fa1b8d0748becafbe452c0cb0231c38224ea824554c9362518eebdd5701f
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x018555a8eb50cf07f64b019ebaf3af3c925c93e631f3ecd455db07bbb52bbdd3
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0cbea457c91c22c6c31fd89afd2541efc2edf31736b9f721e823b2165c90fd41
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t4() {
    let env = Env::default();

    // Input: [0, 1, 2, 3]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 4u32;
    let m_diag = get_mat_diag_bn254_t_4(&env);
    let rc = get_rc_bn254_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t4() {
    let env = Env::default();

    // Input: [0, 1, 2, 3]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BLS12_381");
    let t = 4u32;
    let m_diag = get_mat_diag_bls12_381_t_4(&env);
    let rc = get_rc_bls12_381_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x28ff6c4edf9768c08ae26290487e93449cc8bc155fc2fad92a344adceb3ada6d
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0e56f2b6fad25075aa93560185b70e2b180ed7e269159c507c288b6747a0db2d
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x6d8196f28da6006bb89b3df94600acdc03d0ba7c2b0f3f4409a54c1db6bf30d0
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x07cfb49540ee456cce38b8a7d1a930a57ffc6660737f6589ef184c5e15334e36
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t2() {
    let env = Env::default();

    // Input: [0, 1]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 2u32;
    let m_diag = get_mat_diag_bn254_t_2(&env);
    let rc = get_rc_bn254_t_2(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t3() {
    let env = Env::default();

    // Input: [0, 1, 2]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 3u32;
    let m_diag = get_mat_diag_bn254_t_3(&env);
    let rc = get_rc_bn254_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t2() {
    let env = Env::default();

    // Input: [0, 1]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BLS12_381");
    let t = 2u32;
    let m_diag = get_mat_diag_bls12_381_t_2(&env);
    let rc = get_rc_bls12_381_t_2(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x73c46dd530e248a87b61d19e67fa1b4ed30fc3d09f16531fe189fb945a15ce4e
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1f0e305ee21c9366d5793b80251405032a3fee32b9dd0b5f4578262891b043b4
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t3() {
    let env = Env::default();

    // Input: [0, 1, 2]
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BLS12_381");
    let t = 3u32;
    let m_diag = get_mat_diag_bls12_381_t_3(&env);
    let rc = get_rc_bls12_381_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

// ============================================================================
// Tests for Poseidon2Sponge::compute_hash
// ============================================================================

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t4() {
    let env = Env::default();

    // 3 inputs fit in rate=3 for t=4
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic - hash again and compare
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t3() {
    let env = Env::default();

    // 2 inputs fit in rate=2 for t=3
    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let mut sponge = Poseidon2Sponge::<3, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t2() {
    let env = Env::default();

    // 1 input fits in rate=1 for t=2
    let inputs = vec![&env, U256::from_u32(&env, 1)];

    let mut sponge = Poseidon2Sponge::<2, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bls12_381_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = Poseidon2Sponge::<4, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

// ============================================================================
// Tests for poseidon2_hash top-level function
// ============================================================================

#[test]
fn test_poseidon2_hash_bn254_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    // Top-level function should work
    let result = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);

    // Should match sponge directly
    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bls12_381_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let result = poseidon2_hash::<4, Bls12381Fr>(&env, &inputs);

    // Should match sponge directly
    let mut sponge = Poseidon2Sponge::<4, Bls12381Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bn254_t2() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1)];

    let result = poseidon2_hash::<2, Bn254Fr>(&env, &inputs);

    let mut sponge = Poseidon2Sponge::<2, Bn254Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bn254_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let result = poseidon2_hash::<3, Bn254Fr>(&env, &inputs);

    let mut sponge = Poseidon2Sponge::<3, Bn254Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

// ============================================================================
// Tests for sponge reuse (repeated hashing)
// ============================================================================

#[test]
fn test_poseidon2_sponge_reuse() {
    let env = Env::default();

    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);

    let inputs1 = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];
    let inputs2 = vec![
        &env,
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
    ];

    // First hash
    let result1 = sponge.compute_hash(&inputs1);

    // Second hash - should be independent (different inputs, different result)
    let result2 = sponge.compute_hash(&inputs2);
    assert_ne!(result1, result2);

    // Hash inputs1 again - should get the same result as the first time
    let result1_again = sponge.compute_hash(&inputs1);
    assert_eq!(result1, result1_again);
}

#[test]
fn test_poseidon2_sponge_matches_hash_function() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    // Using top-level function
    let hash_result = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);

    // Using sponge directly
    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(hash_result, sponge_result);
}

// ============================================================================
// Partial rate (inputs.len() < RATE) and multi-round absorption tests
// ============================================================================
//
// Each expected value is computed by `noir-lang/poseidon`'s Poseidon2
// implementation, which the Soroban implementation matches.

macro_rules! noir_t4_case {
    ($name:ident, $inputs:expr, $expected:literal $(,)?) => {
        #[test]
        fn $name() {
            let env = Env::default();
            let mut v = vec![&env];
            for x in $inputs {
                v.push_back(U256::from_u32(&env, *x));
            }
            let expected = U256::from_be_bytes(&env, &bytesn!(&env, $expected).into());
            let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
            assert_eq!(sponge.compute_hash(&v), expected);
        }
    };
}

// `n0..n9` cover input lengths 0, 1, 2, 3, 4, 5, 6, 7, 9 — every padding
// regime up to two mid-stream permutations for T=4, RATE=3.
noir_t4_case!(
    test_poseidon2_bn254_t4_n0,
    &[0u32; 0],
    0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n1,
    &[1u32],
    0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n2,
    &[1u32, 2],
    0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n3,
    &[1u32, 2, 3],
    0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n4,
    &[1u32, 2, 3, 4],
    0x130bf204a32cac1f0ace56c78b731aa3809f06df2731ebcf6b3464a15788b1b9
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n5,
    &[1u32, 2, 3, 4, 5],
    0x2247be7014a54d17342a7ef677f58d28877780d203860396967f5d0a18d259db
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n6,
    &[1u32, 2, 3, 4, 5, 6],
    0x07f57fcda925c06dc0a311f3f17fa0218e079b514552744a25ba8a74ee8c9e7a
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n7,
    &[1u32, 2, 3, 4, 5, 6, 7],
    0x16f929bc0d216df4b05bdc44222463edf2b9791bd949ab926eebda06a502d238
);
noir_t4_case!(
    test_poseidon2_bn254_t4_n9,
    &[1u32, 2, 3, 4, 5, 6, 7, 8, 9],
    0x174b592c95a1811beff20ff96e1276cad3d155670a909f90c3658841f0f70fea
);

// `ref_*` cases re-pin published vectors from noir-lang/poseidon's
// `src/tests.nr` (third-party cross-check, independently derived).
noir_t4_case!(
    test_poseidon2_bn254_t4_ref_1000,
    &[1000u32],
    0x16433a80e26a23547e25d61dd95fd5793d1ca2dcd78ae64cd146d3b99a35fa7c
);
noir_t4_case!(
    test_poseidon2_bn254_t4_ref_1000_2000,
    &[1000u32, 2000],
    0x118d5a5ecb25dafe99eb45cb196604a23d0b7c0cbd0c2be29e0787e59b7a1d8a
);
noir_t4_case!(
    test_poseidon2_bn254_t4_ref_1000_2000_3000,
    &[1000u32, 2000, 3000],
    0x0f1badcd0d52ced816fb6e6826fdf66ada038135d53cbb993f320ca6529223cd
);

// ============================================================================
// Equality / inequality assertions across input variations
// ============================================================================
//
// Each test computes Poseidon2 hashes for several closely-related input
// vectors and asserts the expected equality or inequality between them.
// Hash values pinned by the macro sweep above are not re-pinned here.

// Compares hash outputs for inputs that differ only in trailing zeros:
// `hash([])` vs `hash([0])`, then `hash([1])` vs `hash([1, 0])` vs
// `hash([1, 0, 0])` vs `hash([1, 0, 0, 0])`. Asserts every adjacent pair
// is unequal, plus `hash([1])` ≠ `hash([1, 0, 0, 0])`.
#[test]
fn test_poseidon2_length_distinguishes_inputs() {
    let env = Env::default();
    let one = U256::from_u32(&env, 1);
    let zero = U256::from_u32(&env, 0);

    // Anchor at empty: hash([]) (IV = 0) vs hash([0]) (IV = 1 << 64).
    let h0 = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env]);
    let h0_0 = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, zero.clone()]);
    assert_ne!(h0, h0_0);

    // Anchor at 1, sweeping trailing zeros from 0 to 3.
    let h1 = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, one.clone()]);
    let h2 = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, one.clone(), zero.clone()]);
    let h3 =
        poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, one.clone(), zero.clone(), zero.clone()]);
    let h4 = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, one, zero.clone(), zero.clone(), zero]);

    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h3, h4);
    assert_ne!(h1, h4);
}

// Compares `hash([1, 2, 3, 4])`, `hash([4, 3, 2, 1])`, and `hash([2, 1, 4, 3])`.
// Asserts every pair is unequal.
#[test]
fn test_poseidon2_order_sensitivity() {
    let env = Env::default();
    let mk = |a, b, c, d| {
        vec![
            &env,
            U256::from_u32(&env, a),
            U256::from_u32(&env, b),
            U256::from_u32(&env, c),
            U256::from_u32(&env, d),
        ]
    };

    let h_1234 = poseidon2_hash::<4, Bn254Fr>(&env, &mk(1, 2, 3, 4));
    let h_4321 = poseidon2_hash::<4, Bn254Fr>(&env, &mk(4, 3, 2, 1));
    let h_2143 = poseidon2_hash::<4, Bn254Fr>(&env, &mk(2, 1, 4, 3));

    assert_ne!(h_1234, h_4321);
    assert_ne!(h_1234, h_2143);
    assert_ne!(h_4321, h_2143);
}

// Compares `hash([1, 2, 3, 4, 5, 6])` against `hash([4, 5, 6, 1, 2, 3])` —
// the same two RATE-sized blocks in swapped order. Asserts they are unequal.
#[test]
fn test_poseidon2_block_boundary_swap() {
    let env = Env::default();
    let abc_def = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
    ];
    let def_abc = vec![
        &env,
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    assert_ne!(
        poseidon2_hash::<4, Bn254Fr>(&env, &abc_def),
        poseidon2_hash::<4, Bn254Fr>(&env, &def_abc)
    );
}

// Compares `hash([1, 2, 3])` (exactly RATE inputs) against `hash([1, 2, 3, 0])`
// (one extra zero input). Asserts they are unequal, and pins
// `hash([1, 2, 3, 0])` against the Noir reference (this input is not
// covered by the macro sweep).
#[test]
fn test_poseidon2_rate_boundary_distinguishes_extra_zero() {
    let env = Env::default();
    let in_3 = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];
    let in_3_then_zero = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
        U256::from_u32(&env, 0),
    ];

    let h_3 = poseidon2_hash::<4, Bn254Fr>(&env, &in_3);
    let h_3_then_zero = poseidon2_hash::<4, Bn254Fr>(&env, &in_3_then_zero);
    assert_ne!(h_3, h_3_then_zero);

    let exp_3_then_zero = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0a9076323d73796b1f52e9159245aa47be3f5e4f75f6a0b006a1ed3d7062775d
        )
        .into(),
    );
    assert_eq!(h_3_then_zero, exp_3_then_zero);
}

// On a single sponge, computes `hash([1..7])`, then `hash([5, 6])`, then
// `hash([1..7])` again. Asserts the `[5, 6]` result equals a fresh-sponge
// computation of the same input, and that the two `[1..7]` results are
// equal. (Distinct from `test_poseidon2_sponge_reuse`, which only covers
// single-block reuse.)
#[test]
fn test_poseidon2_sponge_resets_between_multi_round_hashes() {
    let env = Env::default();
    let in_long = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
        U256::from_u32(&env, 7),
    ];
    let in_short = vec![&env, U256::from_u32(&env, 5), U256::from_u32(&env, 6)];

    let mut shared = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    let h_long_first = shared.compute_hash(&in_long);
    let h_short_after = shared.compute_hash(&in_short);
    let h_long_again = shared.compute_hash(&in_long);

    assert_eq!(
        h_short_after,
        Poseidon2Sponge::<4, Bn254Fr>::new(&env).compute_hash(&in_short)
    );
    assert_eq!(h_long_first, h_long_again);
}

// Compares `hash([0, 0, 0])` (3 zero inputs, T=4) against `hash([])` (empty
// input). The two cases differ only in IV (`3 << 64` vs `0`) — absorbing
// zeros leaves the rate cells unchanged. Asserts they are unequal and pins
// `hash([0, 0, 0])` against the Noir reference (this input is not covered
// by the macro sweep).
#[test]
fn test_poseidon2_zero_inputs_distinguished_by_length() {
    let env = Env::default();
    let zero = U256::from_u32(&env, 0);
    let h_three_zeros =
        poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env, zero.clone(), zero.clone(), zero.clone()]);
    let h_empty = poseidon2_hash::<4, Bn254Fr>(&env, &vec![&env]);
    assert_ne!(h_three_zeros, h_empty);

    let exp_three_zeros = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2a5de47ed300af27b706aaa14762fc468f5cfc16cd8116eb6b09b0f2643ca2b9
        )
        .into(),
    );
    assert_eq!(h_three_zeros, exp_three_zeros);
}

// Computes `hash([m-1, m-1, m-1, m-1])` where `m` is the BN254 scalar
// modulus — every input is the largest valid field element. Asserts the
// result matches the Noir reference.
#[test]
fn test_poseidon2_modulus_minus_one_multi_round() {
    let env = Env::default();
    let m_minus_1 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
        )
        .into(),
    );
    let inputs = vec![
        &env,
        m_minus_1.clone(),
        m_minus_1.clone(),
        m_minus_1.clone(),
        m_minus_1,
    ];
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0503ef951856c86a9bb84b5208964f3ed61e000c4a28771f71fbce16cb85599b
        )
        .into(),
    );
    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    assert_eq!(sponge.compute_hash(&inputs), expected);
}

// Hashes `[1, 2]` under T=2, T=3, and T=4. Asserts every pair of outputs
// is unequal.
#[test]
fn test_poseidon2_cross_t_divergence() {
    let env = Env::default();
    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let h_t2 = poseidon2_hash::<2, Bn254Fr>(&env, &inputs);
    let h_t3 = poseidon2_hash::<3, Bn254Fr>(&env, &inputs);
    let h_t4 = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);

    assert_ne!(h_t2, h_t3);
    assert_ne!(h_t2, h_t4);
    assert_ne!(h_t3, h_t4);
}

// For a 7-input multi-round case, compares `poseidon2_hash::<4, Bn254Fr>`
// (top-level function) against `Poseidon2Sponge::<4, Bn254Fr>::compute_hash`
// (sponge directly). Asserts they are equal. (`test_poseidon2_sponge_matches_hash_function`
// covers the single-block case.)
#[test]
fn test_poseidon2_top_level_matches_sponge_multi_round() {
    let env = Env::default();
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
        U256::from_u32(&env, 7),
    ];
    let h_top = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);
    let h_sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env).compute_hash(&inputs);
    assert_eq!(h_top, h_sponge);
}

// ============================================================================
// Large value tests (values exceeding field modulus must panic)
// ============================================================================

// Test that values equal to or larger than the field modulus are rejected
// BN254 modulus = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bn254_input_exceeds_modulus() {
    let env = Env::default();

    let modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &modulus_plus_42.into()),
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
    ];

    let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that a value exactly equal to the BN254 modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bn254_input_equals_modulus() {
    let env = Env::default();

    let bn254_modulus = bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bn254_modulus.into())];

    let mut sponge = Poseidon2Sponge::<2, Bn254Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Same input as `test_poseidon2_bn254_input_exceeds_modulus` but routed
// through the top-level `poseidon2_hash` function instead of the sponge
// directly. Asserts the panic still fires.
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_hash_bn254_input_exceeds_modulus() {
    let env = Env::default();

    let modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &modulus_plus_42.into()),
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
    ];

    let _ = poseidon2_hash::<4, Bn254Fr>(&env, &inputs); // Should panic
}

// Test that values just below the BN254 modulus are accepted
#[test]
fn test_poseidon2_bn254_input_below_modulus_accepted() {
    let env = Env::default();

    // modulus - 1 (largest valid input)
    let bn254_modulus_minus_1 = bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bn254_modulus_minus_1.into()),
    ];

    let mut sponge = Poseidon2Sponge::<2, Bn254Fr>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}

// Test large values with BLS12-381 field
// BLS12-381 modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bls12_381_input_exceeds_modulus() {
    let env = Env::default();

    let bls_modulus_plus_123 = bytesn!(
        &env,
        // modulus + 123
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff0000007c
    );

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_be_bytes(&env, &bls_modulus_plus_123.into()),
    ];

    let mut sponge = Poseidon2Sponge::<3, Bls12381Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that a value exactly equal to the BLS12-381 modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bls12_381_input_equals_modulus() {
    let env = Env::default();

    let bls_modulus = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus.into())];

    let mut sponge = Poseidon2Sponge::<2, Bls12381Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Same input as `test_poseidon2_bls12_381_input_exceeds_modulus` but routed
// through the top-level `poseidon2_hash` function instead of the sponge
// directly. Asserts the panic still fires.
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_hash_bls12_381_input_exceeds_modulus() {
    let env = Env::default();

    let bls_modulus_plus_123 = bytesn!(
        &env,
        // modulus + 123
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff0000007c
    );

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_be_bytes(&env, &bls_modulus_plus_123.into()),
    ];

    let _ = poseidon2_hash::<3, Bls12381Fr>(&env, &inputs); // Should panic
}

// Test that values just below the BLS12-381 modulus are accepted
#[test]
fn test_poseidon2_bls12_381_input_below_modulus_accepted() {
    let env = Env::default();

    // modulus - 1 (largest valid input)
    let bls_modulus_minus_1 = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus_minus_1.into())];

    let mut sponge = Poseidon2Sponge::<2, Bls12381Fr>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}
