use crate::{
    poseidon::{
        params::{get_mds_bn254_t_3, get_rc_bn254_t_3, SBOX_D},
        PoseidonSponge,
    },
    poseidon_hash,
};
use soroban_sdk::{
    bytesn,
    crypto::{bls12_381::Bls12381Fr, bn254::Bn254Fr},
    vec, Env, Symbol, U256,
};

// Poseidon tests

// This test case matches circom hash([1, 2]) with t=3: https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js#L47
#[test]
fn test_poseidon_bn254_hash_1_2() {
    let env = Env::default();

    // Input: [1, 2]
    let inputs = vec![
        &env,
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

    // Expected output: 7853200120776062878684798364095072458815029376092732009249414926327459813530
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([3, 4]) with t=3: https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js#L57
#[test]
fn test_poseidon_bn254_hash_3_4() {
    let env = Env::default();

    // Input: [3, 4]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output: 14763215145315200506921711489642608356394854266165572616578112107564877678998
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x20a3af0435914ccd84b806164531b0cd36e37d4efb93efab76913a93e1f30996
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1]) with t=2 (N=1)
#[test]
fn test_poseidon_bn254_hash_1() {
    let env = Env::default();

    // Input: [1]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<2, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3]) with t=4 (N=3)
#[test]
fn test_poseidon_bn254_hash_1_2_3() {
    let env = Env::default();

    // Input: [1, 2, 3]
    let inputs = vec![
        &env,
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

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<4, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3, 4]) with t=5 (N=4)
#[test]
fn test_poseidon_bn254_hash_1_2_3_4() {
    let env = Env::default();

    // Input: [1, 2, 3, 4]
    let inputs = vec![
        &env,
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<5, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3, 4, 5]) with t=6 (N=5)
#[test]
fn test_poseidon_bn254_hash_1_2_3_4_5() {
    let env = Env::default();

    // Input: [1, 2, 3, 4, 5]
    let inputs = vec![
        &env,
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000005
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<6, Bn254Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_bls12_381_hash_1_2() {
    let env = Env::default();

    // Input: [1, 2]
    let inputs = vec![
        &env,
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

    // Expected output
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x3fb8310b0e962b75bffec5f9cfcbf3f965a7b1d2dcac8d95ccb13d434e08e5fa
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1]) with t=2 (N=1)
#[test]
fn test_poseidon_bls12_381_hash_1() {
    let env = Env::default();

    // Input: [1]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x49a66f6b01dbc6440d1a5f920e027b94429916f2c821a920cf6203ad3de56cea
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<2, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3]) with t=4 (N=3)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3() {
    let env = Env::default();

    // Input: [1, 2, 3]
    let inputs = vec![
        &env,
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

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x5ad8bcfa9754b5bc043cc74dea65ae15e3fdb0c2295970aaacfc116c802d9895
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<4, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3, 4]) with t=5 (N=4)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3_4() {
    let env = Env::default();

    // Input: [1, 2, 3, 4]
    let inputs = vec![
        &env,
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2ebfd520dd8b5f26dfdc74e4ca0861495e119e6b43f7df3369dbb2f190cd5866
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<5, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3, 4, 5]) with t=6 (N=5)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3_4_5() {
    let env = Env::default();

    // Input: [1, 2, 3, 4, 5]
    let inputs = vec![
        &env,
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000005
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2c0507691a38c8c109572be56878c10a34a741fafe3e6d04c3d1e0be60ddd781
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<6, Bls12381Fr>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_permutation_t3() {
    let env = Env::default();

    // Input: [0, 1, 2] (capacity=0, rate=[1,2])
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
    let t = 3;
    let mds = get_mds_bn254_t_3(&env);
    let rc = get_rc_bn254_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 57;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon_permutation(&input, field, t, d, rounds_f, rounds_p, &mds, &rc);

    // Expected output[0] = 7853200120776062878684798364095072458815029376092732009249414926327459813530
    let expected_0 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    assert_eq!(result.len(), 3);
    assert_eq!(result.get_unchecked(0), expected_0);
}

// ============================================================================
// Tests for poseidon_hash top-level function
// ============================================================================

#[test]
fn test_poseidon_hash_bn254_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    let result = poseidon_hash::<3, Bn254Fr>(&env, &inputs);
    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_hash_bls12_381_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x3fb8310b0e962b75bffec5f9cfcbf3f965a7b1d2dcac8d95ccb13d434e08e5fa
        )
        .into(),
    );

    let result = poseidon_hash::<3, Bls12381Fr>(&env, &inputs);
    assert_eq!(result, expected);
}

// ============================================================================
// Tests for sponge reuse (repeated hashing)
// ============================================================================

#[test]
fn test_poseidon_sponge_reuse() {
    let env = Env::default();

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);

    let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
    let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];

    // Expected outputs
    let expected1 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );
    let expected2 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x20a3af0435914ccd84b806164531b0cd36e37d4efb93efab76913a93e1f30996
        )
        .into(),
    );

    // First hash
    let result1 = sponge.compute_hash(&inputs1);
    assert_eq!(result1, expected1);

    // Second hash - should be independent
    let result2 = sponge.compute_hash(&inputs2);
    assert_eq!(result2, expected2);

    // Hash inputs1 again - should get the same result as before
    let result1_again = sponge.compute_hash(&inputs1);
    assert_eq!(result1_again, expected1);
}

#[test]
fn test_poseidon_sponge_matches_hash_function() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    // Using top-level function
    let hash_result = poseidon_hash::<3, Bn254Fr>(&env, &inputs);

    // Using sponge directly
    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(hash_result, sponge_result);
}

// ============================================================================
// Partial rate rejection tests
// ============================================================================

// Poseidon V1 requires inputs.len() == RATE (full rate), matching circom's
// behavior where nInputs determines T = nInputs + 1. Partial-rate inputs are
// rejected to prevent suffix-zero collisions from implicit zero-padding.

#[test]
#[should_panic(expected = "inputs.len() must equal rate")]
fn test_poseidon_bn254_rejects_partial_rate() {
    let env = Env::default();

    // 1 input with T=3 (rate=2) - partial rate must be rejected
    let inputs = vec![&env, U256::from_u32(&env, 1)];

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    sponge.compute_hash(&inputs); // should panic
}

// ============================================================================
// Failure mode tests
// ============================================================================

#[test]
#[should_panic(expected = "inputs.len() must equal rate")]
fn test_poseidon_sponge_inputs_exceed_rate() {
    let env = Env::default();

    // t=3 means rate=2, so 3 inputs should panic
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// ============================================================================
// Large value tests (values exceeding field modulus must panic)
// ============================================================================

// Test that values equal to or larger than the field modulus are rejected
// BN254 modulus = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_bn254_input_exceeds_modulus() {
    let env = Env::default();

    let bn254_modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bn254_modulus_plus_42.into()),
        U256::from_u32(&env, 1),
    ];

    let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Same input as `test_poseidon_bn254_input_exceeds_modulus` but routed through
// the top-level `poseidon_hash` function instead of the sponge directly.
// Asserts the panic still fires.
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_hash_bn254_input_exceeds_modulus() {
    let env = Env::default();

    let bn254_modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bn254_modulus_plus_42.into()),
        U256::from_u32(&env, 1),
    ];

    let _ = poseidon_hash::<3, Bn254Fr>(&env, &inputs); // Should panic
}

// Test that a value exactly equal to the modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_bn254_input_equals_modulus() {
    let env = Env::default();

    let bn254_modulus = bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bn254_modulus.into())];

    let mut sponge = PoseidonSponge::<2, Bn254Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that values just below the modulus are accepted
#[test]
fn test_poseidon_bn254_input_below_modulus_accepted() {
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

    let mut sponge = PoseidonSponge::<2, Bn254Fr>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}

// Test large values with BLS12-381 field
// BLS12-381 modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_bls12_381_input_exceeds_modulus() {
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

    let mut sponge = PoseidonSponge::<3, Bls12381Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Same input as `test_poseidon_bls12_381_input_exceeds_modulus` but routed
// through the top-level `poseidon_hash` function instead of the sponge
// directly. Asserts the panic still fires.
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_hash_bls12_381_input_exceeds_modulus() {
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

    let _ = poseidon_hash::<3, Bls12381Fr>(&env, &inputs); // Should panic
}

// Test that a value exactly equal to the BLS12-381 modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon_bls12_381_input_equals_modulus() {
    let env = Env::default();

    let bls_modulus = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus.into())];

    let mut sponge = PoseidonSponge::<2, Bls12381Fr>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that values just below the BLS12-381 modulus are accepted
#[test]
fn test_poseidon_bls12_381_input_below_modulus_accepted() {
    let env = Env::default();

    // modulus - 1 (largest valid input)
    let bls_modulus_minus_1 = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus_minus_1.into())];

    let mut sponge = PoseidonSponge::<2, Bls12381Fr>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}

// Empty inputs are rejected because inputs.len() must equal RATE (>= 1).
#[test]
#[should_panic(expected = "inputs.len() must equal rate")]
fn test_poseidon_bn254_empty_inputs_rejected() {
    let env = Env::default();

    let empty_inputs = vec![&env];

    let mut sponge = PoseidonSponge::<2, Bn254Fr>::new(&env);
    // This should panic
    let _ = sponge.compute_hash(&empty_inputs);
}
