#![no_std]

use soroban_sdk::{
    bytesn,
    crypto::{bls12_381::Bls12381Fr, bn254::Bn254Fr},
    symbol_short, Env, Symbol, Vec, U256,
};

pub(crate) mod poseidon;
pub(crate) mod poseidon2;

#[cfg(test)]
mod tests;

pub use poseidon::{PoseidonConfig, PoseidonSponge};
pub use poseidon2::{Poseidon2Config, Poseidon2Sponge};

/// A scalar field whose elements support addition (via [`core::ops::Add`])
/// and round-tripping through `U256`.
pub trait Field: core::ops::Add<Output = Self> + Sized {
    fn symbol() -> Symbol;
    /// Returns the field modulus. Inputs to Poseidon/Poseidon2 must be less than this value.
    fn modulus(env: &Env) -> U256;
    /// Constructs a field element from its canonical `U256` representation.
    fn from_u256(v: U256) -> Self;
    /// Returns the canonical `U256` representation of a field element.
    fn to_u256(self) -> U256;
}

impl Field for Bn254Fr {
    fn symbol() -> Symbol {
        symbol_short!("BN254")
    }

    fn modulus(env: &Env) -> U256 {
        // BN254 scalar field modulus
        U256::from_be_bytes(
            env,
            &bytesn!(
                env,
                0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            )
            .into(),
        )
    }

    fn from_u256(v: U256) -> Self {
        Bn254Fr::from_u256(v)
    }

    fn to_u256(self) -> U256 {
        Bn254Fr::to_u256(&self)
    }
}

impl Field for Bls12381Fr {
    fn symbol() -> Symbol {
        symbol_short!("BLS12_381")
    }

    fn modulus(env: &Env) -> U256 {
        // BLS12-381 scalar field modulus
        U256::from_be_bytes(
            env,
            &bytesn!(
                env,
                0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
            )
            .into(),
        )
    }

    fn from_u256(v: U256) -> Self {
        Bls12381Fr::from_u256(v)
    }

    fn to_u256(self) -> U256 {
        Bls12381Fr::to_u256(&self)
    }
}

/// Computes a Poseidon hash. The sponge construction matches circom's [Poseidon
/// implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom),
///
/// Parameters (round constants, MDS matrix, round counts) are field-specific:
/// - BN254: matches circomlib.
/// - BLS12-381: self-generated, matching
///   [poseidon-bls12381-circom](https://github.com/jmagan/poseidon-bls12381-circom).
///   Circomlib does not ship BLS12-381 parameters.
///
/// # Type Parameters
///
/// - `T`: State size. Must equal `inputs.len() + 1` (rate = T-1, capacity = 1).
/// - `F`: Field type. Use [`Bn254Fr`] for BN254 or [`Bls12381Fr`] for
///   BLS12-381.
///
/// # Supported Configurations
///
/// - BN254: `T` ∈ {2, 3, 4, 5, 6} (i.e., 1–5 inputs)
/// - BLS12-381: `T` ∈ {2, 3, 4, 5, 6} (i.e., 1–5 inputs)
///
/// # Panics
///
/// - if `inputs.len() != T - 1`
/// - if any input value ≥ the field modulus (inputs must be valid field
///   elements)
///
/// # Example
///
/// ```
/// use soroban_sdk::{bytesn, crypto::bn254::Bn254Fr, vec, Env, U256};
/// use soroban_poseidon::poseidon_hash;
///
/// let env = Env::default();
///
/// // Hash two field elements (t=3)
/// let inputs = vec![
///     &env,
///     U256::from_u32(&env, 1),
///     U256::from_u32(&env, 2),
/// ];
/// let hash = poseidon_hash::<3, Bn254Fr>(&env, &inputs);
///
/// // Matches circom's Poseidon([1, 2])
/// let expected = U256::from_be_bytes(
///     &env,
///     &bytesn!(&env, 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a).into(),
/// );
/// assert_eq!(hash, expected);
/// ```
///
/// # Performance
///
/// **WARNING**: each call to `poseidon_hash` constructs a new sponge and
/// rebuilds the full Poseidon parameter tables (MDS matrix and round
/// constants) as host objects. The permutation remains the dominant cost,
/// however, this per-call setup is avoidable overhead that adds up across
/// many hashes.
///
/// For repeated hashing — e.g. hashing leaves of a Merkle tree — construct
/// a [`PoseidonSponge`] **once** outside the loop and call `compute_hash()`
/// per item. The sponge state is reset between calls, so each hash is
/// independent:
///
/// ```
/// # use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};
/// # use soroban_poseidon::PoseidonSponge;
/// # let env = Env::default();
/// let mut sponge = PoseidonSponge::<3, Bn254Fr>::new(&env);
///
/// let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
/// let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];
///
/// let h1 = sponge.compute_hash(&inputs1); // fresh hash
/// let h2 = sponge.compute_hash(&inputs2); // another fresh hash (state was reset)
/// ```
pub fn poseidon_hash<const T: u32, F: Field>(env: &Env, inputs: &Vec<U256>) -> U256
where
    PoseidonSponge<T, F>: PoseidonConfig<T, F>,
{
    let mut sponge = PoseidonSponge::<T, F>::new(env);
    sponge.compute_hash(inputs)
}

/// Computes a Poseidon2 hash matching
/// [`noir-lang/poseidon`](https://github.com/noir-lang/poseidon/blob/main/src/poseidon2.nr)'s
/// Poseidon2 implementation.
///
/// # Type Parameters
///
/// - `T`: State size. Common usage is `T=4` (rate=3) matching noir's default.
///   Inputs longer than the rate are absorbed over multiple rounds.
/// - `F`: Field type. Use [`Bn254Fr`] for BN254 or [`Bls12381Fr`] for
///   BLS12-381.
///
/// # Supported Configurations
///
/// - BN254: `T` ∈ {2, 3, 4} (i.e., rate = 1, 2, or 3)
/// - BLS12-381: `T` ∈ {2, 3, 4} (i.e., rate = 1, 2, or 3)
///
/// # Panics
///
/// - if any input value ≥ the field modulus (inputs must be valid field
///   elements)
///
/// # Capacity Initialization
///
/// The capacity element is initialized to `inputs.len() << 64`, matching noir's
/// Poseidon2 implementation.
///
/// # Empty Inputs
///
/// Empty input is permitted. With `inputs.is_empty()`, the IV is `0`, no inputs
/// are absorbed, and the result is the Poseidon2 permutation of the all-zero
/// state — a fixed constant for each `(T, F)`. Domain separation from non-empty
/// inputs is preserved by the length-encoded IV: `hash([])` ≠ `hash([0])`.
///
/// Note: V1 [`poseidon_hash`] does *not* accept empty input: V1 only supports
/// `T ∈ {2..=6}` (rate ≥ 1), and `inputs.len()` must equal `RATE`, so the
/// minimum input length is 1.
///
/// # Example
///
/// ```
/// use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};
/// use soroban_poseidon::poseidon2_hash;
///
/// let env = Env::default();
///
/// // Hash four field elements with multi-round absorption (t=4, rate=3)
/// let inputs = vec![
///     &env,
///     U256::from_u32(&env, 1),
///     U256::from_u32(&env, 2),
///     U256::from_u32(&env, 3),
///     U256::from_u32(&env, 4),
/// ];
/// let hash = poseidon2_hash::<4, Bn254Fr>(&env, &inputs);
/// ```
///
/// # Performance
///
/// **WARNING**: each call to `poseidon2_hash` constructs a new sponge and
/// rebuilds the full Poseidon2 parameter tables (diagonal matrix and round
/// constants) as host objects. The permutation remains the dominant cost,
/// however, this per-call setup is avoidable overhead that adds up across many
/// hashes.
///
/// For repeated hashing — e.g. hashing leaves of a Merkle tree — construct a
/// [`Poseidon2Sponge`] **once** outside the loop and call `compute_hash()` per
/// item. The sponge state is reset between calls, so each hash is independent:
///
/// ```
/// # use soroban_sdk::{crypto::bn254::Bn254Fr, vec, Env, U256};
/// # use soroban_poseidon::Poseidon2Sponge;
/// # let env = Env::default();
/// let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
///
/// let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
/// let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];
///
/// let h1 = sponge.compute_hash(&inputs1); // fresh hash
/// let h2 = sponge.compute_hash(&inputs2); // another fresh hash (state was reset)
/// ```
pub fn poseidon2_hash<const T: u32, F: Field>(env: &Env, inputs: &Vec<U256>) -> U256
where
    Poseidon2Sponge<T, F>: Poseidon2Config<T, F>,
{
    let mut sponge = Poseidon2Sponge::<T, F>::new(env);
    sponge.compute_hash(inputs)
}
