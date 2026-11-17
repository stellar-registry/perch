use crate::{
    poseidon2::params::{
        get_mat_diag_bls12_381_t_2, get_mat_diag_bls12_381_t_3, get_mat_diag_bls12_381_t_4,
        get_mat_diag_bn254_t_2, get_mat_diag_bn254_t_3, get_mat_diag_bn254_t_4,
        get_rc_bls12_381_t_2, get_rc_bls12_381_t_3, get_rc_bls12_381_t_4, get_rc_bn254_t_2,
        get_rc_bn254_t_3, get_rc_bn254_t_4, SBOX_D,
    },
    Field,
};
use soroban_sdk::{
    crypto::{bls12_381::Bls12381Fr, bn254::Bn254Fr},
    vec, Env, Vec, U256,
};

const CAPACITY: u32 = 1;

pub trait Poseidon2Config<const T: u32, F: Field> {
    const ROUNDS_F: u32;
    const ROUNDS_P: u32;
    const RATE: u32 = T - CAPACITY;
    fn get_m_diag(e: &Env) -> Vec<U256>;
    fn get_rc(e: &Env) -> Vec<Vec<U256>>;
}

// Internal struct storing the Poseidon2 constants, in the future we can make
// this a #[contracttype], which can be stored as contract data (to reduce the
// actual contract size)
pub(crate) struct Poseidon2Params {
    pub rounds_f: u32,
    pub rounds_p: u32,
    pub m_diag: Vec<U256>,
    pub rc: Vec<Vec<U256>>,
}

/// A Poseidon2 sponge configured for a specific state size `T` and field `F`.
///
/// This is a multi-round absorb, single-squeeze sponge. The primary benefit
/// of creating a sponge instance is to reuse the pre-computed parameters (MDS
/// matrix diagonal and round constants) across multiple independent hash
/// computations, avoiding repeated parameter initialization.
///
/// **Note**: Each call to [`compute_hash`](Self::compute_hash) resets the
/// internal state and computes a fresh hash. The sponge does not accumulate
/// state between calls.
///
/// # Example
/// ```ignore
/// // Create sponge once (initializes parameters)
/// let mut sponge = Poseidon2Sponge::<4, Bn254Fr>::new(&env);
///
/// // Compute multiple independent hashes, reusing the same parameters
/// let hash1 = sponge.compute_hash(&inputs1);
/// let hash2 = sponge.compute_hash(&inputs2);
/// ```
pub struct Poseidon2Sponge<const T: u32, F: Field> {
    env: Env,
    state: Vec<U256>,
    params: Poseidon2Params,
    _phantom: core::marker::PhantomData<F>,
}

// BN254 implementations
impl Poseidon2Config<2, Bn254Fr> for Poseidon2Sponge<2, Bn254Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bn254_t_2(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_2(e)
    }
}

impl Poseidon2Config<3, Bn254Fr> for Poseidon2Sponge<3, Bn254Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bn254_t_3(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_3(e)
    }
}

impl Poseidon2Config<4, Bn254Fr> for Poseidon2Sponge<4, Bn254Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bn254_t_4(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_4(e)
    }
}

// BLS12-381 implementations
impl Poseidon2Config<2, Bls12381Fr> for Poseidon2Sponge<2, Bls12381Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bls12_381_t_2(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_2(e)
    }
}

impl Poseidon2Config<3, Bls12381Fr> for Poseidon2Sponge<3, Bls12381Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bls12_381_t_3(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_3(e)
    }
}

impl Poseidon2Config<4, Bls12381Fr> for Poseidon2Sponge<4, Bls12381Fr> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> {
        get_mat_diag_bls12_381_t_4(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_4(e)
    }
}

impl<const T: u32, F: Field> Poseidon2Sponge<T, F>
where
    Self: Poseidon2Config<T, F>,
{
    /// Resets the sponge state with the supplied capacity IV.
    ///
    /// Layout (length `T = RATE + 1`):
    /// - `state[0..=RATE-1]`: rate cells, initialized to `0`. Filled by
    ///   [`absorb`](Self::absorb).
    /// - `state[T-1]`: capacity cell, initialized to `iv`.
    ///
    /// [`compute_hash`](Self::compute_hash) uses
    /// `iv = (inputs.len() as u128) << 64`.
    fn reset_state(&mut self, iv: U256) {
        self.state = vec![&self.env];
        for _ in 0..Self::RATE {
            self.state.push_back(U256::from_u32(&self.env, 0));
        }
        self.state.push_back(iv);
    }

    pub fn new(env: &Env) -> Self {
        let params = Poseidon2Params {
            rounds_f: <Self as Poseidon2Config<T, F>>::ROUNDS_F,
            rounds_p: <Self as Poseidon2Config<T, F>>::ROUNDS_P,
            m_diag: <Self as Poseidon2Config<T, F>>::get_m_diag(env),
            rc: <Self as Poseidon2Config<T, F>>::get_rc(env),
        };
        let mut inner = Self {
            env: env.clone(),
            state: vec![env],
            params,
            _phantom: core::marker::PhantomData,
        };
        // Initialize with default IV of 0
        inner.reset_state(U256::from_u32(env, 0));
        inner
    }

    fn perform_duplex(&mut self) {
        self.state = self.env.crypto_hazmat().poseidon2_permutation(
            &self.state,
            F::symbol(),
            T,
            SBOX_D,
            self.params.rounds_f,
            self.params.rounds_p,
            &self.params.m_diag,
            &self.params.rc,
        );
    }

    /// Absorbs `inputs` into the rate portion of the state in rate-sized
    /// chunks.
    ///
    /// Each input is added into the next rate cell (`state[0..=RATE-1]`). When
    /// a block fills the rate, the state is permuted before absorbing the next
    /// block. Unused cells in the final block are left unchanged, which is the
    /// sponge's zero-padding behavior for the initial block, and the capacity
    /// cell `state[T-1]` is not touched during absorption.
    fn absorb(&mut self, inputs: &Vec<U256>) {
        let mut idx = 0;
        for i in 0..inputs.len() {
            if idx == Self::RATE {
                self.perform_duplex();
                idx = 0;
            }
            let v = F::from_u256(inputs.get_unchecked(i));
            let state_element = F::from_u256(self.state.get_unchecked(idx));
            self.state.set(idx, (state_element + v).to_u256());
            idx += 1;
        }
    }

    /// Permutes the full state and returns the output cell.
    ///
    /// Applies the Poseidon2 permutation, then returns `state[0]` — the first
    /// rate cell.
    fn squeeze(&mut self) -> U256 {
        self.perform_duplex();
        self.state.get_unchecked(0)
    }

    /// Computes a fresh Poseidon2 hash of the inputs.
    ///
    /// This method resets the sponge state and computes a new hash from
    /// scratch. It does **not** accumulate state from previous calls, i.e. each
    /// invocation is independent. The benefit of calling this on an existing
    /// sponge (vs creating a new one) is reusing the pre-initialized
    /// parameters.
    ///
    /// The capacity element is initialized to `input.len() << 64`, matching
    /// [`noir-lang/poseidon`](https://github.com/noir-lang/poseidon/blob/main/src/poseidon2.nr)'s
    /// Poseidon2 implementation.
    ///
    /// # Empty Inputs
    ///
    /// Empty input is permitted. With `inputs.is_empty()`, the IV is `0`, no
    /// inputs are absorbed, and the result is the Poseidon2 permutation of
    /// the all-zero state — a fixed constant for each `(T, F)`. Domain
    /// separation from non-empty inputs is preserved by the length-encoded
    /// IV: `hash([])` ≠ `hash([0])`. (V1 [`PoseidonSponge::compute_hash`]
    /// rejects empty input — V1 requires `inputs.len() == RATE` and only
    /// supports `T ≥ 2`, so the minimum input length is 1.)
    ///
    /// # Panics
    /// - if any input value is greater than or equal to the field modulus.
    ///   All inputs must be valid field elements (i.e., less than the modulus).
    pub fn compute_hash(&mut self, inputs: &Vec<U256>) -> U256 {
        let modulus = F::modulus(&self.env);
        // Reject non-canonical inputs: `F::from_u256` silently reduces values
        // ≥ modulus inside `absorb`, so without this check `hash([v])` would
        // collide with `hash([v + r])` for any `v` such that `v + r` fits in
        // U256. The check is required for collision resistance.
        assert!(
            inputs.iter().all(|v| v < modulus),
            "input exceeds field modulus"
        );

        // The initial value for the capacity element: input.len() * 2^64 for Poseidon2
        let iv = U256::from_u128(&self.env, (inputs.len() as u128) << 64);
        self.reset_state(iv);
        self.absorb(inputs);
        self.squeeze()
    }
}
