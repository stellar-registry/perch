//! Host-side half of Perch's ZK recovery relation.
//!
//! `circuits/perch_zk/src/lib.nr` is the other half. Every formula here must
//! produce exactly the field element the circuit computes from the same
//! inputs, or no real proof will ever verify on-chain. With `acct` an
//! account's contract id, `enr` the enrollment id its recovery configuration
//! names, and `digest` a recovery-statement digest:
//!
//! ```text
//! inner          = H(DOM_LEAF, secret)                                  client-side commitment
//! leaf           = H(DOM_BIND, acct_hi, acct_lo, enr_hi, enr_lo, inner) computed by the pool
//! node           = H(left, right)                                       interior Merkle node
//! nullifier      = H(DOM_NULLIFIER, acct_hi, acct_lo, enr_hi, enr_lo, secret)
//! statement_hash = H(DOM_AUTH, acct_hi, acct_lo, enr_hi, enr_lo, digest_hi, digest_lo)
//! ```
//!
//! The domain constants, the 16/16 split, the canonicality rule, and the
//! statement projection are `perch-recovery-interface::zk`'s; this crate
//! adds only the hashing. `H` is Poseidon2 over BN254 with state width 4 and
//! the input length in the capacity IV — `soroban-poseidon`'s
//! `Poseidon2Sponge::<4, Bn254Fr>`, which calls the host's
//! `poseidon2_permutation`, and noir-lang/poseidon v0.2.0's
//! `Poseidon2::hash(inputs, inputs.len())` in the circuit. The `parity`
//! tests pin outputs both suites assert.
#![no_std]

use perch_recovery_interface::zk::{
    is_canonical_field, split_hi_lo, ZkStatementFields, DOM_BIND, DOM_LEAF, DOM_NULLIFIER,
};
use perch_recovery_interface::{address_payload, AddressKind};
use soroban_poseidon::Poseidon2Sponge;
use soroban_sdk::crypto::bn254::Bn254Fr;
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, U256};

pub use perch_recovery_interface::zk::BN254_SCALAR_MODULUS as FIELD_MODULUS;

/// The deepest tree the circuit family supports. The release circuit and pool
/// use this depth; `perch_zk_recovery_d24` is the documented fallback.
pub const MAX_TREE_DEPTH: u32 = 32;

/// `ZERO_HASHES[i]` is the root of an empty depth-`i` subtree:
/// `ZERO_HASHES[0] = 0` (the empty leaf) and
/// `ZERO_HASHES[i + 1] = H(ZERO_HASHES[i], ZERO_HASHES[i])`. A constant so a
/// Merkle insert does not spend `depth` extra hashes recomputing it;
/// [`Hasher::zero_hashes`] recomputes it in the tests.
pub const ZERO_HASHES: [[u8; 32]; MAX_TREE_DEPTH as usize + 1] = [
    hex32("0000000000000000000000000000000000000000000000000000000000000000"),
    hex32("0b63a53787021a4a962a452c2921b3663aff1ffd8d5510540f8e659e782956f1"),
    hex32("0e34ac2c09f45a503d2908bcb12f1cbae5fa4065759c88d501c097506a8b2290"),
    hex32("21f9172d72fdcdafc312eee05cf5092980dda821da5b760a9fb8dbdf607c8a20"),
    hex32("2373ea368857ec7af97e7b470d705848e2bf93ed7bef142a490f2119bcf82d8e"),
    hex32("120157cfaaa49ce3da30f8b47879114977c24b266d58b0ac18b325d878aafddf"),
    hex32("01c28fe1059ae0237b72334700697bdf465e03df03986fe05200cadeda66bd76"),
    hex32("2d78ed82f93b61ba718b17c2dfe5b52375b4d37cbbed6f1fc98b47614b0cf21b"),
    hex32("067243231eddf4222f3911defbba7705aff06ed45960b27f6f91319196ef97e1"),
    hex32("1849b85f3c693693e732dfc4577217acc18295193bede09ce8b97ad910310972"),
    hex32("2a775ea761d20435b31fa2c33ff07663e24542ffb9e7b293dfce3042eb104686"),
    hex32("0f320b0703439a8114f81593de99cd0b8f3b9bf854601abb5b2ea0e8a3dda4a7"),
    hex32("0d07f6e7a8a0e9199d6d92801fff867002ff5b4808962f9da2ba5ce1bdd26a73"),
    hex32("1c4954081e324939350febc2b918a293ebcdaead01be95ec02fcbe8d2c1635d1"),
    hex32("0197f2171ef99c2d053ee1fb5ff5ab288d56b9b41b4716c9214a4d97facc4c4a"),
    hex32("2b9cdd484c5ba1e4d6efcc3f18734b5ac4c4a0b9102e2aeb48521a661d3feee9"),
    hex32("14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3"),
    hex32("071d7627ae3b2eabda8a810227bf04206370ac78dbf6c372380182dbd3711fe3"),
    hex32("2fdc08d9fe075ac58cb8c00f98697861a13b3ab6f9d41a4e768f75e477475bf5"),
    hex32("20165fe405652104dceaeeca92950aa5adc571b8cafe192878cba58ff1be49c5"),
    hex32("1c8c3ca0b3a3d75850fcd4dc7bf1e3445cd0cfff3ca510630fd90b47e8a24755"),
    hex32("1f0c1a8fb16b0d2ac9a146d7ae20d8d179695a92a79ed66fc45d9da4532459b3"),
    hex32("038146ec5a2573e1c30d2fb32c66c8440f426fbd108082df41c7bebd1d521c30"),
    hex32("17d3d12b17fe762de4b835b2180b012e808816a7f2ff69ecb9d65188235d8fd4"),
    hex32("0e1a6b7d63a6e5a9e54e8f391dd4e9d49cdfedcbc87f02cd34d4641d2eb30491"),
    hex32("09244eec34977ff795fc41036996ce974136377f521ac8eb9e04642d204783d2"),
    hex32("1646d6f544ec36df9dc41f778a7ef1690a53c730b501471b6acd202194a7e8e9"),
    hex32("064769603ba3f6c41f664d266ecb9a3a0f6567cd3e48b40f34d4894ee4c361b3"),
    hex32("1595bb3cd19f84619dc2e368175a88d8627a7439eda9397202cdb1167531fd3f"),
    hex32("2a529be462b81ca30265b558763b1498289c9d88277ab14f0838cb1fce4b472c"),
    hex32("0c08da612363088ad0bbc78abd233e8ace4c05a56fdabdd5e5e9b05e428bdaee"),
    hex32("14748d0241710ef47f54b931ac5a58082b1d56b0f0c30d55fb71a6e8c9a6be14"),
    hex32("0b59baa35b9dc267744f0ccb4e3b0255c1fc512460d91130c6bc19fb2668568d"),
];

const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("hex32: lowercase hex only"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "hex32: need 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

fn u256(e: &Env, bytes: &[u8; 32]) -> U256 {
    U256::from_be_bytes(e, &Bytes::from_array(e, bytes))
}

fn to_bytes32(e: &Env, v: &U256) -> BytesN<32> {
    let mut out = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut out);
    BytesN::from_array(e, &out)
}

/// Whether `value`, read big-endian, is below the field order. Only canonical
/// values may enter a hash or a proof's public inputs.
pub fn is_canonical(value: &BytesN<32>) -> bool {
    is_canonical_field(&value.to_array())
}

/// The raw 32-byte id of a contract address, or `None` for any other address
/// shape. Accounts are always contracts in this scheme.
pub fn contract_id(e: &Env, addr: &Address) -> Option<BytesN<32>> {
    match address_payload(e, addr)? {
        (AddressKind::Contract, id) => Some(BytesN::from_array(e, &id)),
        (AddressKind::Account, _) => None,
    }
}

/// A reusable Poseidon2 sponge. Building the parameter tables is a fixed
/// per-sponge cost, so hot paths (a Merkle insert hashes once per level) keep
/// one `Hasher` for the whole operation.
pub struct Hasher {
    env: Env,
    sponge: Poseidon2Sponge<4, Bn254Fr>,
}

impl Hasher {
    pub fn new(e: &Env) -> Self {
        Self {
            env: e.clone(),
            sponge: Poseidon2Sponge::<4, Bn254Fr>::new(e),
        }
    }

    fn hash(&mut self, inputs: &[[u8; 32]]) -> BytesN<32> {
        let mut v = vec![&self.env];
        for x in inputs {
            v.push_back(u256(&self.env, x));
        }
        to_bytes32(&self.env, &self.sponge.compute_hash(&v))
    }

    /// Interior node `H(left, right)`. Both children are hash outputs (or the
    /// empty leaf `0`), so they are always canonical.
    pub fn node(&mut self, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        self.hash(&[left.to_array(), right.to_array()])
    }

    /// `inner = H(DOM_LEAF, secret)`: what a user submits to the pool.
    ///
    /// # Panics
    /// If `secret` is not canonical.
    pub fn commitment(&mut self, secret: &BytesN<32>) -> BytesN<32> {
        self.hash(&[DOM_LEAF, secret.to_array()])
    }

    /// `leaf = H(DOM_BIND, account, enrollment_id, inner)`.
    ///
    /// # Panics
    /// If `inner` is not canonical.
    pub fn leaf(
        &mut self,
        account_id: &BytesN<32>,
        enrollment_id: &BytesN<32>,
        inner: &BytesN<32>,
    ) -> BytesN<32> {
        let (a_hi, a_lo) = split_hi_lo(&account_id.to_array());
        let (n_hi, n_lo) = split_hi_lo(&enrollment_id.to_array());
        self.hash(&[DOM_BIND, a_hi, a_lo, n_hi, n_lo, inner.to_array()])
    }

    /// `nullifier = H(DOM_NULLIFIER, account, enrollment_id, secret)`: one per
    /// enrolled credential, independent of pool and tree.
    ///
    /// # Panics
    /// If `secret` is not canonical.
    pub fn nullifier(
        &mut self,
        account_id: &BytesN<32>,
        enrollment_id: &BytesN<32>,
        secret: &BytesN<32>,
    ) -> BytesN<32> {
        let (a_hi, a_lo) = split_hi_lo(&account_id.to_array());
        let (n_hi, n_lo) = split_hi_lo(&enrollment_id.to_array());
        self.hash(&[DOM_NULLIFIER, a_hi, a_lo, n_hi, n_lo, secret.to_array()])
    }

    /// `statement_hash = H(fields.auth_preimage())`: the third public input,
    /// tying a proof to one account, one enrollment, and one statement.
    pub fn statement_hash(&mut self, fields: &ZkStatementFields) -> BytesN<32> {
        self.hash(&fields.auth_preimage())
    }

    /// `zero[i]` for `i in 0..=depth`: `zero[0]` is the empty leaf (`0`),
    /// `zero[i + 1] = H(zero[i], zero[i])`, and `zero[depth]` is the root of
    /// an empty depth-`depth` tree.
    pub fn zero_hashes(&mut self, depth: u32) -> soroban_sdk::Vec<BytesN<32>> {
        let mut out = vec![&self.env];
        let mut cur = BytesN::from_array(&self.env, &[0u8; 32]);
        out.push_back(cur.clone());
        for _ in 0..depth {
            cur = self.node(&cur, &cur);
            out.push_back(cur.clone());
        }
        out
    }
}

#[cfg(test)]
mod test;
