//! Shared constraints for Perch's ZK recovery membership proof.
//!
//! One relation, parameterized only by tree depth. With `acct` the account's
//! contract id, `enr` the enrollment id its recovery configuration names, and
//! `digest` the 32-byte recovery-statement digest (each split into two
//! big-endian 128-bit halves):
//!
//!   inner          = H(DOM_LEAF, secret)                           client-side commitment
//!   leaf           = H(DOM_BIND, acct_hi, acct_lo, enr_hi, enr_lo, inner)   computed by the pool
//!   root           = MerkleRoot(leaf, leaf_index, siblings)        H2 interior nodes, empty leaf 0
//!   nullifier      = H(DOM_NULLIFIER, acct_hi, acct_lo, enr_hi, enr_lo, secret)
//!   statement_hash = H(DOM_AUTH, acct_hi, acct_lo, enr_hi, enr_lo, digest_hi, digest_lo)
//!
//! Public inputs, in order: `root`, `nullifier`, `statement_hash`. Everything
//! else is private. `H` is `Poseidon2::hash(inputs, inputs.len())` from
//! noir-lang/poseidon v0.2.0 (vendored, `../vendor/poseidon`), which
//! `soroban-poseidon`'s `Poseidon2Sponge::<4, Bn254Fr>` reproduces on the
//! Soroban host; `crates/perch-zk-primitives` pins both sides to shared
//! vectors.
//!
//! These are the formulas of `perch-recovery-interface::zk` (the spec's "ZK
//! adapter boundary"). The circuit knows nothing about the statement's
//! layout: the controller hashes its structured statement to 32 bytes, so a
//! statement-format change never needs a new circuit or verification key.
//! What the circuit binds directly is the account and the enrollment id,
//! because the leaf and nullifier are computed from them.
//!
//! Domain constants are `sha256("perch/recovery/zk/v2/<name>") mod r`.

use poseidon::poseidon2::Poseidon2;

pub global DOM_LEAF: Field = 0x1981de3e07709613862272edb5ff4fab545737382d1405fe8d0970dc7d4d7ed6;
pub global DOM_BIND: Field = 0x20ae6172af8bed19c921e91e21641198661035616a6a4d733346853501fd07c5;
pub global DOM_NULLIFIER: Field =
    0x0280c3170f4abb8389838a5c280dbdac8bfd7c75fcb780a9485d93af553ab840;
pub global DOM_AUTH: Field = 0x04e4c99c7477379c7e47c9380170e3fb1e7c565afe67dd56216df99861f1fb3c;

pub fn hash2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

pub fn commitment(secret: Field) -> Field {
    Poseidon2::hash([DOM_LEAF, secret], 2)
}

pub fn leaf(acct_hi: Field, acct_lo: Field, enr_hi: Field, enr_lo: Field, inner: Field) -> Field {
    Poseidon2::hash([DOM_BIND, acct_hi, acct_lo, enr_hi, enr_lo, inner], 6)
}

pub fn nullifier(
    acct_hi: Field,
    acct_lo: Field,
    enr_hi: Field,
    enr_lo: Field,
    secret: Field,
) -> Field {
    Poseidon2::hash([DOM_NULLIFIER, acct_hi, acct_lo, enr_hi, enr_lo, secret], 6)
}

pub fn statement_hash(
    acct_hi: Field,
    acct_lo: Field,
    enr_hi: Field,
    enr_lo: Field,
    digest_hi: Field,
    digest_lo: Field,
) -> Field {
    Poseidon2::hash(
        [DOM_AUTH, acct_hi, acct_lo, enr_hi, enr_lo, digest_hi, digest_lo],
        7,
    )
}

/// Root of a depth-`D` tree containing `leaf` at `leaf_index`. The index is
/// decomposed into exactly `D` little-endian bits, which also range-checks it
/// to `[0, 2^D)`: a bit of 0 means the running node is the left child.
pub fn merkle_root<let D: u32>(leaf: Field, leaf_index: Field, siblings: [Field; D]) -> Field {
    let bits: [u1; D] = leaf_index.to_le_bits();
    let mut cur = leaf;
    for i in 0..D {
        cur = if bits[i] == 0 {
            hash2(cur, siblings[i])
        } else {
            hash2(siblings[i], cur)
        };
    }
    cur
}

/// The whole relation. Each `bin` package's `main` is this function at a
/// fixed depth.
pub fn check<let D: u32>(
    root: Field,
    nullifier_pub: Field,
    statement_hash_pub: Field,
    secret: Field,
    acct_hi: Field,
    acct_lo: Field,
    enr_hi: Field,
    enr_lo: Field,
    digest_hi: Field,
    digest_lo: Field,
    leaf_index: Field,
    siblings: [Field; D],
) {
    let stored = leaf(acct_hi, acct_lo, enr_hi, enr_lo, commitment(secret));
    assert(merkle_root(stored, leaf_index, siblings) == root);
    assert(nullifier(acct_hi, acct_lo, enr_hi, enr_lo, secret) == nullifier_pub);
    assert(
        statement_hash(acct_hi, acct_lo, enr_hi, enr_lo, digest_hi, digest_lo)
            == statement_hash_pub,
    );
}

/// `zero[0] = 0` (the empty leaf), `zero[i + 1] = H2(zero[i], zero[i])`.
pub fn zero_hashes<let D: u32>() -> [Field; D] {
    let mut zeros: [Field; D] = [0; D];
    let mut prev: Field = 0;
    for i in 0..D {
        zeros[i] = prev;
        prev = hash2(prev, prev);
    }
    zeros
}

mod tests;
