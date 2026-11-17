//! BN254 (alt_bn128) scalar-field helpers — the single source of truth for
//! the field order `r` across consumers (nido zk-recovery pool, nido factory,
//! UltraHonk verifiers), replacing per-repo hand-maintained byte constants
//! and their cross-crate drift-guard tests.
//!
//! The byte constant is pinned against the decimal value of `r` by this
//! crate's own tests (`tests/bn254.rs`), and the [`crate::defs`] predicate
//! `bn254_canonical` states the same bound for refinement proofs.

use soroban_sdk::{Bytes, BytesN, Env, U256};

/// Big-endian bytes of the BN254 scalar field order
/// `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// The field order `r` as a host [`U256`].
pub fn field_order(env: &Env) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &BN254_R_BE))
}

/// Whether `bytes`, interpreted as a big-endian integer, is a canonical
/// field element (`< r`). Callers decide the failure action (reject vs
/// reduce) — rejecting avoids silently colliding two byte strings onto one
/// element.
pub fn is_canonical_be(env: &Env, bytes: &BytesN<32>) -> bool {
    let value = U256::from_be_bytes(env, &Bytes::from_array(env, &bytes.to_array()));
    value < field_order(env)
}

/// `bytes mod r`, big-endian in and out — for deterministically deriving a
/// canonical element from an arbitrary 32-byte digest (e.g. dummy
/// commitments). Real user-supplied elements should be gated with
/// [`is_canonical_be`] instead, never reduced.
pub fn reduce_be(env: &Env, bytes: &BytesN<32>) -> BytesN<32> {
    let value = U256::from_be_bytes(env, &Bytes::from_array(env, &bytes.to_array()));
    let reduced = value.rem_euclid(&field_order(env));
    let mut out = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut out);
    BytesN::from_array(env, &out)
}
