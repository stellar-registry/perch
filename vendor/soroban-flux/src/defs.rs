//! Shared refinement predicates (Flux spec functions).
//!
//! Consumers import these inside their own specs via
//! `use soroban_flux::defs::*;` (Flux resolves spec functions cross-crate).
//! Under a normal build this macro emits nothing.
//!
//! - `bn254_canonical(v)`: the BN254 (alt_bn128) scalar field order `r`; a
//!   32-byte value is a canonical field element iff strictly below it. Single
//!   source of truth for nido's zk-recovery pool commitments, the factory's
//!   dummy-commitment guard, and arts1's UltraHonk verifier — replaces the
//!   per-repo hand-maintained `FIELD_ORDER_BE` byte arrays.
//! - `succ(n, m)`: `m` is the successor of `n` — the exact-nonce-increment
//!   relation used by nido's recovery controller and arts1's token state.
//! - `is_btwn(v, lo, hi)`: inclusive-range check for length/index invariants.
//!
//! (Plain `//` comments only inside `defs!` — its grammar rejects doc
//! comments.)

flux_rs::defs! {
    // BN254 r doesn't fit flux's integer-literal parser (~2^254), so it is
    // assembled from 64-bit limbs: r = ((hi3*2^64 + hi2)*2^64 + hi1)*2^64 + lo.
    // Limb values check-verified against the canonical constant
    // 21888242871839275222246405745257275088548364400416034343698204186575808495617.
    fn bn254_r() -> int {
        ((3486998266802970665 * 18446744073709551616 + 13281191951274694749)
            * 18446744073709551616
            + 2896914383306846353)
            * 18446744073709551616
            + 4891460686036598785
    }

    fn bn254_canonical(v: int) -> bool {
        v < bn254_r()
    }

    fn succ(n: int, m: int) -> bool { m == n + 1 }

    fn is_btwn(v: int, lo: int, hi: int) -> bool { lo <= v && v <= hi }
}
