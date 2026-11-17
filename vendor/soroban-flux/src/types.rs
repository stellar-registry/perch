//! Refined newtypes: domain types whose invariants Flux checks statically.
//!
//! Design rule: these carry NO `#[contracttype]` derive — derive-generated
//! conversion code trips the checker. Host-boundary conversions
//! (`TryFromVal`/`IntoVal`) are added per-consumer as hand-written trusted
//! impls that runtime-validate the invariant once at decode; everything after
//! the boundary is static.

use flux_rs::attrs::*;

/// Error for [`Amount`] operations that would violate its invariant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AmountError {
    Insufficient,
}

/// A non-negative `i128` — token balances, spending limits, prices.
///
/// The `v >= 0` invariant is part of the type: any code path that could
/// construct a negative `Amount` fails Flux verification, and arithmetic that
/// could underflow does not typecheck.
#[refined_by(v: int)]
#[invariant(v >= 0)]
pub struct Amount {
    #[field(i128[v])]
    value: i128,
}

impl Amount {
    /// The zero amount.
    #[sig(fn() -> Amount[0])]
    pub fn zero() -> Amount {
        Amount { value: 0 }
    }

    /// Wrap a non-negative value. The precondition is discharged statically —
    /// there is no runtime check and no panic path.
    #[sig(fn({i128[@val] | val >= 0}) -> Amount[val])]
    pub fn new(value: i128) -> Amount {
        Amount { value }
    }

    #[sig(fn(&Amount[@a]) -> i128[a])]
    pub fn get(&self) -> i128 {
        self.value
    }

    /// `self - amount`, rejecting overdrafts. Flux proves the subtraction
    /// cannot underflow and the result is non-negative.
    #[sig(fn(Amount[@bal], Amount[@amt]) -> Result<Amount{v: v == bal - amt && v >= 0}, AmountError>)]
    pub fn spend(self, amount: Amount) -> Result<Amount, AmountError> {
        if amount.value > self.value {
            return Err(AmountError::Insufficient);
        }
        Ok(Amount {
            value: self.value - amount.value,
        })
    }
}
