//! One-stop import for writing Flux specifications:
//!
//! ```ignore
//! use soroban_flux::prelude::*;
//!
//! #[sig(fn(balance: i128{v: v >= 0}, amount: i128{v: v >= 0 && v <= balance})
//!       -> i128{v: v >= 0})]
//! pub fn spend(balance: i128, amount: i128) -> i128 { balance - amount }
//! ```
//!
//! All attributes erase to no-ops outside the flux driver, so this import is
//! free for consumers building on stable.

pub use flux_rs::attrs::*;

pub use crate::types::{Amount, AmountError};
