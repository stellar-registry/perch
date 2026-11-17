//! Minimal admin storage-key convention.
//!
//! This is deliberately not a trait: the importable registry traits only need
//! to *read* the current admin and require its auth. Keeping it as free
//! functions over a fixed instance-storage key means this crate depends on no
//! admin abstraction at all (in particular not `admin-sep`, which pins sdk
//! ^25). The key is byte-identical to `admin-sep`'s, so a registry that wires
//! admin-sep's `Administratable` for its public `admin`/`set_admin` entry
//! points and these helpers for internal auth stay perfectly in sync.

use soroban_sdk::{symbol_short, Address, Env, Symbol};

/// Instance-storage key holding the admin `Address`. Matches `admin-sep`.
pub const ADMIN_KEY: Symbol = symbol_short!("ADMIN");

/// The current admin, if one has been set.
#[must_use]
pub fn admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&ADMIN_KEY)
}

/// Require the admin's authorization. Traps if no admin has been set — a
/// registry always sets one in its constructor.
pub fn require_admin(env: &Env) {
    unsafe { admin(env).unwrap_unchecked() }.require_auth();
}

/// Set the admin without any authorization check. Callers that need to gate
/// this (e.g. an admin rotation) must `require_admin` first.
pub fn set_admin_no_auth(env: &Env, new_admin: &Address) {
    env.storage().instance().set(&ADMIN_KEY, new_admin);
}
