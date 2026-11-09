//! Host values as rule-eval reads them, read through `soroban-facade`, and
//! back where storage needs the host form.
//!
//! An address is its `ScAddress` XDR, a signer is OpenZeppelin's signer with
//! each address so encoded, and an argument value is what
//! `soroban_facade::val_to_rule_eval` makes of it. The account's own address
//! goes through [`address`] like every other, so rules and contexts share one
//! encoding.

use alloc::vec;
use alloc::vec::Vec;

use soroban_facade::{xdr, SdkHost, Val as FVal};
use soroban_sdk::auth::Context;
use soroban_sdk::{Address, Bytes, Env, String, Symbol, Val, Vec as SVec};
use stellar_accounts::smart_account::Signer;

/// The `ScVal` discriminant of an address.
const SCV_ADDRESS: [u8; 4] = [0, 0, 0, 18];

/// The longest symbol the host holds.
const MAX_SYMBOL_LEN: usize = 32;

/// `v` as soroban-facade reads it, or `None` for a value it has no form for.
pub(crate) fn facade(e: &Env, v: Val) -> Option<FVal> {
    SdkHost::new(e).from_sdk(v)
}

/// `a`'s `ScAddress` XDR, or `None` for an address the facade refuses (a
/// claimable-balance or liquidity-pool address).
#[must_use]
pub fn address(e: &Env, a: &Address) -> Option<Vec<u8>> {
    match facade(e, a.to_val())? {
        FVal::Address(a) => Some(xdr::address_xdr(&a)),
        _ => None,
    }
}

/// The argument value `v` as rule-eval reads it, or `None` for a value the
/// facade has no form for.
#[must_use]
pub fn val(e: &Env, v: Val) -> Option<rule_eval::Val> {
    facade(e, v).map(|v| soroban_facade::val_to_rule_eval(&v))
}

/// OpenZeppelin's signer `s` as rule-eval reads it.
#[must_use]
pub fn signer(e: &Env, s: &Signer) -> Option<rule_eval::Signer> {
    Some(match s {
        Signer::Delegated(a) => rule_eval::Signer::Delegated(address(e, a)?),
        Signer::External(verifier, key) => {
            rule_eval::Signer::External(address(e, verifier)?, bytes(key))
        }
    })
}

/// Every signer of `list`, in order, or `None` when one has no rule-eval
/// form.
#[must_use]
pub fn signers(e: &Env, list: &SVec<Signer>) -> Option<Vec<rule_eval::Signer>> {
    list.iter().map(|s| signer(e, &s)).collect()
}

/// `__check_auth`'s contexts as rule-eval reads them, in order, or `None`
/// when the facade cannot read one of them, so the whole batch is refused.
#[must_use]
pub fn contexts(e: &Env, list: &SVec<Context>) -> Option<Vec<rule_eval::Context>> {
    let cs = SdkHost::new(e).auth_contexts(list.to_val())?;
    Some(soroban_facade::contexts_to_rule_eval(&cs))
}

/// The host address whose `ScAddress` XDR is exactly `x`, or `None` when `x`
/// is not the XDR of one address or names a muxed account, which is no
/// `Address` on the host.
#[must_use]
pub fn host_address(e: &Env, x: &[u8]) -> Option<Address> {
    let mut sc = Vec::from(SCV_ADDRESS);
    sc.extend_from_slice(x);
    match xdr::decode(&sc)? {
        FVal::Address(a) => SdkHost::new(e).address(&a),
        _ => None,
    }
}

/// OpenZeppelin's signer for the rule-eval signer `s`, or `None` when one of
/// its addresses has no host form.
#[must_use]
pub fn host_signer(e: &Env, s: &rule_eval::Signer) -> Option<Signer> {
    Some(match s {
        rule_eval::Signer::Delegated(a) => Signer::Delegated(host_address(e, a)?),
        rule_eval::Signer::External(verifier, key) => {
            Signer::External(host_address(e, verifier)?, Bytes::from_slice(e, key))
        }
    })
}

/// The host symbol with the bytes `b`, or `None` when the host holds no such
/// symbol: one longer than 32 bytes or with a byte outside `[a-zA-Z0-9_]`.
/// Checked here because the host traps on such a symbol rather than refusing
/// it.
#[must_use]
pub fn host_symbol(e: &Env, b: &[u8]) -> Option<Symbol> {
    if b.len() > MAX_SYMBOL_LEN || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return None;
    }
    Some(Symbol::new(e, core::str::from_utf8(b).ok()?))
}

/// The bytes of `s`, a symbol, as the facade reads them.
pub(crate) fn symbol_bytes(e: &Env, s: &Symbol) -> Option<Vec<u8>> {
    match facade(e, s.to_val())? {
        FVal::Symbol(b) => Some(b),
        _ => None,
    }
}

/// The bytes of `b`.
pub(crate) fn bytes(b: &Bytes) -> Vec<u8> {
    let mut out = vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut out);
    out
}

/// The bytes of `s`.
pub(crate) fn string_bytes(s: &String) -> Vec<u8> {
    let mut out = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut out);
    out
}
