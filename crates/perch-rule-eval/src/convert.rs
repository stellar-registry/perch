//! Host values as rule-eval reads them, read through `soroban-facade`, and
//! back where storage needs the host form.
//!
//! An address is its `ScAddress` XDR, a signer is the account's [`Signer`] with
//! each address so encoded, and an argument value is what
//! `soroban_facade::val_to_rule_eval` makes of it. The account's own address
//! goes through [`address`] like every other, so rules and contexts share one
//! encoding.
//!
//! [`contexts`] reads `__check_auth`'s batch the way soroban-facade reads it
//! (`SdkHost::auth_contexts`); [`calls`] reads a batch of calls one host
//! value at a time to the same contexts, without the facade's context
//! decoding or value encoding, which is what an account links.

use alloc::vec;
use alloc::vec::Vec;

use perch_account_types::Signer;
use soroban_facade::{xdr, SdkHost, Val as FVal};
use soroban_sdk::auth::Context;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, Env, String, Symbol, Val, Vec as SVec};

/// The `ScVal` discriminant of an address.
const SCV_ADDRESS: [u8; 4] = [0, 0, 0, 18];

/// The longest symbol the host holds.
const MAX_SYMBOL_LEN: usize = 32;

/// `v` as soroban-facade reads it, or `None` for a value it has no form for.
pub(crate) fn facade(e: &Env, v: Val) -> Option<FVal> {
    SdkHost::new(e).from_sdk(v)
}

/// The host's `ScVal` XDR of `v`, which `SdkHost::from_sdk` reads.
pub(crate) fn host_xdr(e: &Env, v: Val) -> Vec<u8> {
    bytes(&v.to_xdr(e))
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

/// The signer `s` as rule-eval reads it.
#[must_use]
pub fn signer(e: &Env, s: &Signer) -> Option<rule_eval::Signer> {
    signer_in(e, s, &mut Addresses::default())
}

/// [`signer`], recording its addresses in `known`.
pub(crate) fn signer_in(e: &Env, s: &Signer, known: &mut Addresses) -> Option<rule_eval::Signer> {
    Some(match s {
        Signer::Delegated(a) => rule_eval::Signer::Delegated(known.read(e, a)?),
        Signer::External(verifier, key) => {
            rule_eval::Signer::External(known.read(e, verifier)?, bytes(key))
        }
    })
}

/// How a rule-eval value's addresses and signers get their host form.
pub trait HostForms {
    /// The host address whose `ScAddress` XDR is `x`, or `None` when there
    /// is none.
    fn address(&self, e: &Env, x: &[u8]) -> Option<Address>;

    /// The account's signer for the rule-eval signer `s`, or `None` when
    /// one of its addresses has no host form.
    fn signer(&self, e: &Env, s: &rule_eval::Signer) -> Option<Signer> {
        Some(match s {
            rule_eval::Signer::Delegated(a) => Signer::Delegated(self.address(e, a)?),
            rule_eval::Signer::External(verifier, key) => {
                Signer::External(self.address(e, verifier)?, Bytes::from_slice(e, key))
            }
        })
    }
}

/// Host forms decoded from the XDR ([`host_address`]).
pub struct Decoded;

impl HostForms for Decoded {
    fn address(&self, e: &Env, x: &[u8]) -> Option<Address> {
        host_address(e, x)
    }
}

/// Host addresses with their `ScAddress` XDR, recorded as a document's
/// model is read ([`crate::doc_of_in`]), so the rules rule-eval lowers it to
/// convert back to host values by lookup rather than by decoding XDR: every
/// address a lowered rule holds is the account's own (read with
/// [`Addresses::read`]) or one the model names.
#[derive(Clone, Debug, Default)]
pub struct Addresses {
    known: Vec<(Vec<u8>, Address)>,
}

impl Addresses {
    /// `a`'s `ScAddress` XDR ([`address`]), recorded.
    pub fn read(&mut self, e: &Env, a: &Address) -> Option<Vec<u8>> {
        let x = address(e, a)?;
        if self.host(&x).is_none() {
            self.known.push((x.clone(), a.clone()));
        }
        Some(x)
    }

    /// The recorded host address whose XDR is `x`.
    #[must_use]
    pub fn host(&self, x: &[u8]) -> Option<Address> {
        self.known
            .iter()
            .find(|(k, _)| k.as_slice() == x)
            .map(|(_, a)| a.clone())
    }
}

impl HostForms for Addresses {
    fn address(&self, _e: &Env, x: &[u8]) -> Option<Address> {
        self.host(x)
    }
}

/// Every signer of `list`, in order, or `None` when one has no rule-eval
/// form or is not a `Signer` at all (a vector converts without reading its
/// items, so a stored signer table is read here item by item).
#[must_use]
pub fn signers(e: &Env, list: &SVec<Signer>) -> Option<Vec<rule_eval::Signer>> {
    let mut out = Vec::new();
    for s in list.try_iter() {
        out.push(signer(e, &s.ok()?)?);
    }
    Some(out)
}

/// `__check_auth`'s contexts as rule-eval reads them, in order, or `None`
/// when the facade cannot read one of them, so the whole batch is refused.
#[must_use]
pub fn contexts(e: &Env, list: &SVec<Context>) -> Option<Vec<rule_eval::Context>> {
    let cs = SdkHost::new(e).auth_contexts(list.to_val())?;
    Some(soroban_facade::contexts_to_rule_eval(&cs))
}

/// A batch of calls as rule-eval reads it: what [`contexts`] gives, each
/// call's contract, function name and arguments read as host values of
/// their own. `None` when the batch holds a creation, which no rule allows,
/// or a value the facade cannot read, so the whole batch is refused.
#[must_use]
pub fn calls(e: &Env, list: &SVec<Context>) -> Option<Vec<rule_eval::Context>> {
    let mut out = Vec::new();
    for c in list.iter() {
        let Context::Contract(c) = c else {
            return None;
        };
        let mut args = Vec::new();
        for v in c.args.iter() {
            args.push(arg(e, v)?);
        }
        out.push(rule_eval::Context::Call {
            contract: address(e, &c.contract)?,
            function: symbol_bytes(e, &c.fn_name)?,
            args,
        });
    }
    Some(out)
}

/// The argument `v` as rule-eval reads it, as [`val`] reads it: a value
/// rule-eval holds as `Other` is the host's `ScVal` XDR of it, which is what
/// `soroban_facade::val_to_rule_eval` encodes of the value the facade read
/// from that XDR.
fn arg(e: &Env, v: Val) -> Option<rule_eval::Val> {
    let x = host_xdr(e, v);
    Some(match xdr::decode(&x)? {
        FVal::I128(n) => rule_eval::Val::I128(n),
        FVal::U64(n) => rule_eval::Val::U64(n),
        FVal::Bool(b) => rule_eval::Val::Bool(b),
        FVal::Bytes(b) => rule_eval::Val::Bytes(b),
        FVal::String(b) => rule_eval::Val::String(b),
        FVal::Symbol(b) => rule_eval::Val::Symbol(b),
        FVal::Address(a) => rule_eval::Val::Address(xdr::address_xdr(&a)),
        _ => rule_eval::Val::Other(x),
    })
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

/// The account's signer for the rule-eval signer `s`, or `None` when one of
/// its addresses has no host form.
#[must_use]
pub fn host_signer(e: &Env, s: &rule_eval::Signer) -> Option<Signer> {
    Decoded.signer(e, s)
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
pub fn symbol_bytes(e: &Env, s: &Symbol) -> Option<Vec<u8>> {
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
pub fn string_bytes(s: &String) -> Vec<u8> {
    let mut out = vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut out);
    out
}
