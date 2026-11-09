//! A stored rule or spending record read back as the value it mirrors, from
//! its host value.
//!
//! A [`StoredRule`](crate::StoredRule) or [`StoredRecord`](crate::StoredRecord)
//! is a host value of its `#[contracttype]` encoding: a struct is a map of
//! its fields by name, in the host's key order, and an enum constructor a
//! vector of its name and fields. [`rule`] and [`record`] read the host's
//! `ScVal` XDR of one (`SdkHost::from_sdk` reads the same bytes) in one pass.
//! An address is the `ScAddress` XDR inside its value, which is what
//! soroban-facade's `xdr::address_xdr` gives for the address it reads there,
//! and a symbol or string is its bytes, as [`crate::convert`] reads them.
//! Bytes that do not lay out such a value are refused, a trailing byte or
//! non-zero padding included; a value's constructor is told by its field's
//! type, and by its name between the two that hold bytes.
//! [`rule`] is the one reading of a stored rule (`StoredRule::to_rule`), so
//! an account that reads its stored rules links no `#[contracttype]`
//! decoding of them.

use alloc::vec::Vec;

use rule_eval::{AuthRoot, Cap, Cond, Functions, Rule, Signer, SpendEntry, SpendRecord};
use soroban_sdk::{Env, Val};

use crate::convert::host_xdr;

const SCV_BOOL: u32 = 0;
const SCV_VOID: u32 = 1;
const SCV_U32: u32 = 3;
const SCV_U64: u32 = 5;
const SCV_I128: u32 = 10;
const SCV_BYTES: u32 = 13;
const SCV_STRING: u32 = 14;
const SCV_SYMBOL: u32 = 15;
const SCV_VEC: u32 = 16;
const SCV_MAP: u32 = 17;
const SCV_ADDRESS: u32 = 18;

const SC_ADDRESS_ACCOUNT: u32 = 0;
const SC_ADDRESS_CONTRACT: u32 = 1;
const SC_ADDRESS_MUXED_ACCOUNT: u32 = 2;
const PUBLIC_KEY_ED25519: u32 = 0;

/// The rule the `StoredRule` whose host value is `v` mirrors, or `None` when
/// `v` is no such value, or holds more than one cap.
#[must_use]
pub fn rule(e: &Env, v: Val) -> Option<Rule> {
    whole(e, v, |x| x.rule())
}

/// The record the `StoredRecord` whose host value is `v` mirrors, or `None`
/// when `v` is no such value.
#[must_use]
pub fn record(e: &Env, v: Val) -> Option<SpendRecord> {
    whole(e, v, |x| x.record())
}

/// What `read` reads of the host's XDR of `v`, when it reads all of it.
fn whole<T>(e: &Env, v: Val, read: impl FnOnce(&mut Xdr) -> Option<T>) -> Option<T> {
    let bytes = host_xdr(e, v);
    let mut x = Xdr {
        bytes: &bytes,
        pos: 0,
    };
    let out = read(&mut x)?;
    (x.pos == bytes.len()).then_some(out)
}

/// A reader of one value's `ScVal` XDR.
struct Xdr<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Xdr<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    /// The next value's type is `tag`.
    fn tag(&mut self, tag: u32) -> Option<()> {
        (self.u32()? == tag).then_some(())
    }

    /// A value of type `tag` holding opaque bytes (bytes, a string or a
    /// symbol), zero-padded to four bytes.
    fn opaque(&mut self, tag: u32) -> Option<&'a [u8]> {
        self.tag(tag)?;
        let n = usize::try_from(self.u32()?).ok()?;
        let b = self.take(n)?;
        let pad = self.take((4 - n % 4) % 4)?;
        pad.iter().all(|p| *p == 0).then_some(b)
    }

    /// A vector's or map's length.
    fn len(&mut self, tag: u32) -> Option<u32> {
        self.tag(tag)?;
        if self.u32()? != 1 {
            return None;
        }
        self.u32()
    }

    /// A struct's next field is `name`.
    fn key(&mut self, name: &[u8]) -> Option<()> {
        (self.opaque(SCV_SYMBOL)? == name).then_some(())
    }

    /// An enum constructor's name and how many fields follow it.
    fn variant(&mut self) -> Option<(&'a [u8], u32)> {
        let n = self.len(SCV_VEC)?.checked_sub(1)?;
        Some((self.opaque(SCV_SYMBOL)?, n))
    }

    fn u32_val(&mut self) -> Option<u32> {
        self.tag(SCV_U32)?;
        self.u32()
    }

    /// The eight bytes of a `u64`.
    fn u64_bits(&mut self) -> Option<u64> {
        Some((u64::from(self.u32()?) << 32) | u64::from(self.u32()?))
    }

    /// The sixteen bytes of an `i128`: its high and low halves.
    fn i128_bits(&mut self) -> Option<i128> {
        let hi = self.u64_bits()?;
        Some(((i128::from(hi as i64)) << 64) | i128::from(self.u64_bits()?))
    }

    fn i128_val(&mut self) -> Option<i128> {
        self.tag(SCV_I128)?;
        self.i128_bits()
    }

    /// `n` symbols, as bytes.
    fn symbols(&mut self, n: u32) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(self.opaque(SCV_SYMBOL)?.to_vec());
        }
        Some(out)
    }

    /// An `Option<u32>` (`Void` for `None`).
    fn opt_u32(&mut self) -> Option<Option<u32>> {
        match self.u32()? {
            SCV_VOID => Some(None),
            SCV_U32 => Some(Some(self.u32()?)),
            _ => None,
        }
    }

    /// An `Option<u64>` (`Void` for `None`).
    fn opt_u64(&mut self) -> Option<Option<u64>> {
        match self.u32()? {
            SCV_VOID => Some(None),
            SCV_U64 => Some(Some(self.u64_bits()?)),
            _ => None,
        }
    }

    /// An address, as its `ScAddress` XDR.
    fn address(&mut self) -> Option<Vec<u8>> {
        self.tag(SCV_ADDRESS)?;
        let start = self.pos;
        match self.u32()? {
            SC_ADDRESS_ACCOUNT => {
                if self.u32()? != PUBLIC_KEY_ED25519 {
                    return None;
                }
                self.take(32)?;
            }
            SC_ADDRESS_CONTRACT => {
                self.take(32)?;
            }
            SC_ADDRESS_MUXED_ACCOUNT => {
                self.take(40)?;
            }
            _ => return None,
        }
        Some(self.bytes.get(start..self.pos)?.to_vec())
    }

    /// A `StoredRule`.
    fn rule(&mut self) -> Option<Rule> {
        // Only the exact legacy eight-key layout is unrestricted by omission.
        // New layouts must name auth_root explicitly; unknown/missing keys,
        // malformed tuples and trailing bytes are never ignored.
        let fields = self.len(SCV_MAP)?;
        let auth_root = match fields {
            8 => None,
            9 => {
                self.key(b"auth_root")?;
                let tag =
                    u32::from_be_bytes(self.bytes.get(self.pos..self.pos + 4)?.try_into().ok()?);
                if tag == SCV_VOID {
                    self.tag(SCV_VOID)?;
                    None
                } else {
                    if self.len(SCV_VEC)? != 1 || self.len(SCV_MAP)? != 2 {
                        return None;
                    }
                    self.key(b"contract")?;
                    let contract = self.address()?;
                    // Only contract addresses can be an invocation root.
                    if contract.get(..4)? != SC_ADDRESS_CONTRACT.to_be_bytes() {
                        return None;
                    }
                    self.key(b"function")?;
                    let function = self.opaque(SCV_SYMBOL)?.to_vec();
                    if function.is_empty() || function.len() > 32 {
                        return None;
                    }
                    Some(AuthRoot { contract, function })
                }
            }
            _ => return None,
        };
        self.key(b"cap")?;
        let cap = match self.len(SCV_VEC)? {
            0 => None,
            1 => Some(self.cap()?),
            _ => return None,
        };
        self.key(b"conds")?;
        let mut conds = Vec::new();
        for _ in 0..self.len(SCV_VEC)? {
            conds.push(self.cond()?);
        }
        self.key(b"contract")?;
        let contract = self.address()?;
        self.key(b"functions")?;
        let functions = self.functions()?;
        self.key(b"generation")?;
        let generation = self.opt_u64()?;
        self.key(b"signers")?;
        let mut signers = Vec::new();
        for _ in 0..self.len(SCV_VEC)? {
            signers.push(self.signer()?);
        }
        self.key(b"threshold")?;
        let threshold = self.u32_val()?;
        self.key(b"valid_until")?;
        let valid_until = self.opt_u32()?;
        Some(Rule {
            auth_root,
            contract,
            functions,
            conds,
            signers,
            threshold,
            cap,
            valid_until,
            generation,
        })
    }

    /// A `StoredRecord`.
    fn record(&mut self) -> Option<SpendRecord> {
        if self.len(SCV_MAP)? != 2 {
            return None;
        }
        self.key(b"history")?;
        let mut history = Vec::new();
        for _ in 0..self.len(SCV_VEC)? {
            if self.len(SCV_MAP)? != 2 {
                return None;
            }
            self.key(b"amount")?;
            let amount = self.i128_val()?;
            self.key(b"ledger")?;
            let ledger = self.u32_val()?;
            history.push(SpendEntry { ledger, amount });
        }
        self.key(b"total")?;
        let total = self.i128_val()?;
        Some(SpendRecord { history, total })
    }

    /// A `StoredCap`.
    fn cap(&mut self) -> Option<Cap> {
        if self.len(SCV_MAP)? != 3 {
            return None;
        }
        self.key(b"amount_arg")?;
        let amount_arg = self.u32_val()?;
        self.key(b"limit")?;
        let limit = self.i128_val()?;
        self.key(b"period")?;
        let period = self.u32_val()?;
        Some(Cap {
            limit,
            period,
            amount_arg,
        })
    }

    /// A `StoredFunctions`.
    fn functions(&mut self) -> Option<Functions> {
        let (name, 1) = self.variant()? else {
            return None;
        };
        let n = self.len(SCV_VEC)?;
        let names = self.symbols(n)?;
        match name {
            b"AnyExcept" => Some(Functions::AnyExcept(names)),
            b"Only" => Some(Functions::Only(names)),
            _ => None,
        }
    }

    /// A `StoredCond`.
    fn cond(&mut self) -> Option<Cond> {
        let (name, 2) = self.variant()? else {
            return None;
        };
        let i = self.u32_val()?;
        Some(match name {
            b"ArgEq" => Cond::ArgEq(i, self.val()?),
            b"ArgI128AtMost" => Cond::ArgI128AtMost(i, self.i128_val()?),
            b"ArgIn" => {
                let mut vs = Vec::new();
                for _ in 0..self.len(SCV_VEC)? {
                    vs.push(self.val()?);
                }
                Cond::ArgIn(i, vs)
            }
            b"ArgStrPrefix" => Cond::ArgStrPrefix(i, self.opaque(SCV_STRING)?.to_vec()),
            _ => return None,
        })
    }

    /// A `StoredVal`: its constructor's one field, read by its `ScVal`
    /// type, which names the constructor; the name tells `Bytes` and
    /// `Other`, which both hold bytes, apart.
    fn val(&mut self) -> Option<rule_eval::Val> {
        let (name, 1) = self.variant()? else {
            return None;
        };
        let start = self.pos;
        Some(match self.u32()? {
            SCV_I128 => rule_eval::Val::I128(self.i128_bits()?),
            SCV_U64 => rule_eval::Val::U64(self.u64_bits()?),
            SCV_BOOL => match self.u32()? {
                0 => rule_eval::Val::Bool(false),
                1 => rule_eval::Val::Bool(true),
                _ => return None,
            },
            SCV_ADDRESS => {
                self.pos = start;
                rule_eval::Val::Address(self.address()?)
            }
            tag => {
                self.pos = start;
                let b = self.opaque(tag)?.to_vec();
                match (tag, name) {
                    (SCV_BYTES, b"Other") => rule_eval::Val::Other(b),
                    (SCV_BYTES, _) => rule_eval::Val::Bytes(b),
                    (SCV_SYMBOL, _) => rule_eval::Val::Symbol(b),
                    (SCV_STRING, _) => rule_eval::Val::String(b),
                    _ => return None,
                }
            }
        })
    }

    /// A `perch_account_types::Signer`.
    fn signer(&mut self) -> Option<Signer> {
        match self.variant()? {
            (b"Delegated", 1) => Some(Signer::Delegated(self.address()?)),
            (b"External", 2) => {
                let verifier = self.address()?;
                Some(Signer::External(verifier, self.opaque(SCV_BYTES)?.to_vec()))
            }
            _ => None,
        }
    }
}
