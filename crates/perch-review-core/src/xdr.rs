//! The XDR the core reads: the account's `SorobanAuthorizationEntry`, as the
//! wallet signs it, and each of the account's ledger entries as
//! `getLedgerEntries` returns it (`LedgerEntryData`), at stellar-xdr 28.0.0,
//! the version soroban-sdk 29.0.1 reads.
//!
//! Every value inside them is read with soroban-facade's `ScVal` codec
//! (`soroban_facade::xdr::decode`), the one rule-core tests against the
//! host, so a value reaches the core exactly as the account's own reading of
//! it does (`perch_rule_eval::convert`). This module only walks the
//! structures around those values. A union arm it does not know (a newer
//! credential or address kind) makes the whole input unreadable rather than
//! guessed at.

use alloc::vec::Vec;

use soroban_facade::{xdr as fxdr, Val};

/// The deepest `ScVal` nesting walked; the facade reads no deeper.
const MAX_DEPTH: u32 = fxdr::MAX_DEPTH;

/// `ScVal` discriminants walked here beyond the facade's.
const SCV_ERROR: u32 = 2;
const SCV_VEC: u32 = 16;
const SCV_MAP: u32 = 17;
const SCV_ADDRESS: u32 = 18;
const SCV_CONTRACT_INSTANCE: u32 = 19;
const SCV_LEDGER_KEY_CONTRACT_INSTANCE: u32 = 20;
const SCV_LEDGER_KEY_NONCE: u32 = 21;

/// `LedgerEntryType::ContractData`.
const CONTRACT_DATA: u32 = 6;
/// `ContractDataDurability::Persistent`.
const PERSISTENT: u32 = 1;

/// A cursor over XDR bytes.
pub(crate) struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    pub(crate) fn new(b: &'a [u8]) -> R<'a> {
        R { b, p: 0 }
    }

    pub(crate) fn done(&self) -> bool {
        self.p == self.b.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    /// A length-prefixed opaque or string, zero-padded to four bytes.
    pub(crate) fn opaque(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok()?;
        let b = self.take(n)?;
        let pad = self.take((4 - n % 4) % 4)?;
        pad.iter().all(|x| *x == 0).then_some(b)
    }

    /// The bytes read since `start`.
    fn since(&self, start: usize) -> Option<&'a [u8]> {
        self.b.get(start..self.p)
    }

    /// An XDR optional's flag.
    fn present(&mut self) -> Option<bool> {
        match self.u32()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// An `SCAddress`, as its XDR.
    pub(crate) fn address(&mut self) -> Option<&'a [u8]> {
        let start = self.p;
        match self.u32()? {
            // Account: a `PublicKey`, whose one arm is ed25519.
            0 => {
                if self.u32()? != 0 {
                    return None;
                }
                self.take(32)?;
            }
            // Contract.
            1 => {
                self.take(32)?;
            }
            // Muxed ed25519 account: an id and a key.
            2 => {
                self.take(40)?;
            }
            // Claimable balance: a `ClaimableBalanceID`, whose one arm is V0.
            3 => {
                if self.u32()? != 0 {
                    return None;
                }
                self.take(32)?;
            }
            // Liquidity pool.
            4 => {
                self.take(32)?;
            }
            _ => return None,
        }
        self.since(start)
    }

    /// A `ContractExecutable`.
    fn executable(&mut self) -> Option<()> {
        match self.u32()? {
            0 => {
                self.take(32)?;
            }
            1 => {}
            2 => {
                self.address()?;
                self.opaque()?;
            }
            _ => return None,
        }
        Some(())
    }

    /// One `SCVal`, as its XDR.
    pub(crate) fn scval(&mut self, depth: u32) -> Option<&'a [u8]> {
        if depth > MAX_DEPTH {
            return None;
        }
        let start = self.p;
        match self.u32()? {
            // Bool, U32, I32.
            0 | 3 | 4 => {
                self.take(4)?;
            }
            // Void, the instance's ledger key.
            1 | SCV_LEDGER_KEY_CONTRACT_INSTANCE => {}
            SCV_ERROR => {
                self.take(8)?;
            }
            // U64, I64, TimePoint, Duration, the nonce key.
            5..=8 | SCV_LEDGER_KEY_NONCE => {
                self.take(8)?;
            }
            // U128, I128.
            9 | 10 => {
                self.take(16)?;
            }
            // U256, I256.
            11 | 12 => {
                self.take(32)?;
            }
            // Bytes, String, Symbol.
            13..=15 => {
                self.opaque()?;
            }
            SCV_VEC => {
                if self.present()? {
                    for _ in 0..self.u32()? {
                        self.scval(depth + 1)?;
                    }
                }
            }
            SCV_MAP => {
                if self.present()? {
                    for _ in 0..self.u32()? {
                        self.scval(depth + 1)?;
                        self.scval(depth + 1)?;
                    }
                }
            }
            SCV_ADDRESS => {
                self.address()?;
            }
            SCV_CONTRACT_INSTANCE => {
                self.executable()?;
                if self.present()? {
                    for _ in 0..self.u32()? {
                        self.scval(depth + 1)?;
                        self.scval(depth + 1)?;
                    }
                }
            }
            _ => return None,
        }
        self.since(start)
    }

    /// One `SCVal`, read with the facade.
    pub(crate) fn val(&mut self) -> Option<Val> {
        fxdr::decode(self.scval(0)?)
    }
}

/// One context `__check_auth` receives, as the account reads it.
pub enum Ctx {
    /// A call of `function` on `contract` (its `SCAddress` XDR). `args` is
    /// `None` when an argument is a value the facade cannot read, which the
    /// account's `convert::calls` refuses.
    Call {
        contract: Vec<u8>,
        function: Vec<u8>,
        args: Option<Vec<Val>>,
    },
    /// A contract creation.
    Create,
}

/// The parts of the account's authorization entry the verdict reads.
pub struct Entry {
    /// The account: the credentials' address, as its `SCAddress` XDR.
    pub account: Vec<u8>,
    /// The credentials' signature: the account's `AuthPayload`.
    pub payload: Val,
    /// The delegates the credentials carry (CAP-0071), as `SCAddress` XDR;
    /// `None` for credentials without delegates.
    pub delegates: Option<Vec<Vec<u8>>>,
    /// The invocation tree in preorder, root first: what the host hands
    /// `__check_auth` (soroban-env-host `invocation_tree_to_auth_contexts`).
    pub contexts: Vec<Ctx>,
}

/// `SorobanAddressCredentials`: the address and the signature.
fn address_credentials<'a>(r: &mut R<'a>) -> Option<(&'a [u8], Val)> {
    let address = r.address()?;
    r.take(8)?; // nonce
    r.u32()?; // signature expiration ledger
    Some((address, r.val()?))
}

/// A `SorobanDelegateSignature`'s address, its nested delegates skipped.
fn delegate<'a>(r: &mut R<'a>, depth: u32) -> Option<&'a [u8]> {
    if depth > MAX_DEPTH {
        return None;
    }
    let address = r.address()?;
    r.scval(0)?;
    for _ in 0..r.u32()? {
        delegate(r, depth + 1)?;
    }
    Some(address)
}

/// A `ContractIDPreimage`.
fn preimage(r: &mut R<'_>) -> Option<()> {
    match r.u32()? {
        0 => {
            r.address()?;
            r.take(32)?;
        }
        1 => match r.u32()? {
            0 => {}
            // AlphaNum4 / AlphaNum12: the code and the issuer's account id.
            t @ (1 | 2) => {
                r.take(if t == 1 { 4 } else { 12 })?;
                if r.u32()? != 0 {
                    return None;
                }
                r.take(32)?;
            }
            _ => return None,
        },
        _ => return None,
    }
    Some(())
}

/// A `SorobanAuthorizedInvocation`, its contexts appended in preorder.
fn invocation(r: &mut R<'_>, out: &mut Vec<Ctx>, depth: u32) -> Option<()> {
    if depth > MAX_DEPTH {
        return None;
    }
    match r.u32()? {
        0 => {
            let contract = r.address()?.to_vec();
            let function = r.opaque()?;
            if function.len() > 32 {
                return None;
            }
            let function = function.to_vec();
            let mut args = Some(Vec::new());
            for _ in 0..r.u32()? {
                let v = fxdr::decode(r.scval(0)?);
                args = match (args, v) {
                    (Some(mut a), Some(v)) => {
                        a.push(v);
                        Some(a)
                    }
                    _ => None,
                };
            }
            out.push(Ctx::Call {
                contract,
                function,
                args,
            });
        }
        // A creation, without and with constructor arguments.
        n @ (1 | 2) => {
            preimage(r)?;
            r.executable()?;
            if n == 2 {
                for _ in 0..r.u32()? {
                    r.scval(0)?;
                }
            }
            out.push(Ctx::Create);
        }
        _ => return None,
    }
    for _ in 0..r.u32()? {
        invocation(r, out, depth + 1)?;
    }
    Some(())
}

/// The account's authorization entry, or `None` for bytes that are not one
/// `SorobanAuthorizationEntry` with address credentials.
#[must_use]
pub fn entry(b: &[u8]) -> Option<Entry> {
    let mut r = R::new(b);
    let (account, payload, delegates) = match r.u32()? {
        // Address and AddressV2: the same credentials, V2 binding the
        // address into the signature payload, which the verdict does not read.
        1 | 2 => {
            let (a, p) = address_credentials(&mut r)?;
            (a, p, None)
        }
        3 => {
            let (a, p) = address_credentials(&mut r)?;
            let mut ds = Vec::new();
            for _ in 0..r.u32()? {
                ds.push(delegate(&mut r, 0)?.to_vec());
            }
            (a, p, Some(ds))
        }
        // Source-account credentials run no `__check_auth`.
        _ => return None,
    };
    let mut contexts = Vec::new();
    invocation(&mut r, &mut contexts, 0)?;
    r.done().then(|| Entry {
        account: account.to_vec(),
        payload,
        delegates,
        contexts,
    })
}

/// One contract-data ledger entry: its contract, and its key and value as
/// facade values.
pub struct DataEntry {
    pub contract: Vec<u8>,
    pub kind: Kind,
}

/// What a contract-data entry is to the account.
pub enum Kind {
    /// The instance entry: its storage map.
    Instance(Vec<(Val, Val)>),
    /// A persistent entry: its key and value.
    Persistent(Val, Val),
    /// A temporary entry (the host's nonces among them), which
    /// `__check_auth` never reads: left unread.
    Temporary,
}

/// A `LedgerEntryData` of type contract data, or `None` for any other bytes.
#[must_use]
pub fn ledger_entry(b: &[u8]) -> Option<DataEntry> {
    let mut r = R::new(b);
    if r.u32()? != CONTRACT_DATA || r.u32()? != 0 {
        return None;
    }
    let contract = r.address()?.to_vec();
    let key = r.scval(0)?;
    let durability = r.u32()?;
    if durability != PERSISTENT {
        r.scval(0)?;
        return r.done().then_some(DataEntry {
            contract,
            kind: Kind::Temporary,
        });
    }
    let kind = if key == SCV_LEDGER_KEY_CONTRACT_INSTANCE.to_be_bytes() {
        if r.u32()? != SCV_CONTRACT_INSTANCE {
            return None;
        }
        r.executable()?;
        let mut storage = Vec::new();
        if r.present()? {
            for _ in 0..r.u32()? {
                let k = r.val()?;
                let v = r.val()?;
                storage.push((k, v));
            }
        }
        Kind::Instance(storage)
    } else {
        Kind::Persistent(fxdr::decode(key)?, r.val()?)
    };
    r.done().then_some(DataEntry { contract, kind })
}
