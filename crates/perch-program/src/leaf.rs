//! Leaf-predicate evaluation, kept separate from the [`crate::rpn`] op
//! dispatch so leaf semantics stay independent of the wire encoding.
//!
//! Fail-closed rule: any decode failure — non-`Contract` context, missing
//! argument index, wrong argument type — yields [`Verdict::Unknown`], never
//! `False`. `Unknown` denies at the root and stays `Unknown` under `Not`,
//! so a decode failure can neither allow nor satisfy a negated guardrail.

use soroban_flux::prelude::*;
use soroban_sdk::{auth::Context, Address, Bytes, Env, String, Symbol, TryFromVal, Val, Vec};

use crate::{EvalInputs, Verdict};

/// Longest string `ArgStrPrefix`/`ArgStrIn` will buffer, so no copy in
/// `no_std` is unbounded. An `ArgStrIn` argument or an `ArgStrPrefix` prefix
/// over this length evaluates to [`Verdict::Unknown`] (fail closed), and an
/// over-long `ArgStrIn` candidate never matches. `ArgStrPrefix` buffers only
/// the argument's first prefix-length bytes, so its argument may be any
/// length. `perch-ir` validation refuses a `string-prefix` prefix over this
/// length (`MAX_STRING_PRED_LEN`).
const MAX_STR_ARG_LEN: usize = 256;

/// Decode argument `i` of a contract-call context as `T`.
/// `None` == decode failure (caller maps to `Unknown`).
///
/// TRUST: pure host-value decode with no arithmetic; its generic
/// `TryFromVal` projection is the pattern that ICEs flux
/// (flux-infer/projections.rs:720). Callers fail closed on `None`.
#[trusted]
fn arg<T: TryFromVal<Env, Val>>(env: &Env, context: &Context, i: u32) -> Option<T> {
    let Context::Contract(c) = context else {
        return None;
    };
    let val = c.args.get(i)?;
    T::try_from_val(env, &val).ok()
}

/// `MinSigners(n)`: at least `n` authenticated signers. Context-independent,
/// so it always decodes — the verdict is always definite.
pub(crate) fn min_signers(inputs: &EvalInputs, n: u32) -> Verdict {
    Verdict::from(inputs.signer_count >= n)
}

/// `FnIn(fns)`: the invoked function is one of `fns`.
///
/// TRUST: pure host-value comparisons over a soroban iterator — nothing to
/// refine, and the closure's `TryFromVal` projection ICEs flux
/// (flux-infer/projections.rs:720, "ambiguous substitution").
#[trusted]
pub(crate) fn fn_in(inputs: &EvalInputs, fns: &Vec<Symbol>) -> Verdict {
    let Context::Contract(c) = inputs.context else {
        return Verdict::Unknown;
    };
    Verdict::from(fns.iter().any(|f| f == c.fn_name))
}

/// `ArgAddrEq(i, addr)`: argument `i` is exactly `addr`.
pub(crate) fn arg_addr_eq(env: &Env, inputs: &EvalInputs, i: u32, want: &Address) -> Verdict {
    match arg::<Address>(env, inputs.context, i) {
        Some(a) => Verdict::from(a == *want),
        None => Verdict::Unknown,
    }
}

/// `ArgAddrIsSelf(i)`: argument `i` is the protected account itself.
pub(crate) fn arg_addr_is_self(env: &Env, inputs: &EvalInputs, i: u32) -> Verdict {
    match arg::<Address>(env, inputs.context, i) {
        Some(a) => Verdict::from(a == *inputs.self_addr),
        None => Verdict::Unknown,
    }
}

/// `ArgSymEq(i, sym)`: argument `i` is exactly `sym`.
pub(crate) fn arg_sym_eq(env: &Env, inputs: &EvalInputs, i: u32, want: &Symbol) -> Verdict {
    match arg::<Symbol>(env, inputs.context, i) {
        Some(s) => Verdict::from(s == *want),
        None => Verdict::Unknown,
    }
}

/// `ArgU32Eq(i, n)`: argument `i` is exactly `n`.
pub(crate) fn arg_u32_eq(env: &Env, inputs: &EvalInputs, i: u32, want: u32) -> Verdict {
    match arg::<u32>(env, inputs.context, i) {
        Some(n) => Verdict::from(n == want),
        None => Verdict::Unknown,
    }
}

/// `ArgI128Eq(i, n)`: argument `i` is exactly `n`.
pub(crate) fn arg_i128_eq(env: &Env, inputs: &EvalInputs, i: u32, want: i128) -> Verdict {
    match arg::<i128>(env, inputs.context, i) {
        Some(n) => Verdict::from(n == want),
        None => Verdict::Unknown,
    }
}

/// `ArgBytesEq(i, want)`: argument `i` is exactly these bytes.
pub(crate) fn arg_bytes_eq(env: &Env, inputs: &EvalInputs, i: u32, want: &Bytes) -> Verdict {
    match arg::<Bytes>(env, inputs.context, i) {
        Some(b) => Verdict::from(b == *want),
        None => Verdict::Unknown,
    }
}

/// Copy a soroban [`String`] into a fixed buffer, or `None` if it is longer
/// than [`MAX_STR_ARG_LEN`]. Fail-closed: an over-long argument denies.
/// Flux proves the returned length keeps every downstream slice in-bounds.
#[sig(fn(s: &String, buf: &mut [u8; _]) -> Option<usize{v: v <= MAX_STR_ARG_LEN}>)]
fn str_bytes(s: &String, buf: &mut [u8; MAX_STR_ARG_LEN]) -> Option<usize> {
    let n = s.len() as usize;
    if n > MAX_STR_ARG_LEN {
        return None;
    }
    s.copy_into_slice(&mut buf[..n]);
    Some(n)
}

/// Copy the first `n` bytes of a soroban [`String`] into a fixed buffer, or
/// `false` if the string is shorter than `n`. The string itself may be any
/// length; only `n` (bounded by [`MAX_STR_ARG_LEN`]) bytes are copied.
#[sig(fn(s: &String, n: usize{n <= MAX_STR_ARG_LEN}, buf: &mut [u8; _]) -> bool)]
fn str_head(s: &String, n: usize, buf: &mut [u8; MAX_STR_ARG_LEN]) -> bool {
    if (s.len() as usize) < n {
        return false;
    }
    s.to_bytes()
        .slice(..n as u32)
        .copy_into_slice(&mut buf[..n]);
    true
}

/// Equality of two buffered strings by their filled prefixes. Flux proves
/// both slice reads in-bounds from the length preconditions.
#[sig(fn(a: &[u8; _], an: usize{an <= MAX_STR_ARG_LEN}, b: &[u8; _], bn: usize{bn <= MAX_STR_ARG_LEN}) -> bool)]
fn buf_eq(a: &[u8; MAX_STR_ARG_LEN], an: usize, b: &[u8; MAX_STR_ARG_LEN], bn: usize) -> bool {
    an == bn && a[..an] == b[..bn]
}

/// `ArgStrIn(i, set)`: argument `i` (a string) equals one of `set`.
///
/// TRUST: iterating a soroban `Vec` ICEs flux (same projections.rs:720
/// class as [`fn_in`]); the bounds-critical byte comparison is delegated to
/// the checked [`buf_eq`], and the buffer fills to checked [`str_bytes`].
#[trusted]
pub(crate) fn arg_str_in(env: &Env, inputs: &EvalInputs, i: u32, set: &Vec<String>) -> Verdict {
    let Some(s) = arg::<String>(env, inputs.context, i) else {
        return Verdict::Unknown;
    };
    let mut sbuf = [0u8; MAX_STR_ARG_LEN];
    let Some(sn) = str_bytes(&s, &mut sbuf) else {
        return Verdict::Unknown;
    };
    let mut cand = [0u8; MAX_STR_ARG_LEN];
    for want in set.iter() {
        if let Some(cn) = str_bytes(&want, &mut cand) {
            if buf_eq(&cand, cn, &sbuf, sn) {
                return Verdict::True;
            }
        }
    }
    Verdict::False
}

/// `ArgStrPrefix(i, prefix)`: argument `i` (a string) starts with `prefix`.
pub(crate) fn arg_str_prefix(env: &Env, inputs: &EvalInputs, i: u32, prefix: &String) -> Verdict {
    let Some(s) = arg::<String>(env, inputs.context, i) else {
        return Verdict::Unknown;
    };
    let mut pbuf = [0u8; MAX_STR_ARG_LEN];
    let Some(pn) = str_bytes(prefix, &mut pbuf) else {
        return Verdict::Unknown;
    };
    // Only the argument's first `pn` bytes are read, so the argument's own
    // length is unbounded.
    let mut sbuf = [0u8; MAX_STR_ARG_LEN];
    if !str_head(&s, pn, &mut sbuf) {
        return Verdict::False;
    }
    Verdict::from(sbuf[..pn] == pbuf[..pn])
}

/// `ArgCount(n)`: the contract call has exactly `n` arguments.
pub(crate) fn arg_count(inputs: &EvalInputs, n: u32) -> Verdict {
    let Context::Contract(c) = inputs.context else {
        return Verdict::Unknown;
    };
    Verdict::from(c.args.len() == n)
}

/// `LedgerBefore(n)`: current ledger sequence is strictly below `n`.
pub(crate) fn ledger_before(env: &Env, n: u32) -> Verdict {
    Verdict::from(env.ledger().sequence() < n)
}

/// `LedgerAtOrAfter(n)`: current ledger sequence is at least `n`.
pub(crate) fn ledger_at_or_after(env: &Env, n: u32) -> Verdict {
    Verdict::from(env.ledger().sequence() >= n)
}
