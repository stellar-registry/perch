//! Leaf-predicate evaluation, kept separate from the [`crate::rpn`] op
//! dispatch so leaf semantics stay independent of the wire encoding.
//!
//! Fail-closed rule: any decode failure — non-`Contract` context, missing
//! argument index, wrong argument type — yields [`Verdict::Unknown`], never
//! `False`. `Unknown` denies at the root and stays `Unknown` under `Not`,
//! so a decode failure can neither allow nor satisfy a negated guardrail.

use soroban_sdk::{auth::Context, Address, Env, Symbol, TryFromVal, Val, Vec};

use crate::{EvalInputs, Verdict};

/// Decode argument `i` of a contract-call context as `T`.
/// `None` == decode failure (caller maps to `Unknown`).
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

/// `LedgerBefore(n)`: current ledger sequence is strictly below `n`.
pub(crate) fn ledger_before(env: &Env, n: u32) -> Verdict {
    Verdict::from(env.ledger().sequence() < n)
}

/// `LedgerAtOrAfter(n)`: current ledger sequence is at least `n`.
pub(crate) fn ledger_at_or_after(env: &Env, n: u32) -> Verdict {
    Verdict::from(env.ledger().sequence() >= n)
}
