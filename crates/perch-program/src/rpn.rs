//! Postfix (RPN) encoding — the frozen perch-program v1 wire format,
//! chosen by the benchmark in `crates/perch-program/BENCH.md`.
//!
//! Ops are evaluated left-to-right against a [`Verdict`] value stack:
//! leaves push, `Not` pops one, `All(n)`/`Any(n)` pop `n` and push the
//! fold. Validation is a stack-effect simulation — each op pops/pushes
//! statically known counts, and a program is valid iff the simulation
//! never underflows, never exceeds [`MAX_STACK_DEPTH`], and ends with
//! exactly one value (the root verdict).

use soroban_sdk::{contracttype, Address, Bytes, Env, String, Symbol, Vec};

use crate::{
    leaf, EvalInputs, ValidationError, Verdict, MAX_PROGRAM_LEN, MAX_STACK_DEPTH, PROGRAM_VERSION,
};

/// One op of a postfix-encoded constraint program.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Op {
    /// Pop `n` verdicts, push their Kleene conjunction.
    All(u32),
    /// Pop `n` verdicts, push their Kleene disjunction.
    Any(u32),
    /// Pop one verdict, push its Kleene negation.
    Not,
    /// At least this many authenticated signers.
    MinSigners(u32),
    /// Invoked function is one of these symbols.
    FnIn(Vec<Symbol>),
    /// Argument at index equals this address.
    ArgAddrEq(u32, Address),
    /// Argument at index is the protected account itself.
    ArgAddrIsSelf(u32),
    /// Argument at index equals this symbol.
    ArgSymEq(u32, Symbol),
    /// Argument at index (a string) is one of these strings.
    ArgStrIn(u32, Vec<String>),
    /// Argument at index (a string) starts with this prefix.
    ArgStrPrefix(u32, String),
    /// Argument at index equals these bytes.
    ArgBytesEq(u32, Bytes),
    /// Argument at index equals this i128.
    ArgI128Eq(u32, i128),
    /// Argument at index equals this u32.
    ArgU32Eq(u32, u32),
    /// The call has exactly this many arguments.
    ArgCount(u32),
    /// Current ledger sequence is strictly below this.
    LedgerBefore(u32),
    /// Current ledger sequence is at least this.
    LedgerAtOrAfter(u32),
}

/// A postfix-encoded constraint program. The last op produces the root
/// verdict.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpnProgram {
    pub version: u32,
    pub ops: Vec<Op>,
}

/// What the compiler stores in the interpreter for one `(account, rule)`: the
/// program plus the `doc_hash` of the source PolicyDoc. Sharing this
/// `#[contracttype]` between the compiler and the interpreter is what keeps
/// install params from ever being a hand-built `ScVal` — both sides encode and
/// decode through exactly these types. `doc_hash` binds the on-chain program to
/// the reviewed document (provenance for lift/diff).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallParams {
    pub program: RpnProgram,
    pub doc_hash: soroban_sdk::BytesN<32>,
}

/// How many verdicts an op pops. Every op pushes exactly one.
fn pops(op: &Op) -> Result<u32, ValidationError> {
    match op {
        Op::All(n) | Op::Any(n) => {
            if *n == 0 {
                Err(ValidationError::ArityMismatch)
            } else {
                Ok(*n)
            }
        }
        Op::Not => Ok(1),
        _ => Ok(0),
    }
}

/// Validate an RPN program by simulating its stack effect.
pub fn validate(program: &RpnProgram) -> Result<(), ValidationError> {
    if program.version != PROGRAM_VERSION {
        return Err(ValidationError::UnknownVersion);
    }
    let len = program.ops.len();
    if len == 0 {
        return Err(ValidationError::Empty);
    }
    if len > MAX_PROGRAM_LEN {
        return Err(ValidationError::TooLarge);
    }
    let mut depth: u32 = 0;
    for op in program.ops.iter() {
        let pops = pops(&op)?;
        if depth < pops {
            return Err(ValidationError::StackUnderflow);
        }
        depth = depth - pops + 1;
        if depth > MAX_STACK_DEPTH {
            return Err(ValidationError::StackOverflow);
        }
    }
    if depth == 1 {
        Ok(())
    } else {
        Err(ValidationError::NotSingleResult)
    }
}

/// Evaluate an RPN program with an explicit verdict stack.
///
/// Assumes a validated program but stays fail-closed on malformed input:
/// stack underflow, overflow past [`MAX_STACK_DEPTH`], a zero-arity
/// composite, or a final stack size other than one yields
/// [`Verdict::Unknown`].
pub fn eval(env: &Env, program: &RpnProgram, inputs: &EvalInputs) -> Verdict {
    let mut stack = [Verdict::Unknown; MAX_STACK_DEPTH as usize];
    let mut sp: usize = 0;
    for op in program.ops.iter() {
        let v = match op {
            Op::All(n) => {
                if n == 0 || (sp as u32) < n {
                    return Verdict::Unknown;
                }
                let mut v = Verdict::True;
                for _ in 0..n {
                    sp -= 1;
                    v = v.and(stack[sp]);
                }
                v
            }
            Op::Any(n) => {
                if n == 0 || (sp as u32) < n {
                    return Verdict::Unknown;
                }
                let mut v = Verdict::False;
                for _ in 0..n {
                    sp -= 1;
                    v = v.or(stack[sp]);
                }
                v
            }
            Op::Not => {
                if sp == 0 {
                    return Verdict::Unknown;
                }
                sp -= 1;
                !stack[sp]
            }
            Op::MinSigners(n) => leaf::min_signers(inputs, n),
            Op::FnIn(fns) => leaf::fn_in(inputs, &fns),
            Op::ArgAddrEq(i, addr) => leaf::arg_addr_eq(env, inputs, i, &addr),
            Op::ArgAddrIsSelf(i) => leaf::arg_addr_is_self(env, inputs, i),
            Op::ArgSymEq(i, sym) => leaf::arg_sym_eq(env, inputs, i, &sym),
            Op::ArgStrIn(i, set) => leaf::arg_str_in(env, inputs, i, &set),
            Op::ArgStrPrefix(i, prefix) => leaf::arg_str_prefix(env, inputs, i, &prefix),
            Op::ArgBytesEq(i, want) => leaf::arg_bytes_eq(env, inputs, i, &want),
            Op::ArgI128Eq(i, want) => leaf::arg_i128_eq(env, inputs, i, want),
            Op::ArgU32Eq(i, n) => leaf::arg_u32_eq(env, inputs, i, n),
            Op::ArgCount(n) => leaf::arg_count(inputs, n),
            Op::LedgerBefore(n) => leaf::ledger_before(env, n),
            Op::LedgerAtOrAfter(n) => leaf::ledger_at_or_after(env, n),
        };
        if sp >= MAX_STACK_DEPTH as usize {
            return Verdict::Unknown;
        }
        stack[sp] = v;
        sp += 1;
    }
    if sp == 1 {
        stack[0]
    } else {
        Verdict::Unknown
    }
}
