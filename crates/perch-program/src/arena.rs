//! Encoding A — node arena.
//!
//! `#[contracttype]` cannot express recursive enums, so composite nodes
//! (`All`/`Any`/`Not`) reference children by `u32` index into a flat node
//! vector. Indices are FORWARD-ONLY (`child > own index`), so a single
//! linear validation pass proves acyclicity; node 0 is the root.

use soroban_sdk::{contracttype, Address, Env, Symbol, Vec};

use crate::{leaf, EvalInputs, ValidationError, Verdict, MAX_PROGRAM_LEN, PROGRAM_VERSION};

/// One node of an arena-encoded constraint program. Composite variants hold
/// child *indices*; leaves hold their parameters inline.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// Kleene conjunction of the child nodes at these indices.
    All(Vec<u32>),
    /// Kleene disjunction of the child nodes at these indices.
    Any(Vec<u32>),
    /// Kleene negation of the child node at this index.
    Not(u32),
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
    /// Argument at index equals this u32.
    ArgU32Eq(u32, u32),
    /// Current ledger sequence is strictly below this.
    LedgerBefore(u32),
    /// Current ledger sequence is at least this.
    LedgerAtOrAfter(u32),
}

/// An arena-encoded constraint program. `nodes[0]` is the root.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArenaProgram {
    pub version: u32,
    pub nodes: Vec<Node>,
}

fn check_child(parent: u32, child: u32, len: u32) -> Result<(), ValidationError> {
    if child <= parent {
        return Err(ValidationError::ForwardRefViolation);
    }
    if child >= len {
        return Err(ValidationError::IndexOutOfRange);
    }
    Ok(())
}

/// Validate an arena program in a single forward pass.
///
/// Checks: known version, non-empty, bounded size, `All`/`Any` arity >= 1,
/// and every child index strictly greater than its parent's index and in
/// range. Forward-only indices make the child graph a DAG with no back
/// edges, so evaluation from node 0 always terminates.
pub fn validate(program: &ArenaProgram) -> Result<(), ValidationError> {
    if program.version != PROGRAM_VERSION {
        return Err(ValidationError::UnknownVersion);
    }
    let len = program.nodes.len();
    if len == 0 {
        return Err(ValidationError::Empty);
    }
    if len > MAX_PROGRAM_LEN {
        return Err(ValidationError::TooLarge);
    }
    for (i, node) in program.nodes.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let i = i as u32;
        match node {
            Node::All(kids) | Node::Any(kids) => {
                if kids.is_empty() {
                    return Err(ValidationError::ArityMismatch);
                }
                for k in kids.iter() {
                    check_child(i, k, len)?;
                }
            }
            Node::Not(k) => check_child(i, k, len)?,
            _ => {}
        }
    }
    Ok(())
}

/// Evaluate an arena program from its root (node 0).
///
/// Assumes a validated program but stays fail-closed on malformed input:
/// an out-of-range index or a recursion depth past [`MAX_PROGRAM_LEN`]
/// (only reachable with non-forward references, i.e. unvalidated input)
/// yields [`Verdict::Unknown`].
///
/// Composites deliberately do NOT short-circuit: every referenced child is
/// evaluated, so cost depends on program shape, not runtime data — and the
/// wire-format benchmark compares encodings on identical work.
pub fn eval(env: &Env, program: &ArenaProgram, inputs: &EvalInputs) -> Verdict {
    eval_node(env, program, inputs, 0, 0)
}

fn eval_node(
    env: &Env,
    program: &ArenaProgram,
    inputs: &EvalInputs,
    idx: u32,
    depth: u32,
) -> Verdict {
    if depth > MAX_PROGRAM_LEN {
        return Verdict::Unknown;
    }
    let Some(node) = program.nodes.get(idx) else {
        return Verdict::Unknown;
    };
    match node {
        Node::All(kids) => {
            let mut v = Verdict::True;
            for k in kids.iter() {
                v = v.and(eval_node(env, program, inputs, k, depth + 1));
            }
            v
        }
        Node::Any(kids) => {
            let mut v = Verdict::False;
            for k in kids.iter() {
                v = v.or(eval_node(env, program, inputs, k, depth + 1));
            }
            v
        }
        Node::Not(k) => !eval_node(env, program, inputs, k, depth + 1),
        Node::MinSigners(n) => leaf::min_signers(inputs, n),
        Node::FnIn(fns) => leaf::fn_in(inputs, &fns),
        Node::ArgAddrEq(i, addr) => leaf::arg_addr_eq(env, inputs, i, &addr),
        Node::ArgAddrIsSelf(i) => leaf::arg_addr_is_self(env, inputs, i),
        Node::ArgSymEq(i, sym) => leaf::arg_sym_eq(env, inputs, i, &sym),
        Node::ArgU32Eq(i, n) => leaf::arg_u32_eq(env, inputs, i, n),
        Node::LedgerBefore(n) => leaf::ledger_before(env, n),
        Node::LedgerAtOrAfter(n) => leaf::ledger_at_or_after(env, n),
    }
}
