//! Static analysis over a compiled [`Plan`] (#19, idea 1 — Miniscript's
//! "the compiled form answers questions about itself").
//!
//! A `doc_hash` is an identity; these queries make the thing it identifies an
//! *auditable object*. They read only the ops — no execution, no environment —
//! and are **total** because perch-program v1 is a decidable fragment (see
//! `perch_program`'s "Decidable fragment" section, pinned by
//! `perch-program/tests/fragment_v1.rs`).
//!
//! - [`reachable_calls`] — every `(scope, function-set)` a plan can authorize.
//!   For the flagship CI-publish policy this is exactly
//!   `{ (REGISTRY, {publish, publish_hash}) }` plus the policy-free admin rule.
//! - [`program_bounds`] — worst-case op count and stack depth, so gas is
//!   provable before deploy.
//! - [`can_ever_authorize`] — a sound liveness check: `false` means the rule is
//!   dead (can never yield `True`); `true` means "not provably dead".

use crate::{LoweredRule, Plan, ScopeSpec};
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use perch_program::{Op, RpnProgram, Verdict};
use soroban_sdk::Symbol;

/// The functions a rule can authorize on its scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FnSet {
    /// Any function on the scope — the rule carries no function restriction
    /// (a policy-free / constraint-free rule; INV-2), so OZ's native
    /// all-signers check gates it for every function in the context.
    Any,
    /// Only these functions (the rule's `FnIn` allowlist).
    Only(Vec<Symbol>),
}

/// One `(rule, scope, functions)` the plan can authorize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReachableScope {
    pub rule: String,
    pub scope: ScopeSpec,
    pub functions: FnSet,
}

/// Worst-case execution shape of a program, derived from the ops alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramBounds {
    /// Number of ops (bounded by `perch_program::MAX_PROGRAM_LEN`).
    pub ops: u32,
    /// Maximum verdict-stack depth reached (bounded by
    /// `perch_program::MAX_STACK_DEPTH`).
    pub max_stack_depth: u32,
}

impl ProgramBounds {
    /// Whether the program fits within an op budget.
    #[must_use]
    pub fn fits(&self, max_ops: u32) -> bool {
        self.ops <= max_ops
    }
}

/// Every `(scope, function-set)` the plan can authorize — an upper bound read
/// from the ops, no execution.
///
/// For a plan produced by [`crate::compile`] each rule carries at most one
/// `FnIn`, so the result is exact. If a hand-built program stacked several
/// `FnIn` ops the union returned here is an upper bound on what could pass.
#[must_use]
pub fn reachable_calls(plan: &Plan) -> Vec<ReachableScope> {
    plan.rules
        .iter()
        .map(|rule| ReachableScope {
            rule: rule.name.clone(),
            scope: rule.scope.clone(),
            functions: rule_functions(rule),
        })
        .collect()
}

fn rule_functions(rule: &LoweredRule) -> FnSet {
    // No interpreter attached ⇒ no function restriction: any function on the
    // scope (INV-2 policy-free rule).
    let Some(install) = &rule.install else {
        return FnSet::Any;
    };
    let mut fns: Vec<Symbol> = Vec::new();
    let mut saw_fnin = false;
    for op in install.program.ops.iter() {
        if let Op::FnIn(set) = op {
            saw_fnin = true;
            for s in set.iter() {
                if !fns.contains(&s) {
                    fns.push(s);
                }
            }
        }
    }
    if saw_fnin {
        FnSet::Only(fns)
    } else {
        // Constrained on arguments only, no function allowlist — any function.
        FnSet::Any
    }
}

/// Worst-case op count and stack depth of a program. Same stack-effect model as
/// `perch_program::rpn::validate`, tracking the peak depth.
#[must_use]
pub fn program_bounds(program: &RpnProgram) -> ProgramBounds {
    let mut depth: u32 = 0;
    let mut max_depth: u32 = 0;
    for op in program.ops.iter() {
        let pops = match op {
            Op::All(n) | Op::Any(n) => n,
            Op::Not => 1,
            _ => 0,
        };
        depth = depth.saturating_sub(pops).saturating_add(1);
        max_depth = max_depth.max(depth);
    }
    ProgramBounds {
        ops: program.ops.len(),
        max_stack_depth: max_depth,
    }
}

/// Whether any input could make this program authorize (root verdict `True`).
///
/// Sound over-approximation: each leaf is modelled as free over the Kleene
/// lattice `False < Unknown < True`, except the structurally-constant leaves
/// (`MinSigners(0)` is always `True`; `LedgerBefore(0)` is always `False`, since
/// a ledger sequence is never below zero). The `All`/`Any`/`Not` folds are
/// evaluated as intervals. Therefore **`false` is a definite verdict — the rule
/// is dead and can never authorize** — while `true` means "not provably dead"
/// (a specific runtime leaf could still deny). Argument- and ledger-window
/// contradictions across independent leaves are not modelled.
#[must_use]
pub fn can_ever_authorize(program: &RpnProgram) -> bool {
    max_verdict(program) == Verdict::True
}

/// Best-case (maximum) root verdict under the free-leaf interval abstraction.
/// A malformed program (underflow / not-single-result) folds to `Unknown`,
/// matching `rpn::eval`'s fail-closed behaviour.
fn max_verdict(program: &RpnProgram) -> Verdict {
    // Each stack entry is an interval `(lo, hi)` of achievable verdicts.
    let mut stack: Vec<(Verdict, Verdict)> = Vec::new();
    for op in program.ops.iter() {
        match op {
            Op::All(n) => {
                let n = n as usize;
                if n == 0 || stack.len() < n {
                    return Verdict::Unknown;
                }
                // Conjunction is min: min the los and the his.
                let (mut lo, mut hi) = (Verdict::True, Verdict::True);
                for _ in 0..n {
                    let (l, h) = stack.pop().expect("checked len");
                    lo = lo.min(l);
                    hi = hi.min(h);
                }
                stack.push((lo, hi));
            }
            Op::Any(n) => {
                let n = n as usize;
                if n == 0 || stack.len() < n {
                    return Verdict::Unknown;
                }
                // Disjunction is max: max the los and the his.
                let (mut lo, mut hi) = (Verdict::False, Verdict::False);
                for _ in 0..n {
                    let (l, h) = stack.pop().expect("checked len");
                    lo = lo.max(l);
                    hi = hi.max(h);
                }
                stack.push((lo, hi));
            }
            Op::Not => {
                let Some((lo, hi)) = stack.pop() else {
                    return Verdict::Unknown;
                };
                // Negation is antitone: the interval flips.
                stack.push((!hi, !lo));
            }
            leaf => stack.push(leaf_interval(&leaf)),
        }
    }
    match stack.as_slice() {
        [(_, hi)] => *hi,
        _ => Verdict::Unknown,
    }
}

/// The interval of verdicts a leaf op can take, over all inputs.
fn leaf_interval(op: &Op) -> (Verdict, Verdict) {
    match op {
        // "At least zero signers" is always satisfied.
        Op::MinSigners(0) => (Verdict::True, Verdict::True),
        // A ledger sequence is never below zero.
        Op::LedgerBefore(0) => (Verdict::False, Verdict::False),
        // Every other leaf can, for some input, take any verdict.
        _ => (Verdict::False, Verdict::True),
    }
}
