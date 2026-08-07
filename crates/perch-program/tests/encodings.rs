//! Validation + evaluation tests for both candidate wire formats.
//!
//! Every test that exercises a leaf decode failure asserts the fail-closed
//! contract in BOTH polarities: `Unknown` in allow position (root leaf)
//! must deny, and `Unknown` in deny position (under `Not`) must still deny.

use perch_program::{
    arena, rpn, ArenaProgram, EvalInputs, Node, Op, RpnProgram, ValidationError, Verdict,
    PROGRAM_VERSION,
};
use soroban_sdk::auth::{
    Context, ContractContext, ContractExecutable, CreateContractHostFnContext,
};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{vec, Address, BytesN, Env, IntoVal, Symbol, Vec as SVec};

struct Fixture {
    env: Env,
    self_addr: Address,
    target: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        let self_addr = Address::generate(&env);
        let target = Address::generate(&env);
        Fixture {
            env,
            self_addr,
            target,
        }
    }

    /// Contract-call context: `target.transfer(42u32, "transfer", self_addr)`.
    fn contract_context(&self) -> Context {
        Context::Contract(ContractContext {
            contract: self.target.clone(),
            fn_name: Symbol::new(&self.env, "transfer"),
            args: vec![
                &self.env,
                42u32.into_val(&self.env),
                Symbol::new(&self.env, "transfer").into_val(&self.env),
                self.self_addr.into_val(&self.env),
            ],
        })
    }

    /// A non-`Contract` authorization context (deploy host fn).
    fn non_contract_context(&self) -> Context {
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(BytesN::from_array(&self.env, &[7u8; 32])),
            salt: BytesN::from_array(&self.env, &[9u8; 32]),
        })
    }

    fn eval_arena(&self, nodes: SVec<Node>, context: &Context, signer_count: u32) -> Verdict {
        let program = ArenaProgram {
            version: PROGRAM_VERSION,
            nodes,
        };
        let inputs = EvalInputs {
            context,
            signer_count,
            self_addr: &self.self_addr,
        };
        arena::eval(&self.env, &program, &inputs)
    }

    fn eval_rpn(&self, ops: SVec<Op>, context: &Context, signer_count: u32) -> Verdict {
        let program = RpnProgram {
            version: PROGRAM_VERSION,
            ops,
        };
        let inputs = EvalInputs {
            context,
            signer_count,
            self_addr: &self.self_addr,
        };
        rpn::eval(&self.env, &program, &inputs)
    }
}

/// The CI-publish shape: All(MinSigners(1), FnIn[2 syms], ArgAddrIsSelf(1)),
/// arena encoding.
fn ci_shape_arena(f: &Fixture) -> ArenaProgram {
    ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: vec![
            &f.env,
            Node::All(vec![&f.env, 1, 2, 3]),
            Node::MinSigners(1),
            Node::FnIn(vec![
                &f.env,
                Symbol::new(&f.env, "transfer"),
                Symbol::new(&f.env, "approve"),
            ]),
            Node::ArgAddrIsSelf(2),
        ],
    }
}

/// Same logical program, postfix encoding.
fn ci_shape_rpn(f: &Fixture) -> RpnProgram {
    RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![
            &f.env,
            Op::MinSigners(1),
            Op::FnIn(vec![
                &f.env,
                Symbol::new(&f.env, "transfer"),
                Symbol::new(&f.env, "approve"),
            ]),
            Op::ArgAddrIsSelf(2),
            Op::All(3),
        ],
    }
}

// ---------------------------------------------------------------- validation

#[test]
fn arena_validates_ci_shape() {
    let f = Fixture::new();
    assert_eq!(arena::validate(&ci_shape_arena(&f)), Ok(()));
}

#[test]
fn rpn_validates_ci_shape() {
    let f = Fixture::new();
    assert_eq!(rpn::validate(&ci_shape_rpn(&f)), Ok(()));
}

#[test]
fn arena_rejects_backward_and_self_reference() {
    let f = Fixture::new();
    // Not at index 1 pointing back at the root: backward edge.
    let backward = ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: vec![&f.env, Node::Not(1), Node::Not(0)],
    };
    assert_eq!(
        arena::validate(&backward),
        Err(ValidationError::ForwardRefViolation)
    );
    // Self-cycle: node references itself.
    let cycle = ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: vec![&f.env, Node::Not(0)],
    };
    assert_eq!(
        arena::validate(&cycle),
        Err(ValidationError::ForwardRefViolation)
    );
}

#[test]
fn arena_rejects_out_of_range_child() {
    let f = Fixture::new();
    let program = ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: vec![&f.env, Node::All(vec![&f.env, 1, 2]), Node::MinSigners(1)],
    };
    assert_eq!(
        arena::validate(&program),
        Err(ValidationError::IndexOutOfRange)
    );
}

#[test]
fn arena_rejects_zero_arity_composite() {
    let f = Fixture::new();
    let program = ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: vec![&f.env, Node::All(SVec::new(&f.env))],
    };
    assert_eq!(
        arena::validate(&program),
        Err(ValidationError::ArityMismatch)
    );
}

#[test]
fn arena_rejects_unknown_version_and_empty() {
    let f = Fixture::new();
    let mut program = ci_shape_arena(&f);
    program.version = PROGRAM_VERSION + 1;
    assert_eq!(
        arena::validate(&program),
        Err(ValidationError::UnknownVersion)
    );
    let empty = ArenaProgram {
        version: PROGRAM_VERSION,
        nodes: SVec::new(&f.env),
    };
    assert_eq!(arena::validate(&empty), Err(ValidationError::Empty));
}

#[test]
fn rpn_rejects_stack_underflow() {
    let f = Fixture::new();
    // Not with nothing on the stack.
    let bare_not = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&f.env, Op::Not],
    };
    assert_eq!(
        rpn::validate(&bare_not),
        Err(ValidationError::StackUnderflow)
    );
    // All(3) with only two operands pushed.
    let short_all = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&f.env, Op::MinSigners(1), Op::LedgerBefore(10), Op::All(3)],
    };
    assert_eq!(
        rpn::validate(&short_all),
        Err(ValidationError::StackUnderflow)
    );
}

#[test]
fn rpn_rejects_more_than_one_result() {
    let f = Fixture::new();
    let program = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&f.env, Op::MinSigners(1), Op::LedgerBefore(10)],
    };
    assert_eq!(
        rpn::validate(&program),
        Err(ValidationError::NotSingleResult)
    );
}

#[test]
fn rpn_rejects_zero_arity_composite() {
    let f = Fixture::new();
    let program = RpnProgram {
        version: PROGRAM_VERSION,
        ops: vec![&f.env, Op::MinSigners(1), Op::All(0)],
    };
    assert_eq!(rpn::validate(&program), Err(ValidationError::ArityMismatch));
}

#[test]
fn rpn_rejects_unknown_version_and_empty() {
    let f = Fixture::new();
    let mut program = ci_shape_rpn(&f);
    program.version = 0;
    assert_eq!(
        rpn::validate(&program),
        Err(ValidationError::UnknownVersion)
    );
    let empty = RpnProgram {
        version: PROGRAM_VERSION,
        ops: SVec::new(&f.env),
    };
    assert_eq!(rpn::validate(&empty), Err(ValidationError::Empty));
}

// ---------------------------------------------------------------------- eval

#[test]
fn ci_shape_allows_matching_call_in_both_encodings() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    let inputs = EvalInputs {
        context: &ctx,
        signer_count: 1,
        self_addr: &f.self_addr,
    };
    assert_eq!(
        arena::eval(&f.env, &ci_shape_arena(&f), &inputs),
        Verdict::True
    );
    assert_eq!(rpn::eval(&f.env, &ci_shape_rpn(&f), &inputs), Verdict::True);
}

#[test]
fn ci_shape_denies_definitely_on_wrong_fn_and_zero_signers() {
    let f = Fixture::new();
    let ctx = Context::Contract(ContractContext {
        contract: f.target.clone(),
        fn_name: Symbol::new(&f.env, "burn"),
        args: vec![&f.env, 1u32.into_val(&f.env)],
    });
    let inputs = EvalInputs {
        context: &ctx,
        signer_count: 0,
        self_addr: &f.self_addr,
    };
    // MinSigners(1) with 0 signers is False; FnIn misses: False, and the
    // missing arg 2 makes ArgAddrIsSelf Unknown. min(False, ...) = False.
    assert_eq!(
        arena::eval(&f.env, &ci_shape_arena(&f), &inputs),
        Verdict::False
    );
    assert_eq!(
        rpn::eval(&f.env, &ci_shape_rpn(&f), &inputs),
        Verdict::False
    );
}

/// Every context-inspecting leaf yields Unknown (denies) on a missing arg,
/// a wrong-typed arg, and a non-contract context — in allow position and,
/// via Not, in deny position.
#[test]
fn leaf_decode_failure_is_unknown_in_both_polarities() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    let non_contract = f.non_contract_context();
    let sym = Symbol::new(&f.env, "transfer");

    let leaves = [
        // Missing argument index (context has 3 args).
        Node::ArgAddrEq(9, f.target.clone()),
        Node::ArgAddrIsSelf(9),
        Node::ArgSymEq(9, sym.clone()),
        Node::ArgU32Eq(9, 42),
        // Wrong argument type (arg 0 is u32; arg 2 is an address).
        Node::ArgAddrEq(0, f.target.clone()),
        Node::ArgAddrIsSelf(0),
        Node::ArgSymEq(0, sym.clone()),
        Node::ArgU32Eq(2, 42),
    ];
    for node in leaves {
        let op = node_to_op(&node);
        // Allow position: the leaf is the root.
        assert_eq!(
            f.eval_arena(vec![&f.env, node.clone()], &ctx, 1),
            Verdict::Unknown,
            "arena allow position: {node:?}"
        );
        assert_eq!(
            f.eval_rpn(vec![&f.env, op.clone()], &ctx, 1),
            Verdict::Unknown,
            "rpn allow position: {node:?}"
        );
        // Deny position: Not(leaf) must stay Unknown, not flip to True.
        assert_eq!(
            f.eval_arena(vec![&f.env, Node::Not(1), node.clone()], &ctx, 1),
            Verdict::Unknown,
            "arena deny position: {node:?}"
        );
        assert_eq!(
            f.eval_rpn(vec![&f.env, op.clone(), Op::Not], &ctx, 1),
            Verdict::Unknown,
            "rpn deny position: {node:?}"
        );
    }

    // Non-contract context: every context-inspecting leaf is Unknown, even
    // ones that would be True/False under a contract context.
    let ctx_leaves = [
        Node::FnIn(vec![&f.env, sym.clone()]),
        Node::ArgAddrEq(0, f.target.clone()),
        Node::ArgAddrIsSelf(2),
        Node::ArgSymEq(1, sym.clone()),
        Node::ArgU32Eq(0, 42),
    ];
    for node in ctx_leaves {
        let op = node_to_op(&node);
        assert_eq!(
            f.eval_arena(vec![&f.env, node.clone()], &non_contract, 1),
            Verdict::Unknown,
            "arena non-contract ctx: {node:?}"
        );
        assert_eq!(
            f.eval_rpn(vec![&f.env, op], &non_contract, 1),
            Verdict::Unknown,
            "rpn non-contract ctx: {node:?}"
        );
    }
}

/// Leaf-for-leaf translation for tests that run the same leaf through both
/// encodings.
fn node_to_op(node: &Node) -> Op {
    match node {
        Node::MinSigners(n) => Op::MinSigners(*n),
        Node::FnIn(fns) => Op::FnIn(fns.clone()),
        Node::ArgAddrEq(i, a) => Op::ArgAddrEq(*i, a.clone()),
        Node::ArgAddrIsSelf(i) => Op::ArgAddrIsSelf(*i),
        Node::ArgSymEq(i, s) => Op::ArgSymEq(*i, s.clone()),
        Node::ArgU32Eq(i, n) => Op::ArgU32Eq(*i, *n),
        Node::LedgerBefore(n) => Op::LedgerBefore(*n),
        Node::LedgerAtOrAfter(n) => Op::LedgerAtOrAfter(*n),
        composite => panic!("not a leaf: {composite:?}"),
    }
}

#[test]
fn min_signers_boundary() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    for (signers, want) in [(1, Verdict::False), (2, Verdict::True), (3, Verdict::True)] {
        assert_eq!(
            f.eval_arena(vec![&f.env, Node::MinSigners(2)], &ctx, signers),
            want
        );
        assert_eq!(
            f.eval_rpn(vec![&f.env, Op::MinSigners(2)], &ctx, signers),
            want
        );
    }
}

#[test]
fn ledger_leaves_track_sequence() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    f.env.ledger().with_mut(|l| l.sequence_number = 100);
    for (node, want) in [
        (Node::LedgerBefore(101), Verdict::True),
        (Node::LedgerBefore(100), Verdict::False),
        (Node::LedgerAtOrAfter(100), Verdict::True),
        (Node::LedgerAtOrAfter(101), Verdict::False),
    ] {
        let op = node_to_op(&node);
        assert_eq!(f.eval_arena(vec![&f.env, node], &ctx, 1), want);
        assert_eq!(f.eval_rpn(vec![&f.env, op], &ctx, 1), want);
    }
}

/// Nested composition: All(Any(False, Not(False)), Not(Unknown)) — the Any
/// rescues a False branch via Not(False)=True, but the Unknown under the
/// outer Not still poisons the conjunction down to Unknown.
#[test]
fn nested_composition_mixes_kleene_correctly() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    // False leaf: ArgU32Eq(0, 43) (arg 0 is 42). Unknown leaf: ArgU32Eq(9, 1).
    let nodes = vec![
        &f.env,
        Node::All(vec![&f.env, 1, 5]), // 0
        Node::Any(vec![&f.env, 2, 3]), // 1
        Node::ArgU32Eq(0, 43),         // 2: False
        Node::Not(4),                  // 3
        Node::ArgU32Eq(0, 43),         // 4: False -> Not = True
        Node::Not(6),                  // 5
        Node::ArgU32Eq(9, 1),          // 6: Unknown -> Not = Unknown
    ];
    let ops = vec![
        &f.env,
        Op::ArgU32Eq(0, 43),
        Op::ArgU32Eq(0, 43),
        Op::Not,
        Op::Any(2),
        Op::ArgU32Eq(9, 1),
        Op::Not,
        Op::All(2),
    ];
    assert_eq!(f.eval_arena(nodes, &ctx, 1), Verdict::Unknown);
    assert_eq!(f.eval_rpn(ops, &ctx, 1), Verdict::Unknown);

    // Swap the Unknown branch for a True one: the whole thing goes True.
    let nodes_true = vec![
        &f.env,
        Node::All(vec![&f.env, 1, 5]),
        Node::Any(vec![&f.env, 2, 3]),
        Node::ArgU32Eq(0, 43),
        Node::Not(4),
        Node::ArgU32Eq(0, 43),
        Node::Not(6),
        Node::ArgU32Eq(0, 43), // False -> Not = True
    ];
    let ops_true = vec![
        &f.env,
        Op::ArgU32Eq(0, 43),
        Op::ArgU32Eq(0, 43),
        Op::Not,
        Op::Any(2),
        Op::ArgU32Eq(0, 43),
        Op::Not,
        Op::All(2),
    ];
    assert_eq!(f.eval_arena(nodes_true, &ctx, 1), Verdict::True);
    assert_eq!(f.eval_rpn(ops_true, &ctx, 1), Verdict::True);
}

/// Defensive eval on *unvalidated* garbage stays fail-closed (Unknown).
#[test]
fn eval_is_fail_closed_on_unvalidated_programs() {
    let f = Fixture::new();
    let ctx = f.contract_context();
    // Arena: out-of-range child.
    assert_eq!(
        f.eval_arena(vec![&f.env, Node::Not(7)], &ctx, 1),
        Verdict::Unknown
    );
    // Arena: self-cycle terminates via the depth guard.
    assert_eq!(
        f.eval_arena(vec![&f.env, Node::All(vec![&f.env, 0])], &ctx, 1),
        Verdict::Unknown
    );
    // RPN: underflow and non-single result.
    assert_eq!(f.eval_rpn(vec![&f.env, Op::Not], &ctx, 1), Verdict::Unknown);
    assert_eq!(
        f.eval_rpn(vec![&f.env, Op::MinSigners(1), Op::MinSigners(1)], &ctx, 1),
        Verdict::Unknown
    );
}
