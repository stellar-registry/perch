//! Perch's hand-written eval vectors (`perch_conformance::cases`, pinned to
//! `testdata/eval/eval-vectors.json`) against rule-eval, on the fragment
//! Perch's lowering emits: argument leaves of the kinds it emits
//! (`ArgAddrEq`, `ArgAddrIsSelf`, `ArgStrIn`, `ArgStrPrefix`, `ArgU32Eq`), at
//! most one `MinSigners` and one `FnIn`, and one `All` over all of them; a
//! case that is a single such leaf is read as that `All` of one.
//!
//! For each valid case in the fragment, the interpreter policy allows the
//! case's context when the case's hand-written verdict is `True`, at least
//! one signer authenticated (its signer floor), and the context is a
//! contract call (OZ refuses any other for the contract-call rules Perch
//! installs, before a policy runs). That must equal
//! rule-eval's `rule_allows` for the program's denotation
//! (`perch_rule_eval::denote`) on the context as the account reads it
//! (`convert::calls`), under `signer_count` of the rule's signers. For a
//! single-leaf case on a contract call, the leaf's verdict must also equal
//! `cond_holds` of its one condition, `functions_match` of its functions, or
//! `signers_met` at its own count (without the floor), whichever the leaf
//! denotes.

use perch_conformance::{cases, materialize, AddrBook, CtxKind, OpSpec};
use perch_program::{Op, RpnProgram, Verdict};
use perch_rule_eval::convert::{calls, signers};
use perch_rule_eval::{denote, Installed};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, Vec as SVec};
use stellar_accounts::smart_account::Signer;

/// Whether `ops` is in the fragment Perch's lowering emits, and whether it
/// is a single leaf without its `All`.
fn fragment(ops: &[OpSpec]) -> Option<bool> {
    let (leaves, bare) = match ops {
        [.., OpSpec::All(n)] if *n as usize == ops.len() - 1 => (&ops[..ops.len() - 1], false),
        [_] => (ops, true),
        _ => return None,
    };
    let (mut min_signers, mut fn_in) = (0, 0);
    for op in leaves {
        match op {
            OpSpec::MinSigners(_) => min_signers += 1,
            OpSpec::FnIn(_) => fn_in += 1,
            OpSpec::ArgAddrEq(..)
            | OpSpec::ArgAddrIsSelf(_)
            | OpSpec::ArgStrIn(..)
            | OpSpec::ArgStrPrefix(..)
            | OpSpec::ArgU32Eq(..) => {}
            _ => return None,
        }
    }
    (!leaves.is_empty() && min_signers <= 1 && fn_in <= 1).then_some(bare)
}

#[test]
fn the_hand_written_leaf_vectors_agree_with_rule_eval_on_the_lowered_fragment() {
    let env = Env::default();
    let mut book = AddrBook::new();
    let (mut run, mut leaves, mut allowed) = (0, 0, 0);
    for c in cases() {
        if c.expect_valid.is_err() {
            continue;
        }
        let Some(bare) = fragment(&c.ops) else {
            continue;
        };
        let (program, context, signer_count, me) = materialize(&env, &mut book, &c);
        let mut ops = program.ops.clone();
        if bare {
            ops.push_back(Op::All(1));
        }
        let program = RpnProgram {
            version: program.version,
            ops,
        };
        let threshold = program
            .ops
            .iter()
            .find_map(|op| match op {
                Op::MinSigners(n) => Some(n),
                _ => None,
            })
            .unwrap_or(0);
        let rule_signers: std::vec::Vec<Signer> = (0..signer_count.max(threshold).max(1))
            .map(|_| Signer::Delegated(Address::generate(&env)))
            .collect();
        let rule = denote(
            &env,
            &me,
            &Installed {
                contract: book.get(&env, "target-contract"),
                signers: SVec::from_slice(&env, &rule_signers),
                valid_until: None,
                program: Some(program),
                cap: None,
            },
        )
        .unwrap_or_else(|| panic!("case `{}`: denote refuses it", c.name));
        let authenticated = signers(
            &env,
            &SVec::from_slice(&env, &rule_signers[..signer_count as usize]),
        )
        .unwrap();
        let read = calls(&env, &SVec::from_array(&env, [context]));
        let allows = read
            .as_ref()
            .and_then(|cs| cs.first())
            .is_some_and(|ctx| rule_eval::rule_allows(&rule, ctx, &authenticated));
        // Every rule Perch installs is a contract-call rule, which OZ refuses
        // for any other context before a policy runs.
        let interpreter = c.expect_verdict == Verdict::True
            && signer_count >= 1
            && c.inv.ctx == CtxKind::Contract;
        assert_eq!(
            allows, interpreter,
            "case `{}` ({}): rule-eval and the hand-written verdict disagree",
            c.name, c.pins
        );
        run += 1;
        allowed += usize::from(allows);

        // The leaf alone.
        if !bare || c.inv.ctx != CtxKind::Contract {
            continue;
        }
        let Some(rule_eval::Context::Call { function, args, .. }) =
            read.as_ref().and_then(|cs| cs.first())
        else {
            panic!("case `{}`: a contract call the account cannot read", c.name);
        };
        let holds = match &c.ops[0] {
            OpSpec::MinSigners(n) => rule_eval::signers_met(&rule.signers, *n, &authenticated),
            OpSpec::FnIn(_) => rule_eval::functions_match(&rule.functions, function),
            _ => {
                let [cond] = rule.conds.as_slice() else {
                    panic!("case `{}`: a leaf without one condition", c.name);
                };
                rule_eval::cond_holds(cond, args)
            }
        };
        assert_eq!(
            holds,
            c.expect_verdict == Verdict::True,
            "case `{}` ({}): the leaf and its rule-eval denotation disagree",
            c.name,
            c.pins
        );
        leaves += 1;
    }
    println!("cases run: {run} (allowed: {allowed}), single leaves compared: {leaves}");
    assert!(run >= 30 && leaves >= 25, "the fragment lost its cases");
}
