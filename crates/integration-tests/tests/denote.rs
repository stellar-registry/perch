//! `denote` on installed rules Perch's lowering does not produce: what the
//! module documentation states for them, and the programs it refuses. The
//! rules Perch does produce are checked against rule-eval's lowering in
//! `tests/perch_rule_eval.rs`.

use perch_account_types::Signer;
use perch_program::{Op, RpnProgram, PROGRAM_VERSION};
use perch_rule_eval::convert::address;
use perch_testkit::denote::{denote, Installed};
use rule_eval::{Cap, Cond, Functions, Rule, Signer as ESigner};
use rule_eval_conformance::rules_eq;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String, Symbol, Vec};
use stellar_accounts::policies::spending_limit::SpendingLimitAccountParams;

struct Fixture {
    e: Env,
    me: Address,
    contract: Address,
    signers: [Address; 2],
}

impl Fixture {
    fn new() -> Fixture {
        let e = Env::default();
        let me = Address::generate(&e);
        let contract = Address::generate(&e);
        let signers = [Address::generate(&e), Address::generate(&e)];
        Fixture {
            e,
            me,
            contract,
            signers,
        }
    }

    fn installed(&self, program: Option<&[Op]>, cap: Option<i128>) -> Installed {
        Installed {
            contract: self.contract.clone(),
            signers: Vec::from_iter(
                &self.e,
                self.signers.iter().map(|s| Signer::Delegated(s.clone())),
            ),
            valid_until: Some(7),
            program: program.map(|ops| RpnProgram {
                version: PROGRAM_VERSION,
                ops: Vec::from_slice(&self.e, ops),
            }),
            cap: cap.map(|limit| SpendingLimitAccountParams {
                spending_limit: limit,
                period_ledgers: 10,
            }),
        }
    }

    fn denote(&self, program: Option<&[Op]>, cap: Option<i128>) -> Option<Rule> {
        denote(&self.e, &self.me, &self.installed(program, cap))
    }

    /// The rule on the fixture's contract and signers with these parts.
    fn rule(
        &self,
        functions: Functions,
        conds: std::vec::Vec<Cond>,
        threshold: u32,
        cap: Option<Cap>,
    ) -> Rule {
        Rule {
            contract: address(&self.e, &self.contract).unwrap(),
            functions,
            conds,
            signers: self
                .signers
                .iter()
                .map(|s| ESigner::Delegated(address(&self.e, s).unwrap()))
                .collect(),
            threshold,
            cap,
            valid_until: Some(7),
            auth_root: None,
            generation: None,
        }
    }

    fn fns(&self, names: &[&str]) -> Vec<Symbol> {
        Vec::from_iter(&self.e, names.iter().map(|n| Symbol::new(&self.e, n)))
    }
}

fn same(got: Option<Rule>, want: Rule, what: &str) {
    let got = got.unwrap_or_else(|| panic!("{what}: denote refuses"));
    assert!(rules_eq(&[got], &[want]), "{what}");
}

fn transfer_cap() -> Cap {
    Cap {
        limit: 5,
        period: 10,
        amount_arg: 2,
    }
}

#[test]
fn a_policy_requires_one_signer_at_least() {
    let f = Fixture::new();
    same(
        f.denote(None, None),
        f.rule(Functions::AnyExcept(vec![]), vec![], 2, None),
        "no policy: every signer",
    );
    same(
        f.denote(Some(&[Op::FnIn(f.fns(&["f"])), Op::All(1)]), None),
        f.rule(Functions::Only(vec![b"f".to_vec()]), vec![], 1, None),
        "a program without MinSigners",
    );
    same(
        f.denote(Some(&[Op::MinSigners(0), Op::All(1)]), None),
        f.rule(Functions::AnyExcept(vec![]), vec![], 1, None),
        "MinSigners(0)",
    );
    same(
        f.denote(Some(&[Op::MinSigners(3), Op::All(1)]), None),
        f.rule(Functions::AnyExcept(vec![]), vec![], 3, None),
        "MinSigners(3)",
    );
    same(
        f.denote(None, Some(5)),
        f.rule(
            Functions::Only(vec![b"transfer".to_vec()]),
            vec![Cond::ArgI128AtMost(2, i128::MAX)],
            1,
            Some(transfer_cap()),
        ),
        "the spending limit alone",
    );
}

#[test]
fn a_cap_allows_transfer_only_when_the_program_does() {
    let f = Fixture::new();
    same(
        f.denote(Some(&[Op::FnIn(f.fns(&["approve"])), Op::All(1)]), Some(5)),
        f.rule(
            Functions::Only(vec![]),
            vec![Cond::ArgI128AtMost(2, i128::MAX)],
            1,
            Some(transfer_cap()),
        ),
        "a program without transfer",
    );
    same(
        f.denote(
            Some(&[Op::FnIn(f.fns(&["approve", "transfer"])), Op::All(1)]),
            Some(5),
        ),
        f.rule(
            Functions::Only(vec![b"transfer".to_vec()]),
            vec![Cond::ArgI128AtMost(2, i128::MAX)],
            1,
            Some(transfer_cap()),
        ),
        "a program with transfer",
    );
}

#[test]
fn strings_over_256_bytes_never_match() {
    let f = Fixture::new();
    let long = "x".repeat(257);
    let at_most = "y".repeat(256);
    let set = Vec::from_array(
        &f.e,
        [
            String::from_str(&f.e, &long),
            String::from_str(&f.e, &at_most),
        ],
    );
    same(
        f.denote(
            Some(&[
                Op::ArgStrIn(0, set),
                Op::ArgStrPrefix(1, String::from_str(&f.e, &long)),
                Op::ArgStrPrefix(2, String::from_str(&f.e, &at_most)),
                Op::All(3),
            ]),
            None,
        ),
        f.rule(
            Functions::AnyExcept(vec![]),
            vec![
                Cond::ArgIn(
                    0,
                    vec![rule_eval::Val::String(at_most.clone().into_bytes())],
                ),
                Cond::ArgIn(1, vec![]),
                Cond::ArgStrPrefix(2, at_most.into_bytes()),
            ],
            1,
            None,
        ),
        "long strings",
    );
}

#[test]
fn a_program_outside_the_lowering_fragment_is_refused() {
    let f = Fixture::new();
    let fns = f.fns(&["f"]);
    let refused: [(&str, std::vec::Vec<Op>); 9] = [
        ("empty", vec![]),
        ("no All", vec![Op::MinSigners(1)]),
        ("All over nothing", vec![Op::All(0)]),
        (
            "All over fewer leaves",
            vec![Op::MinSigners(1), Op::FnIn(fns.clone()), Op::All(1)],
        ),
        (
            "All not last",
            vec![Op::MinSigners(1), Op::All(1), Op::FnIn(fns.clone())],
        ),
        ("Any", vec![Op::MinSigners(1), Op::Any(1)]),
        ("Not", vec![Op::MinSigners(1), Op::Not, Op::All(1)]),
        (
            "two FnIn",
            vec![Op::FnIn(fns.clone()), Op::FnIn(fns), Op::All(2)],
        ),
        (
            "two MinSigners",
            vec![Op::MinSigners(1), Op::MinSigners(2), Op::All(2)],
        ),
    ];
    for (what, ops) in refused {
        assert!(f.denote(Some(&ops), None).is_none(), "{what}");
    }
    for leaf in [
        Op::ArgSymEq(0, Symbol::new(&f.e, "a")),
        Op::ArgBytesEq(0, soroban_sdk::Bytes::new(&f.e)),
        Op::ArgI128Eq(0, 1),
        Op::ArgCount(1),
        Op::LedgerBefore(1),
        Op::LedgerAtOrAfter(1),
    ] {
        assert!(
            f.denote(Some(&[leaf.clone(), Op::All(1)]), None).is_none(),
            "{leaf:?}"
        );
    }
}
