//! Every mirror round-trips: a rule-eval value converted to its
//! `#[contracttype]` mirror and back is the same value, the mirror survives
//! the host's XDR, and a conversion refuses exactly the values with no host
//! form.
//!
//! The values are hand-written to hold every constructor, then drawn by a
//! seeded generator over the same pools.

use perch_rule_eval::convert::{address, contexts, host_address, val};
use perch_rule_eval::{
    doc_of, CompiledModel, ModelArg, ModelCap, ModelPred, ModelPrincipals, ModelRecovery,
    ModelRule, ModelScope, ModelSigner, ModelZk, StoredCap, StoredRecord, StoredRule,
};
use rule_eval::{
    ArgConstraint, Cap, Cond, Doc, DocCap, DocRule, Functions, Pred, Principals, Recovery, Rule,
    Scope, Signer, SignerDecl, SpendEntry, SpendRecord, Val, ZkFactor,
};
use rule_eval_conformance::rules_eq;
use soroban_facade::xdr;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::{FromXdr, ToXdr};
use soroban_sdk::{
    Address, Bytes, Env, IntoVal, String as SString, Symbol, TryFromVal, Val as SVal, Vec as SVec,
};

/// SplitMix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<T: Clone>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len())].clone()
    }

    fn list<T>(&mut self, max: usize, mut f: impl FnMut(&mut Rng) -> T) -> Vec<T> {
        let n = self.below(max + 1);
        (0..n).map(|_| f(self)).collect()
    }
}

/// What the generator draws identifiers from: the `ScAddress` XDR of contract
/// and account addresses, keys, names and strings.
struct Pools {
    addresses: Vec<Vec<u8>>,
    keys: Vec<Vec<u8>>,
    names: Vec<Vec<u8>>,
    strings: Vec<Vec<u8>>,
    others: Vec<Vec<u8>>,
}

fn account_xdr(key: u8) -> Vec<u8> {
    let mut x = vec![0, 0, 0, 0, 0, 0, 0, 0];
    x.extend_from_slice(&[key; 32]);
    x
}

fn pools(e: &Env) -> Pools {
    let mut addresses: Vec<Vec<u8>> = (0..4)
        .map(|_| address(e, &Address::generate(e)).unwrap())
        .collect();
    addresses.push(account_xdr(7));
    addresses.push(account_xdr(9));
    Pools {
        addresses,
        keys: vec![vec![], vec![1], vec![2; 32], vec![0xff; 65]],
        names: [
            "transfer",
            "approve",
            "",
            "f_2",
            "a_name_of_exactly_32_bytes_here_",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect(),
        strings: vec![
            b"".to_vec(),
            b"pkg_".to_vec(),
            vec![0xc3, 0x28],
            vec![b'x'; 300],
        ],
        others: vec![
            rule_eval::u32_xdr(0),
            rule_eval::u32_xdr(u32::MAX),
            xdr::encode(&soroban_facade::Val::Void),
            xdr::encode(&soroban_facade::Val::Vec(vec![
                soroban_facade::Val::U32(1),
                soroban_facade::Val::Symbol(b"a".to_vec()),
            ])),
            // Not the XDR of any value: a mirror keeps the bytes as they are.
            vec![0xde, 0xad],
        ],
    }
}

fn gen_val(r: &mut Rng, p: &Pools) -> Val {
    match r.below(8) {
        0 => Val::I128(r.pick(&[0, -1, i128::MIN, i128::MAX, 42])),
        1 => Val::U64(r.pick(&[0, u64::MAX, 7])),
        2 => Val::Bool(r.below(2) == 0),
        3 => Val::Bytes(r.pick(&p.keys)),
        4 => Val::Address(r.pick(&p.addresses)),
        5 => Val::Symbol(r.pick(&p.names)),
        6 => Val::String(r.pick(&p.strings)),
        _ => Val::Other(r.pick(&p.others)),
    }
}

fn gen_signer(r: &mut Rng, p: &Pools) -> Signer {
    if r.below(2) == 0 {
        Signer::Delegated(r.pick(&p.addresses))
    } else {
        Signer::External(r.pick(&p.addresses), r.pick(&p.keys))
    }
}

fn gen_cond(r: &mut Rng, p: &Pools) -> Cond {
    let i = r.below(5) as u32;
    match r.below(4) {
        0 => Cond::ArgEq(i, gen_val(r, p)),
        1 => Cond::ArgI128AtMost(i, r.pick(&[i128::MIN, 0, i128::MAX])),
        2 => Cond::ArgIn(i, r.list(3, |r| gen_val(r, p))),
        _ => Cond::ArgStrPrefix(i, r.pick(&p.strings)),
    }
}

fn gen_rule(r: &mut Rng, p: &Pools) -> Rule {
    let names = r.list(3, |r| r.pick(&p.names));
    Rule {
        contract: r.pick(&p.addresses),
        functions: if r.below(2) == 0 {
            Functions::AnyExcept(names)
        } else {
            Functions::Only(names)
        },
        conds: r.list(4, |r| gen_cond(r, p)),
        signers: r.list(4, |r| gen_signer(r, p)),
        threshold: r.pick(&[0, 1, 3, u32::MAX]),
        cap: (r.below(2) == 0).then(|| Cap {
            limit: r.pick(&[1, i128::MAX]),
            period: r.pick(&[1, u32::MAX]),
            amount_arg: r.below(4) as u32,
        }),
        valid_until: r.pick(&[None, Some(0), Some(u32::MAX)]),
        generation: r.pick(&[None, Some(0), Some(u64::MAX)]),
    }
}

/// A rule holding every value constructor, both signer kinds and a cap.
fn sample(p: &Pools) -> Rule {
    Rule {
        contract: p.addresses[4].clone(),
        functions: Functions::AnyExcept(vec![]),
        conds: vec![
            Cond::ArgIn(
                0,
                vec![
                    Val::I128(-1),
                    Val::U64(1),
                    Val::Bool(true),
                    Val::Bytes(p.keys[3].clone()),
                    Val::Address(p.addresses[5].clone()),
                    Val::Symbol(p.names[4].clone()),
                    Val::String(p.strings[2].clone()),
                    Val::Other(p.others[3].clone()),
                ],
            ),
            Cond::ArgStrPrefix(1, vec![]),
            Cond::ArgI128AtMost(2, i128::MAX),
            Cond::ArgEq(3, Val::Other(p.others[4].clone())),
        ],
        signers: vec![
            Signer::Delegated(p.addresses[0].clone()),
            Signer::External(p.addresses[5].clone(), vec![]),
        ],
        threshold: 2,
        cap: Some(Cap {
            limit: 5,
            period: 10,
            amount_arg: 2,
        }),
        valid_until: Some(9),
        generation: Some(3),
    }
}

/// [`sample`], then rules drawn by the generator, `n` in all.
fn rules(e: &Env, n: usize) -> Vec<Rule> {
    let p = pools(e);
    let mut out = vec![sample(&p)];
    let mut r = Rng(20_261_103);
    while out.len() < n {
        out.push(gen_rule(&mut r, &p));
    }
    out
}

fn xdr_round_trip<T>(e: &Env, x: &T) -> T
where
    T: Clone + IntoVal<Env, SVal> + TryFromVal<Env, SVal>,
{
    let b: Bytes = x.clone().to_xdr(e);
    T::from_xdr(e, &b).unwrap_or_else(|_| panic!("the host does not read its own XDR back"))
}

#[test]
fn every_rule_round_trips_through_its_mirror_and_the_host() {
    let e = Env::default();
    // 400 rules, each read back through its host XDR, outrun the default
    // budget of one `Env`.
    e.cost_estimate().budget().reset_unlimited();
    for (i, r) in rules(&e, 400).iter().enumerate() {
        let s = StoredRule::from_rule(&e, r).unwrap_or_else(|| panic!("rule {i}: no mirror"));
        assert!(
            rules_eq(&[s.to_rule(&e).unwrap()], std::slice::from_ref(r)),
            "rule {i}: rule -> mirror -> rule changed it"
        );
        let back = xdr_round_trip(&e, &s);
        assert_eq!(back, s, "rule {i}: the mirror's XDR round trip changed it");
        assert_eq!(
            StoredRule::from_rule(&e, &back.to_rule(&e).unwrap()),
            Some(s),
            "rule {i}: mirror -> rule -> mirror changed it"
        );
    }
}

/// A mirror is laid out as the `#[contracttype]` of its fields: the sample
/// rule's mirror, and a record's, equal ones built field by field from host
/// values, and the sample's reads back as the sample.
#[test]
fn a_mirror_is_the_contracttype_of_its_fields() {
    use perch_account_types::Signer as HostSigner;
    use perch_rule_eval::{StoredCond, StoredEntry, StoredFunctions, StoredVal};
    let e = Env::default();
    let p = pools(&e);
    let a = |x: &[u8]| host_address(&e, x).expect("an address");
    let b = |x: &[u8]| Bytes::from_slice(&e, x);
    let expected = StoredRule {
        contract: a(&p.addresses[4]),
        functions: StoredFunctions::AnyExcept(SVec::new(&e)),
        conds: SVec::from_array(
            &e,
            [
                StoredCond::ArgIn(
                    0,
                    SVec::from_array(
                        &e,
                        [
                            StoredVal::I128(-1),
                            StoredVal::U64(1),
                            StoredVal::Bool(true),
                            StoredVal::Bytes(b(&p.keys[3])),
                            StoredVal::Address(a(&p.addresses[5])),
                            StoredVal::Symbol(Symbol::new(&e, "a_name_of_exactly_32_bytes_here_")),
                            StoredVal::String(SString::from_bytes(&e, &p.strings[2])),
                            StoredVal::Other(b(&p.others[3])),
                        ],
                    ),
                ),
                StoredCond::ArgStrPrefix(1, SString::from_bytes(&e, b"")),
                StoredCond::ArgI128AtMost(2, i128::MAX),
                StoredCond::ArgEq(3, StoredVal::Other(b(&p.others[4]))),
            ],
        ),
        signers: SVec::from_array(
            &e,
            [
                HostSigner::Delegated(a(&p.addresses[0])),
                HostSigner::External(a(&p.addresses[5]), Bytes::new(&e)),
            ],
        ),
        threshold: 2,
        cap: SVec::from_array(
            &e,
            [StoredCap {
                limit: 5,
                period: 10,
                amount_arg: 2,
            }],
        ),
        valid_until: Some(9),
        generation: Some(3),
    };
    assert_eq!(
        StoredRule::from_rule(&e, &sample(&p)),
        Some(expected.clone())
    );
    assert!(rules_eq(
        &[expected.to_rule(&e).expect("the mirror reads back")],
        &[sample(&p)]
    ));

    let record = SpendRecord {
        history: vec![
            SpendEntry {
                ledger: 3,
                amount: 4,
            },
            SpendEntry {
                ledger: u32::MAX,
                amount: i128::MIN,
            },
        ],
        total: i128::MAX,
    };
    let expected = StoredRecord {
        history: SVec::from_array(
            &e,
            [
                StoredEntry {
                    ledger: 3,
                    amount: 4,
                },
                StoredEntry {
                    ledger: u32::MAX,
                    amount: i128::MIN,
                },
            ],
        ),
        total: i128::MAX,
    };
    assert_eq!(StoredRecord::from_record(&e, &record), expected);
}

#[test]
fn a_rule_with_no_host_form_has_no_mirror() {
    let e = Env::default();
    let p = pools(&e);
    assert!(StoredRule::from_rule(&e, &sample(&p)).is_some());

    let contract = p.addresses[0].clone();
    let mut muxed = vec![0, 0, 0, 2];
    muxed.extend_from_slice(&[0; 8]);
    muxed.extend_from_slice(&[1; 32]);
    let mut trailing = contract.clone();
    trailing.push(0);
    let short = contract[..contract.len() - 1].to_vec();
    for (what, bad) in [
        ("not an address", b"not xdr".to_vec()),
        ("a muxed account", muxed),
        ("trailing bytes", trailing),
        ("a short address", short),
        ("empty", vec![]),
    ] {
        let r = Rule {
            contract: bad.clone(),
            ..sample(&p)
        };
        assert!(
            StoredRule::from_rule(&e, &r).is_none(),
            "{what}: a contract"
        );
        let r = Rule {
            signers: vec![Signer::Delegated(bad.clone())],
            ..sample(&p)
        };
        assert!(StoredRule::from_rule(&e, &r).is_none(), "{what}: a signer");
        let r = Rule {
            conds: vec![Cond::ArgEq(0, Val::Address(bad))],
            ..sample(&p)
        };
        assert!(StoredRule::from_rule(&e, &r).is_none(), "{what}: a value");
    }
    for name in ["a-b", "a_name_of_exactly_33_bytes_here__", "\u{e9}", " "] {
        let r = Rule {
            functions: Functions::Only(vec![name.as_bytes().to_vec()]),
            ..sample(&p)
        };
        assert!(StoredRule::from_rule(&e, &r).is_none(), "function {name:?}");
        let r = Rule {
            conds: vec![Cond::ArgEq(0, Val::Symbol(name.as_bytes().to_vec()))],
            ..sample(&p)
        };
        assert!(StoredRule::from_rule(&e, &r).is_none(), "symbol {name:?}");
    }

    let mut two_caps = StoredRule::from_rule(&e, &sample(&p)).unwrap();
    let cap = StoredCap {
        limit: 1,
        period: 1,
        amount_arg: 2,
    };
    two_caps.cap = SVec::from_array(&e, [cap.clone(), cap]);
    assert!(two_caps.to_rule(&e).is_none(), "two caps");
}

#[test]
fn every_record_round_trips_through_its_mirror_and_the_host() {
    let e = Env::default();
    let mut r = Rng(7);
    for i in 0..200 {
        let record = SpendRecord {
            history: r.list(6, |r| SpendEntry {
                ledger: r.pick(&[0, 1, u32::MAX]),
                amount: r.pick(&[0, 1, i128::MAX, i128::MIN]),
            }),
            total: r.pick(&[0, -5, i128::MAX]),
        };
        let s = StoredRecord::from_record(&e, &record);
        let read = perch_rule_eval::mirror::record(&e, s.clone().into_val(&e))
            .unwrap_or_else(|| panic!("record {i}: the mirror does not read back"));
        for back in [s.to_record(), read] {
            assert_eq!(back.total, record.total, "record {i}");
            assert_eq!(back.history.len(), record.history.len(), "record {i}");
            for (x, y) in back.history.iter().zip(&record.history) {
                assert_eq!((x.ledger, x.amount), (y.ledger, y.amount), "record {i}");
            }
        }
        assert_eq!(xdr_round_trip(&e, &s), s, "record {i}");
    }
}

// ---------------------------------------------------------------------------
// The document model
// ---------------------------------------------------------------------------

/// The model of `d`: the inverse of `doc_of`, written here from the types
/// alone. Every identifier `d` holds has a host form.
fn model_from_doc(e: &Env, d: &Doc) -> CompiledModel {
    let a = |x: &[u8]| host_address(e, x).expect("an address");
    let s = |x: &[u8]| SString::from_bytes(e, x);
    let ss = |xs: &[Vec<u8>]| SVec::from_iter(e, xs.iter().map(|x| s(x)));
    let signer = |x: &Signer| perch_rule_eval::convert::host_signer(e, x).expect("a signer");
    let mut rules = SVec::new(e);
    for r in &d.rules {
        rules.push_back(ModelRule {
            scope: match &r.scope {
                Scope::Contract(x) => ModelScope::Contract(a(x)),
                Scope::SelfAdmin => ModelScope::SelfAdmin,
            },
            principals: match &r.principals {
                Principals::All(ids) => ModelPrincipals::All(ss(ids)),
                Principals::Threshold(ids, m) => ModelPrincipals::Threshold(ss(ids), *m),
            },
            functions: r.functions.as_ref().map(|fs| {
                SVec::from_iter(
                    e,
                    fs.iter()
                        .map(|f| Symbol::new(e, std::str::from_utf8(f).unwrap())),
                )
            }),
            args: r.args.as_ref().map(|args| {
                SVec::from_iter(
                    e,
                    args.iter().map(|c| ModelArg {
                        index: c.index,
                        pred: match &c.pred {
                            Pred::IsSelf => ModelPred::IsSelf,
                            Pred::AddressEq(x) => ModelPred::AddressEq(a(x)),
                            Pred::StringIn(vs) => ModelPred::StringIn(ss(vs)),
                            Pred::StringPrefix(x) => ModelPred::StringPrefix(s(x)),
                            Pred::U32Eq(v) => ModelPred::U32Eq(*v),
                        },
                    }),
                )
            }),
            not_after_ledger: r.not_after_ledger,
            cap: SVec::from_iter(
                e,
                r.cap.iter().map(|c| ModelCap {
                    limit: c.limit,
                    period_ledgers: c.period_ledgers,
                }),
            ),
        });
    }
    CompiledModel {
        signers: SVec::from_iter(
            e,
            d.signers.iter().map(|x| ModelSigner {
                id: s(&x.id),
                signer: signer(&x.signer),
            }),
        ),
        rules,
        recovery: SVec::from_iter(
            e,
            d.recovery.iter().map(|r| ModelRecovery {
                controller: a(&r.controller),
                zk: SVec::from_iter(
                    e,
                    r.zk.iter().map(|z| ModelZk {
                        adapter: a(&z.adapter),
                        pool: a(&z.pool),
                    }),
                ),
            }),
        ),
    }
}

fn gen_doc(r: &mut Rng, p: &Pools) -> Doc {
    let ids: Vec<Vec<u8>> = ["owner", "", "s1", "\u{e9}"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    let names = p.names.clone();
    Doc {
        signers: r.list(4, |r| SignerDecl {
            id: r.pick(&ids),
            signer: gen_signer(r, p),
        }),
        rules: r.list(4, |r| DocRule {
            scope: if r.below(3) == 0 {
                Scope::SelfAdmin
            } else {
                Scope::Contract(r.pick(&p.addresses))
            },
            principals: if r.below(2) == 0 {
                Principals::All(r.list(3, |r| r.pick(&ids)))
            } else {
                Principals::Threshold(r.list(3, |r| r.pick(&ids)), r.pick(&[0, 1, u32::MAX]))
            },
            functions: (r.below(2) == 0).then(|| r.list(3, |r| r.pick(&names))),
            args: (r.below(2) == 0).then(|| {
                r.list(3, |r| ArgConstraint {
                    index: r.below(5) as u32,
                    pred: match r.below(5) {
                        0 => Pred::IsSelf,
                        1 => Pred::AddressEq(r.pick(&p.addresses)),
                        2 => Pred::StringIn(r.list(3, |r| r.pick(&p.strings))),
                        3 => Pred::StringPrefix(r.pick(&p.strings)),
                        _ => Pred::U32Eq(r.pick(&[0, u32::MAX])),
                    },
                })
            }),
            not_after_ledger: r.pick(&[None, Some(0), Some(u32::MAX)]),
            cap: (r.below(2) == 0).then(|| DocCap {
                limit: r.pick(&[1, i128::MAX, -1]),
                period_ledgers: r.pick(&[0, 1, u32::MAX]),
            }),
        }),
        recovery: (r.below(2) == 0).then(|| Recovery {
            controller: r.pick(&p.addresses),
            zk: (r.below(2) == 0).then(|| ZkFactor {
                adapter: r.pick(&p.addresses),
                pool: r.pick(&p.addresses),
            }),
        }),
    }
}

#[test]
fn every_document_round_trips_through_its_model_and_the_host() {
    let e = Env::default();
    let p = pools(&e);
    let me = p.addresses[0].clone();
    let mut r = Rng(11);
    for i in 0..300 {
        let d = gen_doc(&mut r, &p);
        let m = model_from_doc(&e, &d);
        let back = doc_of(&e, &m).unwrap_or_else(|| panic!("document {i}: no document"));
        // `model_from_doc` maps each field one to one, so equal models mean
        // `back` is `d`.
        assert_eq!(
            model_from_doc(&e, &back),
            m,
            "document {i}: document -> model -> document"
        );
        assert!(
            rules_eq(&rule_eval::lower(&back, &me), &rule_eval::lower(&d, &me)),
            "document {i}: the round trip changed the lowering"
        );
        assert_eq!(
            xdr_round_trip(&e, &m),
            m,
            "document {i}: the model's XDR round trip"
        );
    }
}

#[test]
fn a_model_holding_two_of_what_holds_one_has_no_document() {
    let e = Env::default();
    let a = Address::generate(&e);
    let rule = ModelRule {
        scope: ModelScope::SelfAdmin,
        principals: ModelPrincipals::All(SVec::new(&e)),
        functions: None,
        args: None,
        not_after_ledger: None,
        cap: SVec::new(&e),
    };
    let recovery = ModelRecovery {
        controller: a.clone(),
        zk: SVec::new(&e),
    };
    let model = |rules: Vec<ModelRule>, recovery: Vec<ModelRecovery>| CompiledModel {
        signers: SVec::new(&e),
        rules: SVec::from_iter(&e, rules),
        recovery: SVec::from_iter(&e, recovery),
    };
    assert!(doc_of(&e, &model(vec![rule.clone()], vec![recovery.clone()])).is_some());

    let cap = ModelCap {
        limit: 1,
        period_ledgers: 1,
    };
    let two_caps = ModelRule {
        cap: SVec::from_array(&e, [cap.clone(), cap]),
        ..rule.clone()
    };
    assert!(
        doc_of(&e, &model(vec![two_caps], vec![])).is_none(),
        "two caps"
    );
    assert!(
        doc_of(&e, &model(vec![], vec![recovery.clone(), recovery.clone()])).is_none(),
        "two recovery configurations"
    );
    let zk = ModelZk {
        adapter: a.clone(),
        pool: a,
    };
    let two_zk = ModelRecovery {
        zk: SVec::from_array(&e, [zk.clone(), zk]),
        ..recovery
    };
    assert!(
        doc_of(&e, &model(vec![], vec![two_zk])).is_none(),
        "two ZK factors"
    );
}

// ---------------------------------------------------------------------------
// Contexts and values
// ---------------------------------------------------------------------------

/// `contexts` reads a batch as `address` and `val` read its parts.
#[test]
fn contexts_read_as_their_parts_do() {
    let e = Env::default();
    let c = Address::generate(&e);
    let holder = Address::generate(&e);
    let args: SVec<SVal> = SVec::from_array(
        &e,
        [
            holder.to_val(),
            5i128.into_val(&e),
            7u32.into_val(&e),
            SString::from_str(&e, "pkg_a").into_val(&e),
            Symbol::new(&e, "go").into_val(&e),
            ().into_val(&e),
        ],
    );
    let batch = SVec::from_array(
        &e,
        [Context::Contract(ContractContext {
            contract: c.clone(),
            fn_name: Symbol::new(&e, "transfer"),
            args: args.clone(),
        })],
    );
    let read = contexts(&e, &batch).expect("a readable batch");
    assert_eq!(read.len(), 1);
    let rule_eval::Context::Call {
        contract,
        function,
        args: got,
    } = &read[0]
    else {
        panic!("a call");
    };
    assert_eq!(*contract, address(&e, &c).unwrap());
    assert_eq!(function.as_slice(), b"transfer");
    let want: Vec<Val> = args.iter().map(|v| val(&e, v).unwrap()).collect();
    assert_eq!(got.len(), want.len());
    for (k, (x, y)) in got.iter().zip(&want).enumerate() {
        assert!(rule_eval::val_eq(x, y), "argument {k}");
    }
    assert!(matches!(&want[0], Val::Address(x) if *x == address(&e, &holder).unwrap()));
    assert!(matches!(&want[2], Val::Other(x) if *x == rule_eval::u32_xdr(7)));
    assert!(matches!(&want[3], Val::String(x) if x == b"pkg_a"));
    assert!(matches!(&want[4], Val::Symbol(x) if x == b"go"));
}

/// An address's XDR names it: `host_address` inverts `address`.
#[test]
fn host_address_inverts_address() {
    let e = Env::default();
    for a in [
        Address::generate(&e),
        host_address(&e, &account_xdr(3)).expect("an account address"),
    ] {
        let x = address(&e, &a).unwrap();
        assert_eq!(host_address(&e, &x), Some(a));
    }
    assert_eq!(
        address(&e, &host_address(&e, &account_xdr(3)).unwrap()),
        Some(account_xdr(3))
    );
}

// ---------------------------------------------------------------------------
// Authorizing on the chosen rules
// ---------------------------------------------------------------------------

fn val_copy(v: &Val) -> Val {
    match v {
        Val::I128(x) => Val::I128(*x),
        Val::U64(x) => Val::U64(*x),
        Val::Bool(x) => Val::Bool(*x),
        Val::Bytes(x) => Val::Bytes(x.clone()),
        Val::Address(x) => Val::Address(x.clone()),
        Val::Symbol(x) => Val::Symbol(x.clone()),
        Val::String(x) => Val::String(x.clone()),
        Val::Other(x) => Val::Other(x.clone()),
    }
}

fn signer_copy(s: &Signer) -> Signer {
    match s {
        Signer::Delegated(a) => Signer::Delegated(a.clone()),
        Signer::External(v, k) => Signer::External(v.clone(), k.clone()),
    }
}

/// A call `rule` may allow: its contract, a function it may name, and
/// arguments that meet its conditions where one names a value, the amount
/// at argument 2 small. Some of the drawn calls miss the rule.
fn call_for(r: &mut Rng, p: &Pools, rule: &Rule) -> rule_eval::Context {
    let function = match &rule.functions {
        Functions::Only(xs) if !xs.is_empty() && r.below(4) > 0 => xs[r.below(xs.len())].clone(),
        _ => r.pick(&p.names),
    };
    let mut args: Vec<Val> = (0..5).map(|_| gen_val(r, p)).collect();
    args[2] = Val::I128(r.pick(&[0, 1, 4]));
    for c in &rule.conds {
        if r.below(5) == 0 {
            continue;
        }
        match c {
            Cond::ArgEq(i, v) => args[*i as usize] = val_copy(v),
            Cond::ArgIn(i, vs) if !vs.is_empty() => args[*i as usize] = val_copy(&vs[0]),
            Cond::ArgStrPrefix(i, pre) => args[*i as usize] = Val::String(pre.clone()),
            Cond::ArgI128AtMost(i, bound) => args[*i as usize] = Val::I128((*bound).min(3)),
            Cond::ArgIn(..) => {}
        }
    }
    rule_eval::Context::Call {
        contract: if r.below(8) == 0 {
            r.pick(&p.addresses)
        } else {
            rule.contract.clone()
        },
        function,
        args,
    }
}

fn refusal(x: &rule_eval::Refusal) -> u8 {
    use rule_eval::{CapError, Refusal};
    match x {
        Refusal::ChoicesMismatch => 0,
        Refusal::RecordsMismatch => 1,
        Refusal::NoSuchRule => 2,
        Refusal::Expired => 3,
        Refusal::StaleGeneration => 4,
        Refusal::NotAllowed => 5,
        Refusal::UnauthorizedSigner => 6,
        Refusal::NoAmount => 7,
        Refusal::Cap(CapError::NegativeAmount) => 8,
        Refusal::Cap(CapError::LedgerBeforeNewest) => 9,
        Refusal::Cap(CapError::Overflow) => 10,
        Refusal::Cap(CapError::LimitExceeded) => 11,
        Refusal::Cap(CapError::HistoryFull) => 12,
    }
}

fn record_eq(a: &SpendRecord, b: &SpendRecord) -> bool {
    a.total == b.total
        && a.history.len() == b.history.len()
        && a.history
            .iter()
            .zip(&b.history)
            .all(|(x, y)| (x.ledger, x.amount) == (y.ledger, y.amount))
}

/// rule-eval's `authorize` reads only the rules its choices name and their
/// records: run on the chosen rules alone, the choices renumbered to them,
/// it accepts and refuses as on the whole set, charges the same records,
/// and the whole set's other records come back unchanged. The account's
/// check runs it that way (`perch_smart_account`'s `gate`).
#[test]
fn authorize_on_the_chosen_rules_is_authorize_on_the_set() {
    let e = Env::default();
    let p = pools(&e);
    let mut r = Rng(20_261_104);
    let record = |r: &mut Rng| match r.below(3) {
        0 => SpendRecord {
            history: vec![],
            total: 0,
        },
        _ => SpendRecord {
            history: vec![SpendEntry {
                ledger: r.pick(&[0, 2]),
                amount: 3,
            }],
            total: 3,
        },
    };
    let (mut accepted, mut refused) = (0, 0);
    for case in 0..10_000 {
        let seeds: Vec<u64> = (0..1 + r.below(5)).map(|_| r.next()).collect();
        let rule = |i: usize| gen_rule(&mut Rng(seeds[i]), &p);
        let rules: Vec<Rule> = (0..seeds.len()).map(rule).collect();
        let records: Vec<SpendRecord> = (0..seeds.len()).map(|_| record(&mut r)).collect();
        let choices: Vec<u32> = (0..1 + r.below(3))
            .map(|_| r.below(seeds.len()) as u32)
            .collect();
        let contexts: Vec<rule_eval::Context> = choices
            .iter()
            .map(|&c| call_for(&mut r, &p, &rules[c as usize]))
            .collect();
        let mut signers: Vec<Signer> = vec![];
        for &c in &choices {
            for s in &rules[c as usize].signers {
                if r.below(4) > 0 {
                    signers.push(signer_copy(s));
                }
            }
        }
        if r.below(10) == 0 {
            signers.push(gen_signer(&mut r, &p));
        }
        let now = r.pick(&[0, 5, 10]);
        let generation = r.pick(&[0, 3]);
        let full = rule_eval::authorize(
            &rules, &records, &contexts, &choices, &signers, now, generation,
        );

        let mut ids: Vec<u32> = vec![];
        let mut sub_choices = vec![];
        for &c in &choices {
            let j = ids.iter().position(|x| *x == c).unwrap_or_else(|| {
                ids.push(c);
                ids.len() - 1
            });
            sub_choices.push(j as u32);
        }
        let sub_rules: Vec<Rule> = ids.iter().map(|&c| rule(c as usize)).collect();
        let sub_records: Vec<SpendRecord> = ids
            .iter()
            .map(|&c| {
                let x = &records[c as usize];
                SpendRecord {
                    history: x
                        .history
                        .iter()
                        .map(|h| SpendEntry {
                            ledger: h.ledger,
                            amount: h.amount,
                        })
                        .collect(),
                    total: x.total,
                }
            })
            .collect();
        let sub = rule_eval::authorize(
            &sub_rules,
            &sub_records,
            &contexts,
            &sub_choices,
            &signers,
            now,
            generation,
        );
        match (full, sub) {
            (Ok(f), Ok(s)) => {
                accepted += 1;
                for (j, x) in f.iter().enumerate() {
                    let want = match ids.iter().position(|c| *c as usize == j) {
                        Some(k) => &s[k],
                        None => &records[j],
                    };
                    assert!(record_eq(x, want), "case {case}: record {j}");
                }
            }
            (Err(a), Err(b)) => {
                refused += 1;
                assert_eq!(refusal(&a), refusal(&b), "case {case}: the refusals differ");
            }
            (a, b) => panic!(
                "case {case}: on the set {}, on the chosen rules {}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
    println!("cases: 10000, accepted: {accepted}, refused: {refused}, differences: 0");
    assert!(
        accepted > 100 && refused > 100,
        "{accepted} accepted, {refused} refused"
    );
}
