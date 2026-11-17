//! `perch-review-core` reads the account's stored rules and records as the
//! account does. The account reads a stored rule with
//! `perch_rule_eval::mirror::rule` and a record with `mirror::record`, from
//! the host's XDR; the core reads the same XDR with soroban-facade and
//! `perch_review_core::stored`. For every stored value both are given, they
//! must read the same rule or record, or both refuse it:
//!
//! - every rule a seeded generator draws, through its mirror
//!   (`StoredRule::from_rule`), with the signer table its signers are
//!   interned in: the tuple of nine fields the account writes;
//! - each of those changed into a value the host still holds but the account
//!   never writes: the map of named fields earlier builds stored, a missing
//!   or extra field, a second cap, a cap of named fields, a root on an
//!   account address or with an empty function, a field of the wrong type,
//!   a value constructor named for another type, an `ArgIn` of a value that
//!   is not a string, a signer position past the table or of the wrong
//!   type, and a table holding a value that is not a signer;
//! - every record the generator draws, and some changed the same way.

use perch_review_core::stored;
use perch_review_core::witness::rule_eq;
use perch_rule_eval::{convert, mirror, StoredRecord, StoredRule};
use rule_eval::{AuthRoot, Cap, Cond, Functions, Rule, Signer, SpendEntry, SpendRecord, Val};
use soroban_facade::{xdr, Val as FVal};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Env, IntoVal, TryFromVal, Val as SVal};

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
}

struct Pools {
    contracts: Vec<Vec<u8>>,
    addresses: Vec<Vec<u8>>,
}

fn pools(e: &Env) -> Pools {
    let xdr = |a: &Address| perch_rule_eval::convert::address(e, a).unwrap();
    let contracts: Vec<Vec<u8>> = (0..4).map(|_| xdr(&Address::generate(e))).collect();
    let mut addresses = contracts.clone();
    for k in [1u8, 2] {
        let mut a = vec![0, 0, 0, 0, 0, 0, 0, 0];
        a.extend([k; 32]);
        addresses.push(a);
    }
    Pools {
        contracts,
        addresses,
    }
}

const NAMES: [&[u8]; 5] = [
    b"transfer",
    b"f",
    b"approve",
    b"",
    b"a_long_name_of_thirty_two_bytes_",
];

fn gen_val(r: &mut Rng, p: &Pools) -> Val {
    match r.below(8) {
        0 => Val::I128(r.pick(&[0, -1, 7, i128::MAX, i128::MIN])),
        1 => Val::U64(r.pick(&[0, 9, u64::MAX])),
        2 => Val::Bool(r.below(2) == 1),
        3 => Val::Bytes(r.pick(&[vec![], vec![1, 2, 3]])),
        4 => Val::Address(r.pick(&p.addresses)),
        5 => Val::Symbol(r.pick(&NAMES).to_vec()),
        6 => Val::String(r.pick(&[b"".to_vec(), b"hello".to_vec()])),
        _ => Val::Other(rule_eval::u32_xdr(r.next() as u32)),
    }
}

fn gen_signer(r: &mut Rng, p: &Pools) -> Signer {
    if r.below(2) == 0 {
        Signer::Delegated(r.pick(&p.addresses))
    } else {
        Signer::External(r.pick(&p.contracts), vec![r.below(256) as u8; 32])
    }
}

fn gen_rule(r: &mut Rng, p: &Pools) -> Rule {
    let names = |r: &mut Rng| (0..r.below(3)).map(|_| r.pick(&NAMES).to_vec()).collect();
    Rule {
        contract: r.pick(&p.addresses),
        functions: if r.below(2) == 0 {
            Functions::Only(names(r))
        } else {
            Functions::AnyExcept(names(r))
        },
        conds: (0..r.below(3))
            .map(|_| match r.below(4) {
                0 => Cond::ArgEq(r.below(4) as u32, gen_val(r, p)),
                1 => Cond::ArgI128AtMost(r.below(4) as u32, r.pick(&[0, 10, i128::MAX])),
                2 => Cond::ArgIn(
                    r.below(4) as u32,
                    (0..r.below(3))
                        .map(|_| Val::String(r.pick(&[b"".to_vec(), b"hello".to_vec()])))
                        .collect(),
                ),
                _ => Cond::ArgStrPrefix(r.below(4) as u32, r.pick(&[b"".to_vec(), b"he".to_vec()])),
            })
            .collect(),
        signers: (0..r.below(3)).map(|_| gen_signer(r, p)).collect(),
        threshold: r.below(4) as u32,
        cap: (r.below(2) == 0).then(|| Cap {
            limit: r.pick(&[1, 100, i128::MAX]),
            period: r.pick(&[1, 100, u32::MAX]),
            amount_arg: r.below(4) as u32,
        }),
        valid_until: (r.below(2) == 0).then(|| r.pick(&[0, 1000, u32::MAX])),
        generation: (r.below(2) == 0).then(|| r.pick(&[0, 1, u64::MAX])),
        auth_root: (r.below(3) == 0).then(|| AuthRoot {
            contract: r.pick(&p.contracts),
            function: r.pick(&NAMES[..3]).to_vec(),
        }),
    }
}

/// The host value whose XDR is `x`, if the host holds one.
fn host(e: &Env, x: &FVal) -> Option<SVal> {
    let sc = <soroban_sdk::xdr::ScVal as soroban_sdk::xdr::ReadXdr>::from_xdr(
        xdr::encode(x),
        soroban_sdk::xdr::Limits::none(),
    )
    .ok()?;
    SVal::try_from_val(e, &sc).ok()
}

/// The facade's reading of a host value.
fn facade(e: &Env, v: SVal) -> FVal {
    let b = v.to_xdr(e);
    let mut out = vec![0u8; b.len() as usize];
    b.copy_into_slice(&mut out);
    xdr::decode(&out).expect("the facade reads every stored value")
}

/// Both readings of the stored rule `v` with the signer table `table`, as
/// `gate::stored_rule` and the core's `stored_rule` read a record's: they
/// agree, or the test fails.
fn same_rule(e: &Env, v: SVal, table: SVal, what: &str) -> bool {
    let account = soroban_sdk::Vec::<perch_account_types::Signer>::try_from_val(e, &table)
        .ok()
        .and_then(|t| convert::signers(e, &t))
        .and_then(|t| mirror::rule(e, v, &t));
    let core = stored::table(&facade(e, table)).and_then(|t| stored::rule(&facade(e, v), &t));
    match (&account, &core) {
        (Some(a), Some(c)) => assert!(rule_eq(a, c), "{what}"),
        (None, None) => {}
        _ => panic!(
            "{what}: the account {} it, the core {} it",
            if account.is_some() {
                "reads"
            } else {
                "refuses"
            },
            if core.is_some() { "reads" } else { "refuses" }
        ),
    }
    account.is_some()
}

/// `f` applied to the fields of a stored tuple, as a new value.
fn edit(v: &FVal, f: impl FnOnce(&mut Vec<FVal>)) -> FVal {
    let FVal::Vec(mut fields) = v.clone() else {
        panic!("a tuple struct is a vector")
    };
    f(&mut fields);
    FVal::Vec(fields)
}

/// `f` applied to the map entries of a stored value, as a new value.
fn edit_map(v: &FVal, f: impl FnOnce(&mut Vec<(FVal, FVal)>)) -> FVal {
    let FVal::Map(mut entries) = v.clone() else {
        panic!("a struct with named fields is a map")
    };
    f(&mut entries);
    FVal::Map(entries)
}

fn sym(s: &str) -> FVal {
    FVal::Symbol(s.as_bytes().to_vec())
}

fn at<'a>(entries: &'a mut [(FVal, FVal)], key: &str) -> &'a mut FVal {
    &mut entries
        .iter_mut()
        .find(|(k, _)| *k == sym(key))
        .expect("the key")
        .1
}

/// A stored rule's fields, by position.
const CONDS: usize = 2;
const SIGNERS: usize = 3;
const THRESHOLD: usize = 4;
const CAP: usize = 5;
const GENERATION: usize = 7;
const ROOT: usize = 8;

/// The rule as an earlier build stored it: a map of its named fields.
fn as_map(f: &FVal) -> FVal {
    let FVal::Vec(x) = f else { unreachable!() };
    let names = [
        "contract",
        "functions",
        "conds",
        "signers",
        "threshold",
        "cap",
        "valid_until",
        "generation",
        "auth_root",
    ];
    let mut entries: Vec<(FVal, FVal)> = names
        .iter()
        .zip(x)
        .map(|(n, v)| (sym(n), v.clone()))
        .collect();
    entries.sort_by_key(|e| xdr::encode(&e.0));
    FVal::Map(entries)
}

#[test]
fn the_core_reads_every_stored_rule_as_the_account_does() {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    let p = pools(&e);
    let mut r = Rng(0x0005_7123);
    let (mut read, mut refused, mut changed) = (0, 0, 0);
    for k in 0..1500 {
        let rule = gen_rule(&mut r, &p);
        let mut signers = soroban_sdk::Vec::new(&e);
        let Some(m) = StoredRule::from_rule(&e, &rule, &mut signers) else {
            continue;
        };
        let v: SVal = m.into_val(&e);
        let table: SVal = signers.into_val(&e);
        assert!(same_rule(&e, v, table, &format!("rule {k}")));
        read += 1;
        let f = facade(&e, v);
        let ft = facade(&e, table);
        let positions = |f: &mut Vec<FVal>| -> Vec<FVal> {
            let FVal::Vec(p) = &f[SIGNERS] else {
                unreachable!()
            };
            p.clone()
        };
        // An `ScVal` address (18) of an account (0) with an ed25519 key (0).
        let mut account = vec![0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 0];
        account.extend([9u8; 32]);
        let FVal::Address(account) = xdr::decode(&account).unwrap() else {
            unreachable!()
        };
        let mut variants: Vec<(&str, FVal, FVal)> = vec![
            ("the earlier map layout", as_map(&f), ft.clone()),
            (
                "eight fields",
                edit(&f, |x| {
                    x.pop();
                }),
                ft.clone(),
            ),
            ("ten fields", edit(&f, |x| x.push(FVal::Void)), ft.clone()),
            (
                "two caps",
                edit(&f, |x| {
                    if let FVal::Vec(c) = &mut x[CAP] {
                        let one = c.first().cloned().unwrap_or(FVal::Void);
                        *c = vec![one.clone(), one];
                    }
                }),
                ft.clone(),
            ),
            (
                "a cap of named fields",
                edit(&f, |x| {
                    x[CAP] = FVal::Vec(vec![FVal::Map(vec![
                        (sym("amount_arg"), FVal::U32(2)),
                        (sym("limit"), FVal::I128(1)),
                        (sym("period"), FVal::U32(1)),
                    ])]);
                }),
                ft.clone(),
            ),
            (
                "a u64 threshold",
                edit(&f, |x| x[THRESHOLD] = FVal::U64(1)),
                ft.clone(),
            ),
            (
                "a u32 generation",
                edit(&f, |x| x[GENERATION] = FVal::U32(1)),
                ft.clone(),
            ),
            (
                "a root on an account",
                edit(&f, |x| {
                    x[ROOT] = FVal::Vec(vec![FVal::Map(vec![
                        (sym("contract"), FVal::Address(account.clone())),
                        (sym("function"), sym("f")),
                    ])]);
                }),
                ft.clone(),
            ),
            (
                "a root with no function",
                edit(&f, |x| {
                    if let FVal::Vec(root) = &mut x[ROOT] {
                        if let Some(m) = root.first_mut() {
                            *m = edit_map(m, |es| *at(es, "function") = sym(""));
                        }
                    }
                }),
                ft.clone(),
            ),
            (
                "an ArgIn of a value that is not a string",
                edit(&f, |x| {
                    if let FVal::Vec(conds) = &mut x[CONDS] {
                        conds.push(FVal::Vec(vec![
                            sym("ArgIn"),
                            FVal::U32(0),
                            FVal::Vec(vec![FVal::Vec(vec![sym("U64"), FVal::U64(1)])]),
                        ]));
                    }
                }),
                ft.clone(),
            ),
            (
                "a position past the table",
                edit(&f, |x| {
                    let FVal::Vec(t) = &ft else { unreachable!() };
                    let mut p = positions(x);
                    p.push(FVal::U32(t.len() as u32));
                    x[SIGNERS] = FVal::Vec(p);
                }),
                ft.clone(),
            ),
            (
                "a u64 position",
                edit(&f, |x| {
                    let mut p = positions(x);
                    if let Some(first) = p.first_mut() {
                        *first = FVal::U64(0);
                    }
                    x[SIGNERS] = FVal::Vec(p);
                }),
                ft.clone(),
            ),
            (
                "a table holding a value that is not a signer",
                f.clone(),
                edit(&ft, |t| {
                    if let Some(first) = t.first_mut() {
                        *first = FVal::U32(0);
                    }
                }),
            ),
            ("an empty table", f.clone(), FVal::Vec(vec![])),
        ];
        // A value constructor named for another type: read by its field.
        variants.push((
            "a value named for another type",
            edit(&f, |x| {
                if let FVal::Vec(conds) = &mut x[CONDS] {
                    for c in conds.iter_mut() {
                        if let FVal::Vec(parts) = c {
                            if parts.first() == Some(&sym("ArgEq")) {
                                if let Some(FVal::Vec(v)) = parts.get_mut(2) {
                                    v[0] = sym("U64");
                                }
                            }
                        }
                    }
                }
            }),
            ft.clone(),
        ));
        for (what, x, t) in variants {
            let (Some(hv), Some(ht)) = (host(&e, &x), host(&e, &t)) else {
                continue;
            };
            changed += 1;
            if !same_rule(&e, hv, ht, &format!("rule {k}, {what}")) {
                refused += 1;
            }
        }
    }
    println!("stored rules read alike: {read}; changed values compared: {changed} (both refuse: {refused})");
    assert!(read > 1000 && refused > 0 && changed > refused);
}

fn gen_record(r: &mut Rng) -> SpendRecord {
    let n = r.below(4);
    let mut ledger = r.below(100) as u32;
    let history: Vec<SpendEntry> = (0..n)
        .map(|_| {
            ledger += r.below(10) as u32;
            SpendEntry {
                ledger,
                amount: r.pick(&[0, 5, i128::MAX, -3]),
            }
        })
        .collect();
    SpendRecord {
        total: history.iter().fold(0i128, |t, x| t.wrapping_add(x.amount)),
        history,
    }
}

#[test]
fn the_core_reads_every_stored_record_as_the_account_does() {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    let mut r = Rng(0x0005_7124);
    let (mut read, mut changed) = (0, 0);
    let parts = |x: &SpendRecord| -> (Vec<(u32, i128)>, i128) {
        (
            x.history.iter().map(|h| (h.ledger, h.amount)).collect(),
            x.total,
        )
    };
    let check = |v: SVal, what: &str| -> bool {
        let account = mirror::record(&e, v);
        let core = stored::record(&facade(&e, v));
        assert_eq!(
            account.as_ref().map(parts),
            core.as_ref().map(parts),
            "{what}"
        );
        account.is_some()
    };
    for k in 0..500 {
        let rec = gen_record(&mut r);
        let v: SVal = StoredRecord::from_record(&e, &rec).into_val(&e);
        assert!(check(v, &format!("record {k}")));
        read += 1;
        let f = facade(&e, v);
        for (what, x) in [
            (
                "an unknown key",
                edit_map(&f, |es| es.push((sym("zz"), FVal::Void))),
            ),
            (
                "a u64 total",
                edit_map(&f, |es| *at(es, "total") = FVal::U64(1)),
            ),
            (
                "a history entry with a u64 ledger",
                edit_map(&f, |es| {
                    if let FVal::Vec(h) = at(es, "history") {
                        if let Some(FVal::Map(m)) = h.first_mut() {
                            m[1].1 = FVal::U64(1);
                        }
                    }
                }),
            ),
        ] {
            if let Some(hv) = host(&e, &x) {
                changed += 1;
                check(hv, &format!("record {k}, {what}"));
            }
        }
    }
    println!("stored records read alike: {read}; changed values compared: {changed}");
    assert!(read == 500 && changed > 0);
}
