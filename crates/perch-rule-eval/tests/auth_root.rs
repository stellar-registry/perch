//! A stored rule's exact root reads back, and the decoder reads only the
//! stored layout: the tuple of nine fields. The map layouts earlier builds
//! stored (nine named fields, and the eight-field one with no root) are
//! refused, as are a malformed root, any other number of fields, and a
//! signer position past the record's table.

use perch_account_types::Signer;
use perch_rule_eval::{mirror, StoredAuthRoot, StoredCap, StoredFunctions, StoredRule};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec};

fn env() -> Env {
    Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    })
}

/// A rule with a root, a cap, a last ledger, a generation, and one signer at
/// position 0 of `table`.
fn fixture(e: &Env, table: &mut Vec<Signer>) -> StoredRule {
    table.push_back(Signer::External(
        Address::generate(e),
        Bytes::from_array(e, &[7; 32]),
    ));
    StoredRule(
        Address::generate(e),
        StoredFunctions::Only(Vec::from_array(e, [Symbol::new(e, "transfer")])),
        Vec::new(e),
        Vec::from_array(e, [0u32]),
        1,
        Vec::from_array(e, [StoredCap(17, 20, 2)]),
        Some(999),
        Some(7),
        Some(Vec::from_array(
            e,
            [StoredAuthRoot {
                contract: Address::generate(e),
                function: Symbol::new(e, "guess"),
            }],
        )),
    )
}

/// The rule-eval form of `table`.
fn rule_eval_table(e: &Env, table: &Vec<Signer>) -> std::vec::Vec<rule_eval::Signer> {
    perch_rule_eval::convert::signers(e, table).unwrap()
}

#[test]
fn a_root_round_trips_with_every_other_field() {
    let e = env();
    let mut table = Vec::new(&e);
    let stored = fixture(&e, &mut table);
    let rule = stored.to_rule(&e, &table).unwrap();
    assert_eq!(rule.auth_root.as_ref().unwrap().function, b"guess");
    assert_eq!(rule.cap.as_ref().unwrap().limit, 17);
    assert_eq!((rule.valid_until, rule.generation), (Some(999), Some(7)));
    assert_eq!(rule.signers.len(), 1);
    let mut again = Vec::new(&e);
    assert_eq!(
        StoredRule::from_rule(&e, &rule, &mut again).unwrap(),
        stored
    );
    assert_eq!(again, table);
}

/// The value of `stored` as an earlier build stored it: a map of its named
/// fields, its signers in full.
fn as_map(e: &Env, stored: &StoredRule, table: &Vec<Signer>) -> Map<Symbol, Val> {
    let mut m: Map<Symbol, Val> = Map::new(e);
    let signers = stored.signers_in(e, table).unwrap();
    m.set(Symbol::new(e, "auth_root"), stored.8.clone().into_val(e));
    m.set(Symbol::new(e, "cap"), stored.5.clone().into_val(e));
    m.set(Symbol::new(e, "conds"), stored.2.clone().into_val(e));
    m.set(Symbol::new(e, "contract"), stored.0.clone().into_val(e));
    m.set(Symbol::new(e, "functions"), stored.1.clone().into_val(e));
    m.set(Symbol::new(e, "generation"), stored.7.into_val(e));
    m.set(Symbol::new(e, "signers"), signers.into_val(e));
    m.set(Symbol::new(e, "threshold"), stored.4.into_val(e));
    m.set(Symbol::new(e, "valid_until"), stored.6.into_val(e));
    m
}

#[test]
fn only_the_stored_layout_reads_back() {
    let e = env();
    let mut table = Vec::new(&e);
    let stored = fixture(&e, &mut table);
    let t = rule_eval_table(&e, &table);

    // The earlier map layouts, with and without the root field.
    let mut map = as_map(&e, &stored, &table);
    assert!(mirror::rule(&e, map.clone().into_val(&e), &t).is_none());
    map.remove(Symbol::new(&e, "auth_root"));
    assert_eq!(map.len(), 8);
    assert!(mirror::rule(&e, map.into_val(&e), &t).is_none());

    // Eight or ten fields.
    let value: Val = stored.clone().into_val(&e);
    let fields: Vec<Val> = Vec::try_from_val(&e, &value).unwrap();
    let mut short = fields.clone();
    short.pop_back();
    assert!(mirror::rule(&e, short.into_val(&e), &t).is_none());
    let mut long = fields;
    long.push_back(Val::VOID.into());
    assert!(mirror::rule(&e, long.into_val(&e), &t).is_none());

    // A position past the table, and an empty table.
    let mut past = stored.clone();
    past.3 = Vec::from_array(&e, [1u32]);
    assert!(mirror::rule(&e, past.into_val(&e), &t).is_none());
    assert!(mirror::rule(&e, stored.into_val(&e), &[]).is_none());
}

#[test]
fn a_malformed_root_is_refused() {
    let e = env();
    let mut table = Vec::new(&e);
    let stored = fixture(&e, &mut table);
    let t = rule_eval_table(&e, &table);
    let value: Val = stored.clone().into_val(&e);
    let fields: Vec<Val> = Vec::try_from_val(&e, &value).unwrap();
    let root = stored.8.unwrap().get_unchecked(0);
    for bad in [
        Vec::<Val>::new(&e).into_val(&e),
        Vec::from_array(&e, [root.clone(), root]).into_val(&e),
        0u32.into_val(&e),
        Vec::from_array(&e, [Symbol::new(&e, "guess")]).into_val(&e),
    ] {
        let mut value = fields.clone();
        value.set(8, bad);
        assert!(mirror::rule(&e, value.into_val(&e), &t).is_none());
    }
}
