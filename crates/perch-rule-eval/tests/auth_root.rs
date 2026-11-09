use perch_rule_eval::{mirror, StoredAuthRoot, StoredCap, StoredFunctions, StoredRule};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, IntoVal, Map, Symbol, TryFromVal, Val, Vec};

fn fixture(e: &Env) -> StoredRule {
    StoredRule {
        auth_root: Some(Vec::from_array(
            e,
            [StoredAuthRoot {
                contract: Address::generate(e),
                function: Symbol::new(e, "guess"),
            }],
        )),
        contract: Address::generate(e),
        functions: StoredFunctions::Only(Vec::from_array(e, [Symbol::new(e, "transfer")])),
        conds: Vec::new(e),
        signers: Vec::new(e),
        threshold: 1,
        cap: Vec::from_array(
            e,
            [StoredCap {
                limit: 17,
                period: 20,
                amount_arg: 2,
            }],
        ),
        valid_until: Some(999),
        generation: Some(7),
    }
}

#[test]
fn root_and_legacy_layouts_round_trip_without_changing_other_conditions() {
    let e = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let stored = fixture(&e);
    let pure = stored.to_rule(&e).unwrap();
    assert_eq!(pure.auth_root.as_ref().unwrap().function, b"guess");
    assert_eq!(StoredRule::from_rule(&e, &pure).unwrap(), stored);
    let value: Val = stored.clone().into_val(&e);
    let mut legacy: Map<Symbol, Val> = Map::try_from_val(&e, &value).unwrap();
    legacy.remove(Symbol::new(&e, "auth_root"));
    assert_eq!(legacy.len(), 8);
    let legacy_val: Val = legacy.into_val(&e);
    let decoded = mirror::rule(&e, legacy_val).unwrap();
    assert!(decoded.auth_root.is_none());
    assert_eq!(
        decoded.cap.as_ref().unwrap().limit,
        pure.cap.as_ref().unwrap().limit
    );
    assert_eq!(decoded.generation, pure.generation);
    assert_eq!(decoded.valid_until, pure.valid_until);
    let sdk = StoredRule::try_from_val(&e, &legacy_val).unwrap();
    assert!(sdk.auth_root.is_none());
    assert!(sdk.to_rule(&e).unwrap().auth_root.is_none());
}

#[test]
fn malformed_new_layouts_cannot_be_read_as_legacy_unrestricted_rules() {
    let e = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
        capture_snapshot_at_drop: false,
    });
    let stored = fixture(&e);
    let value: Val = stored.clone().into_val(&e);
    let base: Map<Symbol, Val> = Map::try_from_val(&e, &value).unwrap();
    let key = Symbol::new(&e, "auth_root");
    let roots = stored.auth_root.unwrap();
    for bad in [
        Vec::<Val>::new(&e).into_val(&e),
        Vec::from_array(&e, [roots.get_unchecked(0), roots.get_unchecked(0)]).into_val(&e),
        0u32.into_val(&e),
        Vec::from_array(&e, [Symbol::new(&e, "guess")]).into_val(&e),
    ] {
        let mut value = base.clone();
        value.set(key.clone(), bad);
        assert!(mirror::rule(&e, value.into_val(&e)).is_none());
    }
    let mut misspelled = base.clone();
    let root = misspelled.get(key.clone()).unwrap();
    misspelled.remove(key.clone());
    misspelled.set(Symbol::new(&e, "auth_rooot"), root);
    assert!(mirror::rule(&e, misspelled.into_val(&e)).is_none());
    let mut missing_old = base.clone();
    missing_old.remove(Symbol::new(&e, "threshold"));
    assert!(mirror::rule(&e, missing_old.into_val(&e)).is_none());
    let mut extra = base;
    extra.set(Symbol::new(&e, "future"), Val::VOID.into());
    assert!(mirror::rule(&e, extra.into_val(&e)).is_none());
}
