extern crate std;

use crate::merkle::{self, PoolKey, TreeState};
use crate::{
    Insertion, LeafInserted, LeafPosition, PerchZkPool, PerchZkPoolClient, PoolError, MAX_PAGE,
    TREE_DEPTH,
};
use perch_zk_primitives::{contract_id, Hasher, FIELD_MODULUS, ZERO_HASHES};
use soroban_sdk::testutils::storage::Persistent as _;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{ContractDataDurability, LedgerKey, ScVal};
use soroban_sdk::{Address, BytesN, Env, Event, IntoVal, Vec};
use std::vec::Vec as StdVec;

/// `rcv_insert` returns nothing; read back where the leaf landed the way a
/// client does, from `enrollment` and the tree views.
fn insert(
    client: &PerchZkPoolClient,
    account: &Address,
    n: &BytesN<32>,
    c: &BytesN<32>,
) -> Insertion {
    client.rcv_insert(account, n, c);
    let at = client.enrollment(account, n).expect("recorded");
    Insertion {
        tree_id: at.tree_id,
        index: at.index,
        leaf: client.leaves(&at.tree_id, &at.index, &1).get_unchecked(0),
        root: client.tree(&at.tree_id).root,
    }
}

fn setup() -> (Env, Address, PerchZkPoolClient<'static>) {
    let e = Env::default();
    let id = e.register(PerchZkPool, ());
    let client = PerchZkPoolClient::new(&e, &id);
    (e, id, client)
}

fn commitment(e: &Env, n: u64) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    Hasher::new(e).commitment(&BytesN::from_array(e, &b))
}

/// A distinct enrollment id per `n`.
fn enr(e: &Env, n: u64) -> BytesN<32> {
    let mut b = [0xee; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(e, &b)
}

fn bytes(e: &Env, n: u64) -> BytesN<32> {
    let mut b = [0u8; 32];
    b[24..].copy_from_slice(&n.to_be_bytes());
    BytesN::from_array(e, &b)
}

/// Root of a depth-`depth` tree over `leaves`, recomputed level by level from
/// scratch — deliberately not the frontier algorithm the pool uses, so a
/// wrong sibling or level in `merkle::append` is caught rather than agreeing
/// with itself.
fn reference_root(e: &Env, depth: u32, leaves: &[BytesN<32>]) -> BytesN<32> {
    let mut h = Hasher::new(e);
    let mut level: StdVec<BytesN<32>> = leaves.to_vec();
    for d in 0..depth {
        let z = BytesN::from_array(e, &ZERO_HASHES[d as usize]);
        let mut next = StdVec::new();
        for pair in level.chunks(2) {
            let right = pair.get(1).cloned().unwrap_or_else(|| z.clone());
            next.push(h.node(&pair[0], &right));
        }
        if next.is_empty() {
            next.push(BytesN::from_array(e, &ZERO_HASHES[d as usize + 1]));
        }
        level = next;
    }
    level[0].clone()
}

#[test]
fn insertion_requires_the_accounts_own_authorization() {
    let (e, id, client) = setup();
    let account = Address::generate(&e);
    let other = Address::generate(&e);
    let c = commitment(&e, 1);
    let n = enr(&e, 1);

    assert!(
        client.try_rcv_insert(&account, &n, &c).is_err(),
        "no auth at all"
    );

    let invoke = MockAuthInvoke {
        contract: &id,
        fn_name: "rcv_insert",
        args: (account.clone(), n.clone(), c.clone()).into_val(&e),
        sub_invokes: &[],
    };
    let by_other = client
        .mock_auths(&[MockAuth {
            address: &other,
            invoke: &invoke,
        }])
        .try_rcv_insert(&account, &n, &c);
    assert!(
        by_other.is_err(),
        "another address cannot insert for the account"
    );

    let by_account = client
        .mock_auths(&[MockAuth {
            address: &account,
            invoke: &invoke,
        }])
        .try_rcv_insert(&account, &n, &c);
    assert!(by_account.is_ok());
}

/// The stored leaf is the pool's own wrap of the authorized account and the
/// enrollment id, never a caller-supplied value.
#[test]
fn leaf_binds_the_authorized_account_and_enrollment_id() {
    let (e, id, client) = setup();
    e.mock_all_auths();
    let account = Address::generate(&e);
    let c = commitment(&e, 7);
    let n = enr(&e, 7);

    client.rcv_insert(&account, &n, &c);

    let want_leaf = Hasher::new(&e).leaf(&contract_id(&e, &account).unwrap(), &n, &c);
    let want_root = reference_root(&e, TREE_DEPTH, core::slice::from_ref(&want_leaf));
    assert_eq!(
        e.events().all().filter_by_contract(&id),
        [LeafInserted {
            account: account.clone(),
            tree_id: 0,
            enrollment_id: n.clone(),
            index: 0,
            leaf: want_leaf.clone(),
            root: want_root.clone(),
        }
        .to_xdr(&e, &id)]
    );
    assert_eq!(client.leaves(&0, &0, &1).get_unchecked(0), want_leaf);
    assert_eq!(client.tree(&0).root, want_root);
    assert_eq!(
        client.enrollment(&account, &n),
        Some(LeafPosition {
            tree_id: 0,
            index: 0
        })
    );

    // The same commitment under another account, or under another
    // enrollment id of the same account, is a different leaf.
    let other = Address::generate(&e);
    assert_ne!(insert(&client, &other, &n, &c).leaf, want_leaf);
    assert_ne!(insert(&client, &account, &enr(&e, 8), &c).leaf, want_leaf);
}

/// One leaf per `(account, enrollment_id)`: a second insertion under an id
/// already in use is refused, even with a different commitment, so no second
/// secret can be added under the id a recovery configuration names.
#[test]
fn an_enrollment_id_is_inserted_at_most_once_per_account() {
    let (e, _id, client) = setup();
    e.mock_all_auths();
    let account = Address::generate(&e);
    let n = enr(&e, 1);
    client.rcv_insert(&account, &n, &commitment(&e, 1));
    assert_eq!(
        client.try_rcv_insert(&account, &n, &commitment(&e, 2)),
        Err(Ok(PoolError::EnrollmentIdTaken))
    );
    assert_eq!(client.tree(&0).size, 1);
    // Another account may use the same id; it binds a different leaf.
    client.rcv_insert(&Address::generate(&e), &n, &commitment(&e, 2));
}

#[test]
fn roots_match_an_independent_recomputation() {
    let (e, _id, client) = setup();
    e.mock_all_auths();
    let mut leaves = StdVec::new();
    for n in 0..9u64 {
        let account = Address::generate(&e);
        let got = insert(&client, &account, &enr(&e, n), &commitment(&e, n));
        assert_eq!(got.index, n);
        leaves.push(got.leaf.clone());
        assert_eq!(
            got.root,
            reference_root(&e, TREE_DEPTH, &leaves),
            "after {n}"
        );
        assert!(client.is_known_root(&0, &got.root));
    }
    let info = client.tree(&0);
    assert_eq!(info.size, 9);
    assert_eq!(info.capacity, 1u64 << 32);
    assert!(!info.sealed);
    assert_eq!(info.root, reference_root(&e, TREE_DEPTH, &leaves));
}

#[test]
fn rejects_non_canonical_commitments_and_non_contract_accounts() {
    let (e, _id, client) = setup();
    e.mock_all_auths();
    let account = Address::generate(&e);

    let r = BytesN::from_array(&e, &FIELD_MODULUS);
    assert_eq!(
        client.try_rcv_insert(&account, &enr(&e, 1), &r),
        Err(Ok(PoolError::NonCanonicalCommitment))
    );
    let mut below = FIELD_MODULUS;
    below[31] -= 1;
    assert!(client
        .try_rcv_insert(&account, &enr(&e, 1), &BytesN::from_array(&e, &below))
        .is_ok());

    let g = Address::from_str(
        &e,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
    );
    assert_eq!(
        client.try_rcv_insert(&g, &enr(&e, 1), &commitment(&e, 1)),
        Err(Ok(PoolError::AccountNotContract))
    );
}

#[test]
fn empty_and_unopened_trees_accept_no_root() {
    let (e, _id, client) = setup();
    let empty_root = BytesN::from_array(&e, &ZERO_HASHES[TREE_DEPTH as usize]);
    assert_eq!(client.tree(&0).root, empty_root);
    assert!(!client.is_known_root(&0, &empty_root));
    assert!(!client.is_known_root(&1, &empty_root));
    assert_eq!(client.try_tree(&1), Err(Ok(PoolError::UnknownTree)));
}

/// Drives `merkle::append` directly at a small depth inside the pool's own
/// storage context, so a tree can be filled.
fn append_at(e: &Env, id: &Address, depth: u32, leaf: &BytesN<32>) -> Insertion {
    e.as_contract(id, || {
        merkle::append(e, &mut Hasher::new(e), depth, leaf).unwrap()
    })
}

/// Every root a tree has ever had stays acceptable, however many insertions
/// follow: nobody can push a victim's root out by inserting quickly.
#[test]
fn every_historical_root_stays_acceptable() {
    let (e, id, client) = setup();
    let mut roots = StdVec::new();
    // More insertions than any recent-roots window this pool might have had
    // (Nido's kept 128).
    for n in 0..130u64 {
        roots.push(append_at(&e, &id, 8, &bytes(&e, n + 1)).root);
    }
    for (n, r) in roots.iter().enumerate() {
        assert!(client.is_known_root(&0, r), "root {n}");
    }
    assert!(!client.is_known_root(&1, &roots[0]), "roots are per tree");
}

/// Filling a tree rolls new insertions into the next one, and the sealed
/// tree's roots stay acceptable however many insertions follow.
#[test]
fn full_tree_is_sealed_and_keeps_its_roots() {
    let (e, id, client) = setup();
    let depth = 2;
    let mut tree0 = StdVec::new();
    let mut roots0 = StdVec::new();
    for n in 0..4u64 {
        let got = append_at(&e, &id, depth, &bytes(&e, n + 1));
        assert_eq!((got.tree_id, got.index), (0, n));
        tree0.push(got.leaf);
        assert_eq!(got.root, reference_root(&e, depth, &tree0));
        roots0.push(got.root);
    }
    assert_eq!(
        client.current_tree(),
        1,
        "eager rollover after the last slot"
    );

    for n in 0..9u64 {
        let got = append_at(&e, &id, depth, &bytes(&e, 100 + n));
        assert_eq!(got.tree_id, 1 + (n / 4) as u32);
        assert_eq!(got.index, n % 4);
    }
    assert_eq!(client.current_tree(), 3);
    for r in &roots0 {
        assert!(client.is_known_root(&0, r));
        assert!(!client.is_known_root(&1, r), "roots are per tree");
    }
    assert_eq!(client.leaves(&0, &0, &4), Vec::from_slice(&e, &tree0));
}

/// The real depth-32 boundary, without `2^32` insertions: tree 0 is
/// synthesized one slot short of full (as if every earlier leaf were the
/// empty leaf), then the last slot — index `2^32 - 1`, every path bit set —
/// is filled through the real `rcv_insert` entry point.
#[test]
fn depth_32_boundary_fills_the_last_slot_and_rolls_over() {
    let (e, id, client) = setup();
    e.mock_all_auths();
    let mut frontier = Vec::new(&e);
    for level in 0..TREE_DEPTH {
        frontier.push_back(BytesN::from_array(&e, &ZERO_HASHES[level as usize]));
    }
    e.as_contract(&id, || {
        e.storage().persistent().set(
            &PoolKey::Tree(0),
            &TreeState {
                size: (1u64 << 32) - 1,
                root: BytesN::from_array(&e, &ZERO_HASHES[TREE_DEPTH as usize]),
                frontier,
            },
        );
    });

    let account = Address::generate(&e);
    let last = insert(&client, &account, &enr(&e, 42), &commitment(&e, 42));
    assert_eq!((last.tree_id, last.index), (0, (1u64 << 32) - 1));

    let mut h = Hasher::new(&e);
    let mut want = last.leaf.clone();
    for level in 0..TREE_DEPTH {
        want = h.node(&BytesN::from_array(&e, &ZERO_HASHES[level as usize]), &want);
    }
    assert_eq!(last.root, want);

    let info = client.tree(&0);
    assert_eq!(info.size, 1u64 << 32);
    assert!(info.sealed);
    assert_eq!(client.current_tree(), 1);

    let next = insert(&client, &account, &enr(&e, 43), &commitment(&e, 43));
    assert_eq!((next.tree_id, next.index), (1, 0));
    assert!(
        client.is_known_root(&0, &last.root),
        "sealed tree still provable"
    );
    assert_eq!(
        client.leaves(&0, &((1u64 << 32) - 1), &MAX_PAGE),
        Vec::from_array(&e, [last.leaf])
    );
}

#[test]
fn leaf_pages_are_bounded_and_clamped() {
    let (e, id, client) = setup();
    for n in 0..5u64 {
        append_at(&e, &id, 4, &bytes(&e, n + 1));
    }
    assert_eq!(client.leaves(&0, &3, &10).len(), 2);
    assert_eq!(client.leaves(&0, &9, &10).len(), 0);
    assert_eq!(client.leaves(&0, &u64::MAX, &10).len(), 0);
    assert_eq!(
        client.try_leaves(&0, &0, &(MAX_PAGE + 1)),
        Err(Ok(PoolError::PageTooLarge))
    );
    assert_eq!(
        client.try_leaves(&1, &0, &1),
        Err(Ok(PoolError::UnknownTree))
    );
}

fn ttl(e: &Env, id: &Address, key: &PoolKey) -> u32 {
    e.as_contract(id, || e.storage().persistent().get_ttl(key))
}

/// The renew entry points are permissionless and only ever extend TTLs.
#[test]
fn renew_extends_every_entry_a_witness_needs() {
    let (e, id, client) = setup();
    e.mock_all_auths();
    let account = Address::generate(&e);
    let first = insert(&client, &account, &enr(&e, 1), &commitment(&e, 1));
    let latest = insert(
        &client,
        &Address::generate(&e),
        &enr(&e, 2),
        &commitment(&e, 2),
    );
    let max = e.as_contract(&id, || e.storage().max_ttl());
    let keys = [
        PoolKey::Tree(0),
        PoolKey::Root(0, latest.root.clone()),
        PoolKey::Root(0, first.root.clone()),
        PoolKey::Leaf(0, 0),
        PoolKey::Enrollment(account.clone(), enr(&e, 1)),
    ];

    e.ledger().with_mut(|l| l.sequence_number += max / 2);
    for key in &keys {
        assert!(ttl(&e, &id, key) < max);
    }
    e.set_auths(&[]);
    client.renew_tree(&0);
    client.renew_root(&0, &first.root);
    client.renew_leaves(&0, &0, &1);
    client.renew_enrollment(&account, &enr(&e, 1));
    for key in &keys {
        assert_eq!(ttl(&e, &id, key), max, "{key:?}");
    }
    assert!(client.is_known_root(&0, &first.root));
}

/// An expired persistent entry is archived, never deleted, and the host never
/// reads it as absent: touching it restores the original value (the test host
/// emulates protocol 23's automatic restoration; on a live network the
/// invoking transaction's footprint marks it for restore, or a
/// `RestoreFootprint` operation does). So an archived tree resumes where it
/// left off instead of being silently restarted at index 0, and its old roots
/// stay provable.
#[test]
fn archived_tree_is_restored_not_reset() {
    let (e, id, client) = setup();
    e.mock_all_auths();
    let first = insert(
        &client,
        &Address::generate(&e),
        &enr(&e, 1),
        &commitment(&e, 1),
    );
    let max = e.as_contract(&id, || e.storage().max_ttl());
    e.ledger().with_mut(|l| l.sequence_number += max + 1);
    // Inspect the raw ledger rather than calling `get_ttl`, which would
    // itself restore the entry it reads.
    let seq = e.ledger().sequence();
    let archived = e
        .to_ledger_snapshot()
        .ledger_entries
        .iter()
        .filter(|(key, (_, live_until))| {
            matches!(key.as_ref(), LedgerKey::ContractData(d)
                if d.durability == ContractDataDurability::Persistent
                    && d.key != ScVal::LedgerKeyContractInstance)
                && live_until.is_some_and(|l| l < seq)
        })
        .count();
    assert_eq!(
        archived, 4,
        "tree state, root, leaf, and enrollment record all archived"
    );

    let next = insert(
        &client,
        &Address::generate(&e),
        &enr(&e, 2),
        &commitment(&e, 2),
    );
    assert_eq!((next.tree_id, next.index), (0, 1), "resumed, not reset");
    assert!(client.is_known_root(&0, &first.root));
    assert_eq!(client.leaves(&0, &0, &2).get_unchecked(0), first.leaf);
}

/// The pool through `perch-recovery-interface`'s own `MembershipPoolClient`,
/// as the account and the adapter call it: `rcv_insert` returns nothing and
/// fails the call on refusal.
#[test]
fn implements_the_membership_pool_interface() {
    use perch_recovery_interface::zk::MembershipPoolClient;
    let (e, id, client) = setup();
    e.mock_all_auths();
    let pool = MembershipPoolClient::new(&e, &id);
    let account = Address::generate(&e);

    assert_eq!(pool.depth(), TREE_DEPTH);
    pool.rcv_insert(&account, &enr(&e, 1), &commitment(&e, 1));
    let root = client.tree(&0).root;
    assert!(pool.is_known_root(&0, &root));
    assert!(pool
        .try_rcv_insert(&account, &enr(&e, 1), &commitment(&e, 2))
        .is_err());
}

/// Reads every leaf of `tree_id` through the pool's own `leaves` pages, as an
/// indexer working from contract storage does.
fn pages(client: &PerchZkPoolClient, tree_id: u32) -> StdVec<[u8; 32]> {
    let size = client.tree(&tree_id).size;
    let mut out = StdVec::new();
    let mut start = 0u64;
    while start < size {
        for l in client.leaves(&tree_id, &start, &MAX_PAGE).iter() {
            out.push(l.to_array());
        }
        start += u64::from(MAX_PAGE);
    }
    out
}

fn hex(b: &[u8; 32]) -> std::string::String {
    perch_zk_prover::hex(b)
}

/// The witness index (`perch_zk_prover::PoolWitnessIndex`, the structure
/// `packages/perch-zk` mirrors) replays this pool's storage and serves
/// witnesses for every leaf — the last leaf of each sealed tree included —
/// against roots the pool itself accepts. Sealed trees use the merkle code at
/// depth 3; the depth-32 tree goes through `rcv_insert`. The same data is
/// pinned in `testdata/zk/witness-replay.json` for the TypeScript suite
/// (rewrite it with `PERCH_ZK_WRITE_VECTORS=1`).
#[test]
fn witness_index_replays_the_pool_storage() {
    use perch_zk_prover::{host, root_from_path, Insertion, PoolWitnessIndex};
    let (e, id, client) = setup();
    e.mock_all_auths();
    let he = host();
    let mut vector = serde_json::Map::new();

    // Depth 3: two sealed trees and a partly filled third.
    for n in 0..19u64 {
        append_at(&e, &id, 3, &bytes(&e, n + 1));
    }
    assert_eq!(client.current_tree(), 2);
    let mut idx = PoolWitnessIndex::new(3, 1);
    let mut trees = StdVec::new();
    for t in 0..=2u32 {
        let leaves = pages(&client, t);
        for (i, l) in leaves.iter().enumerate() {
            idx.ingest(
                &he,
                &Insertion {
                    tree_id: t,
                    index: i as u64,
                    leaf: *l,
                },
            )
            .unwrap();
        }
        let tree = idx.tree(t).unwrap();
        let read = |s: u64, c: usize| leaves[s as usize..s as usize + c].to_vec();
        let root = tree.root(&he, read);
        assert_eq!(root, client.tree(&t).root.to_array(), "tree {t}");
        assert!(client.is_known_root(&t, &BytesN::from_array(&e, &root)));
        for (i, l) in leaves.iter().enumerate() {
            let w = tree.witness(&he, i as u64, read);
            assert_eq!(w.root, root);
            assert_eq!(root_from_path(&he, l, i as u64, &w.siblings), root);
        }
        trees.push(serde_json::json!({
            "tree_id": t,
            "sealed": tree.sealed(),
            "leaves": leaves.iter().map(hex).collect::<StdVec<_>>(),
            "root": hex(&root),
        }));
    }
    assert!(idx.tree(0).unwrap().sealed() && idx.tree(1).unwrap().sealed());
    vector.insert(
        "depth_3".into(),
        serde_json::json!({ "depth": 3, "trees": trees }),
    );

    // Depth 32, through the real entry point, across several chunk boundaries
    // at chunk level 3.
    let (e2, _id2, client2) = setup();
    e2.mock_all_auths();
    for n in 0..41u64 {
        client2.rcv_insert(&Address::generate(&e2), &enr(&e2, n), &commitment(&e2, n));
    }
    let leaves = pages(&client2, 0);
    let mut idx32 = PoolWitnessIndex::new(32, 3);
    for (i, l) in leaves.iter().enumerate() {
        idx32
            .ingest(
                &he,
                &Insertion {
                    tree_id: 0,
                    index: i as u64,
                    leaf: *l,
                },
            )
            .unwrap();
    }
    let tree = idx32.tree(0).unwrap();
    let read = |s: u64, c: usize| leaves[s as usize..s as usize + c].to_vec();
    let root = tree.root(&he, read);
    assert_eq!(root, client2.tree(&0).root.to_array());
    for (i, l) in leaves.iter().enumerate() {
        let w = tree.witness(&he, i as u64, read);
        assert_eq!(root_from_path(&he, l, i as u64, &w.siblings), root);
    }
    vector.insert(
        "depth_32".into(),
        serde_json::json!({
            "depth": 32,
            "trees": [{ "tree_id": 0, "sealed": false, "leaves": leaves.iter().map(hex).collect::<StdVec<_>>(), "root": hex(&root) }],
        }),
    );

    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/zk/witness-replay.json");
    let mut json = serde_json::to_vec_pretty(&serde_json::Value::Object(vector)).unwrap();
    json.push(b'\n');
    if std::env::var("PERCH_ZK_WRITE_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &json).unwrap();
    }
    assert_eq!(
        std::fs::read(&path).expect("run with PERCH_ZK_WRITE_VECTORS=1 to create it"),
        json,
        "testdata/zk/witness-replay.json is stale"
    );
}
