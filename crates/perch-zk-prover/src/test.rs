use super::*;
use perch_zk_primitives::ZERO_HASHES;

fn leaf(n: u8) -> Bytes32 {
    let mut b = [0u8; 32];
    b[31] = n;
    b
}

#[test]
fn empty_and_single_leaf_roots() {
    let e = host();
    assert_eq!(Tree::new(&e, 32, &[]).root(), ZERO_HASHES[32]);
    let t = Tree::new(&e, 32, &[leaf(1)]);
    assert_eq!(t.path(0), ZERO_HASHES[..32].to_vec());
    assert_eq!(root_from_path(&e, &leaf(1), 0, &t.path(0)), t.root());
}

#[test]
fn every_path_recomputes_the_root() {
    let e = host();
    let leaves: Vec<Bytes32> = (1..=11).map(leaf).collect();
    for depth in [4, 5, 32] {
        let t = Tree::new(&e, depth, &leaves);
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(root_from_path(&e, l, i as u64, &t.path(i as u64)), t.root());
        }
    }
}

#[test]
fn inputs_round_trip_through_the_leaf_they_prove() {
    let e = host();
    let (secret, account, enrollment, digest) = (leaf(7), [0x11; 32], [0x22; 32], [0x33; 32]);
    let l = super::leaf(&e, &account, &enrollment, &secret);
    let t = Tree::new(&e, 32, &[leaf(1), l, leaf(3)]);
    let inputs = Inputs::new(&e, secret, account, enrollment, digest, 1, t.path(1));
    assert_eq!(inputs.root, t.root());
    assert_eq!(inputs.leaf(&e), l);
    let toml = inputs.prover_toml();
    assert!(toml.contains(
        "acct_hi = \"0x0000000000000000000000000000000011111111111111111111111111111111\""
    ));
    assert!(toml.contains(
        "leaf_index = \"0x0000000000000000000000000000000000000000000000000000000000000001\""
    ));
}

/// The naive construction: every level of the tree, rebuilt from all leaves.
fn naive(e: &Env, depth: u32, leaves: &[Bytes32]) -> Vec<Vec<Bytes32>> {
    let mut h = Hasher::new(e);
    let mut levels = vec![leaves.to_vec()];
    for level in 0..depth as usize {
        let zero = ZERO_HASHES[level];
        let cur = levels[level].clone();
        levels.push(
            (0..cur.len().max(1))
                .step_by(2)
                .map(|i| {
                    let l = cur.get(i).copied().unwrap_or(zero);
                    let r = cur.get(i + 1).copied().unwrap_or(zero);
                    h.node(&bn(e, &l), &bn(e, &r)).to_array()
                })
                .collect(),
        );
    }
    levels
}

/// The incremental tree agrees with the naive construction at every size up
/// to full, for every chunk level, on the root and on every leaf's path.
#[test]
fn incremental_tree_matches_a_full_rebuild() {
    let e = host();
    let depth = 4;
    let all: Vec<Bytes32> = (1..=16).map(leaf).collect();
    for chunk in 0..=depth {
        let mut t = IncrementalTree::new(depth, chunk);
        for n in 1..=all.len() {
            t.append(&e, all[n - 1]);
            let read = |s: u64, c: usize| all[s as usize..s as usize + c].to_vec();
            let levels = naive(&e, depth, &all[..n]);
            let root = levels[depth as usize][0];
            assert_eq!(t.root(&e, read), root, "chunk {chunk} size {n}");
            for i in 0..n as u64 {
                let w = t.witness(&e, i, read);
                assert_eq!(w.root, root);
                assert_eq!(root_from_path(&e, &all[i as usize], i, &w.siblings), root);
            }
        }
        assert!(t.sealed());
    }
}

/// Insertions are applied in pool order only, and the index follows the
/// pool's eager rollover; sealed trees stay witnessable.
#[test]
fn pool_index_follows_rollover_and_refuses_disorder() {
    let e = host();
    let mut idx = PoolWitnessIndex::new(2, 1);
    let ins = |tree_id, index, n| Insertion {
        tree_id,
        index,
        leaf: leaf(n),
    };
    assert!(idx.ingest(&e, &ins(0, 1, 1)).is_err(), "gap");
    for i in 0..4 {
        idx.ingest(&e, &ins(0, i, i as u8 + 1)).unwrap();
    }
    assert_eq!(idx.current_tree(), 1, "sealed tree 0 rolls over eagerly");
    assert!(idx.ingest(&e, &ins(0, 4, 9)).is_err(), "sealed tree");
    idx.ingest(&e, &ins(1, 0, 10)).unwrap();
    let t0 = idx.tree(0).unwrap();
    assert!(t0.sealed());
    let leaves0: Vec<Bytes32> = (1..=4).map(leaf).collect();
    let w = t0.witness(&e, 3, |s, c| leaves0[s as usize..s as usize + c].to_vec());
    assert_eq!(root_from_path(&e, &leaf(4), 3, &w.siblings), w.root);
    assert_eq!(w.root, naive(&e, 2, &leaves0)[2][0]);
}

/// The last leaf of a full depth-32 tree, through the production witness
/// code. The node store is what an indexer would have persisted for a tree
/// whose 2^32 leaves are all the same value `x`, written in closed form
/// (every subtree root at level `l` is `x` hashed up `l` times) because
/// ingesting 2^32 leaves is out of reach; the leaf reader serves `x` for any
/// chunk. The witness reads one 2^16-leaf chunk and 16 stored nodes.
#[test]
fn last_leaf_of_a_sealed_depth_32_tree() {
    let e = host();
    let x = leaf(7);
    let mut h = Hasher::new(&e);
    let mut chain = vec![x];
    for l in 0..32 {
        chain.push(h.node(&bn(&e, &chain[l]), &bn(&e, &chain[l])).to_array());
    }
    let mut nodes = MemoryNodeStore::default();
    for level in CHUNK_LEVEL..=32 {
        for k in 0..(1u64 << (32 - level)) {
            nodes.set(level, k, chain[level as usize]);
        }
    }
    let t = IncrementalTree::with_store(
        32,
        CHUNK_LEVEL,
        nodes,
        Some(TreeState {
            size: 1 << 32,
            frontier: chain[..32].to_vec(),
        }),
    );
    assert!(t.sealed());
    let read = |_s: u64, c: usize| vec![x; c];
    let last = (1u64 << 32) - 1;
    let w = t.witness(&e, last, read);
    assert_eq!(w.root, chain[32]);
    assert_eq!(w.siblings, chain[..32].to_vec());
    assert_eq!(root_from_path(&e, &x, last, &w.siblings), chain[32]);
}
