//! Merkle witnesses for a membership pool, scaled to full depth-32 trees.
//!
//! The same structure as `packages/perch-zk`'s `IncrementalTree`: leaves are
//! appended in insertion order, and the tree keeps only a `depth`-sized
//! frontier plus the roots of completed subtrees at or above `chunk_level`
//! (a [`NodeStore`]; about `size / 2^(chunk_level - 1)` of them). Leaves stay
//! with the caller; a witness reads the `2^chunk_level`-leaf chunk its leaf is
//! in and, while the tree is not full, the partly filled last chunk.

use crate::{bn, Bytes32};
use perch_zk_primitives::{Hasher, ZERO_HASHES};
use soroban_sdk::Env;
use std::collections::HashMap;

/// Default chunk level: witnesses read `2^16` leaves.
pub const CHUNK_LEVEL: u32 = 16;

/// Completed subtree roots, keyed by `(level, index at that level)`.
pub trait NodeStore {
    fn get(&self, level: u32, index: u64) -> Option<Bytes32>;
    fn set(&mut self, level: u32, index: u64, value: Bytes32);
}

#[derive(Default)]
pub struct MemoryNodeStore(HashMap<(u32, u64), Bytes32>);

impl MemoryNodeStore {
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl NodeStore for MemoryNodeStore {
    fn get(&self, level: u32, index: u64) -> Option<Bytes32> {
        self.0.get(&(level, index)).copied()
    }
    fn set(&mut self, level: u32, index: u64, value: Bytes32) {
        self.0.insert((level, index), value);
    }
}

/// What an [`IncrementalTree`] persists besides its node store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeState {
    pub size: u64,
    /// `frontier[level]`: the most recent node at `level` that was a left child.
    pub frontier: Vec<Bytes32>,
}

/// A Merkle path and the root it proves against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub root: Bytes32,
    pub siblings: Vec<Bytes32>,
}

fn node(h: &mut Hasher, e: &Env, l: &Bytes32, r: &Bytes32) -> Bytes32 {
    h.node(&bn(e, l), &bn(e, r)).to_array()
}

/// Every level of the complete height-`height` subtree over `leaves`
/// (padded with empty leaves), leaves first.
fn subtree(h: &mut Hasher, e: &Env, leaves: Vec<Bytes32>, height: u32) -> Vec<Vec<Bytes32>> {
    let mut levels = vec![leaves];
    for level in 0..height as usize {
        let zero = ZERO_HASHES[level];
        let cur = &levels[level];
        let next = (0..cur.len().max(1))
            .step_by(2)
            .map(|i| {
                let l = cur.get(i).copied().unwrap_or(zero);
                let r = cur.get(i + 1).copied().unwrap_or(zero);
                node(h, e, &l, &r)
            })
            .collect();
        levels.push(next);
    }
    levels
}

pub struct IncrementalTree<S: NodeStore = MemoryNodeStore> {
    depth: u32,
    chunk_level: u32,
    nodes: S,
    state: TreeState,
}

impl IncrementalTree<MemoryNodeStore> {
    pub fn new(depth: u32, chunk_level: u32) -> Self {
        Self::with_store(depth, chunk_level, MemoryNodeStore::default(), None)
    }
}

impl<S: NodeStore> IncrementalTree<S> {
    /// A tree over `nodes`, resuming from `state` when given.
    pub fn with_store(depth: u32, chunk_level: u32, nodes: S, state: Option<TreeState>) -> Self {
        assert!(depth <= perch_zk_primitives::MAX_TREE_DEPTH);
        let state = state.unwrap_or_else(|| TreeState {
            size: 0,
            frontier: ZERO_HASHES[..depth as usize].to_vec(),
        });
        Self {
            depth,
            chunk_level: chunk_level.min(depth),
            nodes,
            state,
        }
    }

    pub fn depth(&self) -> u32 {
        self.depth
    }

    pub fn size(&self) -> u64 {
        self.state.size
    }

    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    pub fn sealed(&self) -> bool {
        self.state.size == self.capacity()
    }

    pub fn state(&self) -> &TreeState {
        &self.state
    }

    pub fn nodes(&self) -> &S {
        &self.nodes
    }

    /// Append the next leaf: amortized two hashes, storing every subtree root
    /// the insertion completes at or above `chunk_level`.
    pub fn append(&mut self, e: &Env, leaf: Bytes32) {
        assert!(!self.sealed(), "tree is full");
        let index = self.state.size;
        if self.chunk_level == 0 {
            self.nodes.set(0, index, leaf);
        }
        let mut h = Hasher::new(e);
        let mut cur = leaf;
        for level in 0..self.depth {
            if (index >> level) & 1 == 0 {
                self.state.frontier[level as usize] = cur;
                break;
            }
            cur = node(&mut h, e, &self.state.frontier[level as usize], &cur);
            if level + 1 >= self.chunk_level {
                self.nodes.set(level + 1, index >> (level + 1), cur);
            }
        }
        self.state.size += 1;
    }

    fn value(
        &self,
        h: &mut Hasher,
        e: &Env,
        level: u32,
        index: u64,
        read: &mut dyn FnMut(u64, usize) -> Vec<Bytes32>,
    ) -> Bytes32 {
        let start = (index as u128) << level;
        let span = 1u128 << level;
        let size = u128::from(self.state.size);
        if start >= size {
            return ZERO_HASHES[level as usize];
        }
        let complete = start + span <= size;
        if complete && level >= self.chunk_level {
            return self
                .nodes
                .get(level, index)
                .unwrap_or_else(|| panic!("node store has no node ({level}, {index})"));
        }
        if level <= self.chunk_level {
            let end = if complete { start + span } else { size };
            let leaves = read(start as u64, (end - start) as usize);
            return subtree(h, e, leaves, level)[level as usize][0];
        }
        // Partly filled above the chunk level: one child is complete or empty,
        // the other partly filled, so this recursion is at most `depth` deep.
        let l = self.value(h, e, level - 1, index * 2, read);
        let r = self.value(h, e, level - 1, index * 2 + 1, read);
        node(h, e, &l, &r)
    }

    pub fn root(&self, e: &Env, mut read: impl FnMut(u64, usize) -> Vec<Bytes32>) -> Bytes32 {
        let mut h = Hasher::new(e);
        self.value(&mut h, e, self.depth, 0, &mut read)
    }

    /// The witness for the leaf at `index`, against the current root.
    pub fn witness(
        &self,
        e: &Env,
        index: u64,
        mut read: impl FnMut(u64, usize) -> Vec<Bytes32>,
    ) -> MerklePath {
        assert!(index < self.state.size, "no leaf at index {index}");
        let mut h = Hasher::new(e);
        let height = self.chunk_level;
        let chunk_start = (index >> height) << height;
        let chunk_end =
            (u128::from(chunk_start) + (1u128 << height)).min(u128::from(self.state.size));
        let leaves = read(chunk_start, (chunk_end - u128::from(chunk_start)) as usize);
        let levels = subtree(&mut h, e, leaves, height);
        let mut siblings = Vec::with_capacity(self.depth as usize);
        for level in 0..height {
            let sib = (((index - chunk_start) >> level) ^ 1) as usize;
            siblings.push(
                levels[level as usize]
                    .get(sib)
                    .copied()
                    .unwrap_or(ZERO_HASHES[level as usize]),
            );
        }
        for level in height..self.depth {
            siblings.push(self.value(&mut h, e, level, (index >> level) ^ 1, &mut read));
        }
        MerklePath {
            root: self.value(&mut h, e, self.depth, 0, &mut read),
            siblings,
        }
    }
}

/// One insertion of a pool, as its `LeafInserted` event reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insertion {
    pub tree_id: u32,
    pub index: u64,
    pub leaf: Bytes32,
}

/// Witnesses for every tree of one pool: ingests insertions in pool order,
/// follows rollover, and keeps one [`IncrementalTree`] per tree.
pub struct PoolWitnessIndex {
    depth: u32,
    chunk_level: u32,
    trees: HashMap<u32, IncrementalTree>,
    current: u32,
}

impl PoolWitnessIndex {
    pub fn new(depth: u32, chunk_level: u32) -> Self {
        Self {
            depth,
            chunk_level,
            trees: HashMap::new(),
            current: 0,
        }
    }

    pub fn current_tree(&self) -> u32 {
        self.current
    }

    pub fn tree(&self, tree_id: u32) -> Option<&IncrementalTree> {
        self.trees.get(&tree_id)
    }

    /// Apply the next insertion; anything out of pool order is refused.
    pub fn ingest(&mut self, e: &Env, insertion: &Insertion) -> Result<(), String> {
        let (depth, chunk) = (self.depth, self.chunk_level);
        let t = self
            .trees
            .entry(self.current)
            .or_insert_with(|| IncrementalTree::new(depth, chunk));
        if insertion.tree_id != self.current || insertion.index != t.size() {
            return Err(format!(
                "out of order: expected tree {} index {}, got tree {} index {}",
                self.current,
                t.size(),
                insertion.tree_id,
                insertion.index
            ));
        }
        t.append(e, insertion.leaf);
        if t.sealed() {
            self.current += 1;
        }
        Ok(())
    }
}

/// An in-memory tree over a slice of leaves: the convenience the fixture
/// tool and tests use for small trees. Built on [`IncrementalTree`].
pub struct Tree {
    tree: IncrementalTree,
    leaves: Vec<Bytes32>,
    env: Env,
}

impl Tree {
    pub fn new(e: &Env, depth: u32, leaves: &[Bytes32]) -> Self {
        let mut tree = IncrementalTree::new(depth, CHUNK_LEVEL.min(depth));
        for leaf in leaves {
            tree.append(e, *leaf);
        }
        Self {
            tree,
            leaves: leaves.to_vec(),
            env: e.clone(),
        }
    }

    fn reader(&self) -> impl FnMut(u64, usize) -> Vec<Bytes32> + '_ {
        |start, count| self.leaves[start as usize..start as usize + count].to_vec()
    }

    pub fn depth(&self) -> u32 {
        self.tree.depth()
    }

    pub fn size(&self) -> u64 {
        self.tree.size()
    }

    pub fn root(&self) -> Bytes32 {
        self.tree.root(&self.env, self.reader())
    }

    /// Sibling hashes from the leaf level up, for the leaf at `index`.
    pub fn path(&self, index: u64) -> Vec<Bytes32> {
        self.tree.witness(&self.env, index, self.reader()).siblings
    }
}
