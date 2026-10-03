//! Storage-backed incremental Merkle trees with rollover.
//!
//! Every function takes the tree `depth` as a parameter rather than reading
//! `TREE_DEPTH`, so the tests drive the exact production code paths —
//! including filling a tree and rolling over — at depth 2 or 3 instead of
//! needing `2^32` insertions. The contract always passes `TREE_DEPTH`.
//!
//! Storage layout (all persistent, so nothing is ever deleted by expiry —
//! an expired entry is archived and restored on access, never read as
//! missing):
//!
//! | key                  | value          | written by                       |
//! |----------------------|----------------|----------------------------------|
//! | `CurrentTree`        | `u32`          | rollover (absent = tree 0)       |
//! | `Tree(id)`           | `TreeState`    | every insertion into `id`        |
//! | `Root(id, root)`     | `u64`          | the insertion that produced it   |
//! | `Leaf(id, index)`    | `BytesN<32>`   | the insertion of that leaf       |
//! | `Enrollment(a, n)`   | `LeafPosition` | account `a`'s enrollment `n`     |
//!
//! `Root(id, root)` holds the tree size right after `root` was produced. One
//! entry per insertion is what lets every historical root stay acceptable.
//! `Leaf` entries make any leaf's witness reconstructible from contract
//! storage alone, without depending on how long anyone retains events.

use crate::{Insertion, LeafPosition, PoolError, TreeInfo, MAX_PAGE};
use perch_zk_primitives::{Hasher, ZERO_HASHES};
use soroban_sdk::{contracttype, Address, BytesN, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoolKey {
    CurrentTree,
    Tree(u32),
    Root(u32, BytesN<32>),
    Leaf(u32, u64),
    Enrollment(Address, BytesN<32>),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeState {
    /// Leaves inserted so far; also the index the next insertion takes.
    pub size: u64,
    /// The root after the latest insertion.
    pub root: BytesN<32>,
    /// `frontier[level]` is the most recent node at `level` that was a left
    /// child: the left sibling the next right child at that level hashes
    /// with. Entries are written before they are ever read.
    pub frontier: Vec<BytesN<32>>,
}

pub fn capacity(depth: u32) -> u64 {
    1u64 << depth
}

fn zero(e: &Env, level: u32) -> BytesN<32> {
    BytesN::from_array(e, &ZERO_HASHES[level as usize])
}

pub fn bump(e: &Env, key: &PoolKey) {
    let max = e.storage().max_ttl();
    e.storage().persistent().extend_ttl(key, max, max);
}

fn bump_if_present(e: &Env, key: &PoolKey) {
    if e.storage().persistent().has(key) {
        bump(e, key);
    }
}

pub fn current_tree(e: &Env) -> u32 {
    e.storage()
        .persistent()
        .get(&PoolKey::CurrentTree)
        .unwrap_or(0)
}

fn require_opened(e: &Env, tree_id: u32) -> Result<(), PoolError> {
    if tree_id > current_tree(e) {
        return Err(PoolError::UnknownTree);
    }
    Ok(())
}

fn state(e: &Env, tree_id: u32) -> Option<TreeState> {
    e.storage().persistent().get(&PoolKey::Tree(tree_id))
}

/// Append `leaf` to the active tree and return where it landed. If that
/// fills the tree, later insertions go to the next tree: the full tree is
/// never written again.
pub fn append(
    e: &Env,
    h: &mut Hasher,
    depth: u32,
    leaf: &BytesN<32>,
) -> Result<Insertion, PoolError> {
    let tree_id = current_tree(e);
    let mut st = state(e, tree_id).unwrap_or_else(|| {
        let mut frontier = Vec::new(e);
        for level in 0..depth {
            frontier.push_back(zero(e, level));
        }
        TreeState {
            size: 0,
            root: zero(e, depth),
            frontier,
        }
    });
    // Rollover is eager (below), so the active tree always has room.
    let index = st.size;

    let mut cur = leaf.clone();
    for level in 0..depth {
        if (index >> level) & 1 == 0 {
            st.frontier.set(level, cur.clone());
            cur = h.node(&cur, &zero(e, level));
        } else {
            cur = h.node(&st.frontier.get_unchecked(level), &cur);
        }
    }
    st.size += 1;
    st.root = cur.clone();

    let storage = e.storage().persistent();
    storage.set(&PoolKey::Tree(tree_id), &st);
    bump(e, &PoolKey::Tree(tree_id));

    storage.set(&PoolKey::Leaf(tree_id, index), leaf);
    bump(e, &PoolKey::Leaf(tree_id, index));

    let root_key = PoolKey::Root(tree_id, cur.clone());
    storage.set(&root_key, &st.size);
    bump(e, &root_key);

    if st.size == capacity(depth) {
        let next = tree_id.checked_add(1).ok_or(PoolError::TreeIdOverflow)?;
        storage.set(&PoolKey::CurrentTree, &next);
        bump(e, &PoolKey::CurrentTree);
    }

    Ok(Insertion {
        tree_id,
        index,
        leaf: leaf.clone(),
        root: cur,
    })
}

/// Whether `root` is a root tree `tree_id` has ever had. Only insertions
/// produce roots, so an empty tree's root is never accepted (no leaf could be
/// proven under it anyway).
pub fn is_known_root(e: &Env, tree_id: u32, root: &BytesN<32>) -> bool {
    let key = PoolKey::Root(tree_id, root.clone());
    if !e.storage().persistent().has(&key) {
        return false;
    }
    // A root a recovery is about to rely on is kept alive by the check itself.
    bump(e, &key);
    true
}

pub fn tree_info(e: &Env, depth: u32, tree_id: u32) -> Result<TreeInfo, PoolError> {
    require_opened(e, tree_id)?;
    let (size, root) = state(e, tree_id).map_or((0, zero(e, depth)), |st| (st.size, st.root));
    Ok(TreeInfo {
        tree_id,
        size,
        capacity: capacity(depth),
        root,
        sealed: size == capacity(depth),
    })
}

fn page(e: &Env, tree_id: u32, start: u64, count: u32) -> Result<(u64, u32), PoolError> {
    require_opened(e, tree_id)?;
    if count > MAX_PAGE {
        return Err(PoolError::PageTooLarge);
    }
    let size = state(e, tree_id).map_or(0, |st| st.size);
    let end = start.saturating_add(u64::from(count)).min(size);
    let start = start.min(end);
    // The page is at most MAX_PAGE wide.
    Ok((start, (end - start) as u32))
}

/// Leaves `start..start + count` of `tree_id` (clamped to the tree's size).
pub fn leaves(e: &Env, tree_id: u32, start: u64, count: u32) -> Result<Vec<BytesN<32>>, PoolError> {
    let (start, n) = page(e, tree_id, start, count)?;
    let mut out = Vec::new(e);
    for i in 0..u64::from(n) {
        let leaf = e
            .storage()
            .persistent()
            .get(&PoolKey::Leaf(tree_id, start + i))
            .expect("every index below size was written");
        out.push_back(leaf);
    }
    Ok(out)
}

/// Extend a tree's state, its latest root, and the current-tree pointer to
/// the network's maximum TTL.
pub fn renew_tree(e: &Env, tree_id: u32) -> Result<(), PoolError> {
    require_opened(e, tree_id)?;
    bump_if_present(e, &PoolKey::CurrentTree);
    if let Some(st) = state(e, tree_id) {
        bump(e, &PoolKey::Tree(tree_id));
        bump(e, &PoolKey::Root(tree_id, st.root));
    }
    Ok(())
}

/// Extend one root's entry to the maximum TTL, if the tree ever had it.
pub fn renew_root(e: &Env, tree_id: u32, root: &BytesN<32>) {
    bump_if_present(e, &PoolKey::Root(tree_id, root.clone()));
}

/// Extend leaves `start..start + count` of `tree_id` to the maximum TTL.
pub fn renew_leaves(e: &Env, tree_id: u32, start: u64, count: u32) -> Result<(), PoolError> {
    let (start, n) = page(e, tree_id, start, count)?;
    for i in 0..u64::from(n) {
        bump(e, &PoolKey::Leaf(tree_id, start + i));
    }
    Ok(())
}

/// Record that `account` inserted under `enrollment_id`, refusing a second
/// insertion under the same id.
pub fn claim_enrollment(
    e: &Env,
    account: &Address,
    enrollment_id: &BytesN<32>,
) -> Result<PoolKey, PoolError> {
    let key = PoolKey::Enrollment(account.clone(), enrollment_id.clone());
    if e.storage().persistent().has(&key) {
        return Err(PoolError::EnrollmentIdTaken);
    }
    Ok(key)
}

pub fn record_enrollment(e: &Env, key: &PoolKey, at: &Insertion) {
    e.storage().persistent().set(
        key,
        &LeafPosition {
            tree_id: at.tree_id,
            index: at.index,
        },
    );
    bump(e, key);
}

pub fn enrollment(e: &Env, account: &Address, enrollment_id: &BytesN<32>) -> Option<LeafPosition> {
    e.storage()
        .persistent()
        .get(&PoolKey::Enrollment(account.clone(), enrollment_id.clone()))
}

/// Extend one enrollment's position record and its leaf to the maximum TTL.
pub fn renew_enrollment(e: &Env, account: &Address, enrollment_id: &BytesN<32>) {
    let key = PoolKey::Enrollment(account.clone(), enrollment_id.clone());
    if let Some(at) = e.storage().persistent().get::<_, LeafPosition>(&key) {
        bump(e, &key);
        bump(e, &PoolKey::Leaf(at.tree_id, at.index));
    }
}
