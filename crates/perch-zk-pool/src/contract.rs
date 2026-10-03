use crate::merkle;
use crate::{LeafPosition, PoolError, TreeInfo, TREE_DEPTH, VERSION};
use perch_zk_primitives::{contract_id, is_canonical, Hasher};
use soroban_sdk::{contract, contractevent, contractimpl, Address, BytesN, Env, Vec};

/// Emitted for every insertion. Together with the `Leaf` storage entries,
/// this is what an indexer replays to rebuild a tree and serve witnesses.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeafInserted {
    #[topic]
    pub account: Address,
    #[topic]
    pub tree_id: u32,
    pub enrollment_id: BytesN<32>,
    pub index: u64,
    pub leaf: BytesN<32>,
    pub root: BytesN<32>,
}

#[contract]
pub struct PerchZkPool;

#[contractimpl]
impl PerchZkPool {
    /// See [`VERSION`].
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// `MembershipPoolInterface::depth`: see [`TREE_DEPTH`].
    pub fn depth(_e: &Env) -> u32 {
        TREE_DEPTH
    }

    /// Insert `commitment` (`H(DOM_LEAF, secret)`) for `account` under
    /// `enrollment_id` (spec §14.2). Invoker-only: `account.require_auth()`
    /// is satisfiable only by the account's own code calling, because the
    /// account refuses to sign reserved `rcv_*` names (spec §15). The pool,
    /// not the caller, derives the stored leaf from the account and the id,
    /// and refuses a second insertion under the same id. Returns nothing:
    /// the leaf's position is in the `LeafInserted` event and in
    /// [`Self::enrollment`].
    pub fn rcv_insert(
        e: &Env,
        account: Address,
        enrollment_id: BytesN<32>,
        commitment: BytesN<32>,
    ) -> Result<(), PoolError> {
        account.require_auth();
        let account_id = contract_id(e, &account).ok_or(PoolError::AccountNotContract)?;
        if !is_canonical(&commitment) {
            return Err(PoolError::NonCanonicalCommitment);
        }
        let claim = merkle::claim_enrollment(e, &account, &enrollment_id)?;

        let mut h = Hasher::new(e);
        let leaf = h.leaf(&account_id, &enrollment_id, &commitment);
        let at = merkle::append(e, &mut h, TREE_DEPTH, &leaf)?;
        merkle::record_enrollment(e, &claim, &at);
        LeafInserted {
            account,
            tree_id: at.tree_id,
            enrollment_id,
            index: at.index,
            leaf: at.leaf.clone(),
            root: at.root.clone(),
        }
        .publish(e);
        Ok(())
    }

    /// Where `account`'s enrollment `enrollment_id` landed, if it exists.
    pub fn enrollment(
        e: &Env,
        account: Address,
        enrollment_id: BytesN<32>,
    ) -> Option<LeafPosition> {
        merkle::enrollment(e, &account, &enrollment_id)
    }

    /// `MembershipPoolInterface::is_known_root`: whether `root` is a root
    /// tree `tree_id` of this pool has ever had.
    pub fn is_known_root(e: &Env, tree_id: u32, root: BytesN<32>) -> bool {
        merkle::is_known_root(e, tree_id, &root)
    }

    /// The tree insertions currently go into.
    pub fn current_tree(e: &Env) -> u32 {
        merkle::current_tree(e)
    }

    pub fn tree(e: &Env, tree_id: u32) -> Result<TreeInfo, PoolError> {
        merkle::tree_info(e, TREE_DEPTH, tree_id)
    }

    /// A page of `tree_id`'s leaves, for rebuilding witnesses from storage.
    pub fn leaves(
        e: &Env,
        tree_id: u32,
        start: u64,
        count: u32,
    ) -> Result<Vec<BytesN<32>>, PoolError> {
        merkle::leaves(e, tree_id, start, count)
    }

    /// Permissionless keep-alive: extend `tree_id`'s state and latest root
    /// (and the current-tree pointer) to the network's maximum TTL. Changes
    /// nothing else.
    pub fn renew_tree(e: &Env, tree_id: u32) -> Result<(), PoolError> {
        merkle::renew_tree(e, tree_id)
    }

    /// Permissionless keep-alive for one historical root a prover relies on.
    pub fn renew_root(e: &Env, tree_id: u32, root: BytesN<32>) {
        merkle::renew_root(e, tree_id, &root);
    }

    /// Permissionless keep-alive for a page of `tree_id`'s leaves.
    pub fn renew_leaves(e: &Env, tree_id: u32, start: u64, count: u32) -> Result<(), PoolError> {
        merkle::renew_leaves(e, tree_id, start, count)
    }

    /// Permissionless keep-alive for one enrollment's record and leaf.
    pub fn renew_enrollment(e: &Env, account: Address, enrollment_id: BytesN<32>) {
        merkle::renew_enrollment(e, &account, &enrollment_id);
    }
}
