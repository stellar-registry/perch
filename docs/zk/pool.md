# The membership pool

`crates/perch-zk-pool` is the pool a ZK recovery proof shows membership in,
implementing `docs/recovery/spec.md` §14.
It replaces the pool half of Nido's combined `contracts/zk-recovery`
contract. That contract was constructor-configured, held an upgradeable admin
key, and gave a configured factory authority to enroll any account. This pool
has none of those: no constructor, no admin, no upgrade entry point, and no
factory. It also holds no recovery state machine, which is the controller's.

## Entry points

| Entry point | Auth | Effect |
| --- | --- | --- |
| `rcv_insert(account, enrollment_id, commitment)` (returns nothing) | `account`, invoker-only | appends `H(DOM_BIND, account, enrollment_id, commitment)`; once per `(account, enrollment_id)` |
| `enrollment(account, enrollment_id) -> Option<LeafPosition>` | none | where that enrollment's leaf is |
| `is_known_root(tree_id, root) -> bool` | none | `MembershipPoolInterface`, the adapter's root check |
| `depth() -> u32` | none | `MembershipPoolInterface`; the controller compares it with the adapter's `tree_depth()` |
| `current_tree()`, `tree(id)`, `leaves(id, start, count)` | none | reads for clients and indexers |
| `renew_tree(id)`, `renew_root(id, root)`, `renew_leaves(id, start, count)`, `renew_enrollment(account, enrollment_id)` | none | extend TTLs to the network maximum; change nothing else |
| `version()` | none | build constant |

`rcv_insert` is invoker-only (spec §15). It calls `account.require_auth()`,
and the account refuses to sign reserved `rcv_*` names, so only the account's
own `apply_doc` can satisfy it. That flow inserts exactly when the
configuration names a new enrollment id. `rcv_insert` refuses a non-contract
`account` (`AccountNotContract`), a commitment `>= r`
(`NonCanonicalCommitment`), and a reused enrollment id (`EnrollmentIdTaken`).
The pool computes the leaf from the authorized `account` itself, so no caller
can store a leaf bound to an account that did not sign.

**One leaf per `(account, enrollment_id)`.** An account's recovery
configuration names the enrollment id its ZK factor accepts. A second leaf
under that id, with a secret someone else knows, would satisfy the ZK factor
without the enrolled secret, and would give the credential a second
nullifier. The account already refuses this (spec §3.4); the pool refuses it
again as defense in depth. The record that enforces the rule,
`Enrollment(account, id)`, is also how a client finds its leaf.

## Capacity, rollover, and tree identification

- A tree has `2^TREE_DEPTH` leaves (depth 32: 4,294,967,296). Leaf indices
  and counts are `u64`, because a full depth-32 tree's capacity does not fit
  in a `u32`. Trees are numbered by a `u32` `tree_id` from 0.
- Rollover is eager. The insert that fills a tree's last slot also advances
  `CurrentTree`, so the current tree always has room and no enrollment ever
  fails because a tree is full. The full tree is sealed and never written
  again.
- Every root is identified as `(tree_id, root)`. The adapter accepts a root
  only if the enrolled pool retains it for the tree the evidence names. A root
  is never accepted for a different tree, nor by a pool that never computed
  it.

## Root retention

The pool keeps a `Root(tree_id, root)` entry for every root produced by an
insertion, paid for by the inserter. `is_known_root(tree_id, root)` is true
exactly when that entry exists (spec §14.1).

- **Every historical root stays acceptable.** Trees are append-only, so an
  old root proves membership as soundly as the latest one. A recent-roots
  window would be a denial of service: anyone can insert leaves bound to
  their own address, and inserting faster than a victim can prove would push
  the victim's root out before their proof landed. Under `Protected`
  `ZkOnly`, that would block the owner's ZK cancellation while a thief's
  attempt ran out its delay (`every_historical_root_stays_acceptable`,
  `evidence_against_an_older_root_survives_later_insertions`).
- **A sealed tree** never changes. Its roots, including its final root, stay
  acceptable for as long as their entries are kept alive or restored.
  Witnesses for a sealed tree can be computed once and cached
  (`earlier_tree`).
- **An empty tree's root** is never accepted. No insertion produced it, so no
  leaf could be proven under it.

## Storage layout

Every entry is persistent. An expired entry is archived, never deleted.

| Key | Value | Written by |
| --- | --- | --- |
| `CurrentTree` | `u32` | rollover (absent means tree 0) |
| `Tree(id)` | `TreeState { size: u64, root, frontier: Vec<BytesN<32>> }` | every insertion into `id` |
| `Root(id, root)` | `u64`, the tree size right after `root` | the insertion that produced `root` |
| `Leaf(id, index: u64)` | `BytesN<32>` | the insertion of that leaf |
| `Enrollment(account, enrollment_id)` | `LeafPosition { tree_id, index }` | that account's enrollment |

The keys are a `#[contracttype]` enum (`PoolKey`). The layout is public:
`PoolKey` and `TreeState` are exported for tooling.

## Witnesses and indexers

A proof needs the leaf's 32 siblings at the time of some retained root. Both
provers rebuild a tree from its ordered leaves and read the path
(`perch_zk_prover::Tree` and `packages/perch-zk`'s `Tree`, which use the same
`ZERO_HASHES` for empty subtrees). The leaves come from either source:

- **Contract storage.** `leaves(tree_id, start, count)` pages (64 at a time),
  or `Leaf(id, index)` entries read directly with `getLedgerEntries`. This
  does not depend on how long an RPC provider retains events. That is why the
  pool pays for one `Leaf` entry per enrollment.
- **Events.** `LeafInserted { account, tree_id, enrollment_id, index, leaf,
  root }` for every insertion, which the reusable indexer persists and
  replays (spec §14.3). RPC providers keep events only briefly.

`enrollment(account, enrollment_id)` gives a client its own leaf's position.
`tree(tree_id).root` and `is_known_root` let a client check its rebuilt tree
before it proves. Because every historical root stays acceptable, a client
can prove against any root its rebuilt tree has had.

## Renewal and restoration

Every write extends the entries it touches to the network's maximum TTL
(`max_entry_ttl`, 3,110,400 ledgers, about 180 days). `is_known_root` also
renews the root entry it confirms, so a check keeps alive the root it relies
on. Entries that nothing touches expire. A sealed tree's leaves and roots and
the enrollment records of idle accounts are the typical case. For those,
`renew_tree`, `renew_root`, `renew_leaves`, and `renew_enrollment` are
permissionless, extend only, and can be called by anyone: a wallet, a
keeper, or the account itself. A prover whose root entry has been archived
restores it, or proves against a newer root.

Expiry is not loss. A persistent entry past its TTL is archived. The host
never reads an archived entry as absent; any access restores it first,
through the transaction footprint's automatic restoration since protocol 23,
or explicitly with `RestoreFootprint`. An archived tree therefore resumes
where it stopped. It is never silently restarted at index 0, and its old
roots stay provable. `archived_tree_is_restored_not_reset` archives a tree's
state, root entry, leaf, and enrollment record, then shows that the next
insertion lands at index 1 and the earlier root still verifies.

## Testing without 2^32 inserts

The Merkle code (`merkle.rs`) takes the depth as a parameter, and the
contract always passes `TREE_DEPTH`. The tests drive the same code at depth 2
to fill trees, roll over repeatedly, and check that sealed trees' roots
survive (`full_tree_rolls_over_and_keeps_its_roots`). The real depth-32
boundary is reached by writing a `TreeState` one slot short of full, with an
all-empty frontier, and filling the last slot through the real `rcv_insert`
entry point. The resulting root is checked against an independent
computation, the next insertion lands in tree 1, and a real proof for that
last slot verifies after rollover (`earlier_tree`). Roots are also checked
against a from-scratch level-by-level recomputation, not the frontier
algorithm itself (`roots_match_an_independent_recomputation`).

## Costs

See [`measurements.md`](measurements.md). A typical insertion at depth 32 is
about 43.5M instructions (10.9% of the transaction limit) and writes five
entries. Three of the five are new: `Root`, `Leaf`, and `Enrollment`. Those
three dominate the fee, through rent.
