// Trust-free witnesses for a perch membership pool. The indexer replays the
// pool's `LeafInserted` events into a store and serves Merkle paths from
// them. Nothing it returns is trusted: a client checks a witness's root with
// the pool's `is_known_root` before proving, and the adapter refuses any root
// the pool never recorded, so a stale or wrong index can only produce a proof
// that fails, never one that passes for the wrong leaf.

import { TREE_DEPTH, Tree } from '../tree.js';
import { hex } from '../field.js';
import type { Bytes32 } from '../field.js';
import type { LeafRecord, LeafStore } from './store.js';

/** A resumable source of a pool's insertions, oldest first. */
export interface LeafSource {
  /** The next page after `cursor` (from the start when undefined), and the
   * cursor to resume from. An empty page means caught up. */
  page(cursor: string | undefined): Promise<{ records: LeafRecord[]; cursor: string | undefined }>;
}

/** A Merkle witness for one enrollment's leaf. */
export interface Witness {
  treeId: number;
  index: bigint;
  leaf: Bytes32;
  siblings: Bytes32[];
  /** The root the witness proves against: check it is a known root of the
   * enrolled pool's `treeId` before proving. */
  root: Bytes32;
}

export interface SyncResult {
  inserted: number;
  /** Records that disagreed with stored ones. They were not applied: the
   * source contradicted itself, which the indexer cannot resolve. */
  conflicts: LeafRecord[];
}

export class PoolIndexer {
  constructor(
    readonly store: LeafStore,
    private readonly source: LeafSource,
    readonly depth: number = TREE_DEPTH,
  ) {}

  /** Pull pages until the source is caught up (or `maxPages` were read). */
  async sync(maxPages = 100): Promise<SyncResult> {
    const out: SyncResult = { inserted: 0, conflicts: [] };
    let cursor = await this.store.getCursor();
    for (let i = 0; i < maxPages; i++) {
      const { records, cursor: next } = await this.source.page(cursor);
      for (const r of records) {
        const result = await this.store.put(r);
        if (result === 'inserted') out.inserted++;
        if (result === 'conflict') out.conflicts.push(r);
      }
      if (next !== undefined && next !== cursor) {
        cursor = next;
        await this.store.setCursor(next);
      }
      if (records.length === 0 || next === undefined) break;
    }
    return out;
  }

  /** The leaves of `treeId` stored contiguously from index 0. */
  async leaves(treeId: number, from = 0n): Promise<Bytes32[]> {
    const size = await this.store.size(treeId);
    const out: Bytes32[] = [];
    for (let i = from; i < size; i++) out.push((await this.store.get(treeId, i))!.leaf);
    return out;
  }

  /** The tree rebuilt from what has been indexed. */
  async tree(treeId: number): Promise<Tree> {
    return new Tree(await this.leaves(treeId), this.depth);
  }

  /** The witness for `account`'s enrollment `enrollmentId`, against the
   * root of every leaf indexed so far in its tree. Fails if the index has a
   * gap before the leaf. */
  async witness(account: string, enrollmentId: Bytes32): Promise<Witness> {
    const record = await this.store.find(account, enrollmentId);
    if (!record) throw new Error(`no leaf indexed for ${account} / ${hex(enrollmentId)}`);
    const size = await this.store.size(record.treeId);
    if (record.index >= size) {
      throw new Error(`tree ${record.treeId} has a gap before index ${record.index}: sync again`);
    }
    const tree = await this.tree(record.treeId);
    return {
      treeId: record.treeId,
      index: record.index,
      leaf: record.leaf,
      siblings: tree.path(Number(record.index)),
      root: tree.root(),
    };
  }
}
