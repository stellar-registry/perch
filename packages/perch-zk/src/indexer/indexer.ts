// Trust-free witnesses for a perch membership pool. The indexer replays the
// pool's `LeafInserted` events into a store and serves Merkle paths from
// them. Nothing it returns is trusted: a client checks a witness's root with
// the pool's `is_known_root` before proving, and the adapter refuses any root
// the pool never recorded, so a stale or wrong index can only produce a proof
// that fails, never one that passes for the wrong leaf.
//
// Witnesses come from `PoolWitnessIndex`: stored leaves are appended to it in
// pool order, it keeps every completed subtree root at or above its chunk
// level, and a witness reads one chunk of leaves from the store, never the
// whole tree.

import { TREE_DEPTH, PoolWitnessIndex } from '../tree.js';
import type { NodeStore, TreeState } from '../tree.js';
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

/** What the witness index persists besides its node stores. */
export interface IndexSnapshot {
  current: number;
  trees: Map<number, TreeState>;
}

export interface PoolIndexerOptions {
  /** The pool's tree depth (default `TREE_DEPTH`). */
  depth?: number;
  /** A witness reads `2^chunkLevel` leaves from the store (default
   * `CHUNK_LEVEL`). */
  chunkLevel?: number;
  /** Each tree's completed subtree roots (default: in memory). A host that
   * persists them, with a `snapshot()`, resumes without replaying. */
  nodes?: (treeId: number) => NodeStore;
  /** A `snapshot()` taken with these node stores, to resume from. */
  restore?: IndexSnapshot;
}

/** Most leaves `leaves()` returns at once. */
export const MAX_LEAVES_PAGE = 1024;

/** Runs operations one at a time, in call order. */
class Serial {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.tail.then(fn);
    this.tail = next.catch(() => undefined);
    return next;
  }
}

export class PoolIndexer {
  readonly depth: number;
  private readonly index: PoolWitnessIndex;
  // Requests share one witness index: one at a time advances it and reads
  // it, so no request ingests a leaf another already has, and a witness's
  // siblings and root come from one tree size. Syncs take turns too, so a
  // cursor never moves back.
  private readonly indexing = new Serial();
  private readonly syncing = new Serial();

  constructor(
    readonly store: LeafStore,
    private readonly source: LeafSource,
    options: PoolIndexerOptions = {},
  ) {
    this.depth = options.depth ?? TREE_DEPTH;
    this.index = new PoolWitnessIndex((treeId, start, count) => this.read(treeId, start, count), {
      depth: this.depth,
      chunkLevel: options.chunkLevel,
      nodes: options.nodes,
    });
    if (options.restore) this.index.restore(options.restore);
  }

  private async read(treeId: number, start: bigint, count: number): Promise<Bytes32[]> {
    const out: Bytes32[] = [];
    for (let i = start; i < start + BigInt(count); i++) {
      const r = await this.store.get(treeId, i);
      if (!r) throw new Error(`tree ${treeId} leaf ${i} is not stored`);
      out.push(r.leaf);
    }
    return out;
  }

  /** Append every stored leaf the witness index has not seen, in pool
   * order, up to the first one not stored yet. Only inside `indexing`. */
  private async advance(): Promise<void> {
    for (;;) {
      const treeId = this.index.currentTree;
      const index = this.index.size(treeId);
      const r = await this.store.get(treeId, index);
      if (!r) return;
      this.index.ingest({ treeId, index, leaf: r.leaf });
    }
  }

  /** Pull pages until the source is caught up (or `maxPages` were read).
   * Witnesses and roots are served meanwhile, from the leaves indexed so
   * far. */
  sync(maxPages = 100): Promise<SyncResult> {
    return this.syncing.run(() => this.pull(maxPages));
  }

  private async pull(maxPages: number): Promise<SyncResult> {
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
    await this.indexing.run(() => this.advance());
    return out;
  }

  /** The witness index's state, to persist with its node stores. */
  snapshot(): IndexSnapshot {
    return this.index.snapshot();
  }

  /** Up to `count` (at most `MAX_LEAVES_PAGE`) leaves of `treeId` from
   * `from`, stopping at the first one not stored. */
  async leaves(treeId: number, from = 0n, count = MAX_LEAVES_PAGE): Promise<Bytes32[]> {
    const out: Bytes32[] = [];
    for (let i = from; i < from + BigInt(Math.min(count, MAX_LEAVES_PAGE)); i++) {
      const r = await this.store.get(treeId, i);
      if (!r) break;
      out.push(r.leaf);
    }
    return out;
  }

  /** The root of every leaf of `treeId` indexed so far. */
  root(treeId: number): Promise<Bytes32> {
    return this.indexing.run(async () => {
      await this.advance();
      return this.index.root(treeId);
    });
  }

  /** The witness for `account`'s enrollment `enrollmentId`, against the
   * root of every leaf indexed so far in its tree. Fails if the index has a
   * gap before the leaf. */
  async witness(account: string, enrollmentId: Bytes32): Promise<Witness> {
    const record = await this.store.find(account, enrollmentId);
    if (!record) throw new Error(`no leaf indexed for ${account} / ${hex(enrollmentId)}`);
    const path = await this.indexing.run(async () => {
      await this.advance();
      if (record.index >= this.index.size(record.treeId)) {
        throw new Error(`tree ${record.treeId} has a gap before index ${record.index}: sync again`);
      }
      return this.index.witness(record.treeId, record.index);
    });
    return {
      treeId: record.treeId,
      index: record.index,
      leaf: record.leaf,
      siblings: path.siblings,
      root: path.root,
    };
  }
}
