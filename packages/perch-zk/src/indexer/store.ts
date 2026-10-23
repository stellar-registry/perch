// Where an indexer keeps a pool's leaves. Positions are permanent: a pool
// never rewrites `(tree_id, index)`, so a store only appends, and a record
// that disagrees with one already stored is refused, never applied.

import { hex } from '../field.js';
import type { Bytes32 } from '../field.js';

/** One `LeafInserted` event of a perch membership pool. */
export interface LeafRecord {
  treeId: number;
  /** Position in the tree (`u64` on-chain). */
  index: bigint;
  leaf: Bytes32;
  /** The tree's root right after this insertion. */
  root: Bytes32;
  /** The inserting account (`C...`). */
  account: string;
  enrollmentId: Bytes32;
  /** The ledger the insertion closed in, when the source knows it. */
  ledger?: number;
}

export type PutResult = 'inserted' | 'duplicate' | 'conflict';

export interface LeafStore {
  /** Append `record`. A byte-identical repeat is a `duplicate`; a different
   * leaf at a stored position is a `conflict` and changes nothing. */
  put(record: LeafRecord): Promise<PutResult>;
  /** The record at a position, if stored. */
  get(treeId: number, index: bigint): Promise<LeafRecord | undefined>;
  /** How many leaves of `treeId` are stored contiguously from index 0. */
  size(treeId: number): Promise<bigint>;
  /** Every tree id seen, ascending. */
  trees(): Promise<number[]>;
  /** Where `account` inserted `enrollmentId`, if seen. */
  find(account: string, enrollmentId: Bytes32): Promise<LeafRecord | undefined>;
  /** The source's resume cursor, persisted between syncs. */
  getCursor(): Promise<string | undefined>;
  setCursor(cursor: string): Promise<void>;
}

const same = (a: LeafRecord, b: LeafRecord) =>
  a.treeId === b.treeId &&
  a.index === b.index &&
  hex(a.leaf) === hex(b.leaf) &&
  hex(a.root) === hex(b.root) &&
  a.account === b.account &&
  hex(a.enrollmentId) === hex(b.enrollmentId);

/** An in-memory store, for tests, scripts, and short-lived processes. */
export class MemoryStore implements LeafStore {
  private readonly byTree = new Map<number, Map<bigint, LeafRecord>>();
  private readonly byEnrollment = new Map<string, LeafRecord>();
  private cursor: string | undefined;

  async put(record: LeafRecord): Promise<PutResult> {
    const tree = this.byTree.get(record.treeId) ?? new Map<bigint, LeafRecord>();
    const existing = tree.get(record.index);
    if (existing) return same(existing, record) ? 'duplicate' : 'conflict';
    tree.set(record.index, record);
    this.byTree.set(record.treeId, tree);
    this.byEnrollment.set(`${record.account}/${hex(record.enrollmentId)}`, record);
    return 'inserted';
  }

  async get(treeId: number, index: bigint): Promise<LeafRecord | undefined> {
    return this.byTree.get(treeId)?.get(index);
  }

  async size(treeId: number): Promise<bigint> {
    const tree = this.byTree.get(treeId);
    let n = 0n;
    while (tree?.has(n)) n++;
    return n;
  }

  async trees(): Promise<number[]> {
    return [...this.byTree.keys()].sort((a, b) => a - b);
  }

  async find(account: string, enrollmentId: Bytes32): Promise<LeafRecord | undefined> {
    return this.byEnrollment.get(`${account}/${hex(enrollmentId)}`);
  }

  async getCursor(): Promise<string | undefined> {
    return this.cursor;
  }

  async setCursor(cursor: string): Promise<void> {
    this.cursor = cursor;
  }
}
