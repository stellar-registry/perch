// Merkle witnesses for a perch membership pool, scaled to full depth-32 trees.
//
// Mirrors crates/perch-zk-pool's incremental tree (interior nodes H(left,
// right), every unfilled slot the empty leaf 0), but never materializes a
// tree. An `IncrementalTree` is fed leaves in insertion order and keeps only:
//
// - a `depth`-sized frontier (the most recent left child at every level);
// - the roots of completed subtrees at or above `chunkLevel` (default 16), in
//   a pluggable `NodeStore`. A full depth-32 tree has about 2^17 of them.
//
// Leaves themselves stay wherever the caller keeps them (an indexer's
// database, the pool's `leaves` pages, an in-memory `LeafChunks`). A witness
// reads only the `2^chunkLevel`-leaf chunk its leaf is in, plus the partly
// filled last chunk when the tree is not full: a constant amount of work
// whatever the tree's size.

import { node } from './hash.js';
import type { Bytes32 } from './field.js';

/** Depth of the release pool and circuit. */
export const TREE_DEPTH = 32;

/** Default chunk level: witnesses read `2^16` leaves; the node store holds
 * about `size / 2^15` subtree roots. */
export const CHUNK_LEVEL = 16;

const zeroCache = new Map<number, Bytes32[]>();

/** `zero[i]`: root of an empty depth-`i` subtree, for `i` in `0..=depth`. */
export function zeroHashes(depth: number = TREE_DEPTH): Bytes32[] {
  const cached = zeroCache.get(depth);
  if (cached) return cached;
  const out: Bytes32[] = [new Uint8Array(32)];
  for (let i = 0; i < depth; i++) out.push(node(out[i]!, out[i]!));
  zeroCache.set(depth, out);
  return out;
}

/** Recompute a root from a leaf, its index, and its sibling path. */
export function rootFromPath(leafValue: Bytes32, index: bigint, siblings: Bytes32[]): Bytes32 {
  let cur = leafValue;
  siblings.forEach((sib, level) => {
    cur = (index >> BigInt(level)) & 1n ? node(sib, cur) : node(cur, sib);
  });
  return cur;
}

/** Completed subtree roots, keyed by `(level, index at that level)`. */
export interface NodeStore {
  get(level: number, index: bigint): Bytes32 | undefined;
  set(level: number, index: bigint, value: Bytes32): void;
}

export class MemoryNodeStore implements NodeStore {
  private readonly nodes = new Map<string, Bytes32>();
  get(level: number, index: bigint): Bytes32 | undefined {
    return this.nodes.get(`${level}:${index}`);
  }
  set(level: number, index: bigint, value: Bytes32): void {
    this.nodes.set(`${level}:${index}`, value);
  }
  get count(): number {
    return this.nodes.size;
  }
}

/** Reads leaves `start..start + count` of the tree, in order. */
export type LeafReader = (start: bigint, count: number) => Bytes32[] | Promise<Bytes32[]>;

/** Leaves kept in memory in fixed-size chunks, never one big array. */
export class LeafChunks {
  private readonly chunks = new Map<bigint, Bytes32[]>();
  private length = 0n;
  constructor(readonly chunkSize: number = 2 ** CHUNK_LEVEL) {}

  push(leaf: Bytes32): void {
    const c = this.length / BigInt(this.chunkSize);
    let chunk = this.chunks.get(c);
    if (!chunk) this.chunks.set(c, (chunk = []));
    chunk.push(leaf);
    this.length++;
  }

  get size(): bigint {
    return this.length;
  }

  read: LeafReader = (start, count) => {
    const out: Bytes32[] = [];
    for (let i = start; i < start + BigInt(count); i++) {
      const leaf = this.chunks.get(i / BigInt(this.chunkSize))?.[Number(i % BigInt(this.chunkSize))];
      if (!leaf) throw new Error(`leaf ${i} is not stored`);
      out.push(leaf);
    }
    return out;
  };
}

/** What an `IncrementalTree` persists besides its node store. */
export interface TreeState {
  size: bigint;
  /** `frontier[level]`: the most recent node at `level` that was a left child. */
  frontier: Bytes32[];
}

export interface TreeOptions {
  depth?: number;
  chunkLevel?: number;
  nodes?: NodeStore;
  /** Resume from a persisted state (with the node store it was built with). */
  state?: TreeState;
}

/** A Merkle path and the root it proves against. */
export interface MerklePath {
  root: Bytes32;
  siblings: Bytes32[];
}

/** Hash `leaves` (padded with empty leaves) into a complete subtree of
 * `height` levels, returning every level, leaves first. */
function subtree(leaves: Bytes32[], height: number): Bytes32[][] {
  const zeros = zeroHashes(height);
  const levels = [leaves];
  for (let level = 0; level < height; level++) {
    const cur = levels[level]!;
    const next: Bytes32[] = [];
    for (let i = 0; i < Math.max(cur.length, 1); i += 2) {
      next.push(node(cur[i] ?? zeros[level]!, cur[i + 1] ?? zeros[level]!));
    }
    levels.push(next);
  }
  return levels;
}

export class IncrementalTree {
  readonly depth: number;
  readonly chunkLevel: number;
  readonly nodes: NodeStore;
  private count: bigint;
  private readonly frontier: Bytes32[];

  constructor(options: TreeOptions = {}) {
    this.depth = options.depth ?? TREE_DEPTH;
    this.chunkLevel = Math.min(options.chunkLevel ?? CHUNK_LEVEL, this.depth);
    this.nodes = options.nodes ?? new MemoryNodeStore();
    const zeros = zeroHashes(this.depth);
    this.count = options.state?.size ?? 0n;
    this.frontier = options.state?.frontier.slice() ?? zeros.slice(0, this.depth);
  }

  get size(): bigint {
    return this.count;
  }

  get capacity(): bigint {
    return 1n << BigInt(this.depth);
  }

  get sealed(): boolean {
    return this.count === this.capacity;
  }

  snapshot(): TreeState {
    return { size: this.count, frontier: this.frontier.slice() };
  }

  /** Append the next leaf. Amortized two hashes; stores every subtree root
   * the insertion completes at or above `chunkLevel`. */
  append(leaf: Bytes32): void {
    if (this.sealed) throw new Error('tree is full');
    const index = this.count;
    if (this.chunkLevel === 0) this.nodes.set(0, index, leaf);
    let cur = leaf;
    for (let level = 0; level < this.depth; level++) {
      if (((index >> BigInt(level)) & 1n) === 0n) {
        this.frontier[level] = cur;
        break;
      }
      cur = node(this.frontier[level]!, cur);
      if (level + 1 >= this.chunkLevel) this.nodes.set(level + 1, index >> BigInt(level + 1), cur);
    }
    this.count++;
  }

  /** The value of node `index` at `level` for the current size. */
  private async value(level: number, index: bigint, read: LeafReader): Promise<Bytes32> {
    const start = index << BigInt(level);
    const span = 1n << BigInt(level);
    if (start >= this.count) return zeroHashes(this.depth)[level]!;
    const complete = start + span <= this.count;
    if (complete && level >= this.chunkLevel) {
      const stored = this.nodes.get(level, index);
      if (!stored) throw new Error(`node store has no node (${level}, ${index})`);
      return stored;
    }
    if (level <= this.chunkLevel) {
      const end = complete ? start + span : this.count;
      const leaves = await read(start, Number(end - start));
      return subtree(leaves, level)[level]![0]!;
    }
    // A partly filled node above the chunk level: one child is complete or
    // empty, the other partly filled, so this recursion is at most `depth`
    // deep and bottoms out in one partial chunk.
    const left = await this.value(level - 1, index * 2n, read);
    const right = await this.value(level - 1, index * 2n + 1n, read);
    return node(left, right);
  }

  async root(read: LeafReader): Promise<Bytes32> {
    return this.value(this.depth, 0n, read);
  }

  /** The witness for the leaf at `index`, against the current root. Reads
   * the leaf's chunk and, if the tree is not full, its last chunk. */
  async witness(index: bigint, read: LeafReader): Promise<MerklePath> {
    if (index < 0n || index >= this.count) throw new Error(`no leaf at ${index}`);
    const height = this.chunkLevel;
    const chunkStart = (index >> BigInt(height)) << BigInt(height);
    const chunkEnd = chunkStart + (1n << BigInt(height));
    const leaves = await read(chunkStart, Number((chunkEnd < this.count ? chunkEnd : this.count) - chunkStart));
    const levels = subtree(leaves, height);
    const zeros = zeroHashes(this.depth);
    const siblings: Bytes32[] = [];
    for (let level = 0; level < height; level++) {
      const pos = (index - chunkStart) >> BigInt(level);
      const sib = Number(pos % 2n === 0n ? pos + 1n : pos - 1n);
      siblings.push(levels[level]![sib] ?? zeros[level]!);
    }
    for (let level = height; level < this.depth; level++) {
      const pos = index >> BigInt(level);
      siblings.push(await this.value(level, pos % 2n === 0n ? pos + 1n : pos - 1n, read));
    }
    return { root: await this.root(read), siblings };
  }
}

/** One insertion of a pool, as its `LeafInserted` event reports it. */
export interface Insertion {
  treeId: number;
  index: bigint;
  leaf: Bytes32;
}

/** Leaf storage an indexer provides, per tree. */
export interface PoolLeafReader {
  (treeId: number, start: bigint, count: number): Bytes32[] | Promise<Bytes32[]>;
}

/** Witnesses for every tree of one pool: ingests insertions in order,
 * follows rollover, and keeps one `IncrementalTree` per tree. Sealed trees
 * stay witnessable for good. */
export class PoolWitnessIndex {
  private readonly trees = new Map<number, IncrementalTree>();
  private current = 0;

  constructor(
    private readonly read: PoolLeafReader,
    private readonly options: { depth?: number; chunkLevel?: number; nodes?: (treeId: number) => NodeStore } = {},
  ) {}

  private tree(treeId: number): IncrementalTree {
    let t = this.trees.get(treeId);
    if (!t) {
      t = new IncrementalTree({
        depth: this.options.depth,
        chunkLevel: this.options.chunkLevel,
        nodes: this.options.nodes?.(treeId),
      });
      this.trees.set(treeId, t);
    }
    return t;
  }

  /** The tree new insertions go into. */
  get currentTree(): number {
    return this.current;
  }

  size(treeId: number): bigint {
    return this.trees.get(treeId)?.size ?? 0n;
  }

  /** Apply the next insertion. Insertions must arrive in pool order: the
   * next index of the current tree, which moves to the next tree as soon as
   * an insertion seals it (as the pool does). Anything else is refused, not
   * reordered. */
  ingest(insertion: Insertion): void {
    const t = this.tree(this.current);
    if (insertion.treeId !== this.current || insertion.index !== t.size) {
      throw new Error(
        `out of order: expected tree ${this.current} index ${t.size}, got tree ${insertion.treeId} index ${insertion.index}`,
      );
    }
    t.append(insertion.leaf);
    if (t.sealed) this.current++;
  }

  /** Persisted state of every tree, for resuming without replaying. Store
   * it together with each tree's node store. */
  snapshot(): { current: number; trees: Map<number, TreeState> } {
    const trees = new Map<number, TreeState>();
    for (const [id, t] of this.trees) trees.set(id, t.snapshot());
    return { current: this.current, trees };
  }

  /** Resume from a `snapshot()` whose node stores `options.nodes` returns. */
  restore(snapshot: { current: number; trees: Map<number, TreeState> }): void {
    this.trees.clear();
    for (const [id, state] of snapshot.trees) {
      this.trees.set(
        id,
        new IncrementalTree({
          depth: this.options.depth,
          chunkLevel: this.options.chunkLevel,
          nodes: this.options.nodes?.(id),
          state,
        }),
      );
    }
    this.current = snapshot.current;
  }

  async root(treeId: number): Promise<Bytes32> {
    return this.tree(treeId).root((s, c) => this.read(treeId, s, c));
  }

  async witness(treeId: number, index: bigint): Promise<MerklePath> {
    return this.tree(treeId).witness(index, (s, c) => this.read(treeId, s, c));
  }
}
