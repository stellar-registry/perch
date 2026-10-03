// A pool tree rebuilt from its leaves (the pool's `leaves` pages or its
// `LeafInserted` events), and witness paths into it. Mirrors
// crates/perch-zk-pool's incremental tree: interior nodes are H(left, right)
// and every slot not yet filled is the empty leaf 0.

import { node } from './hash.js';
import type { Bytes32 } from './field.js';

/** Depth of the release pool and circuit. */
export const TREE_DEPTH = 32;

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

export class Tree {
  readonly depth: number;
  private readonly levels: Bytes32[][];

  constructor(leaves: Bytes32[], depth: number = TREE_DEPTH) {
    if (BigInt(leaves.length) > 1n << BigInt(depth)) throw new Error('more leaves than slots');
    const zeros = zeroHashes(depth);
    this.depth = depth;
    this.levels = [leaves.slice()];
    for (let level = 0; level < depth; level++) {
      const cur = this.levels[level]!;
      const next: Bytes32[] = [];
      for (let i = 0; i < cur.length; i += 2) next.push(node(cur[i]!, cur[i + 1] ?? zeros[level]!));
      this.levels.push(next);
    }
  }

  get size(): number {
    return this.levels[0]!.length;
  }

  root(): Bytes32 {
    return this.levels[this.depth]![0] ?? zeroHashes(this.depth)[this.depth]!;
  }

  /** Sibling hashes from the leaf level up for the leaf at `index`. */
  path(index: number): Bytes32[] {
    if (!Number.isInteger(index) || index < 0 || index >= this.size) throw new Error(`no leaf at ${index}`);
    const zeros = zeroHashes(this.depth);
    const out: Bytes32[] = [];
    for (let level = 0; level < this.depth; level++) {
      // Plain arithmetic, not `^ 1`: bitwise operators truncate to 32 bits,
      // and a depth-32 tree's indices reach 2^32 - 1.
      const pos = Math.floor(index / 2 ** level);
      const sibling = pos % 2 === 0 ? pos + 1 : pos - 1;
      out.push(this.levels[level]![sibling] ?? zeros[level]!);
    }
    return out;
  }
}

/** Recompute a root from a leaf, its index, and its sibling path. */
export function rootFromPath(leafValue: Bytes32, index: bigint, siblings: Bytes32[]): Bytes32 {
  let cur = leafValue;
  siblings.forEach((sib, level) => {
    cur = (index >> BigInt(level)) & 1n ? node(sib, cur) : node(cur, sib);
  });
  return cur;
}
