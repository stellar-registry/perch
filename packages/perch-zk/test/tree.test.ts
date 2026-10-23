import { beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { init, node } from '../src/hash.js';
import {
  CHUNK_LEVEL,
  IncrementalTree,
  LeafChunks,
  MemoryNodeStore,
  PoolWitnessIndex,
  rootFromPath,
  zeroHashes,
} from '../src/tree.js';
import { hex } from '../src/field.js';
import type { Bytes32 } from '../src/field.js';
import { b, repo } from './helpers.js';

const leafN = (n: number) => b('0x' + n.toString(16).padStart(64, '0'));

/** The naive construction: every level rebuilt from all leaves. */
function naiveRoot(leaves: Bytes32[], depth: number): Bytes32 {
  const zeros = zeroHashes(depth);
  let level = leaves;
  for (let d = 0; d < depth; d++) {
    const next: Bytes32[] = [];
    for (let i = 0; i < Math.max(level.length, 1); i += 2) {
      next.push(node(level[i] ?? zeros[d]!, level[i + 1] ?? zeros[d]!));
    }
    level = next;
  }
  return level[0]!;
}

describe('IncrementalTree', () => {
  beforeAll(init);

  // Every size up to full, every chunk level: same root as a full rebuild,
  // and every leaf's path recomputes it.
  it('matches a full rebuild', async () => {
    const depth = 4;
    const all = Array.from({ length: 16 }, (_, i) => leafN(i + 1));
    for (let chunk = 0; chunk <= depth; chunk++) {
      const store = new LeafChunks(2 ** chunk);
      const tree = new IncrementalTree({ depth, chunkLevel: chunk });
      for (let n = 1; n <= all.length; n++) {
        store.push(all[n - 1]!);
        tree.append(all[n - 1]!);
        const root = naiveRoot(all.slice(0, n), depth);
        expect(hex(await tree.root(store.read))).toBe(hex(root));
        for (let i = 0; i < n; i++) {
          const w = await tree.witness(BigInt(i), store.read);
          expect(hex(rootFromPath(all[i]!, BigInt(i), w.siblings))).toBe(hex(root));
        }
      }
      expect(tree.sealed).toBe(true);
      expect(() => tree.append(all[0]!)).toThrow(/full/);
    }
  });
});

interface ReplayTree {
  tree_id: number;
  sealed: boolean;
  leaves: string[];
  root: string;
}

// `testdata/zk/witness-replay.json` is written by
// crates/perch-zk-pool's `witness_index_replays_the_pool_storage`: leaves read
// through the real pool's `leaves` pages, and the roots the pool reports
// (and accepts) for them. Replaying them through `PoolWitnessIndex` must give
// the pool's roots and a valid witness for every leaf, including the last
// leaf of each sealed tree.
describe('PoolWitnessIndex replays real pool storage', () => {
  beforeAll(init);
  const vector = JSON.parse(readFileSync(repo('testdata/zk/witness-replay.json'), 'utf8')) as Record<
    string,
    { depth: number; trees: ReplayTree[] }
  >;

  for (const [name, { depth, trees }] of Object.entries(vector)) {
    it(name, async () => {
      const stored = new Map<number, Bytes32[]>();
      const index = new PoolWitnessIndex(
        (treeId, start, count) => stored.get(treeId)!.slice(Number(start), Number(start) + count),
        { depth, chunkLevel: depth === 3 ? 1 : 3 },
      );
      for (const t of trees) {
        const leaves = t.leaves.map(b);
        stored.set(t.tree_id, leaves);
        leaves.forEach((leaf, i) => index.ingest({ treeId: t.tree_id, index: BigInt(i), leaf }));
      }
      for (const t of trees) {
        expect(hex(await index.root(t.tree_id))).toBe(t.root);
        expect(index.size(t.tree_id) === 1n << BigInt(depth)).toBe(t.sealed);
        const last = t.leaves.length - 1;
        for (const i of [0, last]) {
          const w = await index.witness(t.tree_id, BigInt(i));
          expect(hex(w.root)).toBe(t.root);
          expect(hex(rootFromPath(b(t.leaves[i]!), BigInt(i), w.siblings))).toBe(t.root);
        }
      }
    });
  }

  it('refuses insertions out of pool order', () => {
    const index = new PoolWitnessIndex(() => [], { depth: 2, chunkLevel: 1 });
    expect(() => index.ingest({ treeId: 0, index: 1n, leaf: leafN(1) })).toThrow(/out of order/);
    for (let i = 0; i < 4; i++) index.ingest({ treeId: 0, index: BigInt(i), leaf: leafN(i + 1) });
    expect(index.currentTree).toBe(1);
    expect(() => index.ingest({ treeId: 0, index: 4n, leaf: leafN(9) })).toThrow(/out of order/);
    index.ingest({ treeId: 1, index: 0n, leaf: leafN(10) });
  });
});

// The last leaf of a full depth-32 tree through the production witness code,
// after the pool has rolled over. The node store is what an indexer would
// have persisted for 2^32 identical leaves `x` (every subtree root at level l
// is `x` hashed up l times), written in closed form because ingesting 2^32
// leaves is out of reach; the leaf reader serves `x` for any chunk. The
// witness reads one 2^16-leaf chunk and 16 stored nodes.
describe('sealed depth-32 tree', () => {
  beforeAll(init);

  it('serves the last leaf after rollover', async () => {
    const x = leafN(7);
    const chain = [x];
    for (let l = 0; l < 32; l++) chain.push(node(chain[l]!, chain[l]!));
    const nodes0 = new MemoryNodeStore();
    for (let level = CHUNK_LEVEL; level <= 32; level++) {
      for (let k = 0n; k < 1n << BigInt(32 - level); k++) nodes0.set(level, k, chain[level]!);
    }
    const tree1 = [leafN(1), leafN(2)];
    const index = new PoolWitnessIndex(
      (treeId, _start, count) => (treeId === 0 ? Array(count).fill(x) : tree1.slice(0, count)),
      { nodes: (treeId) => (treeId === 0 ? nodes0 : new MemoryNodeStore()) },
    );
    index.restore({
      current: 1,
      trees: new Map([[0, { size: 1n << 32n, frontier: chain.slice(0, 32) }]]),
    });
    tree1.forEach((leaf, i) => index.ingest({ treeId: 1, index: BigInt(i), leaf }));

    const last = (1n << 32n) - 1n;
    const w = await index.witness(0, last);
    expect(hex(w.root)).toBe(hex(chain[32]!));
    expect(hex(rootFromPath(x, last, w.siblings))).toBe(hex(chain[32]!));
    expect(w.siblings.map(hex)).toEqual(chain.slice(0, 32).map(hex));
    expect(hex(await index.root(1))).toBe(hex(naiveRoot(tree1, 32)));
  }, 120_000);
});
